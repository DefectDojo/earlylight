package pkgdb

import (
	"errors"
	"path"
	"sort"
	"strings"
	"sync"
)

// Resolver knows the symbolic and hard links of a scanned filesystem and maps
// a path to the other paths that name the same file, so a file found at
// /usr/bin/bash is matched with a package database that lists /bin/bash
// (merged /usr), and a hard-linked copy is matched with the name a package
// lists.
//
// How to feed it, during the single walk over the filesystem or image tar:
//
//   - every symbolic link: AddSymlink(abs, target), where abs is the link's
//     absolute path within the scanned root ("/bin", "/etc/os-release") and
//     target is the link text exactly as stored ("usr/bin",
//     "../usr/lib/os-release", "/usr/bin/php8.2"). Relative targets are
//     relative to the link's directory; absolute targets are interpreted inside
//     the scanned root (chroot semantics), never on the host;
//   - every tar hard link entry: AddHardlink(abs, target), with target the
//     entry's Linkname made absolute ("usr/bin/php8.2" -> "/usr/bin/php8.2").
//     For a directory walk, pass files sharing (device, inode) the same way.
//
// For an image, feed the flattened (whiteouts applied) view: a link removed by
// a later layer must not be added. Paths are cleaned; a link added twice keeps
// the last target. Resolution is bounded: at most maxLinkHops symlink
// expansions per lookup (Linux allows 40), so loops end with an error.
//
// A Resolver may be read (Canonical, Resolve, Aliases) from several goroutines
// once it is fully fed; adding links concurrently with reads is not supported.
type Resolver struct {
	links map[string]string   // symlink path -> target as written
	hard  map[string][]string // hard link group key -> members (see AddHardlink)
	group map[string]string   // member path -> group key

	mu      sync.Mutex
	rev     map[string][]string // resolved symlink target -> symlink paths
	revDone bool
}

const (
	maxLinkHops   = 40
	maxAliases    = 256
	maxPathLength = 4096    // longest symlink target followed
	maxComponents = 1 << 16 // most path components pending during a lookup
)

// ErrLinkLoop is returned when resolving a path needs more than 40 symlink
// expansions.
var ErrLinkLoop = errors.New("too many levels of symbolic links")

// NewResolver returns a resolver for the given symlinks (absolute path ->
// target as written). The map may be nil; more links can be added later.
func NewResolver(symlinks map[string]string) *Resolver {
	r := &Resolver{links: map[string]string{}, hard: map[string][]string{}, group: map[string]string{}}
	for p, t := range symlinks {
		r.AddSymlink(p, t)
	}
	return r
}

func clean(p string) string { return path.Clean("/" + p) }

// AddSymlink records a symbolic link.
func (r *Resolver) AddSymlink(abs, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links[clean(abs)] = target
	r.revDone = false
}

// AddHardlink records that abs is a hard link to target (both name one inode).
func (r *Resolver) AddHardlink(abs, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, b := clean(abs), clean(strings.TrimPrefix(target, "./"))
	ga, okA := r.group[a]
	gb, okB := r.group[b]
	switch {
	case okA && okB && ga == gb:
		return
	case okA && okB: // merge b's group into a's
		for _, m := range r.hard[gb] {
			r.group[m] = ga
		}
		r.hard[ga] = append(r.hard[ga], r.hard[gb]...)
		delete(r.hard, gb)
	case okA:
		r.group[b] = ga
		r.hard[ga] = append(r.hard[ga], b)
	case okB:
		r.group[a] = gb
		r.hard[gb] = append(r.hard[gb], a)
	default:
		r.group[a], r.group[b] = b, b
		r.hard[b] = []string{a, b}
	}
}

// Canonical resolves symlinks in the directories of p (not its last
// component) and returns the cleaned absolute path of the directory entry p
// names. "/bin/bash" becomes "/usr/bin/bash" when /bin -> usr/bin.
func (r *Resolver) Canonical(p string) (string, error) {
	if r == nil {
		return clean(p), nil
	}
	return r.walk(p, false)
}

// Resolve is Canonical that also follows a symlink in the last component, so
// it returns the path of the file p finally refers to ("/usr/bin/php" ->
// "/usr/bin/php8.2" through /etc/alternatives). A dangling link resolves to the
// missing target's path.
func (r *Resolver) Resolve(p string) (string, error) {
	if r == nil {
		return clean(p), nil
	}
	return r.walk(p, true)
}

func (r *Resolver) walk(p string, followLast bool) (string, error) {
	pending := splitPath(p) // components still to resolve, in order
	resolved := ""          // canonical prefix, "" means "/"
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir("/" + resolved)
			if resolved == "/" {
				resolved = ""
			} else {
				resolved = strings.TrimPrefix(resolved, "/")
			}
			continue
		}
		cand := "/" + resolved + "/" + c
		if resolved == "" {
			cand = "/" + c
		}
		t, isLink := r.links[cand]
		if !isLink || (len(pending) == 0 && !followLast) {
			resolved = strings.TrimPrefix(cand, "/")
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", ErrLinkLoop
		}
		if len(t) > maxPathLength || len(pending) > maxComponents {
			return "", errors.New("path too long")
		}
		tc := splitPath(t)
		if strings.HasPrefix(t, "/") {
			resolved = ""
		}
		pending = append(tc, pending...)
	}
	return "/" + resolved, nil
}

func splitPath(p string) []string { return strings.Split(strings.Trim(p, "/"), "/") }

// buildReverse indexes each symlink by its fully resolved target.
func (r *Resolver) buildReverse() map[string][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revDone {
		return r.rev
	}
	rev := map[string][]string{}
	for l := range r.links {
		t, err := r.walk(l, true)
		if err != nil || t == l {
			continue
		}
		rev[t] = append(rev[t], l)
	}
	r.rev, r.revDone = rev, true
	return rev
}

// Aliases returns every path that names the same file as p through symlinked
// parent directories and hard links: p itself, its canonical path, and each
// path obtained by replacing a directory prefix with a symlink that resolves to
// it, or the file with a member of its hard link group. A symlink to the file
// itself is not an alias (it is a different directory entry). The result is
// sorted, deduplicated and bounded to 256 paths. p is expected clean and
// absolute, as a walk produces it; a path with "." or ".." components that
// cross symlinks is first resolved physically.
func (r *Resolver) Aliases(p string) []string {
	start := clean(p)
	if r == nil {
		return []string{start}
	}
	rev := r.buildReverse()
	// p is resolved physically: "/dir/." or "/a/link/.." through symlinks
	// names what the links point to, not what path.Clean says. A clean path
	// (what a walk produces) is its own alias.
	if c, err := r.Canonical(p); err == nil {
		if cs, err := r.Canonical(start); err != nil || cs != c {
			start = c
		}
	}
	seen := map[string]bool{start: true}
	queue := []string{start}
	add := func(s string) {
		if len(seen) < maxAliases && !seen[s] {
			seen[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		a := queue[0]
		queue = queue[1:]
		c, err := r.Canonical(a)
		if err != nil {
			continue
		}
		add(c)
		if g, ok := r.group[c]; ok {
			for _, m := range r.hard[g] {
				add(m)
			}
		}
		if g, ok := r.group[a]; ok {
			for _, m := range r.hard[g] {
				add(m)
			}
		}
		// Replace each directory prefix T of a with every symlink L -> T.
		for i := len(a) - 1; i > 0; i-- {
			if a[i] != '/' {
				continue
			}
			prefix, rest := a[:i], a[i:]
			for _, l := range rev[prefix] {
				add(l + rest)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
