package assess

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
)

// WordSet is the set of words a start script holds, kept small: a script
// is remembered by what it names, not by its text. A word is a run of
// letters, digits and "_.+-" (so every component of a path is one). The
// set can say a word is there when it is not, never the reverse, which is
// the safe side for its one use: deciding that a script may run another.
type WordSet [32]uint64

func nameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '+' || c == '-'
}

// WordsOf returns the words of a script's text, or of a command line.
func WordsOf(text []byte) WordSet {
	var ws WordSet
	for i := 0; i < len(text); {
		if !nameByte(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && nameByte(text[j]) {
			j++
		}
		ws.add(text[i:j])
		i = j
	}
	return ws
}

func wordBits(w []byte) [3]uint {
	h := uint64(14695981039346656037) // FNV-1a
	for _, c := range w {
		h = (h ^ uint64(c)) * 1099511628211
	}
	return [3]uint{uint(h % 2048), uint((h >> 21) % 2048), uint((h >> 42) % 2048)}
}

func (ws *WordSet) add(w []byte) {
	for _, b := range wordBits(w) {
		ws[b/64] |= 1 << (b % 64)
	}
}

// Has reports whether w may be in the set.
func (ws *WordSet) Has(w string) bool {
	if w == "" {
		return false
	}
	for _, b := range wordBits([]byte(w)) {
		if ws[b/64]&(1<<(b%64)) == 0 {
			return false
		}
	}
	return true
}

func (ws *WordSet) merge(o WordSet) {
	for i := range ws {
		ws[i] |= o[i]
	}
}

// names reports whether the set holds the file name of p. A name with a
// character no word has cannot be looked up: it is taken as named.
func (ws *WordSet) names(p string) bool {
	b := path.Base(p)
	for i := 0; i < len(b); i++ {
		if !nameByte(b[i]) {
			return true
		}
	}
	return ws.Has(b)
}

// mitigationVoid says why a mitigation the image's options give cannot be
// reported: the container's command reaches a start script that was not
// read, which can pass an option that undoes it, or one that was read and
// does. "" when nothing does.
//
// A script is reached when the command names it, in any word or inside a
// shell text, by path or by file name alone (a name looked up in PATH, a
// path relative to a directory the scan cannot place), or when a script
// that is reached names it the same way. Going by file names reaches too
// much rather than too little.
func mitigationVoid(in Input) string {
	if len(in.Command) == 0 {
		return ""
	}
	if u := unreadCommandScript(in); u != "" {
		return "the container's start script " + u + " was not read (larger than the scan reads) and can pass an option that undoes it"
	}
	reached := WordsOf([]byte(strings.Join(jvm.CommandWords(in.Command), " ")))
	if in.ScriptsOver && path.Base(in.Command[0]) != "java" {
		return "the target holds more start scripts than the scan records, and one the container's command runs can pass an option that undoes it"
	}
	// Every script the command reaches, through the scripts it reaches.
	seen := map[string]bool{}
	for changed, rounds := true, 0; changed && rounds < 64; rounds++ {
		changed = false
		for p, ws := range in.ScriptWords {
			if !seen[p] && reached.names(p) {
				seen[p], changed = true, true
				reached.merge(ws)
			}
		}
	}
	for _, u := range sortedKeys(in.UnreadScripts) {
		if reached.names(u) {
			return "the start script " + u + ", which the container's command can reach, was not read (larger than the scan reads) and can pass an option that undoes it"
		}
	}
	undo := make([]string, 0, len(in.UndoScripts))
	for p := range in.UndoScripts {
		undo = append(undo, p)
	}
	sort.Strings(undo)
	for _, p := range undo {
		if reached.names(p) {
			return fmt.Sprintf("the script %s, which the container's command can reach, passes %s, which turns the decoder back on", p, in.UndoScripts[p])
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
