package assess

import (
	"strconv"
	"strings"
)

// Account is one /etc/passwd entry and the password field sshd compares
// against, found the way musl and sshd find it.
type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Shell string `json:"shell"`
	// Field is the effective password field: the shadow entry's when musl's
	// getspnam returns one, else /etc/passwd's.
	Field string `json:"-"`
	// From is where Field came from: "shadow", "tcb" or "passwd".
	From string `json:"from"`
	// Expire is the shadow expiry in days since 1970, or -1.
	Expire int64 `json:"expire,omitempty"`
}

// Accounts is the account database of a target.
type Accounts struct {
	List   []Account           // /etc/passwd order: the order getpwent walks
	Groups map[string][]string // group name -> member names
	GIDs   map[int]string      // gid -> group name
	// Read is false when /etc/passwd was not in the target.
	Read bool
}

// musl reads shadow lines with a 256-byte buffer: a longer line makes
// getspnam fail (ERANGE), and sshd then uses the /etc/passwd field.
const muslShadowLine = 256

// ParseAccounts builds the account database from /etc/passwd, /etc/shadow,
// tcb shadow files (/etc/tcb/NAME/shadow, which musl reads first) and
// /etc/group. Missing files are nil.
func ParseAccounts(passwd, shadow, group []byte, tcb map[string][]byte) Accounts {
	a := Accounts{Groups: map[string][]string{}, GIDs: map[int]string{}, Read: passwd != nil}
	for _, line := range lines(passwd) {
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "" {
			continue // musl's getpwent skips malformed lines
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		acc := Account{Name: f[0], UID: uid, GID: gid, Shell: f[6], Field: f[1], From: "passwd", Expire: -1}
		var sh []byte
		from := "shadow"
		if t, ok := tcb[acc.Name]; ok {
			sh, from = t, "tcb"
		} else {
			sh = shadow
		}
		if field, expire, ok := spnam(sh, acc.Name); ok {
			acc.Field, acc.From, acc.Expire = field, from, expire
		}
		a.List = append(a.List, acc)
	}
	for _, line := range lines(group) {
		f := strings.Split(line, ":")
		if len(f) != 4 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if _, ok := a.GIDs[gid]; !ok {
			a.GIDs[gid] = f[0]
		}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" {
				a.Groups[f[0]] = append(a.Groups[f[0]], m)
			}
		}
	}
	return a
}

// GroupsOf returns the groups an account belongs to.
func (a Accounts) GroupsOf(acc Account) []string {
	var out []string
	if g, ok := a.GIDs[acc.GID]; ok {
		out = append(out, g)
	}
	for g, ms := range a.Groups {
		for _, m := range ms {
			if m == acc.Name {
				out = append(out, g)
			}
		}
	}
	return out
}

// spnam is musl's getspnam_r over one shadow file: the first line for name,
// read through a 256-byte buffer, parsed as musl parses it.
func spnam(b []byte, name string) (field string, expire int64, ok bool) {
	if b == nil || name == "" || name[0] == '.' || strings.Contains(name, "/") {
		return "", -1, false
	}
	rest := string(b)
	for len(rest) > 0 {
		i := strings.IndexByte(rest, '\n')
		var line string
		terminated := i >= 0
		if terminated {
			line, rest = rest[:i], rest[i+1:]
		} else {
			line, rest = rest, ""
		}
		if !strings.HasPrefix(line, name+":") {
			continue
		}
		// fgets with a 256-byte buffer holds 255 bytes: the line plus its
		// newline must fit, or getspnam fails with ERANGE.
		if !terminated || len(line)+1 > muslShadowLine-1 {
			return "", -1, false
		}
		f, ok := parseSpent(line)
		if !ok {
			continue // musl skips a line it cannot parse and keeps looking
		}
		return f[1], numField(f[7]), true
	}
	return "", -1, false
}

// parseSpent follows musl's __parsespent: nine fields, numeric ones empty or
// decimal.
func parseSpent(line string) ([]string, bool) {
	f := strings.SplitN(line, ":", 9)
	if len(f) != 9 {
		return nil, false
	}
	for _, n := range f[2:8] {
		if n == "" {
			continue
		}
		if _, err := strconv.ParseInt(n, 10, 64); err != nil {
			return nil, false
		}
	}
	return f, true
}

func numField(s string) int64 {
	if s == "" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

func lines(b []byte) []string {
	if b == nil {
		return nil
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// Donor says which account's hash an unfixed sshd borrows a salt from, and
// what that salt makes musl's crypt do.
type Donor struct {
	Account string `json:"account,omitempty"`
	// Setting is the salt sshd passes to crypt ("$6$abc$").
	Setting string `json:"setting,omitempty"`
	// Fails says which passwords make crypt fail with that setting: "none",
	// "long" (more than 256 bytes, up to sshd's 1024-byte limit) or "any".
	Fails string `json:"fails"`
}

// PickSalt reproduces sshd's pick_salt (openbsd-compat/xcrypt.c before
// 10.6p2): the first account, in /etc/passwd order, whose password field
// starts with '$' and has another '$', cut to its last '$' and to 31 bytes.
// Without one the salt is "xx".
func PickSalt(a Accounts) Donor {
	for _, acc := range a.List {
		p := acc.Field
		if len(p) == 0 || p[0] != '$' {
			continue
		}
		last := strings.LastIndexByte(p[1:], '$')
		if last < 0 {
			continue
		}
		typelen := last + 2 // through the last '$'
		setting := p[:min(typelen, len(p))]
		if len(setting) > 31 {
			setting = setting[:31] // strlcpy into char salt[32]
		}
		return Donor{Account: acc.Name, Setting: setting, Fails: CryptFails(setting)}
	}
	return Donor{Setting: "xx", Fails: "none"}
}

// CryptFails says which keys make musl's crypt fail for a setting (see
// musl src/crypt): md5 never within sshd's 1024-byte limit, sha256 and
// sha512 above 256 bytes or always on a bad rounds= value, bcrypt always
// unless the setting carries its 22-character salt, DES never for a
// setting sshd builds.
func CryptFails(setting string) string {
	if len(setting) >= 3 && setting[0] == '$' {
		switch {
		case setting[1] == '1' && setting[2] == '$':
			return "none"
		case setting[1] == '2' && len(setting) > 3 && setting[3] == '$':
			if bcryptOK(setting) {
				return "none"
			}
			return "any"
		case (setting[1] == '5' || setting[1] == '6') && setting[2] == '$':
			if !shaRoundsOK(setting[3:]) {
				return "any"
			}
			return "long"
		}
	}
	return "none"
}

func bcryptOK(s string) bool {
	if len(s) < 7+22 || s[1] != '2' || s[3] != '$' || s[6] != '$' {
		return false
	}
	if !strings.ContainsRune("abxy", rune(s[2])) {
		return false
	}
	if s[4] < '0' || s[4] > '1' || s[5] < '0' || s[5] > '9' {
		return false
	}
	if (s[4]-'0')*10+(s[5]-'0') < 4 {
		return false
	}
	for _, c := range s[7 : 7+22] {
		if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
			return false
		}
	}
	return true
}

// shaRoundsOK follows musl's rounds= parsing: present means a decimal value
// up to 9999999 closed by '$'.
func shaRoundsOK(salt string) bool {
	r, ok := strings.CutPrefix(salt, "rounds=")
	if !ok {
		return true
	}
	if r == "" || r[0] < '0' || r[0] > '9' {
		return false
	}
	end := 0
	for end < len(r) && r[end] >= '0' && r[end] <= '9' {
		end++
	}
	if end >= len(r) || r[end] != '$' {
		return false
	}
	u, err := strconv.ParseUint(r[:end], 10, 64)
	return err == nil && u <= 9999999
}
