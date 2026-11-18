package knowledge

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		in    string
		nums  string
		build int
		ea    bool
	}{
		{"17.0.21.1+2-LTS", "17.0.21.1", 2, false},
		{"21.0.13.0.3+1-LTS", "21.0.13.0.3", 1, false},
		{"17.0.21+9-1-deb12u1-Debian", "17.0.21", 9, false},
		{"1.8.0_452-b09", "8.0.452", 9, false},
		{"1.8.0_452", "8.0.452", -1, false},
		{"1.8.0_511-perf-b33", "8.0.511", 33, false},
		{"28-ea+24", "28", 24, true},
		{"17.0.6-ea+2", "17.0.6", 2, true},
		{"25.0.5", "25.0.5", -1, false},
		{"21", "21", -1, false},
		{"11.0.33+7", "11.0.33", 7, false},
		{"21.0.13-internal+0-adhoc.root.src", "21.0.13", 0, false},
	} {
		v, ok := Parse(c.in)
		if !ok || v.String() != c.nums || v.Build != c.build || v.EA != c.ea {
			t.Errorf("Parse(%q) = %v %q build %d ea %v, want %q build %d ea %v", c.in, ok, v.String(), v.Build, v.EA, c.nums, c.build, c.ea)
		}
	}
	for _, bad := range []string{"", "abc", "1.9.0", "8", "0.1", "100.0.1", strings.Repeat("1.", 200), "1.8x", "17.0.0.0.0.0.0.0.0.0"} {
		if v, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) accepted: %v", bad, v)
		}
	}
}

func TestJudge(t *testing.T) {
	for _, c := range []struct {
		v    string
		want Status
	}{
		{"1.8.0_452-b09", NotAffected},
		{"11.0.33+7", NotAffected},
		{"16.0.2+7", NotAffected},
		{"17.0.5+8", NotAffected},
		{"17.0.6-ea+2", NotAffected},
		{"17.0.6-ea+3", Vulnerable},
		{"17.0.6+10", Vulnerable},
		{"17.0.21+9", Vulnerable},
		{"17.0.21.0.3+1", Vulnerable},
		{"17.0.21.1+2", Fixed},
		{"17.0.21.2+1", Fixed},
		{"17.0.22+2", Unknown},
		{"17.0.22-ea+2", Unknown},
		{"18.0.2.1+1", Vulnerable},
		{"20.0.2+9", Vulnerable},
		{"21+35", Vulnerable},
		{"21.0.13+9", Vulnerable},
		{"21.0.13.0.3+1", Vulnerable},
		{"21.0.13.1+2", Fixed},
		{"21.0.14+1", Unknown},
		{"21.0.13.11", Unknown}, // Corretto's build number in the fourth place
		{"24.0.2+12", Vulnerable},
		{"25.0.5+8", Vulnerable},
		{"25.0.5.1+2", Fixed},
		{"26.0.2.1+1", Vulnerable},
		{"27+35", Vulnerable},
		{"27.0.1.0.3+1", Vulnerable},
		{"27.0.1.1+4", Fixed},
		{"27.0.2+1", Unknown},
		{"28-ea+24", Vulnerable},
		{"28-ea+25", Unknown},
		{"29-ea+1", Unknown},
	} {
		v, ok := Parse(c.v)
		if !ok {
			t.Fatalf("Parse(%q) failed", c.v)
		}
		got, why := Judge(v)
		if got != c.want || why == "" {
			t.Errorf("Judge(%s) = %s (%s), want %s", c.v, got, why, c.want)
		}
	}
}

func TestLinesConsistent(t *testing.T) {
	prev := 0
	for _, l := range Lines {
		if l.Feature <= prev {
			t.Fatalf("lines out of order at %d", l.Feature)
		}
		prev = l.Feature
		if l.Fixed == nil && l.Note == "" {
			t.Errorf("line %d has no fix and no note", l.Feature)
		}
		if l.Fixed != nil && l.Fixed[0] != l.Feature {
			t.Errorf("line %d fixed version %v is on another line", l.Feature, l.Fixed)
		}
		if l.Fixed != nil && l.Introduced != nil && Compare(l.Introduced, l.Fixed) >= 0 {
			t.Errorf("line %d fixed before it was introduced", l.Feature)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"17.0.21.1+2-LTS", "1.8.0_452-b09", "28-ea+24", "21.0.13-internal+0-adhoc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := Parse(s)
		if !ok {
			return
		}
		if len(v.Nums) == 0 || len(v.Nums) > 9 {
			t.Fatalf("Parse(%q) gave %d numbers", s, len(v.Nums))
		}
		st, why := Judge(v)
		if st == "" || why == "" {
			t.Fatalf("Judge(%q) gave no verdict or reason", s)
		}
	})
}
