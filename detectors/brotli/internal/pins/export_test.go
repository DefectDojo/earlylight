package pins

import "context"

// Scrub is scrub, for the external tests.
var Scrub = scrub

// JudgedSources returns the sources the scan of file recorded as judged
// values of rule on line.
func JudgedSources(root, file string, line int, rule string) []string {
	s, err := scanPins(context.Background(), root, []string{file}, Options{})
	if err != nil {
		return nil
	}
	var out []string
	for k := range s.judged {
		if k.file == file && k.line == line && k.rule == rule && k.source != "" {
			out = append(out, k.source)
		}
	}
	return out
}
