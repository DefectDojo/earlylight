package engine

import (
	"context"
	"io"
)

// RepoScanner is implemented by detectors that check what a source tree
// builds on and deploys (the images its Dockerfiles, Compose, Kubernetes, Helm
// and CI files name) without building it.
type RepoScanner interface {
	ScanRepo(ctx context.Context, dir string, opts Options) *Target
}

// Fixer is implemented by detectors that can rewrite a source tree's
// references to fixed versions. It prints what it changes (or would, with
// opts.DryRun) and returns 0 when everything vulnerable was fixed, 1 when some
// could not be, 2 on error.
type Fixer interface {
	Fix(ctx context.Context, dirs []string, opts Options, stdout, stderr io.Writer) int
}

// ScanRepo runs every repository-capable detector over dir and merges what
// they found into one target.
func ScanRepo(dets []Detector, dir string, opts Options) *Target {
	t := &Target{Name: dir, Type: Repository}
	ran := false
	for _, d := range dets {
		r, ok := d.(RepoScanner)
		if !ok || !d.Manifest().Supports(Repository) {
			continue
		}
		ran = true
		got := r.ScanRepo(context.Background(), dir, opts)
		if got == nil {
			continue
		}
		if got.Name != "" {
			t.Name = got.Name
		}
		t.Files += got.Files
		t.Findings = append(t.Findings, check(d.Manifest().ID, got.Findings)...)
		t.Skipped = append(t.Skipped, got.Skipped...)
		t.Problems = append(t.Problems, got.Problems...)
		if got.Incomplete != "" {
			t.Incomplete = got.Incomplete
		}
		if got.Error != "" {
			t.Error = got.Error
		}
	}
	if !ran {
		t.Error = "none of the selected detectors check repositories"
	}
	return t
}
