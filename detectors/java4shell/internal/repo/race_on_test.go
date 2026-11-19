//go:build race

package repo

// raceDetector is true when the tests run under the race detector, which
// changes how much a run allocates (sync.Pool gives nothing back).
const raceDetector = true
