package assess

import "github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"

// EnvoyStatusForTest exposes envoyStatus to the external tests.
var EnvoyStatusForTest = envoyStatus

var _ = fingerprint.V
