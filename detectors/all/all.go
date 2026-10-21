// Package all registers every detector. Import it for its side effect.
package all

import (
	_ "github.com/DefectDojo/earlylight/detectors/emudhra"
	_ "github.com/DefectDojo/earlylight/detectors/php2shell"
)
