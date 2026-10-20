package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

const Version = "0.1.0-dev"
const Baseline = "2.28.2"
const BaselineCommit = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"

var once sync.Once
var identity string
var identityErr error

// Identity fingerprints the actual executable, including development builds.
// A constant dev version must never reuse evidence from different engine code.
func Identity() (string, error) {
	once.Do(func() {
		path, err := os.Executable()
		if err != nil {
			identityErr = err
			return
		}
		f, err := os.Open(path)
		if err != nil {
			identityErr = err
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			identityErr = err
			return
		}
		identity = hex.EncodeToString(h.Sum(nil))
	})
	return identity, identityErr
}
