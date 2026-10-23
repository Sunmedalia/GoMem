//go:build !cgo || (!linux && !darwin && !windows)

package disasm

import "fmt"

func Supported() bool { return false }
func openNative(library, arch string) (nativeDecoder, error) {
	return nil, fmt.Errorf("Capstone native adapter requires cgo on Windows, Linux or macOS")
}
