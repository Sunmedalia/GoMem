//go:build !cgo || (!linux && !darwin && !windows)

package memory

import "fmt"

func LeechCoreSupported() bool { return false }
func openNativeLeechCore(library, device, remote string) (leechCoreDevice, error) {
	return nil, fmt.Errorf("LeechCore native adapter requires cgo on Windows, Linux or macOS")
}
