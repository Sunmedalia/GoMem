//go:build !cgo || (!windows && !darwin && !linux)

package yara

import "fmt"

func Supported() bool { return false }
func compileNative(string, CompileConfig) (nativeRules, error) {
	return nil, fmt.Errorf("YARA-X native adapter requires cgo on Windows, Linux or macOS")
}
func deserializeNative(string, []byte) (nativeRules, error) {
	return nil, fmt.Errorf("YARA-X native adapter requires cgo on Windows, Linux or macOS")
}
