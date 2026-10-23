package engine

import "testing"

func TestEnginePointerMask(t *testing.T) {
	tests := []struct {
		arch, os string
		want     uint64
	}{
		{"x86", "windows", 0xffffffff},
		{"pae", "windows", 0xffffffff},
		{"x64", "windows", 0x0000ffffffffffff},
		{"x64", "linux", ^uint64(0)},
		{"arm64", "linux", ^uint64(0)},
		{"", "", ^uint64(0)},
	}
	for _, test := range tests {
		if got := enginePointerMask(test.arch, test.os); got != test.want {
			t.Errorf("enginePointerMask(%q, %q) = %#x, want %#x", test.arch, test.os, got, test.want)
		}
	}
}
