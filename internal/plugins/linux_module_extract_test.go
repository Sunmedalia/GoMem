package plugins

import (
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"testing"
)

func TestLinuxModuleInputCoordinates(t *testing.T) {
	for _, tc := range []struct {
		arch            string
		input, expected uint64
		bad             bool
	}{
		{"x64", 0x1234, 0x1234, false}, {"x64", 0xffffa022f170, 0xffffffffa022f170, false}, {"x64", 0xffffffffa022f170, 0xffffffffa022f170, false}, {"x64", 0x800000000000, 0xffff800000000000, false}, {"x64", 0x1000000000000, 0, true}, {"x64", 0xffff000000000000, 0, true},
		{"arm64", 0x1234, 0x1234, false}, {"arm64", 0xffff80008187e000, 0xffff80008187e000, false}, {"arm64", 0x800000000000, 0xffff800000000000, false}, {"arm64", 0x1000000000000, 0, true}, {"arm64", 0x0000800000000000, 0xffff800000000000, false},
		{"x86", 0xffffffff, 0xffffffff, false}, {"pae", 0x100000000, 0, true},
	} {
		got, err := linuxModuleInputAddress(plugin.Environment{Architecture: tc.arch}, tc.input)
		if (err != nil) != tc.bad || !tc.bad && got != tc.expected {
			t.Fatal(tc, got, err)
		}
	}
}
