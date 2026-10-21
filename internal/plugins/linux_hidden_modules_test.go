package plugins

import "testing"

func TestLinuxHiddenScanStep(t *testing.T) {
	if linuxHiddenScanStep(8, nil) != 8 || linuxHiddenScanStep(8, []uint64{0xc000, 0xc400}) != 8 {
		t.Fatal("aligned addresses keep the pointer step")
	}
	if linuxHiddenScanStep(8, []uint64{0xc000, 0xc001}) != 1 || linuxHiddenScanStep(4, []uint64{0xc001}) != 1 || linuxHiddenScanStep(0, nil) != 1 {
		t.Fatal("unaligned or unknown pointer width falls back to one byte")
	}
}

func TestLinuxDwarf2JSONVersion(t *testing.T) {
	for _, version := range []string{"0.8.0", "0.8", "0.9.0", "1.0.0"} {
		if versionLess(mustVersion(t, version), []int{0, 8, 0}) {
			t.Fatal(version)
		}
	}
	for _, version := range []string{"0.7.9", "0.8.0-rc1", ""} {
		got, err := splitSymbolVersion(version)
		if version == "0.7.9" {
			if err != nil || !versionLess(got, []int{0, 8, 0}) {
				t.Fatal(got, err)
			}
			continue
		}
		if err == nil {
			t.Fatal(version)
		}
	}
}

func mustVersion(t *testing.T, value string) []int {
	t.Helper()
	got, err := splitSymbolVersion(value)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
