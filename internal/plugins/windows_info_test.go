package plugins

import (
	"testing"
	"time"
)

func TestWindowsInfoFormatting(t *testing.T) {
	if volHex(0xfffff8043601f000, 64) != "0xf8043601f000" {
		t.Fatal(volHex(0xfffff8043601f000, 64))
	}
	if got := ksystemTimeText(0); got != "-" {
		t.Fatal(got)
	}
	// 2025-03-06 17:59:20 UTC is the selected crash sample.
	when := time.Date(2025, 3, 6, 17, 59, 20, 0, time.UTC)
	ticks := uint64(when.Unix()+11644473600) * 10000000
	if got := ksystemTimeText(ticks); got != "2025-03-06 17:59:20+00:00" {
		t.Fatal(got)
	}
	got := volatilitySymbolURL("/Volumes/l/GoMem/.cache/corpus/symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json")
	want := "jar:file:/Volumes/l/GoMem/.cache/corpus/symbols_win-10_19041-2025_03.zip!167FE94B5641C005AC3036212A01F8DC-1.json"
	if got != want {
		t.Fatal(got)
	}
	if pythonBool(true) != "True" || pythonBool(false) != "False" {
		t.Fatal("bool")
	}
}
