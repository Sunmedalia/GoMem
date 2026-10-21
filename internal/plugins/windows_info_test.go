package plugins

import (
	"net/url"
	"path/filepath"
	"strings"
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
	if pythonBool(true) != "True" || pythonBool(false) != "False" {
		t.Fatal("bool")
	}
}

func TestVolatilitySymbolURLLocalArchive(t *testing.T) {
	for _, archive := range []string{filepath.Join(t.TempDir(), "symbols one.zip"), "symbols one.zip"} {
		member := "windows/kernel.json"
		got := volatilitySymbolURL(archive + "#" + member)
		if strings.Contains(got, `\`) || strings.Contains(got, " ") {
			t.Fatalf("archive URL contains platform separators or unescaped spaces: %q", got)
		}
		outer, entry, ok := strings.Cut(got, "!")
		if !ok || entry != member || !strings.HasPrefix(outer, "jar:") {
			t.Fatal(got)
		}
		parsed, err := url.Parse(strings.TrimPrefix(outer, "jar:"))
		if err != nil {
			t.Fatal(err)
		}
		absolute, err := filepath.Abs(archive)
		if err != nil {
			t.Fatal(err)
		}
		wantPath := filepath.ToSlash(absolute)
		if filepath.VolumeName(absolute) != "" && !strings.HasPrefix(wantPath, "/") {
			wantPath = "/" + wantPath
		}
		if parsed.Scheme != "file" || parsed.Path != wantPath || parsed.Host != "" {
			t.Fatalf("archive URL does not resolve to local path: %q parsed=%+v want=%q", got, parsed, wantPath)
		}
	}
	for _, location := range []string{"kernel.json", "jar:file:/symbols/a.zip!kernel.json"} {
		if got := volatilitySymbolURL(location); got != location {
			t.Fatal(got, location)
		}
	}
}
