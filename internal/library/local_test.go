package library

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

func TestLocalMatchesAllCandidatesAndReportsSourceRecordsAndErrors(t *testing.T) {
	ctx := context.Background()
	l := Library{Root: t.TempDir()}
	banner := "Linux version 6.8.11-arm64 (compiler) #1 SMP Kali\n"
	data := tableData(t, banner)
	path, err := l.save(ctx, Symbols, "kali.json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"kali.json.source.json": `{"source_url":"https://example.test/debug.deb"}`, "broken.json": "invalid ISF"} {
		if _, err := l.save(ctx, Symbols, name, strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	p := Probe{OS: "linux", Status: "ambiguous", Identities: []Identity{{OS: "linux", Banner: "Linux version 4.4.0 embedded string"}, {OS: "linux", Banner: banner}, {OS: "linux", Banner: strings.TrimSuffix(banner, "\n")}}}
	local, err := l.MatchLocal(ctx, p)
	if err != nil || len(local.Matches) != 1 || len(local.Matches[0].Identities) != 1 || len(local.Diagnostics) != 2 {
		t.Fatal(local, err)
	}
	selected, err := local.Unique()
	if err != nil || selected != path {
		t.Fatal(selected, err)
	}
	statuses := map[string]bool{}
	for _, d := range local.Diagnostics {
		statuses[d.Status] = true
	}
	if !statuses["error"] || !statuses["source-only"] {
		t.Fatal(local.Diagnostics)
	}
	// Content duplicates at different locations still select one table.
	if _, err = l.save(ctx, Symbols, "copy.json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	local, err = l.MatchLocal(ctx, p)
	if err != nil || len(local.Matches) != 2 {
		t.Fatal(local, err)
	}
	if _, err = local.Unique(); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err = json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["symbols"].(map[string]any)["linux_banner"].(map[string]any)["address"] = float64(0x5000)
	other, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.save(ctx, Symbols, "different.json", bytes.NewReader(other)); err != nil {
		t.Fatal(err)
	}
	local, err = l.MatchLocal(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = local.Unique(); err == nil {
		t.Fatal("distinct matching tables were selected silently")
	}
	p.Identities = []Identity{{OS: "linux", Banner: strings.Replace(banner, "compiler", "different compiler", 1)}}
	local, err = l.MatchLocal(ctx, p)
	if err != nil || len(local.Matches) != 0 {
		t.Fatal("version-only match accepted", local, err)
	}
}

func TestLocalZIPMembersAndWindowsPDBIdentity(t *testing.T) {
	ctx := context.Background()
	l := Library{Root: t.TempDir()}
	banner := "Linux version 6.1-archive (compiler) #1 SMP"
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, text := range map[string]string{"linux/kernel.json": banner, "linux/other.json": "Linux version 6.2-other (compiler) #1 SMP"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(tableData(t, text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.save(ctx, Symbols, "tables.zip", bytes.NewReader(b.Bytes())); err != nil {
		t.Fatal(err)
	}
	local, err := l.MatchLocal(ctx, Probe{Identities: []Identity{{OS: "linux", Banner: banner}}})
	if err != nil || len(local.Matches) != 1 || !strings.HasSuffix(local.Matches[0].Table.Location, "#linux/kernel.json") {
		t.Fatal(local, err)
	}
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Import(ctx, Symbols, f.Symbols); err != nil {
		t.Fatal(err)
	}
	p, err := ProbeFile(ctx, f.Image)
	if err != nil {
		t.Fatal(err)
	}
	local, err = l.MatchLocal(ctx, p)
	if err != nil || len(local.Matches) != 1 || local.Matches[0].Table.OS != "windows" {
		t.Fatal(local, err)
	}
}

func TestLocalMissingDirectoryIsReadOnlyAndCancellationPropagates(t *testing.T) {
	ctx := context.Background()
	l := Library{Root: filepath.Join(t.TempDir(), "missing")}
	local, err := l.MatchLocal(ctx, Probe{})
	if err != nil || len(local.Matches) != 0 {
		t.Fatal(local, err)
	}
	if _, err = os.Stat(l.Root); !os.IsNotExist(err) {
		t.Fatal("matching created a directory", err)
	}
	if _, err = l.save(ctx, Symbols, "table.json", bytes.NewReader(tableData(t, "Linux version 6.1-test"))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = l.MatchLocal(ctx, Probe{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
