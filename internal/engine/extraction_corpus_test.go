package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

// File digests come from the locked Volatility reference on the pinned public
// acquisitions. Fully padded and mixed captures are accounted for separately.
func TestOfficialRegionExtraction(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected-region differential corpus; not full acceptance")
	}
	for _, tc := range []struct{ os, image, symbols, plugin, pid, address, size, missing, sha string }{
		{"linux", "linux-sample-1.bin", "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", "linux.maps", "1", "0x400000", "36864", "12288", "def8ca5ec5a3ca9b1c4e6ad8e856fd5f3f13d501aea628b7d3eb2aa66fcd6246"},
		{"windows", "win-10_19041-2025_03.dmp", "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json", "windows.vadinfo", "4", "0x7ffe0000", "4096", "4096", "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7"},
		{"windows", "win-10_19041-2025_03.dmp", "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json", "windows.vadinfo", "4", "0x7ff8271d0000", "204800", "200704", "8ec6edd22a71633f259d78e30349226bd344e1d8d32746d0a84b4edf3da401bd"},
	} {
		t.Run(tc.os+tc.address, func(t *testing.T) {
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, tc.image), Symbols: filepath.Join(dir, tc.symbols), CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			expectedHash := map[string]string{"linux": "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc", "windows": "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460"}[tc.os]
			if e.Hash != expectedHash {
				t.Fatal("official image checksum drift", e.Hash)
			}
			result, err := e.Run(ctx, tc.plugin, map[string]string{"pid": tc.pid, "address": tc.address, "dump": "true"}, engine.RunOptions{})
			if err != nil || result.Task.Rows != 1 {
				t.Fatal(result, err)
			}
			artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
			if err != nil || len(artifacts) != 1 {
				t.Fatal(artifacts, err)
			}
			a := artifacts[0]
			if a.Size != tc.size || a.MissingBytes != tc.missing || a.SHA256 != tc.sha || a.State != "completed_with_gaps" {
				t.Fatal("region extraction differs from pinned reference", a)
			}
			if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
