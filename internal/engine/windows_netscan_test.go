package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsNetScanStorageCacheAndFailedRetry(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for sealed network task controls")
	}
	raw, err := os.ReadFile("../plugins/testdata/windows-netscan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Arch, Layout, Type, Scenario string
			Family, Size                 int
			ISF                          json.RawMessage
			Writes                       []struct {
				Offset int
				Data   string
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x86", "pae", "x64"} {
		t.Run(arch, func(t *testing.T) {
			var data []byte
			var table map[string]json.RawMessage
			var name string
			for _, c := range fixture.Cases {
				if c.Arch == arch && c.Type == "_TCP_ENDPOINT" && c.Scenario == "normal" && c.Family == 23 {
					data = make([]byte, c.Size)
					name = c.Layout
					for _, w := range c.Writes {
						b, err := hex.DecodeString(w.Data)
						if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
							t.Fatal("invalid fixture")
						}
						copy(data[w.Offset:], b)
					}
					if err := json.Unmarshal(c.ISF, &table); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if len(data) == 0 {
				t.Fatal("fixture absent")
			}
			// Add an independently checked PE/PDB identity. Move the debug block
			// above the PE and make symbol offsets relative to the kernel base.
			copy(data[0x1c000:0x1c100], data[0x1000:0x1100])
			found := false
			for _, identity := range windowsRegexCases(t) {
				if identity.Arch == arch && identity.Name == "literal" {
					for _, w := range identity.Writes {
						if w.Offset >= 0x10000 && w.Offset < 0x12000 {
							b, err := hex.DecodeString(w.Data)
							if err != nil || w.Offset+len(b) > len(data) {
								t.Fatal("invalid identity bytes")
							}
							copy(data[w.Offset:], b)
						}
					}
					var source map[string]json.RawMessage
					if err := json.Unmarshal(identity.ISF, &source); err != nil {
						t.Fatal(err)
					}
					var original, metadata map[string]json.RawMessage
					json.Unmarshal(table["metadata"], &metadata)
					json.Unmarshal(source["metadata"], &original)
					var windows, identityWindows map[string]json.RawMessage
					json.Unmarshal(metadata["windows"], &windows)
					json.Unmarshal(original["windows"], &identityWindows)
					windows["pdb"] = identityWindows["pdb"]
					metadata["windows"], _ = json.Marshal(windows)
					table["metadata"], _ = json.Marshal(metadata)
					found = true
					break
				}
			}
			if !found {
				t.Fatal("PE identity absent")
			}
			var syms map[string]map[string]uint64
			if err := json.Unmarshal(table["symbols"], &syms); err != nil {
				t.Fatal(err)
			}
			syms["KdVersionBlock"]["address"] = 0xc000
			syms["ObTypeIndexTable"]["address"] = 0xa000
			syms["KdCopyDataBlock"]["address"] = 0xb000
			table["symbols"], _ = json.Marshal(syms)
			isf, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
			if err := os.WriteFile(image, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(symbol, isf, 0600); err != nil {
				t.Fatal(err)
			}
			cache := filepath.Join(dir, "symbols")
			networkCache := filepath.Join(cache, "network-symbols")
			if err := os.MkdirAll(networkCache, 0700); err != nil {
				t.Fatal(err)
			}
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(schema)
			if err := os.WriteFile(filepath.Join(networkCache, name+"-"+hex.EncodeToString(sum[:])+".json"), schema, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, SymbolCache: cache, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if !e.Env.Offline || e.Env.SymbolCache != cache {
				t.Fatal("plugin cache/offline configuration lost")
			}
			var wire bytes.Buffer
			networks := 0
			result, err := e.Run(context.Background(), "windows.netscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "network" {
					networks++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			if err != nil || result.Reused || networks != 1 {
				t.Fatal("initial task", result, networks, err)
			}
			var stored bytes.Buffer
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
				json.NewEncoder(&stored).Encode(row)
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("stored network evidence differs")
			}
			var replay bytes.Buffer
			cached, err := e.Run(context.Background(), "windows.netscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if err != nil || !cached.Reused || !bytes.Equal(wire.Bytes(), replay.Bytes()) {
				t.Fatal("network cache replay differs", err, cached.Reused)
			}
			for retry := 0; retry < 2; retry++ {
				failed, err := e.Run(context.Background(), "windows.netscan", map[string]string{"max-reads": "1"}, engine.RunOptions{})
				if err == nil || failed.Reused {
					t.Fatal("failed network task reused as success", err, failed.Reused)
				}
			}
		})
	}
}
