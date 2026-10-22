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
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsNetStatNativePDBStorageFreshRunAndFailedRetry(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for native NetStat PDB/storage controls")
	}
	raw, err := os.ReadFile("../plugins/testdata/windows-netstat-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Arch, Layout, Scenario string
			Family, Size           int
			ISF                    json.RawMessage
			Driver                 json.RawMessage `json:"driver_isf"`
			Writes                 []struct {
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
			var isf, driver []byte
			var name string
			for _, c := range fixture.Cases {
				if c.Arch == arch && c.Scenario == "normal" && c.Family == 23 {
					data = make([]byte, c.Size)
					name = c.Layout
					isf = c.ISF
					driver = c.Driver
					for _, w := range c.Writes {
						b, err := hex.DecodeString(w.Data)
						if err != nil || w.Offset < 0 || w.Offset > len(data) || len(b) > len(data)-w.Offset {
							t.Fatal("invalid complete fixture")
						}
						copy(data[w.Offset:], b)
					}
					break
				}
			}
			if data == nil {
				t.Fatal("normal NetStat fixture absent")
			}
			var table map[string]json.RawMessage
			if err := json.Unmarshal(isf, &table); err != nil {
				t.Fatal(err)
			}
			matched := false
			for _, identity := range windowsRegexCases(t) {
				if identity.Arch == arch && identity.Name == "literal" {
					for _, w := range identity.Writes {
						if w.Offset >= 0x10000 && w.Offset < 0x12000 {
							b, err := hex.DecodeString(w.Data)
							if err != nil || w.Offset+len(b) > len(data) {
								t.Fatal("invalid PE identity")
							}
							copy(data[w.Offset:], b)
						}
					}
					var source, meta, other, windows, pdb map[string]json.RawMessage
					json.Unmarshal(identity.ISF, &source)
					json.Unmarshal(table["metadata"], &meta)
					json.Unmarshal(source["metadata"], &other)
					json.Unmarshal(meta["windows"], &windows)
					json.Unmarshal(other["windows"], &pdb)
					windows["pdb"] = pdb["pdb"]
					meta["windows"], _ = json.Marshal(windows)
					table["metadata"], _ = json.Marshal(meta)
					matched = true
					break
				}
			}
			if !matched {
				t.Fatal("kernel PE/PDB identity absent")
			}
			isf, err = json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol, driverPath := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json"), filepath.Join(dir, "driver.json")
			for path, b := range map[string][]byte{image: data, symbol: isf, driverPath: driver} {
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			driverTable, err := symbols.Parse(driver)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := driverTable.PDBIdentity()
			if err != nil {
				t.Fatal(err)
			}
			index := symbols.Index{Schema: "gomem.symbol-index/v1", Entries: []symbols.IndexEntry{{Location: driverPath, SHA256: driverTable.Digest(), OS: "windows", Architecture: driverTable.Architecture(), PointerSize: driverTable.PointerSize(), PDB: &identity}}}
			indexPath := filepath.Join(dir, "index.json")
			indexBytes, _ := json.Marshal(index)
			if err := os.WriteFile(indexPath, indexBytes, 0600); err != nil {
				t.Fatal(err)
			}
			cache := filepath.Join(dir, "symbols")
			network := filepath.Join(cache, "network-symbols")
			if err := os.MkdirAll(network, 0700); err != nil {
				t.Fatal(err)
			}
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(schema)
			if err := os.WriteFile(filepath.Join(network, name+"-"+hex.EncodeToString(sum[:])+".json"), schema, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, SymbolIndex: indexPath, SymbolCache: cache, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			// No injected provider: engine scans the actual resident RSDS, verifies its
			// GUID/Age against the local driver index and supplies that native table.
			var wire bytes.Buffer
			networks := 0
			result, err := e.Run(context.Background(), "windows.netstat", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "network" {
					networks++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			if err != nil || result.Reused || networks != 5 {
				t.Fatal("native NetStat task", networks, result.Reused, err)
			}
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if err := row.Verify(); err != nil {
						t.Fatal(err)
					}
					json.NewEncoder(&stored).Encode(row)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(stored.Bytes(), wire.Bytes()) {
				t.Fatal("sealed NetStat store differs")
			}
			again, err := e.Run(context.Background(), "windows.netstat", nil, engine.RunOptions{})
			if err != nil || again.Reused || again.Task.ID == result.Task.ID {
				t.Fatal("external driver dependency bypassed fresh execution", again.Reused, err)
			}
			for retry := 0; retry < 2; retry++ {
				failed, err := e.Run(context.Background(), "windows.netstat", map[string]string{"max-nodes": "1"}, engine.RunOptions{})
				if err == nil || failed.Reused {
					t.Fatal("failed network index reused as success", err, failed.Reused)
				}
			}
		})
	}
}
