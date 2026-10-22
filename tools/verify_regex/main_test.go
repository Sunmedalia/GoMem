package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func auditFixture(t *testing.T) (*engine.Engine, []evidence.Row) {
	t.Helper()
	raw, e := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		VMAs []struct {
			Name, Arch string
			Size       int
			Writes     []struct {
				Offset int
				Data   string
			}
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, c := range fixture.VMAs {
		if c.Name != "literal" || c.Arch != "x64" {
			continue
		}
		data := make([]byte, c.Size)
		for _, w := range c.Writes {
			b, e := hex.DecodeString(w.Data)
			if e != nil {
				t.Fatal(e)
			}
			copy(data[w.Offset:], b)
		}
		directory := t.TempDir()
		image := filepath.Join(directory, "memory.raw")
		if e = os.WriteFile(image, data, 0600); e != nil {
			t.Fatal(e)
		}
		eng, e := engine.Open(context.Background(), engine.Config{Image: image, CaseDir: filepath.Join(directory, "case"), OS: "linux", Arch: "x64", DTB: "0x8000", Offline: true})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { eng.Close() })
		var rows []evidence.Row
		_, e = eng.Run(context.Background(), "regexscan", map[string]string{"pattern": "MATCH"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
		if e != nil {
			t.Fatal(e)
		}
		return eng, rows
	}
	t.Fatal("missing fixture")
	return nil, nil
}
func TestAuditOriginalSourceAndRejectResealedFalseClaims(t *testing.T) {
	eng, rows := auditFixture(t)
	fresh := func() *audit { return &audit{ctx: context.Background(), engine: eng, roots: map[string]uint64{}} }
	original := fresh()
	for _, r := range rows {
		if e := original.verify(r); e != nil {
			t.Fatal(e)
		}
	}
	if original.Matches != 4 || original.Chunks != 1 || original.HardwareProofs != 4 {
		t.Fatal(original)
	}
	for _, mode := range []string{"match", "context", "chunk", "hardware", "duplicate-parent"} {
		t.Run(mode, func(t *testing.T) {
			check := fresh()
			tampered := false
			for _, r := range rows {
				raw, e := json.Marshal(r)
				if e != nil {
					t.Fatal(e)
				}
				var clone evidence.Row
				if e = json.Unmarshal(raw, &clone); e != nil {
					t.Fatal(e)
				}
				kind := clone.Cells["RecordType"].String()
				if !tampered && (kind == "regex_match" && mode != "chunk" && mode != "duplicate-parent" || kind == "scan_chunk" && (mode == "chunk" || mode == "duplicate-parent")) {
					switch mode {
					case "match":
						clone.Cells["MatchRaw"] = evidence.Bytes([]byte("wrong"))
					case "context":
						proof, _ := structure(clone.Cells["Context"])
						proof["Raw"] = evidence.Bytes([]byte("wrong"))
						clone.Cells["Context"] = evidence.Value{Kind: "structure", Data: proof}
					case "chunk":
						clone.Cells["SHA256"] = evidence.Text("bad digest")
					case "hardware":
						source, _ := structure(clone.Cells["Source"])
						ps, _ := parts(source["Parts"])
						proofs, _ := parts(ps[0]["Translation"])
						proofs[0]["Entry"] = evidence.Address(0)
						ps[0]["Translation"] = evidence.Value{Kind: "structure", Data: proofs}
						source["Parts"] = evidence.Value{Kind: "structure", Data: ps}
						clone.Cells["Source"] = evidence.Value{Kind: "structure", Data: source}
					case "duplicate-parent":
						if e = check.verify(clone); e != nil {
							t.Fatal(e)
						}
					}
					if mode != "duplicate-parent" {
						clone.Seal()
					}
					if e = check.verify(clone); e == nil {
						t.Fatal("resealed false source claim accepted", mode)
					}
					tampered = true
					break
				}
				if e = check.verify(clone); e != nil {
					t.Fatal(e)
				}
			}
			if !tampered {
				t.Fatal("test failed to reach record")
			}
		})
	}
}
