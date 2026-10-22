package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type mftOracleCase struct {
	Name   string
	Size   int
	Writes []struct {
		Offset int
		Data   string
	}
	Expected map[string]struct {
		Rows []struct {
			Level  int
			Values []json.RawMessage
		}
		Error any
	}
}

func mftOracleCases(t *testing.T) []mftOracleCase {
	raw, err := os.ReadFile("testdata/windows-mft-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []mftOracleCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 70 {
		t.Fatal("fixture drift")
	}
	return f.Cases
}
func mftOracleEngine(t *testing.T, c mftOracleCase) (*engine.Engine, []byte) {
	t.Helper()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, _ := hex.DecodeString(w.Data)
		copy(data[w.Offset:], raw)
	}
	dir := t.TempDir()
	image := filepath.Join(dir, "memory.raw")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, OS: "windows", Arch: "x64", Offline: true, CaseDir: filepath.Join(dir, "case")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, data
}
func mftColumns(name string) []string {
	switch name {
	case "mftscan":
		return []string{"Offset", "RecordSignature", "RecordNumber", "LinkCount", "MFTType", "Permissions", "AttributeType", "Created", "Modified", "Updated", "Accessed", "Filename"}
	case "ads":
		return []string{"Offset", "RecordSignature", "RecordNumber", "AttributeType", "Filename", "ADSFilename", "Hexdump"}
	default:
		return []string{"Offset", "RecordSignature", "RecordNumber", "AttributeType", "Filename", "Hexdump"}
	}
}
func TestWindowsMFTActualGeneratorsAndOriginalEvidence(t *testing.T) {
	for _, c := range mftOracleCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			e, data := mftOracleEngine(t, c)
			for _, name := range []string{"mftscan", "ads", "residentdata"} {
				t.Run(name, func(t *testing.T) {
					var rows, all []evidence.Row
					var wire bytes.Buffer
					result, runErr := e.Run(context.Background(), "windows."+name, nil, engine.RunOptions{Emit: func(row evidence.Row) error {
						if err := row.Verify(); err != nil {
							t.Fatal(err)
						}
						all = append(all, row)
						kind := row.Cells["RecordType"].String()
						if kind == "result" {
							rows = append(rows, row)
						}
						if kind == "memory_read" || kind == "scan_read" {
							at, _ := row.Cells["Offset"].Uint()
							requested, _ := row.Cells["Requested"].Uint()
							captured, _ := row.Cells["Captured"].Uint()
							raw := make([]byte, requested)
							n, cause := e.Env.Physical.ReadAt(context.Background(), raw, at)
							if uint64(n) != captured || (cause == nil) != (row.Cells["Error"].Kind == "missing") {
								t.Fatal("independent acquisition", at, n, cause)
							}
							if kind == "memory_read" {
								if !bytes.Equal(stringsEvidenceBytes(t, row.Cells["Raw"]), raw[:n]) {
									t.Fatal("raw source differs")
								}
							} else {
								hash := sha256.Sum256(raw[:n])
								if row.Cells["RawSHA256"].String() != hex.EncodeToString(hash[:]) {
									t.Fatal("scan digest differs")
								}
							}
							if n > 0 && !bytes.Equal(raw[:n], data[at:at+uint64(n)]) {
								t.Fatal("source fixture differs")
							}
						}
						return json.NewEncoder(&wire).Encode(row)
					}})
					damaged := strings.HasSuffix(c.Name, "zero-length") || strings.HasSuffix(c.Name, "header-truncated") || strings.HasSuffix(c.Name, "attributes-truncated") || name == "residentdata" && (strings.HasSuffix(c.Name, "data-content-hole") || strings.HasSuffix(c.Name, "data-content-oversize")) || name == "ads" && strings.HasSuffix(c.Name, "stream-name-hole")
					if (runErr != nil) != damaged {
						t.Fatal("coverage state", c.Name, name, runErr)
					}
					expected := c.Expected[name]
					if expected.Error != nil || len(rows) != len(expected.Rows) {
						t.Fatal("rows", len(rows), len(expected.Rows), runErr)
					}
					parent := ""
					for i, want := range expected.Rows {
						row := rows[i]
						level, _ := row.Cells["BaselineLevel"].Uint()
						if level != uint64(want.Level) {
							t.Fatal("level")
						}
						wantParent := ""
						if name == "mftscan" {
							if want.Level == 1 && parent != "" {
								wantParent = parent
							} else {
								parent = row.ID
							}
						}
						if row.ParentID != wantParent {
							t.Fatal("baseline hierarchy", row.ParentID, wantParent)
						}
						for j, key := range mftColumns(name) {
							var reference any
							json.Unmarshal(want.Values[j], &reference)
							cell := row.Cells[key]
							if absent, ok := reference.(map[string]any); ok {
								if missing, ok := absent["missing"]; ok {
									if cell.Kind != "missing" || cell.Reason != map[any]string{"NotApplicableValue": "not_applicable", "NotAvailableValue": "not_available", "UnparsableValue": "unparsable_filetime"}[missing] {
										t.Fatal(key, cell, missing)
									}
									continue
								}
								if key == "Hexdump" {
									if cell.Kind != "bytes" || hex.EncodeToString(stringsEvidenceBytes(t, cell)) != absent["raw"] {
										t.Fatal(key, cell, reference)
									}
									at, _ := row.Cells["ContentOffset"].Uint()
									length, _ := row.Cells["ContentLength"].Uint()
									if at != uint64(absent["offset"].(float64)) || length != uint64(absent["length"].(float64)) {
										t.Fatal("content coordinates")
									}
									continue
								}
							}
							if numeric, ok := reference.(float64); ok {
								got, err := cell.Uint()
								if err != nil || got != uint64(numeric) {
									t.Fatal(key, cell, reference)
								}
							} else if cell.Kind != "string" || cell.String() != reference {
								t.Fatal(key, cell, reference)
							}
						}
					}
					// Seal/store round trip and successful cache must preserve exact JSONL.
					var stored bytes.Buffer
					offset := 0
					for {
						page, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 256, Offset: offset})
						if err != nil {
							t.Fatal(err)
						}
						if len(page) == 0 {
							break
						}
						for _, row := range page {
							if err = row.Verify(); err != nil {
								t.Fatal(err)
							}
							json.NewEncoder(&stored).Encode(row)
						}
						offset += len(page)
					}
					if !bytes.Equal(stored.Bytes(), wire.Bytes()) {
						t.Fatal("stored stream differs")
					}
					var replay bytes.Buffer
					again, err := e.Run(context.Background(), "windows."+name, nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
					if runErr == nil {
						if err != nil || !again.Reused || !bytes.Equal(replay.Bytes(), wire.Bytes()) {
							t.Fatal("cache", again, err)
						}
					} else {
						if err == nil || again.Reused || again.Task.ID == result.Task.ID {
							t.Fatal("failed task reused", again, err)
						}
					}
					if len(all) == 0 || !reflect.DeepEqual(all[len(all)-1].Cells["RecordType"].String(), "summary") {
						t.Fatal("summary missing")
					}
				})
			}
		})
	}
}
