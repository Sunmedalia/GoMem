package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func iatOracleCases(t testing.TB) []suspendedOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-iat-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []suspendedOracleCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 90 {
		t.Fatal("fixture drift")
	}
	for i := range f.Cases {
		f.Cases[i].PDB = f.Cases[i].ISF
	}
	return f.Cases
}
func TestIATActualPinnedGenerator(t *testing.T) {
	cases := iatOracleCases(t)
	for _, c := range append([]suspendedOracleCase(nil), cases...) {
		if c.Width == 4 {
			c.NativeArch = "pae"
			c.Name += "-pae"
			cases = append(cases, c)
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%s", c.Width, c.Name), func(t *testing.T) {
			e, data := etwOracleEngine(t, c)
			layers, roots := etwOracleLayers(t, e)
			ctx := context.Background()
			var found []evidence.Row
			var encoded bytes.Buffer
			captures := 0
			parameters := map[string]string{}
			if strings.HasPrefix(c.Name, "pid-match") {
				parameters["pid"] = "104"
			}
			if strings.HasPrefix(c.Name, "pid-mismatch") || strings.HasPrefix(c.Name, "second-filtered") {
				parameters["pid"] = "108"
			}
			result, runErr := e.Run(ctx, "windows.iat", parameters, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "import" {
					found = append(found, row)
				}
				if row.Cells["RecordType"].String() == "memory_read" {
					captures++
					at, cause := row.Cells["Offset"].Uint()
					if cause != nil {
						t.Fatal(cause)
					}
					requested, cause := row.Cells["Requested"].Uint()
					if cause != nil {
						t.Fatal(cause)
					}
					raw, ok := row.Cells["Raw"].Data.([]byte)
					physical := at
					if roots[row.Provenance.Layer] == 0xb000 && at >= 0x101000 && at+requested <= 0x102000 {
						physical = at - 0x101000 + 0x1e0000
					}
					if !ok || physical+requested > uint64(len(data)) || !bytes.Equal(raw, data[physical:physical+uint64(len(raw))]) {
						t.Fatal("raw source differs", at, requested)
					}
					layer := layers[row.Provenance.Layer]
					if layer == nil {
						t.Fatal("unknown layer", row.Provenance.Layer)
					}
					actual := make([]byte, requested)
					n, readErr := layer.ReadAt(ctx, actual, at)
					if n != len(raw) || !bytes.Equal(actual[:n], raw) || (readErr == nil) != (row.Cells["Error"].Kind == "missing") {
						t.Fatal("independent reread differs", readErr)
					}
				}
				return json.NewEncoder(&encoded).Encode(row)
			}})
			if len(found) != len(c.Expected) || captures == 0 {
				t.Fatal(len(found), len(c.Expected), captures, runErr)
			}
			for i, want := range c.Expected {
				for j, col := range []string{"PID", "Name", "Library", "Bound", "Function", "Address"} {
					got := found[i].Cells[col]
					if string(want[j]) == "null" {
						if got.Kind != "missing" {
							t.Fatal(col, got)
						}
						continue
					}
					if got.Kind == "uint64" || got.Kind == "address" {
						var n uint64
						json.Unmarshal(want[j], &n)
						v, cause := got.Uint()
						if cause != nil || v != n {
							t.Fatal(col, got, n, cause)
						}
					} else {
						raw, cause := json.Marshal(got.Data)
						if cause != nil || !bytes.Equal(raw, want[j]) {
							t.Fatal(col, string(raw), string(want[j]))
						}
					}
				}
				slot, _ := found[i].Cells["IATSlot"].Uint()
				addr, _ := found[i].Cells["Address"].Uint()
				if addr != slot+0x100000 {
					t.Fatal("baseline/actual coordinate drift")
				}
				if found[i].Cells["ProcessIdentity"].String() == "" {
					t.Fatal("missing identity")
				}
			}
			if runErr == nil && result.Task.State != "completed" {
				t.Fatal(result)
			}
			if runErr != nil && result.Task.State != "failed" {
				t.Fatal(result, runErr)
			}
			var sealed bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, cause := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if cause != nil {
					t.Fatal(cause)
				}
				for _, row := range rows {
					if cause = row.Verify(); cause != nil {
						t.Fatal(cause)
					}
					json.NewEncoder(&sealed).Encode(row)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(encoded.Bytes(), sealed.Bytes()) {
				t.Fatal("stored rows changed")
			}
			var replay bytes.Buffer
			again, cause := e.Run(ctx, "windows.iat", parameters, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if runErr == nil {
				if cause != nil || !again.Reused || !bytes.Equal(encoded.Bytes(), replay.Bytes()) {
					t.Fatal("successful cache replay differs", again, cause)
				}
			} else if again.Reused || cause == nil {
				t.Fatal("failed task reused", again, cause)
			}
		})
	}
}

type iatPhysicalFault struct {
	memory.MemoryLayer
	at    uint64
	mode  string
	calls *int
}

func (l iatPhysicalFault) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	*l.calls++
	if at == l.at {
		switch l.mode {
		case "hole":
			return 0, memory.ErrUnmapped
		case "short":
			return 0, nil
		case "invalid":
			return len(p) + 1, nil
		}
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func TestIATFaultsBoundsFilterAndCancellation(t *testing.T) {
	var normal suspendedOracleCase
	for _, c := range iatOracleCases(t) {
		if c.Width == 8 && c.Name == "normal" {
			normal = c
		}
	}
	modes := []string{"process-cycle", "descriptors", "imports", "thunks", "bytes", "peb-hole", "root-hole", "hint-hole", "hint-short", "hint-invalid", "emit-metadata", "emit-import", "cancel-metadata", "cancel-import", "pid-mismatch", "pid-match"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			c := normal
			p := map[string]string{}
			switch mode {
			case "process-cycle":
				c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
					Offset int
					Data   string
				}{0x400, hex.EncodeToString(binary.LittleEndian.AppendUint64(nil, 0x400))})
			case "descriptors", "imports", "thunks":
				p["max-"+mode] = "1"
			case "bytes":
				p["max-read-bytes"] = "1"
			case "pid-mismatch":
				p["pid"] = "108"
			case "pid-match":
				p["pid"] = "104"
			}
			e, _ := suspendedOracleEngine(t, c)
			calls, atStop := 0, -1
			e.Env.Physical = iatPhysicalFault{MemoryLayer: e.Env.Physical, at: ^uint64(0), calls: &calls}
			if mode == "peb-hole" {
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x458}
			}
			if mode == "root-hole" {
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x450}
			}
			if strings.HasPrefix(mode, "hint-") {
				e.Env.Physical = iatPhysicalFault{MemoryLayer: e.Env.Physical, at: 0x101f00, mode: strings.TrimPrefix(mode, "hint-"), calls: &calls}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("IAT output failure")
			found := 0
			result, err := e.Run(ctx, "windows.iat", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				kind := row.Cells["RecordType"].String()
				if kind == "import" {
					found++
				}
				stop := strings.HasSuffix(mode, "metadata") && kind == "memory_read" || strings.HasSuffix(mode, "-import") && kind == "import"
				if stop {
					atStop = calls
					if strings.HasPrefix(mode, "cancel-") {
						cancel()
						return nil
					}
					return sentinel
				}
				return nil
			}})
			if mode == "pid-match" || mode == "pid-mismatch" {
				want := 2
				if mode == "pid-mismatch" {
					want = 0
				}
				if err != nil || found != want {
					t.Fatal(result, err, found)
				}
				return
			}
			wantState := "failed"
			if strings.HasPrefix(mode, "cancel-") {
				wantState = "canceled"
			}
			if err == nil || result.Task.State != wantState {
				t.Fatal("failure hidden", result, err)
			}
			if strings.HasPrefix(mode, "emit-") && !errors.Is(err, sentinel) {
				t.Fatal("lost output error", err)
			}
			if strings.HasPrefix(mode, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancel", err)
			}
			if atStop >= 0 && calls != atStop {
				t.Fatal("read after output/cancel", calls, atStop)
			}
			if strings.HasPrefix(mode, "hint-") && found != 0 {
				t.Fatal("damaged descriptor emitted partial invalid imports", found)
			}
		})
	}
}
