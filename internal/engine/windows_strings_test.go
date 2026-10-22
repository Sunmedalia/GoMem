package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type stringsOracleCase struct {
	Width      int
	Name       string
	NativeArch string
	ISF        json.RawMessage
	Size       int
	Input      string
	Writes     []struct {
		Offset int
		Data   string
	}
	ExpectedNative [][]json.RawMessage `json:"expected_native"`
}

func stringsOracleCases(t *testing.T) []stringsOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-strings-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []stringsOracleCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 24 {
		t.Fatal("fixture drift")
	}
	return f.Cases
}
func stringsOracleEngine(t *testing.T, c stringsOracleCase) (*engine.Engine, string, []byte) {
	t.Helper()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset+len(raw) > len(data) {
			t.Fatal("bad fixture")
		}
		copy(data[w.Offset:], raw)
	}
	arch := "x64"
	if c.Width == 4 {
		arch = "x86"
	}
	if c.NativeArch != "" {
		arch = c.NativeArch
	}
	if arch == "pae" {
		original := append([]byte(nil), data[0x9000:0xa000]...)
		clear(data[0x8000:0xb000])
		binary.LittleEndian.PutUint64(data[0x8000:], 0x9003)
		binary.LittleEndian.PutUint64(data[0x9000:], 0xa003)
		for i := range 512 {
			binary.LittleEndian.PutUint64(data[0xa000+i*8:], uint64(binary.LittleEndian.Uint32(original[i*4:])))
		}
		for _, root := range []int{0x20000, 0x30000} {
			entry := binary.LittleEndian.Uint32(data[root:])
			original := append([]byte(nil), data[root+0x1000:root+0x2000]...)
			clear(data[root : root+0x3000])
			if entry == 0 {
				continue
			}
			binary.LittleEndian.PutUint64(data[root:], uint64(root+0x1000)|3)
			if int(entry&^4095) != root+0x1000 {
				binary.LittleEndian.PutUint64(data[root+0x1000:], uint64(entry))
				continue
			}
			binary.LittleEndian.PutUint64(data[root+0x1000:], uint64(root+0x2000)|3)
			for i := range 512 {
				binary.LittleEndian.PutUint64(data[root+0x2000+i*8:], uint64(binary.LittleEndian.Uint32(original[i*4:])))
			}
		}
	}
	dir := t.TempDir()
	image, symbol, input := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json"), filepath.Join(dir, "strings.txt")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symbol, c.ISF, 0600); err != nil {
		t.Fatal(err)
	}
	text, err := hex.DecodeString(c.Input)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, text, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, input, data
}
func stringsEvidenceBytes(t *testing.T, v evidence.Value) []byte {
	t.Helper()
	if v.Kind != "bytes" {
		t.Fatal(v)
	}
	switch x := v.Data.(type) {
	case nil:
		return nil
	case []byte:
		return x
	case string:
		raw, err := base64.StdEncoding.DecodeString(x)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	default:
		t.Fatal(v)
		return nil
	}
}
func TestWindowsStringsActualGeneratorAndOriginalEvidence(t *testing.T) {
	cases := stringsOracleCases(t)
	for _, c := range append([]stringsOracleCase(nil), cases...) {
		if c.Width == 4 {
			c.NativeArch = "pae"
			cases = append(cases, c)
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%s/%s", c.Width, c.NativeArch, c.Name), func(t *testing.T) {
			e, input, data := stringsOracleEngine(t, c)
			params := map[string]string{"strings_file": input}
			if c.Name == "filter-match" {
				params["pid"] = "108"
			}
			if c.Name == "filter-miss" {
				params["pid"] = "999"
			}
			var found, all []evidence.Row
			var encoded bytes.Buffer
			reads := 0
			result, err := e.Run(context.Background(), "windows.strings", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
				all = append(all, row)
				if row.Cells["RecordType"].String() == "string" {
					found = append(found, row)
				}
				if row.Cells["RecordType"].String() == "memory_read" {
					reads++
					at, cause := row.Cells["Offset"].Uint()
					if cause != nil {
						t.Fatal(cause)
					}
					requested, _ := row.Cells["Requested"].Uint()
					raw := stringsEvidenceBytes(t, row.Cells["Raw"])
					if at+uint64(len(raw)) > uint64(len(data)) && len(raw) > 0 {
						t.Fatal("capture outside physical fixture")
					}
					if len(raw) > 0 && !bytes.Equal(raw, data[at:at+uint64(len(raw))]) {
						t.Fatal("original bytes differ")
					}
					layer := e.Env.Physical
					if row.Provenance.Layer == e.Env.Kernel.Name() {
						layer = e.Env.Kernel
					} else if row.Provenance.Layer != e.Env.Physical.Name() {
						t.Fatal("unknown layer")
					}
					actual := make([]byte, requested)
					n, cause := layer.ReadAt(context.Background(), actual, at)
					if n != len(raw) || !bytes.Equal(raw, actual[:n]) || (cause == nil) != (row.Cells["Error"].Kind == "missing") {
						t.Fatal("independent source reread", at, cause)
					}
				}
				return json.NewEncoder(&encoded).Encode(row)
			}})
			damaged := c.Name == "invalid-lines" || c.Name == "greedy-lines" || c.Name == "table-hole" || c.Name == "high-pfn" && c.Width == 8
			if (err != nil) != damaged {
				t.Fatal("coverage state", result, err)
			}
			if len(found) != len(c.ExpectedNative) {
				t.Fatal("row count", len(found), len(c.ExpectedNative), err)
			}
			for index, want := range c.ExpectedNative {
				var text, address string
				var associations []string
				json.Unmarshal(want[0], &text)
				json.Unmarshal(want[1], &address)
				json.Unmarshal(want[2], &associations)
				sort.Strings(associations)
				got := found[index]
				offset, _ := got.Cells["PhysicalAddress"].Uint()
				actual := strings.Split(got.Cells["Result"].String(), ", ")
				sort.Strings(actual)
				if got.Cells["String"].String() != text || strconv.FormatUint(offset, 10) != address || !reflect.DeepEqual(actual, associations) {
					t.Fatalf("%d got %s %d %v want %q %s %v", index, got.Cells["String"], offset, actual, text, address, associations)
				}
				lineOffset, _ := got.Cells["InputOffset"].Uint()
				raw := stringsEvidenceBytes(t, got.Cells["RawLine"])
				source, _ := hex.DecodeString(c.Input)
				if lineOffset+uint64(len(raw)) > uint64(len(source)) || !bytes.Equal(raw, source[lineOffset:lineOffset+uint64(len(raw))]) {
					t.Fatal("input byte provenance differs")
				}
			}
			if len(found) > 0 && reads == 0 {
				t.Fatal("no source captures")
			}
			var stored bytes.Buffer
			for off := 0; ; off += 1000 {
				rows, cause := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: off, Limit: 1000})
				if cause != nil {
					t.Fatal(cause)
				}
				for _, row := range rows {
					if cause := row.Verify(); cause != nil {
						t.Fatal(cause)
					}
					json.NewEncoder(&stored).Encode(row)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(encoded.Bytes(), stored.Bytes()) {
				t.Fatal("sealed storage drift")
			}
			var cached bytes.Buffer
			again, cause := e.Run(context.Background(), "windows.strings", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
			if damaged {
				if cause == nil || again.Reused {
					t.Fatal("partial evidence cached")
				}
			} else if cause != nil || !again.Reused || !bytes.Equal(cached.Bytes(), encoded.Bytes()) {
				t.Fatal("cache replay drift", cause)
			}
			// Independently translate every claimed physical association from each
			// process's own original page root, rather than trusting display fields.
			layers, _ := etwOracleLayers(t, e)
			for _, row := range all {
				if row.Cells["RecordType"].String() != "string" {
					continue
				}
				raw, _ := json.Marshal(row.Cells["PhysicalAssociations"].Data)
				var mappings []map[string]evidence.Value
				if cause := json.Unmarshal(raw, &mappings); cause != nil {
					t.Fatal(cause)
				}
				for _, m := range mappings {
					layer := e.Env.Kernel
					if m["Name"].String() != "kernel" {
						layer = layers["process:"+m["Identity"].String()]
					}
					space, ok := layer.(*memory.Virtual)
					if !ok {
						t.Fatal("unknown claimed address space")
					}
					va, _ := m["VirtualAddress"].Uint()
					physical, _ := m["PhysicalAddress"].Uint()
					tr, cause := space.Translator.Translate(context.Background(), va)
					if cause != nil || tr.Physical != physical {
						t.Fatal("false physical association", m, cause, tr)
					}
				}
			}
		})
	}
}

func TestWindowsStringsLimitsCancellationAndOutputStops(t *testing.T) {
	var c stringsOracleCase
	for _, candidate := range stringsOracleCases(t) {
		if candidate.Width == 8 && candidate.Name == "normal" {
			c = candidate
			break
		}
	}
	for _, key := range []string{"max-lines", "max-line-bytes", "max-map-tables", "max-map-entries", "max-mappings", "max-associations", "max-read-bytes"} {
		t.Run(key, func(t *testing.T) {
			e, input, _ := stringsOracleEngine(t, c)
			result, err := e.Run(context.Background(), "windows.strings", map[string]string{"strings_file": input, key: "1"}, engine.RunOptions{})
			if err == nil || result.Task.State != "failed" {
				t.Fatal("budget accepted", result, err)
			}
			again, cause := e.Run(context.Background(), "windows.strings", map[string]string{"strings_file": input, key: "1"}, engine.RunOptions{})
			if cause == nil || again.Reused {
				t.Fatal("budget failure reused", again, cause)
			}
		})
	}
	for _, kind := range []string{"input", "query_page", "memory_read", "association", "string"} {
		for _, mode := range []string{"cancel", "emitter"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				e, input, _ := stringsOracleEngine(t, c)
				counted := &stringsCountingLayer{MemoryLayer: e.Env.Physical}
				e.Env.Physical = counted
				translator, err := memory.NewIntelForOS(counted, 0x8000, "x64", "windows", 8)
				if err != nil {
					t.Fatal(err)
				}
				e.Env.Kernel = &memory.Virtual{Physical: counted, Translator: translator, ID: e.Env.Kernel.Name()}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stop := fmt.Errorf("test output stop")
				triggered := false
				calls := 0
				result, err := e.Run(ctx, "windows.strings", map[string]string{"strings_file": input}, engine.RunOptions{Emit: func(row evidence.Row) error {
					if triggered {
						t.Fatal("emitted after stop")
					}
					if row.Cells["RecordType"].String() == kind {
						triggered = true
						calls = counted.calls
						if mode == "cancel" {
							cancel()
							return nil
						}
						return stop
					}
					return nil
				}})
				if err == nil || !triggered || counted.calls != calls || result.Task.State == "completed" {
					t.Fatal("stop ignored", triggered, calls, counted.calls, result, err)
				}
			})
		}
	}
}

type stringsCountingLayer struct {
	memory.MemoryLayer
	calls int
}

func (l *stringsCountingLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.calls++
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

type stringsFaultLayer struct {
	memory.MemoryLayer
	mode string
}

func (l stringsFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x20000 {
		if l.mode == "short" {
			return 0, nil
		}
		if l.mode == "invalid" {
			return len(p) + 1, nil
		}
		return 0, fmt.Errorf("missing table")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func TestWindowsStringsExplicitReadFailuresAndRetry(t *testing.T) {
	var normal stringsOracleCase
	for _, c := range stringsOracleCases(t) {
		if c.Width == 8 && c.Name == "normal" {
			normal = c
			break
		}
	}
	for _, mode := range []string{"short", "invalid", "missing", "range-hole", "root-metadata"} {
		t.Run(mode, func(t *testing.T) {
			c := normal
			if mode == "root-metadata" {
				var isf map[string]any
				json.Unmarshal(c.ISF, &isf)
				fields := isf["user_types"].(map[string]any)["_KPROCESS"].(map[string]any)["fields"].(map[string]any)
				delete(fields, "DirectoryTableBase")
				c.ISF, _ = json.Marshal(isf)
			}
			e, input, _ := stringsOracleEngine(t, c)
			if mode == "range-hole" {
				physical, err := memory.NewMapped(e.Source, "physical:hole", []memory.Range{{Start: 0, Length: 0x180000}, {Start: 0x181000, Length: uint64(c.Size) - 0x181000, FileOffset: 0x181000}})
				if err != nil {
					t.Fatal(err)
				}
				e.Env.Physical = physical
			} else if mode != "root-metadata" {
				e.Env.Physical = stringsFaultLayer{e.Env.Physical, mode}
			}
			var diagnostics, stringsFound int
			result, err := e.Run(context.Background(), "windows.strings", map[string]string{"strings_file": input}, engine.RunOptions{Emit: func(row evidence.Row) error {
				kind := row.Cells["RecordType"].String()
				if kind == "mapping_unavailable" || kind == "process_unavailable" || kind == "memory_read" && row.Cells["Error"].Kind != "missing" {
					diagnostics++
				}
				if kind == "string" {
					stringsFound++
				}
				return row.Verify()
			}})
			if err == nil || diagnostics == 0 || stringsFound == 0 || result.Task.State != "failed" {
				t.Fatal("read failure hidden", mode, diagnostics, stringsFound, result, err)
			}
			again, err := e.Run(context.Background(), "windows.strings", map[string]string{"strings_file": input}, engine.RunOptions{})
			if err == nil || again.Reused {
				t.Fatal("failed source cached")
			}
		})
	}
}
