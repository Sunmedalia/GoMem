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
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func windowsMalfindCases(t testing.TB) []suspendedOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-malfind-oracle.json")
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
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 70 {
		t.Fatal("fixture drift")
	}
	return f.Cases
}
func windowsMalfindEngine(t *testing.T, c suspendedOracleCase) (*engine.Engine, []byte) {
	t.Helper()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset+len(raw) > len(data) {
			t.Fatal("invalid fixture")
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
		clear(data[0x8000:0xc000])
		binary.LittleEndian.PutUint64(data[0x8000:], 0x9003)
		binary.LittleEndian.PutUint64(data[0x9000:], 0xb003)
		for index := range 512 {
			binary.LittleEndian.PutUint64(data[0xb000+index*8:], uint64(binary.LittleEndian.Uint32(original[index*4:])))
		}
		if strings.HasPrefix(c.Name, "second-") {
			original := append([]byte(nil), data[0x25000:0x26000]...)
			clear(data[0x20000:0x24000])
			binary.LittleEndian.PutUint64(data[0x20000:], 0x21003)
			binary.LittleEndian.PutUint64(data[0x21000:], 0x23003)
			for index := range 512 {
				binary.LittleEndian.PutUint64(data[0x23000+index*8:], uint64(binary.LittleEndian.Uint32(original[index*4:])))
			}
		}
	}
	dir := t.TempDir()
	image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symbol, c.ISF, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, data
}

func TestWindowsMalfindActualPinnedGenerator(t *testing.T) {
	cases := windowsMalfindCases(t)
	for _, c := range append([]suspendedOracleCase(nil), cases...) {
		if c.Width == 4 {
			c.NativeArch = "pae"
			c.Name += "-pae"
			cases = append(cases, c)
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%s", c.Width, c.Name), func(t *testing.T) {
			e, data := windowsMalfindEngine(t, c)
			layers, roots := etwOracleLayers(t, e)
			layers[e.Env.Physical.Name()] = e.Env.Physical
			var found []evidence.Row
			var encoded bytes.Buffer
			calls := 0
			ctx := context.Background()
			parameters := map[string]string{}
			if strings.HasPrefix(c.Name, "pid-match") {
				parameters["pid"] = "104"
			}
			if strings.HasPrefix(c.Name, "pid-mismatch") || strings.HasPrefix(c.Name, "second-filtered") {
				parameters["pid"] = "108"
			}
			if strings.HasPrefix(c.Name, "dump-") {
				parameters["dump"] = "true"
			}
			result, runErr := e.Run(ctx, "windows.malfind", parameters, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "memory_read" {
					calls++
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
					if roots[row.Provenance.Layer] == 0x20000 && at >= 0x100000 && at+requested <= 0x101000 {
						physical = at - 0x100000 + 0x1e0000
					}
					if !ok || physical+uint64(len(raw)) > uint64(len(data)) || !bytes.Equal(raw, data[physical:physical+uint64(len(raw))]) {
						t.Fatal("physical fixture bytes drift", at, requested)
					}
					layer := layers[row.Provenance.Layer]
					if layer == nil {
						t.Fatal("unknown captured layer", row.Provenance.Layer)
					}
					actual := make([]byte, requested)
					n, cause := layer.ReadAt(ctx, actual, at)
					if n != len(raw) || !bytes.Equal(raw, actual[:n]) || (cause == nil) != (row.Cells["Error"].Kind == "missing") {
						t.Fatal("independent reread drift", at, requested, cause)
					}
				}
				if row.Cells["RecordType"].String() == "finding" {
					found = append(found, row)
				}
				return json.NewEncoder(&encoded).Encode(row)
			}})
			if len(found) != len(c.Expected) || calls == 0 {
				t.Fatal("finding/capture count", len(found), len(c.Expected), calls, runErr)
			}
			for i, want := range c.Expected {
				for j, col := range []string{"PID", "Process", "Start", "End", "Tag", "Protection", "CommitCharge", "PrivateMemory"} {
					got := found[i].Cells[col]
					if got.Kind == "uint64" || got.Kind == "address" {
						var n uint64
						json.Unmarshal(want[j], &n)
						v, cause := got.Uint()
						if cause != nil || v != n {
							t.Fatal(col, got, n, cause)
						}
					} else {
						var s string
						json.Unmarshal(want[j], &s)
						if got.String() != s {
							t.Fatal(col, got, s)
						}
					}
				}
				if !strings.HasPrefix(c.Name, "dump-") && found[i].Cells["FileOutput"].Reason != "not_requested" {
					t.Fatal("dump not disabled")
				}
				notes := found[i].Cells["Notes"]
				if string(want[9]) == "null" {
					if notes.Kind != "missing" {
						t.Fatal(notes)
					}
				} else {
					var s string
					json.Unmarshal(want[9], &s)
					if notes.String() != s {
						t.Fatal(notes, s)
					}
				}
				var hexdump struct {
					Offset uint64
					Length int
					Raw    string
				}
				var disasm struct{ Data, Architecture string }
				json.Unmarshal(want[10], &hexdump)
				json.Unmarshal(want[11], &disasm)
				if strings.HasPrefix(c.Name, "rwx-first-hole") || strings.HasPrefix(c.Name, "dump-hole") {
					if found[i].Cells["Hexdump"].Reason != "first_bytes_unavailable" || found[i].Cells["Hexdump"].Error == "" {
						t.Fatal("padded unreadable bytes asserted")
					}
				} else {
					raw := found[i].Cells["Hexdump"].Data.([]byte)
					if hex.EncodeToString(raw) != hexdump.Raw || hexdump.Length != 64 || hexdump.Offset != 0x100000 {
						t.Fatal("hexdump drift")
					}
					structure := found[i].Cells["Disassembly"].Data.(map[string]evidence.Value)
					if hex.EncodeToString(structure["Bytes"].Data.([]byte)) != disasm.Data || structure["Architecture"].String() != disasm.Architecture {
						t.Fatal("disassembly bytes/architecture drift", structure)
					}
				}
				if found[i].Cells["ProcessIdentity"].String() == "" {
					t.Fatal("missing process identity")
				}
				if strings.HasPrefix(c.Name, "rx-dirty") || strings.HasPrefix(c.Name, "rx-second-dirty") {
					if found[i].Cells["DirtyPage"].Kind != "address" || found[i].Cells["DirtyLeaf"].Kind != "structure" {
						t.Fatal("missing dirty source evidence")
					}
				}
			}
			damaged := strings.HasPrefix(c.Name, "rx-hole-") || strings.HasPrefix(c.Name, "rwx-first-hole") || strings.HasPrefix(c.Name, "rwx-all-hole") || strings.HasPrefix(c.Name, "dump-hole")
			if (runErr != nil) != damaged {
				t.Fatal("coverage state", result, runErr, damaged)
			}
			if len(c.Files) > 0 {
				artifacts, cause := e.Store.Artifacts(ctx, result.Task.ID)
				if cause != nil || len(artifacts) != len(c.Files) {
					t.Fatal("artifact count", artifacts, cause)
				}
				for _, a := range artifacts {
					actual, cause := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)))
					if cause != nil {
						t.Fatal(cause)
					}
					want, ok := c.Files[a.Name]
					if !ok || hex.EncodeToString(actual) != want {
						t.Fatal("actual pinned dump bytes differ", a.Name)
					}
				}
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
				t.Fatal("sealed store drift")
			}
			var replay bytes.Buffer
			again, cause := e.Run(ctx, "windows.malfind", parameters, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if damaged {
				if cause == nil || again.Reused {
					t.Fatal("failed task reused")
				}
			} else if cause != nil || !again.Reused || !bytes.Equal(encoded.Bytes(), replay.Bytes()) {
				t.Fatal("successful cache replay drift", again, cause)
			}
		})
	}
}

func TestWindowsMalfindExtractionAndOutputStops(t *testing.T) {
	var normal, hole suspendedOracleCase
	for _, c := range windowsMalfindCases(t) {
		if c.Width == 8 && c.Name == "rwx-private-short" {
			normal = c
		}
		if c.Width == 8 && c.Name == "rwx-first-hole" {
			hole = c
		}
	}
	for _, mode := range []string{"complete", "holes", "size-limit", "equal-size", "zero-limit", "stop-dump", "cancel-dump"} {
		t.Run(mode, func(t *testing.T) {
			c := normal
			if mode == "holes" {
				c = hole
			}
			e, data := windowsMalfindEngine(t, c)
			p := map[string]string{"dump": "true"}
			if mode == "size-limit" {
				p["maxsize"] = "16383"
			}
			if mode == "equal-size" {
				p["maxsize"] = "16384"
			}
			if mode == "zero-limit" {
				p["maxsize"] = "0"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := fmt.Errorf("dump output stopped")
			found := 0
			stopReads := 0
			result, err := e.Run(ctx, "windows.malfind", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "finding" {
					found++
					if mode == "size-limit" && row.Cells["FileOutput"].Reason != "maxsize_exceeded" {
						t.Fatal("size skip hidden")
					}
				}
				if row.Cells["RecordType"].String() == "memory_read" {
					raw, _ := json.Marshal(row.Cells["Resolution"].Data)
					var detail struct{ Method string }
					json.Unmarshal(raw, &detail)
					if detail.Method == "dump" && (mode == "stop-dump" || mode == "cancel-dump") {
						stopReads++
						if mode == "cancel-dump" {
							cancel()
							return nil
						}
						return sentinel
					}
				}
				return nil
			}})
			if mode == "stop-dump" || mode == "cancel-dump" {
				if err == nil || stopReads != 1 || found != 0 {
					t.Fatal("dump stop ignored", result, err, stopReads, found)
				}
				return
			}
			if (err != nil) != (mode == "holes") || found != 1 {
				t.Fatal(result, err, found)
			}
			artifacts, cause := e.Store.Artifacts(context.Background(), result.Task.ID)
			if cause != nil {
				t.Fatal(cause)
			}
			if mode == "size-limit" {
				if len(artifacts) != 0 {
					t.Fatal(artifacts)
				}
				return
			}
			if len(artifacts) != 1 {
				t.Fatal(artifacts)
			}
			a := artifacts[0]
			actual, cause := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)))
			if cause != nil {
				t.Fatal(cause)
			}
			want := append([]byte(nil), data[0x100000:0x104000]...)
			if mode == "holes" {
				clear(want[:4096])
				if a.MissingBytes != "4096" || a.GapCount != "1" {
					t.Fatal(a)
				}
			} else if a.MissingBytes != "0" {
				t.Fatal(a)
			}
			if !bytes.Equal(actual, want) {
				t.Fatal("extraction bytes differ")
			}
		})
	}
}

func TestWindowsMalfindFaultsBoundsAndCancellation(t *testing.T) {
	var normal, rx suspendedOracleCase
	for _, c := range windowsMalfindCases(t) {
		if c.Width == 8 && c.Name == "rwx-private-short" {
			normal = c
		}
		if c.Width == 8 && c.Name == "rx-clean" {
			rx = c
		}
	}
	for _, mode := range []string{"process-cycle", "vad-cycle", "node-limit", "region-limit", "page-limit", "byte-limit", "private-hole", "commit-hole", "root-hole", "page-hole", "page-short", "page-invalid", "emit-metadata", "emit-page", "emit-finding", "cancel-page", "cancel-finding", "pid-match", "pid-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			c := normal
			if mode == "page-limit" {
				c = rx
			}
			p := map[string]string{}
			put := func(at int, n uint64) {
				c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
					Offset int
					Data   string
				}{at, hex.EncodeToString(binary.LittleEndian.AppendUint64(nil, n))})
			}
			switch mode {
			case "process-cycle":
				put(0x400, 0x400)
			case "vad-cycle":
				put(0x1000, 0x1000)
			case "node-limit", "region-limit":
				data := make([]byte, c.Size)
				for _, w := range c.Writes {
					raw, _ := hex.DecodeString(w.Data)
					copy(data[w.Offset:], raw)
				}
				node := append([]byte(nil), data[0xff4:0x1038]...)
				clear(node[12:36])
				binary.LittleEndian.PutUint64(node[28:], 0x1000)
				c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
					Offset int
					Data   string
				}{0x11f4, hex.EncodeToString(node)})
				put(0x1000, 0x1200)
				if mode == "node-limit" {
					p["max-nodes"] = "1"
				} else {
					p["max-regions"] = "1"
				}
			case "page-limit":
				p["max-pages"] = "1"
			case "byte-limit":
				p["max-read-bytes"] = "1"
			case "pid-match":
				p["pid"] = "104"
			case "pid-mismatch":
				p["pid"] = "108"
			}
			e, _ := windowsMalfindEngine(t, c)
			calls, atStop := 0, -1
			e.Env.Physical = iatPhysicalFault{MemoryLayer: e.Env.Physical, at: ^uint64(0), calls: &calls}
			switch mode {
			case "private-hole", "commit-hole":
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x1030}
			case "root-hole":
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x450}
			case "page-hole", "page-short", "page-invalid":
				e.Env.Physical = iatPhysicalFault{MemoryLayer: e.Env.Physical, at: 0x100000, mode: strings.TrimPrefix(mode, "page-"), calls: &calls}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("malfind output failure")
			found := 0
			result, err := e.Run(ctx, "windows.malfind", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				kind := row.Cells["RecordType"].String()
				if kind == "finding" {
					found++
				}
				raw, _ := json.Marshal(row.Cells["Resolution"].Data)
				var detail struct{ Method string }
				json.Unmarshal(raw, &detail)
				stop := strings.HasSuffix(mode, "metadata") && kind == "memory_read" || strings.HasSuffix(mode, "-page") && kind == "memory_read" && detail.Method == "nonzero_page" || strings.HasSuffix(mode, "-finding") && kind == "finding"
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
			if strings.HasPrefix(mode, "pid-") {
				want := 1
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
				t.Fatal("lost emitter failure", err)
			}
			if strings.HasPrefix(mode, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
			if atStop >= 0 && calls != atStop {
				t.Fatal("read after stop", calls, atStop)
			}
		})
	}
}
