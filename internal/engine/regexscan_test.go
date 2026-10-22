package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type regexOracleCase struct {
	Name, Arch, Pattern string
	Size                int
	ISF                 json.RawMessage
	Writes              []struct {
		Offset int
		Data   string
	}
	Rows          []struct{ Values []json.RawMessage }
	Error         *string
	KernelGeneric struct {
		Rows  []struct{ Values []json.RawMessage }
		Error *string
	} `json:"kernel_generic"`
}

func regexOracleCases(t *testing.T) []regexOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ VMAs []regexOracleCase }
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.VMAs) != 42 {
		t.Fatal("fixture drift")
	}
	return f.VMAs
}
func regexOracleEngine(t *testing.T, c regexOracleCase, withSymbols bool) (*engine.Engine, []byte) {
	t.Helper()
	dir := t.TempDir()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		b, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
			t.Fatal("invalid fixture")
		}
		copy(data[w.Offset:], b)
	}
	image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if withSymbols {
		if err := os.WriteFile(symbol, c.ISF, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		symbol = ""
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "linux", Arch: c.Arch, DTB: "0x8000", Offline: true, CaseDir: filepath.Join(dir, "case")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, data
}
func regexStructure(t *testing.T, v evidence.Value) map[string]evidence.Value {
	t.Helper()
	raw, err := json.Marshal(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]evidence.Value
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func regexParts(t *testing.T, v evidence.Value) []map[string]evidence.Value {
	t.Helper()
	raw, err := json.Marshal(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]evidence.Value
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func verifyRegexRows(t *testing.T, e *engine.Engine, data []byte, rows []evidence.Row) {
	t.Helper()
	for _, row := range rows {
		if err := row.Verify(); err != nil {
			t.Fatal(err)
		}
		kind := row.Cells["RecordType"].String()
		if kind == "scan_chunk" {
			mapping := regexStructure(t, row.Cells["Mapping"])
			var reconstructed []byte
			for _, p := range regexParts(t, mapping["Parts"]) {
				at, _ := p["Physical"].Uint()
				n, _ := p["Captured"].Uint()
				if at > uint64(len(data)) || n > uint64(len(data))-at {
					t.Fatal("scan capture outside source")
				}
				sum := sha256.Sum256(data[at : at+n])
				if hex.EncodeToString(sum[:]) != p["SHA256"].String() {
					t.Fatal("original scan digest mismatch")
				}
				if p["ReadComplete"].Data == true {
					reconstructed = append(reconstructed, data[at:at+n]...)
				}
			}
			sum := sha256.Sum256(reconstructed)
			if hex.EncodeToString(sum[:]) != row.Cells["SHA256"].String() {
				t.Fatal("buffer digest mismatch")
			}
		}
		if kind == "regex_match" {
			contextProof := regexStructure(t, row.Cells["Context"])
			at, _ := contextProof["Address"].Uint()
			raw := stringsEvidenceBytes(t, contextProof["Raw"])
			// These real paged fixtures map identity; reread the exact original bytes.
			if at+uint64(len(raw)) > uint64(len(data)) || !bytes.Equal(raw, data[at:at+uint64(len(raw))]) {
				t.Fatal("context source mismatch")
			}
			source := regexStructure(t, row.Cells["Source"])
			var matched []byte
			for _, p := range regexParts(t, source["Parts"]) {
				physical, _ := p["Physical"].Uint()
				size, _ := p["Length"].Uint()
				matched = append(matched, data[physical:physical+size]...)
			}
			if !bytes.Equal(matched, stringsEvidenceBytes(t, row.Cells["MatchRaw"])) {
				t.Fatal("match raw source mismatch")
			}
		}
		if raw, ok := row.Cells["Raw"]; ok {
			at, _ := row.Cells["Offset"].Uint()
			b := stringsEvidenceBytes(t, raw)
			if at+uint64(len(b)) > uint64(len(data)) || !bytes.Equal(b, data[at:at+uint64(len(b))]) {
				t.Fatal("source read mismatch", kind, at)
			}
		}
	}
}
func TestLinuxVMARegexActualGeneratorAndSealedCache(t *testing.T) {
	for _, c := range regexOracleCases(t) {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			e, data := regexOracleEngine(t, c, true)
			var found, all []evidence.Row
			var wire bytes.Buffer
			params := map[string]string{"pattern": c.Pattern, "maxsize": "4"}
			result, err := e.Run(context.Background(), "linux.vmaregexscan", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				all = append(all, row)
				if row.Cells["RecordType"].String() == "regex_match" {
					found = append(found, row)
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			damaged := c.Error != nil || c.Name == "missing-page"
			if (err != nil) != damaged {
				t.Fatal("task completeness", result.Task.State, err)
			}
			if len(found) != len(c.Rows) {
				t.Fatal("match count", len(found), len(c.Rows), err)
			}
			for i, want := range c.Rows {
				var pid, offset uint64
				var name, text, hexBytes string
				json.Unmarshal(want.Values[0], &pid)
				json.Unmarshal(want.Values[1], &name)
				json.Unmarshal(want.Values[2], &offset)
				json.Unmarshal(want.Values[3], &text)
				json.Unmarshal(want.Values[4], &hexBytes)
				row := found[i]
				p, _ := row.Cells["PID"].Uint()
				at, _ := row.Cells["Offset"].Uint()
				if p != pid || at != offset || row.Cells["Process"].String() != name || row.Cells["Text"].String() != text || hex.EncodeToString(stringsEvidenceBytes(t, row.Cells["Hex"])) != hexBytes {
					t.Fatalf("%d: got %v want %s", i, row.Cells, want.Values)
				}
			}
			verifyRegexRows(t, e, data, all)
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, cause := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if cause != nil {
					t.Fatal(cause)
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
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("sealed store changed evidence")
			}
			var cached bytes.Buffer
			replay, cause := e.Run(context.Background(), "linux.vmaregexscan", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
			if !damaged && (cause != nil || !replay.Reused || !bytes.Equal(wire.Bytes(), cached.Bytes())) {
				t.Fatal("cache replay", replay, cause)
			}
			if damaged && replay.Reused {
				t.Fatal("incomplete task cached")
			}
		})
	}
}

func TestRegexTranslationDependencyWithoutSymbols(t *testing.T) {
	c := regexOracleCases(t)[0]
	e, data := regexOracleEngine(t, c, false)
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "regexscan", map[string]string{"pattern": "MATCH"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	if e.Env.Symbols != nil {
		t.Fatal("generic regex unexpectedly required symbols")
	}
	found := 0
	for _, r := range rows {
		if r.Cells["RecordType"].String() == "regex_match" {
			found++
		}
		if r.Provenance.Layer == "" {
			t.Fatal("missing layer provenance")
		}
	}
	if found != 4 {
		t.Fatal("unexpected kernel matches", found)
	}
	verifyRegexRows(t, e, data, rows)
	if _, err = e.Run(context.Background(), "regexscan", nil, engine.RunOptions{}); err == nil {
		t.Fatal("missing required pattern accepted")
	}
}

func TestKernelRegexActualGeneratorWithoutSymbols(t *testing.T) {
	for _, c := range regexOracleCases(t) {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			e, data := regexOracleEngine(t, c, false)
			var all, found []evidence.Row
			params := map[string]string{"pattern": c.Pattern, "maxsize": "4"}
			result, err := e.Run(context.Background(), "regexscan", params, engine.RunOptions{Emit: func(r evidence.Row) error {
				all = append(all, r)
				if r.Cells["RecordType"].String() == "regex_match" {
					found = append(found, r)
				}
				return nil
			}})
			if (err != nil) != (c.KernelGeneric.Error != nil) {
				t.Fatal("kernel scan completeness", result.Task.State, err)
			}
			if len(found) != len(c.KernelGeneric.Rows) {
				t.Fatal("match count", len(found), len(c.KernelGeneric.Rows), err)
			}
			for i, want := range c.KernelGeneric.Rows {
				var at uint64
				var text, hexBytes string
				json.Unmarshal(want.Values[0], &at)
				json.Unmarshal(want.Values[1], &text)
				json.Unmarshal(want.Values[2], &hexBytes)
				got := found[i]
				address, _ := got.Cells["Offset"].Uint()
				if address != at || got.Cells["Text"].String() != text || hex.EncodeToString(stringsEvidenceBytes(t, got.Cells["Hex"])) != hexBytes {
					t.Fatal(i, got.Cells, want.Values)
				}
			}
			verifyRegexRows(t, e, data, all)
		})
	}
}

type regexFaultLayer struct {
	memory.MemoryLayer
	mode  string
	reads int
}

func (l *regexFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads++
	if l.mode == "table" && at == 0x8000 && len(p) == 4096 {
		return 0, io.ErrUnexpectedEOF
	}
	if l.mode == "scan" && len(p) > 4096 {
		n, err := l.MemoryLayer.ReadAt(ctx, p[:17], at)
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	if l.mode == "context" && len(p) == 4 {
		n, err := l.MemoryLayer.ReadAt(ctx, p[:2], at)
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func TestRegexFailuresRemainUncachedAndOutputStops(t *testing.T) {
	for _, mode := range []string{"table", "scan", "context", "max-read-bytes", "max-map-tables", "max-map-entries", "max-mappings", "max-matches", "max-proof-pages", "regex-steps", "cancel", "emitter"} {
		t.Run(mode, func(t *testing.T) {
			c := regexOracleCases(t)[0]
			e, _ := regexOracleEngine(t, c, false)
			wrapped := &regexFaultLayer{MemoryLayer: e.Env.Physical, mode: mode}
			e.Env.Physical = wrapped
			params := map[string]string{"pattern": "MATCH", "maxsize": "4"}
			switch mode {
			case "max-read-bytes":
				params[mode] = "4096"
			case "max-map-tables", "max-map-entries", "max-mappings", "max-matches", "max-proof-pages", "regex-steps":
				params[mode] = "1"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("output stopped")
			calls := 0
			result, err := e.Run(ctx, "regexscan", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				calls++
				if mode == "cancel" {
					cancel()
				}
				if mode == "emitter" {
					return sentinel
				}
				return nil
			}})
			if err == nil || result.Task.State == "completed" {
				t.Fatal("failure hidden", result, err)
			}
			if mode == "cancel" && (!errors.Is(err, context.Canceled) || calls != 1) {
				t.Fatal("continued after cancel", calls, err)
			}
			if mode == "emitter" && (!errors.Is(err, sentinel) || calls != 1) {
				t.Fatal("continued after output error", calls, err)
			}
			replay, cause := e.Run(context.Background(), "regexscan", params, engine.RunOptions{})
			if replay.Reused {
				t.Fatal("failed task cached", replay, cause)
			}
		})
	}
	c := regexOracleCases(t)[0]
	e, _ := regexOracleEngine(t, c, false)
	e.Env.Kernel = nil
	if _, err := e.Run(context.Background(), "regexscan", map[string]string{"pattern": "MATCH"}, engine.RunOptions{}); err == nil {
		t.Fatal("missing translation accepted")
	}
}

func TestVMARegexPaddedContextKeepsMissingBytesExplicit(t *testing.T) {
	var c regexOracleCase
	for _, sample := range regexOracleCases(t) {
		if sample.Arch == "x64" && sample.Name == "literal" {
			c = sample
			break
		}
	}
	add := func(at int, data []byte) {
		c.Writes = append(c.Writes, struct {
			Offset int
			Data   string
		}{at, hex.EncodeToString(data)})
	}
	// Place a hit entirely inside the VMA, with context crossing an unmapped page.
	add(0x10000, make([]byte, 32))
	add(0x12000, make([]byte, 32))
	add(0x10ff8, []byte("MATCH"))
	add(0xb000+17*8, make([]byte, 8))
	add(0x11000, []byte("not captured through the process mapping"))
	e, data := regexOracleEngine(t, c, true)
	var found []evidence.Row
	result, err := e.Run(context.Background(), "linux.vmaregexscan", map[string]string{"pattern": "MATCH"}, engine.RunOptions{Emit: func(r evidence.Row) error {
		if r.Cells["RecordType"].String() == "regex_match" {
			found = append(found, r)
		}
		return nil
	}})
	if err == nil || result.Task.State == "completed" || len(found) != 1 {
		t.Fatal(result, len(found), err)
	}
	proof := regexStructure(t, found[0].Cells["Context"])
	raw := stringsEvidenceBytes(t, proof["Raw"])
	if len(raw) != 128 || !bytes.Equal(raw[:8], data[0x10ff8:0x11000]) || !bytes.Equal(raw[8:], make([]byte, 120)) || proof["Complete"].Data != false {
		t.Fatal("padding lost provenance", proof)
	}
	parts := regexParts(t, proof["Parts"])
	if len(parts) != 2 || parts[1]["Padded"].Data != true || parts[1]["Error"].Reason != "unmapped_context" {
		t.Fatal(parts)
	}
	if found[0].Cells["Text"].String() != "MATCH" || found[0].Cells["Error"].Kind != "missing" {
		t.Fatal(found[0].Cells)
	}
}

func TestRegexPinnedWindowsMappingDisagreementIsExplicit(t *testing.T) {
	var c regexOracleCase
	for _, sample := range regexOracleCases(t) {
		if sample.Arch == "x64" && sample.Name == "literal" {
			c = sample
			break
		}
	}
	var entry [8]byte
	binary.LittleEndian.PutUint64(entry[:], 1<<47|0x10003)
	c.Writes = append(c.Writes, struct {
		Offset int
		Data   string
	}{0xb000 + 16*8, hex.EncodeToString(entry[:])})
	e, _ := regexOracleEngine(t, c, false)
	e.Env.OS = "windows"
	var found []evidence.Row
	result, err := e.Run(context.Background(), "regexscan", map[string]string{"pattern": "MATCH", "maxsize": "4"}, engine.RunOptions{Emit: func(r evidence.Row) error {
		if r.Cells["RecordType"].String() == "regex_match" {
			found = append(found, r)
		}
		return nil
	}})
	if err == nil || result.Task.State == "completed" || len(found) != 4 {
		t.Fatal(result, len(found), err)
	}
	disagree := 0
	for _, r := range found {
		source := regexStructure(t, r.Cells["Source"])
		for _, p := range regexParts(t, source["Parts"]) {
			for _, proof := range regexParts(t, p["Translation"]) {
				if proof["MatchesAcquisition"].Data == false {
					disagree++
					if proof["Error"].Reason != "mapping_translation_disagreement" {
						t.Fatal(proof)
					}
				}
			}
		}
	}
	if disagree != 2 {
		t.Fatal("unexplained pinned mapping discrepancy", disagree)
	}
}
