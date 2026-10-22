package memoryscan

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestFindAgainstActualByteScanner(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Pattern, Data string
			Offsets             []uint64 `json:"scanner_offsets"`
			Error               string   `json:"scanner_error"`
			ChunkSize           int      `json:"chunk_size"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 35 {
		t.Fatal("reference fixture drift")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			re, err := byteregex.Compile(c.Pattern, true)
			if c.Error != "" {
				if err == nil {
					t.Fatal("invalid pattern compiled")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := hex.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			layer := &testLayer{data: data}
			chunk := memory.ScanChunk{End: 0x1000 + uint64(len(data))}
			if len(data) > 0 {
				chunk.Parts = []memory.ScanPart{{Virtual: 0x1000, Length: uint64(len(data))}}
			}
			b, err := Acquire(context.Background(), layer, chunk)
			if err != nil {
				t.Fatal(err)
			}
			limit := c.ChunkSize
			if limit == 0 {
				limit = 16 << 20
			}
			got := []uint64{}
			err = Find(context.Background(), re, b, limit, byteregex.Limits{}, 10000, func(h Hit) error {
				got = append(got, h.Offset)
				if h.Length > 0 && (!h.CoordinatesMatchSource || len(h.Sources) != 1 || h.Sources[0].Physical != h.Offset-0x1000 || h.Sources[0].Length != h.Length) {
					t.Fatal("wrong original source", h)
				}
				if h.Length == 0 && (h.CoordinatesMatchSource || len(h.Sources) != 0) {
					t.Fatal("empty match attributed bytes", h)
				}
				return nil
			})
			if err != nil || !reflect.DeepEqual(got, append([]uint64{}, c.Offsets...)) {
				t.Fatal(got, c.Offsets, err)
			}
		})
	}
}

func TestFindPartialAttributionBoundsAndStops(t *testing.T) {
	fault := errors.New("missing physical page")
	layer := &testLayer{data: []byte("AAAAbbbbCCCC")}
	layer.read = func(_ context.Context, p []byte, at uint64) (int, error) {
		if at == 4 {
			return 0, fault
		}
		return copy(p, layer.data[at:]), nil
	}
	chunk := memory.ScanChunk{End: 1012, Parts: []memory.ScanPart{{Virtual: 1000, Physical: 0, Length: 4}, {Virtual: 1004, Physical: 4, Length: 4}, {Virtual: 1008, Physical: 8, Length: 4}}}
	b, err := Acquire(context.Background(), layer, chunk)
	if !errors.Is(err, fault) {
		t.Fatal(err)
	}
	re, _ := byteregex.Compile("AACC", true)
	calls := 0
	err = Find(context.Background(), re, b, 1024, byteregex.Limits{}, 10, func(h Hit) error {
		calls++
		if h.Offset != 1006 || h.Length != 4 || h.CoordinatesMatchSource || len(h.Sources) != 2 || h.Sources[0].Virtual != 1002 || h.Sources[1].Virtual != 1008 {
			t.Fatal("partial source attribution", h)
		}
		return nil
	})
	if !errors.Is(err, ErrIncomplete) || calls != 1 {
		t.Fatal(calls, err)
	}
	b.Complete = true
	re, _ = byteregex.Compile("", true)
	calls = 0
	if err = Find(context.Background(), re, b, 1024, byteregex.Limits{}, 1, func(Hit) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("match bound", calls, err)
	}
	stop := errors.New("sink stopped")
	calls = 0
	if err = Find(context.Background(), re, b, 1024, byteregex.Limits{}, 10, func(Hit) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
		t.Fatal(calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls = 0
	if err = Find(ctx, re, b, 1024, byteregex.Limits{}, 10, func(Hit) error { calls++; cancel(); return nil }); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(calls, err)
	}
}

// Compare the paged scan stage with actual VMA generator result addresses.
// Context extraction/display remains a separate plugin integration requirement.
func TestPagedScanAgainstActualVMAGeneratorOffsets(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		VMAs []struct {
			Name, Arch, Pattern string
			Size                int
			Writes              []struct {
				Offset int
				Data   string
			}
			Sections [][2]uint64
			Rows     []struct{ Values []json.RawMessage }
			Error    *string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.VMAs) != 42 {
		t.Fatal("reference fixture drift")
	}
	for _, c := range fixture.VMAs {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			// Upstream never compiles an invalid regex when every task lacks mm.
			if len(c.Sections) == 0 {
				if len(c.Rows) != 0 || c.Error != nil {
					t.Fatal("unexpected no-mm reference")
				}
				return
			}
			re, err := byteregex.Compile(c.Pattern, true)
			if c.Error != nil && *c.Error == "invalid_pattern" {
				if err == nil {
					t.Fatal("invalid pattern compiled")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			original := make([]byte, c.Size)
			for _, w := range c.Writes {
				data, e := hex.DecodeString(w.Data)
				if e != nil {
					t.Fatal(e)
				}
				copy(original[w.Offset:], data)
			}
			layer := &testLayer{data: original}
			intel, err := memory.NewIntelForOS(layer, 0x8000, c.Arch, "linux", 1)
			if err != nil {
				t.Fatal(err)
			}
			got := []uint64{}
			var selected, mapped uint64
			for _, s := range c.Sections {
				selected += s[1]
				planner, err := memory.NewScanPlanner(context.Background(), memory.ScanPlanOptions{ChunkSize: 16 << 20, Overlap: 4096, MaxChunks: 100}, func(chunk memory.ScanChunk) error {
					b, e := Acquire(context.Background(), layer, chunk)
					if e != nil {
						return e
					}
					// Independently reread each digest from the source byte array.
					for _, a := range b.Parts {
						if a.SHA256 != digest(original[a.Part.Physical:a.Part.Physical+a.Captured]) {
							t.Fatal("source digest mismatch")
						}
					}
					return Find(context.Background(), re, b, 16<<20, byteregex.Limits{}, 10000, func(h Hit) error {
						got = append(got, h.Offset)
						if h.Length > 0 && !h.CoordinatesMatchSource {
							t.Fatal("unexplained coordinate shift", h)
						}
						return nil
					})
				})
				if err != nil {
					t.Fatal(err)
				}
				_, err = intel.VisitPageMappings(context.Background(), memory.PageMapOptions{MaxTables: 100, MaxEntries: 1000, Sections: []memory.Range{{Start: s[0], Length: s[1]}}}, func(m memory.PageMapping) error { mapped += m.Length; return planner.Push(m) })
				if err != nil {
					t.Fatal(err)
				}
				if err = planner.Finish(); err != nil {
					t.Fatal(err)
				}
			}
			want := []uint64{}
			for _, row := range c.Rows {
				var at uint64
				if err = json.Unmarshal(row.Values[2], &at); err != nil {
					t.Fatal(err)
				}
				want = append(want, at)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("paged match offsets", got, want)
			}
			if (mapped < selected) != (c.Name == "missing-page") {
				t.Fatal("selected VMA coverage", mapped, selected)
			}
		})
	}
}

func FuzzMemoryScanPipeline(f *testing.F) {
	f.Add("A.*C", []byte("AAAAbbbbCCCC"), uint8(1))
	f.Add("", []byte("ABC"), uint8(0))
	f.Fuzz(func(t *testing.T, pattern string, data []byte, faultMask uint8) {
		if len(pattern) > 64 || len(data) > 512 {
			return
		}
		re, err := byteregex.Compile(pattern, true)
		if err != nil {
			return
		}
		// Each physical part is independently acquired; selected virtual offsets
		// retain gaps so concatenated-buffer coordinates cannot stand in for proof.
		original := make([]byte, 48)
		copy(original, data)
		layer := &testLayer{data: original}
		layer.read = func(_ context.Context, p []byte, at uint64) (int, error) {
			if faultMask&(1<<uint(at/16)) != 0 {
				return 0, errors.New("missing part")
			}
			return copy(p, original[at:]), nil
		}
		b, readErr := Acquire(context.Background(), layer, memory.ScanChunk{End: 4192, Parts: []memory.ScanPart{{Virtual: 4096, Physical: 0, Length: 16}, {Virtual: 4128, Physical: 16, Length: 16}, {Virtual: 4176, Physical: 32, Length: 16}}})
		calls := 0
		err = Find(context.Background(), re, b, 4096, byteregex.Limits{Steps: 4096}, 64, func(h Hit) error {
			calls++
			if calls > 64 {
				t.Fatal("unbounded matches")
			}
			start := h.Offset - b.Base
			if start > uint64(len(b.Data)) || h.Length > uint64(len(b.Data))-start {
				t.Fatal("reported match outside buffer")
			}
			var actual []byte
			same := len(h.Sources) > 0
			for _, s := range h.Sources {
				if s.Physical > 48 || s.Length > 48-s.Physical {
					t.Fatal("source outside image")
				}
				actual = append(actual, original[s.Physical:s.Physical+s.Length]...)
				if s.Virtual != h.Offset+s.Offset {
					same = false
				}
			}
			if !reflect.DeepEqual(actual, append([]byte(nil), b.Data[start:start+h.Length]...)) || same != h.CoordinatesMatchSource {
				t.Fatal("false source attribution", h)
			}
			return nil
		})
		if readErr != nil && !errors.Is(err, ErrIncomplete) {
			t.Fatal("read failure became successful scan", err)
		}
	})
}
