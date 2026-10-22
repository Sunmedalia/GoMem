package memory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestScanPlanAgainstActualIntelIterator(t *testing.T) {
	rawJSON, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	type sample struct {
		Name, Arch string
		Size       int
		Writes     []struct {
			Offset int
			Data   string
		}
		Sections  [][2]uint64
		Mappings  [][4]uint64
		ChunkSize uint64 `json:"chunk_size"`
		Overlap   uint64
		Chunks    []struct {
			End   uint64
			Parts [][2]uint64
		}
	}
	var fixture struct{ VMAs, Plans []sample }
	if err = json.Unmarshal(rawJSON, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.VMAs) != 42 || len(fixture.Plans) != 17 {
		t.Fatal("reference fixture drift")
	}
	for _, c := range append(fixture.VMAs, fixture.Plans...) {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				v, e := hex.DecodeString(w.Data)
				if e != nil {
					t.Fatal(e)
				}
				copy(data[w.Offset:], v)
			}
			intel, e := NewIntelForOS(raw(t, data), 0x8000, c.Arch, "linux", 1)
			if e != nil {
				t.Fatal(e)
			}
			if c.ChunkSize == 0 {
				c.ChunkSize = 16 << 20
				c.Overlap = 4096
			}
			got := make([]struct {
				End   uint64
				Parts [][2]uint64
			}, 0)
			mappings := make([][4]uint64, 0)
			for _, s := range c.Sections {
				planner, e := NewScanPlanner(context.Background(), ScanPlanOptions{ChunkSize: c.ChunkSize, Overlap: c.Overlap, MaxChunks: 100}, func(chunk ScanChunk) error {
					parts := make([][2]uint64, 0, len(chunk.Parts))
					for _, p := range chunk.Parts {
						// The upstream linear iterator reads the physical layer. Separately
						// prove that the native virtual coordinate resolves to the same bytes.
						tr, err := intel.Translate(context.Background(), p.Virtual)
						if err != nil {
							t.Fatal(err)
						}
						if tr.Physical != p.Physical {
							t.Fatalf("translation=%#x; planned=%#x", tr.Physical, p.Physical)
						}
						parts = append(parts, [2]uint64{p.Physical, p.Length})
					}
					got = append(got, struct {
						End   uint64
						Parts [][2]uint64
					}{chunk.End, parts})
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
				_, e = intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 100, MaxEntries: 1000, Sections: []Range{{Start: s[0], Length: s[1]}}}, func(m PageMapping) error {
					mappings = append(mappings, [4]uint64{m.Virtual, m.Length, m.Physical, m.Length})
					return planner.Push(m)
				})
				if e != nil {
					t.Fatal(e)
				}
				if e = planner.Finish(); e != nil {
					t.Fatal(e)
				}
			}
			if !reflect.DeepEqual(mappings, append([][4]uint64{}, c.Mappings...)) {
				t.Fatalf("mappings=%v want=%v", mappings, c.Mappings)
			}
			want := c.Chunks
			if want == nil {
				want = make([]struct {
					End   uint64
					Parts [][2]uint64
				}, 0)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("chunks=%v want=%v", got, want)
			}
		})
	}
}

func TestScanPlanStopsAndBounds(t *testing.T) {
	sentinel := errors.New("sink stopped")
	options := ScanPlanOptions{ChunkSize: 8, Overlap: 2, MaxChunks: 10}
	for _, name := range []string{"emit", "cancel", "limit", "order", "virtual-overflow", "physical-overflow", "zero"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			opts := options
			if name == "limit" {
				opts.MaxChunks = 1
			}
			p, err := NewScanPlanner(ctx, opts, func(ScanChunk) error {
				calls++
				if name == "emit" {
					return sentinel
				}
				if name == "cancel" {
					cancel()
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			m := PageMapping{Virtual: 16, Physical: 32, Length: 24}
			switch name {
			case "virtual-overflow":
				m.Virtual = ^uint64(0) - 1
			case "physical-overflow":
				m.Physical = ^uint64(0) - 1
			case "zero":
				m.Length = 0
			case "order":
				m.Length = 1
			}
			err = p.Push(m)
			if name == "order" && err == nil {
				err = p.Push(m)
			}
			if err == nil {
				err = p.Finish()
			}
			if err == nil {
				t.Fatal("failure hidden")
			}
			if name == "emit" && !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			count := calls
			if p.Push(PageMapping{Virtual: 128, Length: 8}) == nil || p.Finish() == nil || calls != count {
				t.Fatal("continued after terminal error", calls, count)
			}
		})
	}
	t.Run("closed", func(t *testing.T) {
		p, _ := NewScanPlanner(context.Background(), options, func(ScanChunk) error { t.Fatal("empty plan emitted"); return nil })
		if p.Finish() != nil || p.Finish() == nil || p.Push(PageMapping{Length: 1}) == nil {
			t.Fatal("closed planner reused")
		}
	})
	for _, o := range []ScanPlanOptions{{}, {ChunkSize: 1, Overlap: 2, MaxChunks: 1}, {ChunkSize: MaxScanChunk, Overlap: 1, MaxChunks: 1}, {ChunkSize: 1, MaxChunks: 1000001}} {
		if _, err := NewScanPlanner(context.Background(), o, func(ScanChunk) error { return nil }); err == nil {
			t.Fatal("invalid options", o)
		}
	}
}

func FuzzScanPlan(f *testing.F) {
	f.Add(uint64(17), uint64(43), uint16(33), uint8(8), uint8(2))
	f.Add(uint64(0), uint64(4096), uint16(8192), uint8(255), uint8(0))
	f.Fuzz(func(t *testing.T, v, physical uint64, size uint16, chunk, overlap uint8) {
		step := uint64(chunk) + 1
		over := uint64(overlap) % (step + 1)
		length := uint64(size)
		count := uint64(0)
		var next uint64
		p, e := NewScanPlanner(context.Background(), ScanPlanOptions{ChunkSize: step, Overlap: over, MaxChunks: 100000}, func(c ScanChunk) error {
			if len(c.Parts) == 0 {
				if count != 0 || v == 0 || c.End != 0 {
					t.Fatal("invalid empty chunk")
				}
				return nil
			}
			if len(c.Parts) != 1 {
				t.Fatal("unexpected split")
			}
			part := c.Parts[0]
			wantLen := min(length-next, step+over)
			if part.Virtual != v+next || part.Physical != physical+next || part.Length != wantLen || c.End != part.Virtual+part.Length {
				t.Fatal("lost source correspondence")
			}
			count++
			next += step
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		e = p.Push(PageMapping{Virtual: v, Physical: physical, Length: length})
		invalid := length == 0 || v > ^uint64(0)-length || physical > ^uint64(0)-length
		if invalid {
			if e == nil {
				t.Fatal("invalid interval accepted")
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = p.Finish(); e != nil {
			t.Fatal(e)
		}
		if count != (length+step-1)/step {
			t.Fatal("lost/duplicated chunk", count)
		}
	})
}
