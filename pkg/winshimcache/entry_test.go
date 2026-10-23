package winshimcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type entryCase struct {
	avlCase
	Mask   string
	Kernel json.RawMessage
}

type entryFixture struct {
	Commit string
	Cases  []entryCase
}

func entryOracle(t testing.TB) entryFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/entry-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f entryFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 270 {
		t.Fatal("entry oracle drift")
	}
	return f
}

func entrySetup(t testing.TB, f avlFixture, c entryCase) (*LinkedEntryReader, *avlMemory) {
	t.Helper()
	kernel, err := symbols.Parse(c.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	mask, err := strconv.ParseUint(c.Mask, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	_, m := avlSetup(t, c.avlCase, nil)
	r, err := NewLinkedEntryReader(m, avlSource(t, f, c.Layout), kernel, mask)
	if err != nil {
		t.Fatal(err)
	}
	if r.LayoutSHA256 != f.Layouts[c.Layout].SHA256 {
		t.Fatal("source digest mismatch")
	}
	return r, m
}

func TestShimcacheLinkedEntryOriginal(t *testing.T) {
	original := entryOracle(t)
	layouts := avlOracle(t)
	for _, c := range original.Cases {
		t.Run(c.Layout+"/"+c.Mask+"/"+c.Scenario, func(t *testing.T) {
			r, m := entrySetup(t, layouts, c)
			valid, err := r.Valid(context.Background(), c.At)
			if valid != c.Valid {
				t.Fatal("original/native differs", valid, c.Valid, err)
			}
			if !reflect.DeepEqual(m.reads, c.Reads) {
				t.Fatal("read sequence differs", m.reads, c.Reads)
			}
			if (err != nil) != (m.faults > 0) {
				t.Fatal("hidden or fabricated fault", err, m.faults)
			}
			for i, read := range m.reads {
				raw := m.captures[i]
				if read[0] > uint64(len(m.data)) {
					if len(raw) != 0 {
						t.Fatal("out of bounds capture")
					}
					continue
				}
				if uint64(len(raw)) > uint64(len(m.data))-read[0] || !bytes.Equal(raw, m.data[read[0]:read[0]+uint64(len(raw))]) {
					t.Fatal("source capture mismatch")
				}
			}
		})
	}
}

func TestShimcacheLinkedEntryCancelAndOverflow(t *testing.T) {
	original := entryOracle(t)
	layouts := avlOracle(t)
	r, m := entrySetup(t, layouts, original.Cases[0])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if valid, err := r.Valid(ctx, 0x1000); valid || !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal("cancel", valid, err)
	}
	if valid, err := r.Valid(context.Background(), math.MaxUint64); valid || err == nil {
		t.Fatal("overflow", valid, err)
	}
	if valid, err := (*LinkedEntryReader)(nil).Valid(context.Background(), 0); valid || err == nil {
		t.Fatal("missing reader")
	}
}

func TestShimcacheLinkedEntryMalformedLayout(t *testing.T) {
	original := entryOracle(t)
	layouts := avlOracle(t)
	kernel, err := symbols.Parse(original.Cases[0].Kernel)
	if err != nil {
		t.Fatal(err)
	}
	raw := avlSource(t, layouts, "shimcache-win10-x64")
	// Select matching-width kernel independently of the oracle's sort order.
	for _, c := range original.Cases {
		if c.Width == 8 {
			kernel, err = symbols.Parse(c.Kernel)
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, mask := range []uint64{0, 0x1234} {
		if _, err := NewLinkedEntryReader(&avlMemory{}, raw, kernel, mask); err == nil {
			t.Fatal("invalid mask accepted")
		}
	}
	for _, scenario := range []string{"missing-entry", "missing-list", "list-target", "overrun", "huge", "width", "endian", "signed", "xp", "empty", "bad-json", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			entry := types["SHIM_CACHE_ENTRY"].(map[string]any)
			fields := entry["fields"].(map[string]any)
			switch scenario {
			case "missing-entry":
				delete(types, "SHIM_CACHE_ENTRY")
			case "missing-list":
				delete(fields, "ListEntry")
			case "list-target":
				fields["ListEntry"].(map[string]any)["type"] = map[string]any{"kind": "struct", "name": "_LIST_ENTRY"}
			case "overrun":
				fields["ListEntry"].(map[string]any)["offset"] = entry["size"]
			case "huge":
				entry["size"] = 1 << 21
			case "width":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			case "endian":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["endian"] = "big"
			case "signed":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["signed"] = true
			}
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "xp":
				mutated = avlSource(t, layouts, "shimcache-xp-sp2-x86")
			case "empty":
				mutated = nil
			case "bad-json":
				mutated = []byte("{")
			case "oversized":
				mutated = make([]byte, 4<<20+1)
			}
			if _, err := NewLinkedEntryReader(&avlMemory{}, mutated, kernel, math.MaxUint64); err == nil {
				t.Fatal("malformed entry layout accepted")
			}
		})
	}
	if _, err := NewLinkedEntryReader(nil, raw, nil, math.MaxUint64); err == nil {
		t.Fatal("missing environment")
	}
}

func FuzzShimcacheLinkedEntry(f *testing.F) {
	original := entryOracle(f)
	layouts := avlOracle(f)
	for i := 0; i < len(original.Cases); i += 17 {
		f.Add(uint16(i), []byte{1, 2, 3, 4}, uint64(0x1000))
	}
	f.Fuzz(func(t *testing.T, selector uint16, mutation []byte, at uint64) {
		c := original.Cases[int(selector)%len(original.Cases)]
		r, m := entrySetup(t, layouts, c)
		copy(m.data[0x1000:0x1100], mutation)
		valid, err := r.Valid(context.Background(), at)
		if valid && err != nil {
			t.Fatal("valid despite fault")
		}
		if len(m.reads) > 3 {
			t.Fatal("unbounded reads")
		}
		for _, read := range m.reads {
			if read[1] != c.Width {
				t.Fatal("invalid read width")
			}
		}
	})
}

func FuzzShimcacheLinkedEntryLayout(f *testing.F) {
	layouts := avlOracle(f)
	original := entryOracle(f)
	var kernel *symbols.ISF
	for _, c := range original.Cases {
		if c.Width == 8 {
			var err error
			kernel, err = symbols.Parse(c.Kernel)
			if err != nil {
				f.Fatal(err)
			}
			break
		}
	}
	for name := range layouts.Layouts {
		f.Add(avlSource(f, layouts, name))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		m := &avlMemory{}
		r, err := NewLinkedEntryReader(m, raw, kernel, math.MaxUint64)
		if len(m.reads) != 0 {
			t.Fatal("schema validation read memory")
		}
		if err == nil && (r.LayoutSHA256 == "" || r.mask != math.MaxUint64 || r.reader.Symbols == nil) {
			t.Fatal("incomplete accepted reader")
		}
	})
}
