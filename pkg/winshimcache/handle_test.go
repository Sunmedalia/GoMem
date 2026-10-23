package winshimcache

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type handleCase struct {
	avlCase
	Mask  string
	Valid struct {
		Value *bool
		Error *string
	}
	Head struct {
		Value *uint64
		Error *string
	}
}
type handleFixture struct {
	Commit  string
	Kernels map[string]json.RawMessage
	Cases   []handleCase
}

func handleOracle(t testing.TB) handleFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/handle-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f handleFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 525 || len(f.Kernels) != 2 {
		t.Fatal("handle oracle drift")
	}
	return f
}
func handleSetup(t testing.TB, f handleFixture, layouts avlFixture, c handleCase) (*HandleReader, *avlMemory) {
	t.Helper()
	kernel, err := symbols.Parse(f.Kernels[strconv.FormatUint(c.Width, 10)])
	if err != nil {
		t.Fatal(err)
	}
	_, m := avlSetup(t, c.avlCase, nil)
	mask, err := strconv.ParseUint(c.Mask, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewHandleReader(m, avlSource(t, layouts, c.Layout), kernel, mask)
	if err != nil {
		t.Fatal(err)
	}
	if r.LayoutSHA256 != layouts.Layouts[c.Layout].SHA256 {
		t.Fatal("layout source digest mismatch")
	}
	return r, m
}
func handleCaptures(t testing.TB, m *avlMemory, err error) {
	t.Helper()
	if (err != nil) != (m.faults > 0) {
		t.Fatal("hidden/fabricated read fault", err, m.faults)
	}
	if len(m.reads) > 48 {
		t.Fatal("unbounded handle checks", len(m.reads))
	}
	for i, read := range m.reads {
		raw := m.captures[i]
		if read[1] > 32 {
			t.Fatal("unbounded read", read)
		}
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
}
func TestShimcacheHandleOriginal(t *testing.T) {
	f := handleOracle(t)
	layouts := avlOracle(t)
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Mask+"/"+c.Scenario, func(t *testing.T) {
			r, m := handleSetup(t, f, layouts, c)
			valid, err := r.Valid(context.Background(), c.At, c.PageStart, c.PageEnd)
			want := c.Valid.Value != nil && *c.Valid.Value
			if valid != want || c.Valid.Error != nil && err == nil {
				t.Fatal("original/native validity differs", valid, c.Valid, err)
			}
			handleCaptures(t, m, err)
			r, m = handleSetup(t, f, layouts, c)
			head, valid, err := r.Head(context.Background(), c.At)
			if valid != (c.Head.Value != nil) || valid && head != *c.Head.Value || c.Head.Error != nil && err == nil {
				t.Fatal("original/native head differs", head, valid, c.Head, err)
			}
			handleCaptures(t, m, err)
			wantAnomaly := c.Layout == "shimcache-2003-x86" || c.Layout == "shimcache-vista-x86" || c.Layout == "shimcache-win7-x64" || c.Layout == "shimcache-win8-x64"
			if (len(r.LayoutAnomalies) > 0) != wantAnomaly {
				t.Fatal("missing or fabricated declared-size anomaly", r.LayoutAnomalies)
			}
		})
	}
}
func TestShimcacheHandleCancelAndOverflow(t *testing.T) {
	f := handleOracle(t)
	layouts := avlOracle(t)
	r, m := handleSetup(t, f, layouts, f.Cases[0])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if valid, err := r.Valid(ctx, 0x1000, 0, 0); valid || !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal("cancel valid", valid, err)
	}
	if _, valid, err := r.Head(ctx, 0x1000); valid || !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal("cancel head", valid, err)
	}
	if valid, err := r.Valid(context.Background(), 0, 0, 0); valid || err != nil || len(m.reads) != 0 {
		t.Fatal("zero guard", valid, err)
	}
	if _, valid, err := r.Head(context.Background(), math.MaxUint64); valid || err == nil {
		t.Fatal("overflow", valid, err)
	}
	if valid, err := (*HandleReader)(nil).Valid(context.Background(), 1, 0, 0); valid || err == nil {
		t.Fatal("nil valid")
	}
	if _, valid, err := (*HandleReader)(nil).Head(context.Background(), 0); valid || err == nil {
		t.Fatal("nil head")
	}
}
func TestShimcacheHandleMalformedLayout(t *testing.T) {
	f := handleOracle(t)
	layouts := avlOracle(t)
	kernel, err := symbols.Parse(f.Kernels["8"])
	if err != nil {
		t.Fatal(err)
	}
	raw := avlSource(t, layouts, "shimcache-win10-x64")
	for _, scenario := range []string{"missing-handle", "missing-resource", "missing-table", "wrong-resource", "wrong-table", "scalar", "oversized", "zero-size", "huge-offset", "wrong-base"} {
		t.Run(scenario, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			handle := types["SHIM_CACHE_HANDLE"].(map[string]any)
			fields := handle["fields"].(map[string]any)
			switch scenario {
			case "missing-handle":
				delete(types, "SHIM_CACHE_HANDLE")
			case "missing-resource":
				delete(fields, "eresource")
			case "missing-table":
				delete(fields, "rtl_avl_table")
			case "wrong-resource":
				fields["eresource"].(map[string]any)["type"].(map[string]any)["subtype"] = map[string]any{"kind": "struct", "name": "_ERESOURCE"}
			case "wrong-table":
				fields["rtl_avl_table"].(map[string]any)["type"].(map[string]any)["subtype"] = map[string]any{"kind": "struct", "name": "nt_symbols!_RTL_AVL_TABLE"}
			case "scalar":
				fields["eresource"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "unsigned long long"}
			case "oversized":
				handle["size"] = 1 << 21
			case "zero-size":
				handle["size"] = 0
			case "huge-offset":
				fields["rtl_avl_table"].(map[string]any)["offset"] = 1 << 21
			case "wrong-base":
				fields["eresource"].(map[string]any)["type"].(map[string]any)["base"] = "unsigned int"
			}
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewHandleReader(&avlMemory{}, mutated, kernel, math.MaxUint64); err == nil {
				t.Fatal("malformed handle accepted")
			}
		})
	}
}

func TestShimcacheHandleHeadOverflow(t *testing.T) {
	f := handleOracle(t)
	layouts := avlOracle(t)
	c := f.Cases[0]
	r, m := handleSetup(t, f, layouts, c)
	// Force full-width pointer interpretation and a readable resource, then
	// overflow target+table-size before the head is dereferenced.
	r.mask = math.MaxUint64
	binary.LittleEndian.PutUint64(m.data[c.At+r.tableOffset:], math.MaxUint64-1)
	if _, valid, err := r.Head(context.Background(), c.At); valid || err == nil {
		t.Fatal("overflowing table target accepted", valid, err)
	}
	if m.faults != 0 {
		t.Fatal("overflow detected only after an invalid memory read")
	}
}

type handleShortLayer struct {
	*avlMemory
	at uint64
}

func (m handleShortLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == m.at && len(p) > 1 {
		return m.avlMemory.ReadAt(ctx, p[:len(p)-1], at)
	}
	return m.avlMemory.ReadAt(ctx, p, at)
}

func TestShimcacheHandleShortRead(t *testing.T) {
	f := handleOracle(t)
	layouts := avlOracle(t)
	c := f.Cases[0]
	_, m := handleSetup(t, f, layouts, c)
	kernel, err := symbols.Parse(f.Kernels["8"])
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewHandleReader(handleShortLayer{m, c.At}, avlSource(t, layouts, c.Layout), kernel, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := r.Valid(context.Background(), c.At, c.PageStart, c.PageEnd); valid || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("short read hidden", valid, err)
	}
	if _, valid, err := r.Head(context.Background(), c.At); valid || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("short head read hidden", valid, err)
	}
}

func TestShimcacheHandleKernelMetadata(t *testing.T) {
	path := os.Getenv("GOMEM_SHIMCACHE_KERNEL_ISF")
	if path == "" {
		t.Skip("set GOMEM_SHIMCACHE_KERNEL_ISF for actual kernel schema validation")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := symbols.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	name := "shimcache-win10-x64"
	mask := uint64(0xffffffffffff)
	if kernel.PointerSize() == 4 {
		name = "shimcache-win10-x86"
		mask = math.MaxUint32
	}
	if _, err := NewHandleReader(&avlMemory{}, avlSource(t, avlOracle(t), name), kernel, mask); err != nil {
		t.Fatal(err)
	}
}

func FuzzShimcacheHandleLayout(f *testing.F) {
	original := handleOracle(f)
	layouts := avlOracle(f)
	kernel, err := symbols.Parse(original.Kernels["8"])
	if err != nil {
		f.Fatal(err)
	}
	for name := range layouts.Layouts {
		f.Add(avlSource(f, layouts, name))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		m := &avlMemory{}
		r, err := NewHandleReader(m, raw, kernel, math.MaxUint64)
		if len(m.reads) != 0 {
			t.Fatal("schema validation read image")
		}
		if err == nil && (r.LayoutSHA256 == "" || r.tableOffset > 1<<20 || r.resourceOffset > 1<<20 || r.tableSize > 1<<20) {
			t.Fatal("unbounded or incomplete handle layout")
		}
	})
}
func FuzzShimcacheHandle(f *testing.F) {
	original := handleOracle(f)
	layouts := avlOracle(f)
	for i := 0; i < len(original.Cases); i += 35 {
		f.Add(uint16(i), []byte{1, 2, 3, 4}, uint64(0x1000))
	}
	f.Fuzz(func(t *testing.T, selector uint16, mutation []byte, at uint64) {
		c := original.Cases[int(selector)%len(original.Cases)]
		r, m := handleSetup(t, original, layouts, c)
		copy(m.data[0x1000:0x1100], mutation)
		valid, err := r.Valid(context.Background(), at, c.PageStart, c.PageEnd)
		if valid && err != nil {
			t.Fatal("valid despite fault")
		}
		if len(m.reads) > 48 {
			t.Fatal("unbounded handle validation")
		}
		m.reads = nil
		_, valid, err = r.Head(context.Background(), at)
		if valid && err != nil {
			t.Fatal("valid head despite fault")
		}
		if len(m.reads) > 16 {
			t.Fatal("unbounded head validation")
		}
	})
}
