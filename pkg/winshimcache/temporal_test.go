package winshimcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type temporalExpected struct {
	Time    string `json:"time"`
	Missing string
	Bool    *bool
	Number  string
	Error   string
}

type temporalCase struct {
	Layout   string
	Scenario string
	Width    uint64
	Mask     string
	At       uint64
	Size     int
	Holes    [][2]uint64
	Writes   []struct {
		Offset int
		Data   string
	}
	LastModified temporalExpected `json:"last_modified"`
	LastUpdate   temporalExpected `json:"last_update"`
	ExecFlag     temporalExpected `json:"exec_flag"`
}

type temporalFixture struct {
	Commit  string
	Kernels map[string]json.RawMessage
	Cases   []temporalCase
}

func temporalOracle(t testing.TB) temporalFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/temporal-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f temporalFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 595 || len(f.Kernels) != 2 {
		t.Fatal("Shimcache temporal oracle drift")
	}
	return f
}

func temporalSetup(t testing.TB, f temporalFixture, layouts avlFixture, c temporalCase) (*TemporalReader, *avlMemory) {
	t.Helper()
	kernel, err := symbols.Parse(f.Kernels[strconv.FormatUint(c.Width, 10)])
	if err != nil {
		t.Fatal(err)
	}
	mask, err := strconv.ParseUint(c.Mask, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	base := avlCase{Size: c.Size, Holes: c.Holes, Writes: c.Writes}
	_, m := avlSetup(t, base, nil)
	r, err := NewTemporalReader(m, avlSource(t, layouts, c.Layout), kernel, mask)
	if err != nil {
		t.Fatal(err)
	}
	if r.LayoutSHA256 != layouts.Layouts[c.Layout].SHA256 || r.KernelSHA256 != kernel.Digest() {
		t.Fatal("Shimcache temporal source digest mismatch")
	}
	return r, m
}

func temporalCompare(t testing.TB, got TemporalField, err error, want temporalExpected) {
	t.Helper()
	switch {
	case want.Time != "":
		if err != nil || got.Value.Kind != "string" || got.Value.String() != want.Time {
			t.Fatalf("time differs: got %#v, %v; want %s", got.Value, err, want.Time)
		}
	case want.Missing != "":
		reason := map[string]string{
			"NotApplicableValue": "not_applicable",
			"UnreadableValue":    "unreadable",
			"UnparsableValue":    "unparsable",
		}[want.Missing]
		if got.Value.Kind != "missing" || got.Value.Reason != reason {
			t.Fatalf("absence differs: got %#v, %v; want %s", got.Value, err, want.Missing)
		}
		if (want.Missing == "UnreadableValue") != (err != nil) {
			t.Fatalf("unreadable classification/error mismatch: %#v, %v", got.Value, err)
		}
	case want.Error != "":
		if err == nil || got.Value.Kind != "missing" || got.Value.Reason != "unreadable" {
			t.Fatalf("original read error differs: got %#v, %v; want %s", got.Value, err, want.Error)
		}
	case want.Bool != nil:
		if err != nil || got.Value.Kind != "bool" || got.Value.Data != *want.Bool {
			t.Fatalf("bool differs: got %#v, %v; want %v", got.Value, err, *want.Bool)
		}
	case want.Number != "":
		if err != nil || got.Value.Kind != "uint64" || got.Value.String() != want.Number {
			t.Fatalf("number differs: got %#v, %v; want %s", got.Value, err, want.Number)
		}
	default:
		t.Fatalf("unclassified original value: %#v", want)
	}
}

func temporalCaptures(t testing.TB, field TemporalField, m *avlMemory) {
	t.Helper()
	if field.Requested > memory.MaxRead {
		t.Fatal("unbounded Shimcache temporal read")
	}
	if len(field.Raw) == 0 {
		return
	}
	if field.Address > uint64(len(m.data)) || uint64(len(field.Raw)) > uint64(len(m.data))-field.Address {
		t.Fatal("temporal capture out of bounds")
	}
	if !bytes.Equal(field.Raw, m.data[field.Address:field.Address+uint64(len(field.Raw))]) {
		t.Fatal("temporal capture differs from source")
	}
}

func TestShimcacheTemporalOriginal(t *testing.T) {
	f := temporalOracle(t)
	layouts := avlOracle(t)
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Mask+"/"+c.Scenario, func(t *testing.T) {
			r, m := temporalSetup(t, f, layouts, c)
			got, err := r.LastModified(context.Background(), c.At)
			temporalCompare(t, got, err, c.LastModified)
			temporalCaptures(t, got, m)

			r, m = temporalSetup(t, f, layouts, c)
			got, err = r.LastUpdate(context.Background(), c.At)
			temporalCompare(t, got, err, c.LastUpdate)
			temporalCaptures(t, got, m)

			r, m = temporalSetup(t, f, layouts, c)
			got, err = r.ExecFlag(context.Background(), c.At)
			temporalCompare(t, got, err, c.ExecFlag)
			temporalCaptures(t, got, m)
		})
	}
}

func TestShimcacheTemporalCancelAndBounds(t *testing.T) {
	f := temporalOracle(t)
	layouts := avlOracle(t)
	r, m := temporalSetup(t, f, layouts, f.Cases[0])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := r.LastModified(ctx, f.Cases[0].At); !errors.Is(err, context.Canceled) || got.Complete || len(m.reads) != 0 {
		t.Fatal("cancel modified", got, err)
	}
	if got, err := r.LastUpdate(ctx, f.Cases[0].At); !errors.Is(err, context.Canceled) || got.Complete || len(m.reads) != 0 {
		t.Fatal("cancel update", got, err)
	}
	if got, err := r.ExecFlag(ctx, f.Cases[0].At); !errors.Is(err, context.Canceled) || got.Complete || len(m.reads) != 0 {
		t.Fatal("cancel exec", got, err)
	}
	if got, err := r.LastModified(context.Background(), math.MaxUint64); err == nil || got.Complete {
		t.Fatal("overflow modified", got, err)
	}
	// LastUpdate is absent on this layout, so the original returns N/A without
	// constructing an address and cannot overflow.
	if got, err := r.LastUpdate(context.Background(), math.MaxUint64); err != nil || !got.Complete || got.Value.Reason != "not_applicable" {
		t.Fatal("absent update overflow", got, err)
	}
	// The first oracle layout has no execution fields. The original reaches
	// its successful else branch without forming an address.
	if got, err := r.ExecFlag(context.Background(), math.MaxUint64); err != nil || !got.Complete || got.Value.Reason != "not_applicable" {
		t.Fatal("absent exec overflow", got, err)
	}
	if got, err := (*TemporalReader)(nil).LastModified(context.Background(), 0); err == nil || got.Complete {
		t.Fatal("nil modified", got, err)
	}
	if got, err := (*TemporalReader)(nil).LastUpdate(context.Background(), 0); err == nil || got.Complete {
		t.Fatal("nil update", got, err)
	}
	if got, err := (*TemporalReader)(nil).ExecFlag(context.Background(), 0); err == nil || got.Complete {
		t.Fatal("nil exec", got, err)
	}
}

func TestShimcacheTemporalFiletimeBoundaries(t *testing.T) {
	for _, test := range []struct {
		ticks int64
		want  string
	}{
		{116444736000000000, "1970-01-01T00:00:00+00:00"},
		{116444736011234567, "1970-01-01T00:00:01+00:00"},
		{116444735999999999, "1969-12-31T23:59:59+00:00"},
		{-1, "1600-12-31T23:59:59+00:00"},
		{2534023007999999999, "9630-12-31T23:59:59+00:00"},
	} {
		got := shimcacheFiletime(test.ticks)
		if got.Kind != "string" || got.String() != test.want {
			t.Fatal(test.ticks, got, test.want)
		}
	}
	if got := shimcacheFiletime(0); got.Reason != "not_applicable" {
		t.Fatal(got)
	}
	if got := shimcacheFiletime(math.MinInt64); got.Reason != "unparsable" {
		t.Fatal(got)
	}
	if got := shimcacheFiletime(math.MaxInt64); got.Reason != "unparsable" {
		t.Fatal(got)
	}
}

func TestShimcacheTemporalShortRead(t *testing.T) {
	f := temporalOracle(t)
	layouts := avlOracle(t)
	c := f.Cases[0]
	r, m := temporalSetup(t, f, layouts, c)
	r.layer = temporalShortLayer{m, 4}
	got, err := r.LastModified(context.Background(), c.At)
	if !errors.Is(err, io.ErrUnexpectedEOF) || got.Complete || len(got.Raw) != 4 {
		t.Fatal("short modified read", got, err)
	}
}

type temporalShortLayer struct {
	*avlMemory
	prefix int
}

func (m temporalShortLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if len(p) > m.prefix {
		return m.avlMemory.ReadAt(ctx, p[:m.prefix], at)
	}
	return m.avlMemory.ReadAt(ctx, p, at)
}

func TestShimcacheTemporalMalformedSchema(t *testing.T) {
	f := temporalOracle(t)
	layouts := avlOracle(t)
	raw := avlSource(t, layouts, "shimcache-win10-x64")
	kernel, err := symbols.Parse(f.Kernels["8"])
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{
		"missing-entry", "missing-detail", "detail-target", "detail-overrun",
		"large-target", "quad-pointer", "modified-scalar", "insert-pointer",
		"blob-missing-size", "blob-size-pointer", "blob-overrun",
		"pointer-width", "pointer-endian", "empty", "oversized", "malformed",
	} {
		t.Run(scenario, func(t *testing.T) {
			var doc, kernelDoc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(f.Kernels["8"], &kernelDoc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			entry := types["SHIM_CACHE_ENTRY"].(map[string]any)
			fields := entry["fields"].(map[string]any)
			detail := types["SHIM_CACHE_ENTRY_DETAIL"].(map[string]any)
			detailFields := detail["fields"].(map[string]any)
			large := types["_LARGE_INTEGER"].(map[string]any)
			largeFields := large["fields"].(map[string]any)
			switch scenario {
			case "missing-entry":
				delete(types, "SHIM_CACHE_ENTRY")
			case "missing-detail":
				delete(types, "SHIM_CACHE_ENTRY_DETAIL")
			case "detail-target":
				fields["ListEntryDetail"].(map[string]any)["type"].(map[string]any)["subtype"].(map[string]any)["name"] = "_RTL_AVL_TABLE"
			case "detail-overrun":
				fields["ListEntryDetail"].(map[string]any)["offset"] = entry["size"]
			case "large-target":
				detailFields["LastModified"].(map[string]any)["type"].(map[string]any)["name"] = "_RTL_AVL_TABLE"
			case "quad-pointer":
				largeFields["QuadPart"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "base", "name": "void"}}
			case "modified-scalar":
				fields["LastModified"] = map[string]any{"offset": 16, "type": map[string]any{"kind": "base", "name": "unsigned long long"}}
				delete(fields, "ListEntryDetail")
			case "insert-pointer":
				detailFields["InsertFlags"] = map[string]any{"offset": 8, "type": map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "base", "name": "void"}}}
			case "blob-missing-size":
				delete(detailFields, "BlobSize")
			case "blob-size-pointer":
				detailFields["BlobSize"] = map[string]any{"offset": 16, "type": map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "base", "name": "void"}}}
			case "blob-overrun":
				detailFields["BlobBuffer"].(map[string]any)["offset"] = 32
			case "pointer-width":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			case "pointer-endian":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["endian"] = "big"
			}
			mutated, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "empty":
				mutated = nil
			case "oversized":
				mutated = make([]byte, 4<<20+1)
			case "malformed":
				mutated = []byte("{")
			}
			if _, err := NewTemporalReader(&avlMemory{}, mutated, kernel, math.MaxUint64); err == nil {
				t.Fatal("malformed temporal schema accepted")
			}
		})
	}
}

func TestShimcacheTemporalKernelMetadata(t *testing.T) {
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
	name, mask := "shimcache-win10-x64", uint64(0xffffffffffff)
	if kernel.PointerSize() == 4 {
		name, mask = "shimcache-win10-x86", math.MaxUint32
	}
	if _, err := NewTemporalReader(&avlMemory{}, avlSource(t, avlOracle(t), name), kernel, mask); err != nil {
		t.Fatal(err)
	}
}

func FuzzShimcacheTemporal(f *testing.F) {
	original := temporalOracle(f)
	layouts := avlOracle(f)
	for i := 0; i < len(original.Cases); i += 31 {
		f.Add(uint16(i), []byte{1, 2, 3, 4}, uint64(0x1000))
	}
	f.Fuzz(func(t *testing.T, selector uint16, mutation []byte, at uint64) {
		c := original.Cases[int(selector)%len(original.Cases)]
		r, m := temporalSetup(t, original, layouts, c)
		copy(m.data[0x1000:0x1500], mutation)
		for _, read := range []func() (TemporalField, error){
			func() (TemporalField, error) { return r.LastModified(context.Background(), at) },
			func() (TemporalField, error) { return r.LastUpdate(context.Background(), at) },
			func() (TemporalField, error) { return r.ExecFlag(context.Background(), at) },
		} {
			got, err := read()
			if err != nil && got.Complete {
				t.Fatal("fault marked complete")
			}
			if got.Requested > memory.MaxRead || len(got.Raw) > memory.MaxRead {
				t.Fatal("unbounded temporal evidence")
			}
		}
	})
}

func FuzzShimcacheTemporalLayout(f *testing.F) {
	original := temporalOracle(f)
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
		r, err := NewTemporalReader(m, raw, kernel, math.MaxUint64)
		if len(m.reads) != 0 {
			t.Fatal("schema parser read memory")
		}
		if err == nil && (r.LayoutSHA256 == "" || r.KernelSHA256 == "") {
			t.Fatal("accepted reader lacks provenance")
		}
	})
}

func TestShimcacheTemporalExpectedType(t *testing.T) {
	// Guard the decoder above: the original fixture may encode bools in future
	// versions, and silently treating them as absent would weaken acceptance.
	var value temporalExpected
	if err := json.Unmarshal([]byte(`{"bool":false}`), &value); err != nil || value.Bool == nil || *value.Bool {
		t.Fatal("temporal bool control drift", err, value)
	}
	_ = evidence.Bool(false)
}
