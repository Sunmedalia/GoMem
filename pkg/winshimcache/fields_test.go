package winshimcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type fieldExpected struct {
	String       *string
	StringSHA256 string `json:"string_sha256"`
	StringLength int    `json:"string_length"`
	Number       *string
	Missing      string
	Error        string
}
type fieldsCase struct {
	avlCase
	Mask     string
	Inline   bool
	Path     fieldExpected
	FileSize fieldExpected `json:"file_size"`
}
type fieldsFixture struct {
	Commit  string
	Kernels map[string]json.RawMessage
	Cases   []fieldsCase
}

func fieldsOracle(t testing.TB) fieldsFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/fields-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fieldsFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 493 || len(f.Kernels) != 2 {
		t.Fatal("fields oracle drift")
	}
	return f
}

// Match the original BufferDataLayer's zero-length-at-zero boundary. Native
// memory layers define their own empty-read behavior; this is a byte-layer
// control, not a claim that all original layer classes have identical rules.
type fieldsMemory struct{ *avlMemory }

func (m fieldsMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if len(p) == 0 && at == 0 {
		m.reads = append(m.reads, [2]uint64{0, 0})
		m.captures = append(m.captures, nil)
		m.faults++
		return 0, memory.ErrUnmapped
	}
	return m.avlMemory.ReadAt(ctx, p, at)
}
func fieldsSetup(t testing.TB, f fieldsFixture, layouts avlFixture, c fieldsCase) (*EntryFieldsReader, *avlMemory) {
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
	r, err := NewEntryFieldsReader(fieldsMemory{m}, avlSource(t, layouts, c.Layout), kernel, mask)
	if err != nil {
		t.Fatal(err)
	}
	if r.LayoutSHA256 != layouts.Layouts[c.Layout].SHA256 || r.KernelSHA256 != kernel.Digest() {
		t.Fatal("source digest mismatch")
	}
	return r, m
}
func fieldsCompare(t testing.TB, got evidence.Value, want fieldExpected) {
	t.Helper()
	switch {
	case want.String != nil:
		if got.Kind != "string" || got.String() != *want.String {
			t.Fatalf("path differs: got %q want %q", got.String(), *want.String)
		}
	case want.StringSHA256 != "":
		text := got.String()
		sum := sha256.Sum256([]byte(text))
		if got.Kind != "string" || hex.EncodeToString(sum[:]) != want.StringSHA256 || utf8.RuneCountInString(text) != want.StringLength {
			t.Fatal("long path differs")
		}
	case want.Number != nil:
		if got.Kind != "uint64" || got.String() != *want.Number {
			t.Fatal("file size differs", got, *want.Number)
		}
	case want.Missing != "" || want.Error != "":
		reason := "unreadable"
		if want.Missing == "NotApplicableValue" {
			reason = "not_applicable"
		}
		if got.Kind != "missing" || got.Reason != reason {
			t.Fatal("absent classification differs", got, want)
		}
	default:
		t.Fatal("unclassified original value", want)
	}
}
func fieldsCaptures(t testing.TB, m *avlMemory, err error) {
	t.Helper()
	if (err != nil) != (m.faults > 0) {
		t.Fatal("hidden or fabricated fault", err, m.faults)
	}
	if len(m.reads) > 3 {
		t.Fatal("unbounded field reads", len(m.reads))
	}
	for i, read := range m.reads {
		raw := m.captures[i]
		if read[1] > 65535 {
			t.Fatal("unbounded path read")
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
func TestShimcachePathAndSizeOriginal(t *testing.T) {
	f := fieldsOracle(t)
	layouts := avlOracle(t)
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Mask+"/"+c.Scenario, func(t *testing.T) {
			r, m := fieldsSetup(t, f, layouts, c)
			path, err := r.FilePath(context.Background(), c.At)
			fieldsCompare(t, path.Value, c.Path)
			fieldsCaptures(t, m, err)
			if len(path.Raw) > 0 && !bytes.Equal(path.Raw, m.data[path.Address:path.Address+uint64(len(path.Raw))]) {
				t.Fatal("returned raw path differs")
			}
			if path.Value.Kind == "string" && !path.Complete {
				t.Fatal("oracle success marked incomplete")
			}
			r, m = fieldsSetup(t, f, layouts, c)
			size, err := r.FileSize(context.Background(), c.At)
			fieldsCompare(t, size, c.FileSize)
			fieldsCaptures(t, m, err)
		})
	}
}
func TestShimcacheFieldsCancelAndPartial(t *testing.T) {
	f := fieldsOracle(t)
	layouts := avlOracle(t)
	c := f.Cases[0]
	r, m := fieldsSetup(t, f, layouts, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if path, err := r.FilePath(ctx, c.At); !errors.Is(err, context.Canceled) || path.Complete || len(m.reads) != 0 {
		t.Fatal("cancel path", path, err)
	}
	if _, err := r.FileSize(ctx, c.At); !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal("cancel size", err)
	}
	if _, err := r.FilePath(context.Background(), math.MaxUint64); err == nil {
		t.Fatal("overflow path")
	}
	if _, err := r.FileSize(context.Background(), math.MaxUint64); err == nil {
		t.Fatal("overflow size")
	}
	if _, err := (*EntryFieldsReader)(nil).FilePath(context.Background(), 0); err == nil {
		t.Fatal("nil path")
	}
	if _, err := (*EntryFieldsReader)(nil).FileSize(context.Background(), 0); err == nil {
		t.Fatal("nil size")
	}
	for _, c := range f.Cases {
		if c.Layout != "shimcache-xp-sp2-x86" || c.Scenario != "normal" {
			continue
		}
		r, m = fieldsSetup(t, f, layouts, c)
		// A layer may return a readable translated prefix followed by a fault.
		r.reader.Layer = pathPrefixLayer{m, c.At}
		path, err := r.FilePath(context.Background(), c.At)
		if !errors.Is(err, io.ErrUnexpectedEOF) || path.Complete || len(path.Raw) != 4 || path.Value.Kind != "string" || path.Value.String() != "C:" {
			t.Fatal("partial prefix lost", path, err)
		}
	}
	r, m = fieldsSetup(t, f, layouts, f.Cases[0])
	r.reader.Layer = pathPrefixLayer{m, 0x4000}
	path, err := r.FilePath(context.Background(), f.Cases[0].At)
	if !errors.Is(err, io.ErrUnexpectedEOF) || path.Complete || len(path.Raw) != 4 || path.Value.Kind != "missing" || path.Value.Reason != "unreadable" {
		t.Fatal("descriptor partial capture lost", path, err)
	}
}

type pathPrefixLayer struct {
	*avlMemory
	at uint64
}

func (m pathPrefixLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if len(p) > 4 && at == m.at {
		n, err := m.avlMemory.ReadAt(ctx, p[:4], at)
		if err != nil {
			return n, err
		}
		// Short reads without errors must not become successful empty paths.
		return n, nil
	}
	return m.avlMemory.ReadAt(ctx, p, at)
}

func TestShimcacheFieldsMalformedSchema(t *testing.T) {
	f := fieldsOracle(t)
	layouts := avlOracle(t)
	raw := avlSource(t, layouts, "shimcache-win10-x64")
	for _, scenario := range []string{"missing-entry", "missing-path", "path-target", "path-overrun", "entry-huge", "pointer-width", "pointer-endian", "signed-length", "length-width", "missing-buffer", "buffer-scalar", "buffer-overrun", "file-size-pointer", "file-size-overrun", "file-size-float", "inline-wide", "inline-huge", "empty", "oversized", "malformed"} {
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
			unicodeFields := kernelDoc["user_types"].(map[string]any)["_UNICODE_STRING"].(map[string]any)["fields"].(map[string]any)
			switch scenario {
			case "missing-entry":
				delete(types, "SHIM_CACHE_ENTRY")
			case "missing-path":
				delete(fields, "Path")
			case "path-target":
				fields["Path"].(map[string]any)["type"] = map[string]any{"kind": "struct", "name": "_UNICODE_STRING"}
			case "path-overrun":
				fields["Path"].(map[string]any)["offset"] = entry["size"]
			case "entry-huge":
				entry["size"] = 1 << 21
			case "pointer-width":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			case "pointer-endian":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["endian"] = "big"
			case "signed-length":
				kernelDoc["base_types"].(map[string]any)["unsigned short"].(map[string]any)["signed"] = true
			case "length-width":
				kernelDoc["base_types"].(map[string]any)["unsigned short"].(map[string]any)["size"] = 4
			case "missing-buffer":
				delete(unicodeFields, "Buffer")
			case "buffer-scalar":
				unicodeFields["Buffer"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "unsigned long long"}
			case "buffer-overrun":
				unicodeFields["Buffer"].(map[string]any)["offset"] = 15
			case "file-size-pointer":
				fields["FileSize"] = map[string]any{"offset": 0, "type": map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "base", "name": "wchar"}}}
			case "file-size-overrun":
				fields["FileSize"] = map[string]any{"offset": entry["size"], "type": map[string]any{"kind": "base", "name": "unsigned long long"}}
			case "file-size-float":
				kernelDoc["base_types"].(map[string]any)["unsigned long long"].(map[string]any)["kind"] = "float"
				fields["FileSize"] = map[string]any{"offset": 0, "type": map[string]any{"kind": "base", "name": "unsigned long long"}}
			case "inline-wide", "inline-huge":
				count := 520
				name := "wchar"
				if scenario == "inline-huge" {
					count = 65536
					name = "unsigned char"
				}
				fields["Path"].(map[string]any)["type"] = map[string]any{"kind": "array", "count": count, "subtype": map[string]any{"kind": "base", "name": name}}
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
			encoded, err := json.Marshal(kernelDoc)
			if err != nil {
				t.Fatal(err)
			}
			kernel, err := symbols.Parse(encoded)
			if err != nil {
				return
			}
			if _, err = NewEntryFieldsReader(&avlMemory{}, mutated, kernel, math.MaxUint64); err == nil {
				t.Fatal("malformed field schema accepted")
			}
		})
	}
}

func FuzzShimcacheEntryFieldsLayout(f *testing.F) {
	original := fieldsOracle(f)
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
		r, err := NewEntryFieldsReader(m, raw, kernel, math.MaxUint64)
		if len(m.reads) != 0 {
			t.Fatal("schema parser read memory")
		}
		if err == nil && (r.LayoutSHA256 == "" || r.pathBytes > 65535) {
			t.Fatal("unbounded or incomplete field reader")
		}
	})
}
func TestShimcacheFieldKernelMetadata(t *testing.T) {
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
	if _, err := NewEntryFieldsReader(&avlMemory{}, avlSource(t, avlOracle(t), name), kernel, mask); err != nil {
		t.Fatal(err)
	}
}
func FuzzShimcacheEntryFields(f *testing.F) {
	original := fieldsOracle(f)
	layouts := avlOracle(f)
	for i := 0; i < len(original.Cases); i += 29 {
		f.Add(uint16(i), []byte{1, 2, 3, 4}, uint64(0x1000))
	}
	f.Fuzz(func(t *testing.T, selector uint16, mutation []byte, at uint64) {
		c := original.Cases[int(selector)%len(original.Cases)]
		r, m := fieldsSetup(t, original, layouts, c)
		copy(m.data[0x1000:0x1300], mutation)
		path, err := r.FilePath(context.Background(), at)
		if err != nil && path.Complete {
			t.Fatal("fault marked complete")
		}
		if path.Requested > 65535 || len(path.Raw) > 65535 || len(m.reads) > 3 {
			t.Fatal("unbounded path decoding")
		}
		m.reads = nil
		if _, err := r.FileSize(context.Background(), at); err == nil && len(m.reads) > 1 {
			t.Fatal("unbounded size decoding")
		}
	})
}
