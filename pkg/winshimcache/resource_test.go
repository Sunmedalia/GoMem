package winshimcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type resourceFixture struct {
	Commit  string
	Layouts map[string]json.RawMessage
	Cases   []avlCase
}

func resourceOracle(t testing.TB) resourceFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/resource-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f resourceFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Layouts) != 4 || len(f.Cases) != 84 {
		t.Fatal("resource oracle drift")
	}
	return f
}

func resourceSetup(t testing.TB, f resourceFixture, c avlCase) (*ResourceReader, *avlMemory) {
	t.Helper()
	kernel, err := symbols.Parse(f.Layouts[c.Layout])
	if err != nil {
		t.Fatal(err)
	}
	_, m := avlSetup(t, c, nil)
	r, err := NewResourceReader(m, kernel)
	if err != nil {
		t.Fatal(err)
	}
	return r, m
}

func TestShimcacheResourceOriginal(t *testing.T) {
	f := resourceOracle(t)
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := resourceSetup(t, f, c)
			valid, err := r.Valid(context.Background(), c.At)
			if valid != c.Valid {
				t.Fatal("original/native validity differs", valid, c.Valid, err)
			}
			if (err != nil) != (m.faults > 0) {
				t.Fatal("missing/fabricated fault", err, m.faults)
			}
			for i, read := range m.reads {
				raw := m.captures[i]
				if read[0] > uint64(len(m.data)) || uint64(len(raw)) > uint64(len(m.data))-read[0] || !bytes.Equal(raw, m.data[read[0]:read[0]+uint64(len(raw))]) {
					t.Fatal("capture differs from source")
				}
			}
		})
	}
}

func TestShimcacheResourceCancelAndOverflow(t *testing.T) {
	f := resourceOracle(t)
	r, m := resourceSetup(t, f, f.Cases[0])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if valid, err := r.Valid(ctx, 0x1000); valid || !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal(valid, err, m.reads)
	}
	if valid, err := r.Valid(context.Background(), math.MaxUint64); valid || err == nil {
		t.Fatal(valid, err)
	}
	if valid, err := (*ResourceReader)(nil).Valid(context.Background(), 0); valid || err == nil {
		t.Fatal(valid, err)
	}
	if _, err := NewResourceReader(nil, nil); err == nil {
		t.Fatal("missing environment accepted")
	}
}

// This optional test validates metadata only; it does not establish successful
// resource discovery or positive plugin output on a real memory image.
func TestShimcacheResourceKernelMetadata(t *testing.T) {
	path := os.Getenv("GOMEM_SHIMCACHE_KERNEL_ISF")
	if path == "" {
		t.Skip("set GOMEM_SHIMCACHE_KERNEL_ISF for actual kernel metadata validation")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := symbols.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewResourceReader(&avlMemory{}, kernel); err != nil {
		t.Fatal(err)
	}
}

func TestShimcacheResourceRejectsMalformedKernel(t *testing.T) {
	f := resourceOracle(t)
	for _, scenario := range []string{"missing-list", "list-target", "waiter-target", "link-target", "scalar-link", "count-pointer", "count-overrun", "huge-semaphore", "empty-semaphore", "big-endian", "signed-pointer", "pointer-base"} {
		t.Run(scenario, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(f.Layouts["w8-list16"], &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			fields := types["_ERESOURCE"].(map[string]any)["fields"].(map[string]any)
			links := types["_LIST_ENTRY"].(map[string]any)["fields"].(map[string]any)
			switch scenario {
			case "missing-list":
				delete(fields, "SystemResourcesList")
			case "list-target":
				fields["SystemResourcesList"].(map[string]any)["type"] = map[string]any{"kind": "struct", "name": "_KSEMAPHORE"}
			case "waiter-target":
				fields["SharedWaiters"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "_LIST_ENTRY"}}
			case "link-target":
				links["Flink"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "_KSEMAPHORE"}}
			case "scalar-link":
				links["Flink"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "unsigned int"}
			case "count-pointer":
				fields["NumberOfSharedWaiters"].(map[string]any)["type"] = fields["SharedWaiters"].(map[string]any)["type"]
			case "count-overrun":
				fields["NumberOfSharedWaiters"].(map[string]any)["offset"] = 127
			case "huge-semaphore":
				types["_KSEMAPHORE"].(map[string]any)["size"] = 1 << 21
			case "empty-semaphore":
				types["_KSEMAPHORE"].(map[string]any)["size"] = 0
			case "big-endian":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["endian"] = "big"
			case "signed-pointer":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["signed"] = true
			case "pointer-base":
				links["Flink"].(map[string]any)["type"].(map[string]any)["base"] = "unsigned int"
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			kernel, err := symbols.Parse(raw)
			if err != nil {
				return
			}
			if _, err = NewResourceReader(&avlMemory{data: make([]byte, 65536)}, kernel); err == nil {
				t.Fatal("malformed metadata accepted")
			}
		})
	}
}

func FuzzShimcacheResource(f *testing.F) {
	oracle := resourceOracle(f)
	for i := 0; i < len(oracle.Cases); i += 21 {
		f.Add(uint8(i), []byte{0, 1, 2, 3}, uint64(0x1000))
	}
	f.Fuzz(func(t *testing.T, selector uint8, mutation []byte, at uint64) {
		c := oracle.Cases[int(selector)%len(oracle.Cases)]
		r, m := resourceSetup(t, oracle, c)
		copy(m.data[0x1000:0x1100], mutation)
		valid, err := r.Valid(context.Background(), at)
		if valid && err != nil {
			t.Fatal("valid despite error")
		}
		if len(m.reads) > 8 {
			t.Fatal("unbounded validation", len(m.reads))
		}
		for _, read := range m.reads {
			if read[1] > 32 {
				t.Fatal("unbounded probe")
			}
		}
	})
}
