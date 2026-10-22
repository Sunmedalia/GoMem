package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type callbacksGeneratorCase struct {
	Arch, Scenario string
	Width, Size    int
	Vista, Legacy  bool
	KernelBase     uint64 `json:"kernel_base"`
	ISF            json.RawMessage
	Writes         []networkWrite
	Rows           [][]json.RawMessage
	Error          *struct{ Type, Message string }
}

func callbacksGeneratorCases(t testing.TB) []callbacksGeneratorCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-callbacks-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []callbacksGeneratorCase
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 144 {
		t.Fatal("complete callback generator drift")
	}
	return f.Cases
}
func callbacksGeneratorEnvironment(t testing.TB, c callbacksGeneratorCase) (plugin.Environment, flatMemory) {
	t.Helper()
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for complete original callback generators")
	}
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := networkBytes(t, c.Size, c.Writes)
	intel, err := memory.NewIntelForOS(data, 0x8000, c.Arch, "windows", 16)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	cache := t.TempDir()
	folder := filepath.Join(cache, "callback-symbols")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	name := "callbacks-x86"
	if c.Width == 8 {
		name = "callbacks-x64"
	}
	raw, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if err := os.WriteFile(filepath.Join(folder, name+"-"+hex.EncodeToString(hash[:])+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return plugin.Environment{OS: "windows", Architecture: c.Arch, Offline: true, SymbolCache: cache, Symbols: table, Physical: data, Kernel: kernel, KernelBase: c.KernelBase, Objects: &object.Reader{Layer: kernel, Symbols: table}}, data
}
func callbackGeneratorProjection(t testing.TB, row []json.RawMessage) string {
	t.Helper()
	if len(row) != 5 {
		t.Fatal("invalid original callback columns")
	}
	values := make([]evidence.Value, 5)
	for i, raw := range row {
		if i == 1 {
			var at uint64
			if err := json.Unmarshal(raw, &at); err != nil {
				t.Fatal(err)
			}
			values[i] = evidence.Address(at)
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			values[i] = evidence.Text(text)
			continue
		}
		var missing struct{ Missing string }
		if err := json.Unmarshal(raw, &missing); err != nil {
			t.Fatal(err)
		}
		reasons := map[string]string{"NotApplicableValue": "not_applicable", "NotAvailableValue": "not_available", "UnreadableValue": "unreadable", "UnparsableValue": "unparsable"}
		reason, ok := reasons[missing.Missing]
		if !ok {
			t.Fatal("invalid original absent class", string(raw))
		}
		values[i] = evidence.Missing(reason, nil)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func callbackNativeProjection(t testing.TB, row evidence.Row) string {
	t.Helper()
	values := make([]evidence.Value, 0, 5)
	for _, key := range []string{"Type", "Callback", "Module", "Symbol", "Detail"} {
		v, ok := row.Cells[key]
		if !ok {
			t.Fatal("missing native callback column", key)
		}
		v.Error = ""
		values = append(values, v)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func verifyCallbackOriginalCapture(t testing.TB, env plugin.Environment, row evidence.Row) {
	t.Helper()
	layerName := row.Cells["Layer"].String()
	var layer memory.MemoryLayer
	switch layerName {
	case env.Kernel.Name():
		layer = env.Kernel
	case env.Physical.Name():
		layer = env.Physical
	default:
		t.Fatal("unknown captured layer", layerName)
	}
	at, err := row.Cells["Offset"].Uint()
	if err != nil {
		t.Fatal(err)
	}
	sourceAt, err := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || row.Provenance.Layer != layerName || sourceAt != at {
		t.Fatal("capture provenance differs")
	}
	requested, err := row.Cells["Requested"].Uint()
	if err != nil || requested > memory.MaxRead {
		t.Fatal("invalid capture request")
	}
	buf := make([]byte, int(requested))
	n, readErr := layer.ReadAt(context.Background(), buf, at)
	if n < 0 || n > len(buf) {
		t.Fatal("invalid original read")
	}
	if n < len(buf) && readErr == nil {
		readErr = io.ErrUnexpectedEOF
	}
	captured, err := row.Cells["Captured"].Uint()
	if err != nil || captured != uint64(n) {
		t.Fatal("capture length differs")
	}
	if row.Cells["ReadComplete"].Data != (readErr == nil) {
		t.Fatal("capture completeness differs")
	}
	if readErr != nil && row.Cells["Error"].Error == "" {
		t.Fatal("lost original read error")
	}
	sum := sha256.Sum256(buf[:n])
	if row.Cells["SHA256"].String() != hex.EncodeToString(sum[:]) {
		t.Fatal("capture digest differs")
	}
	if raw, ok := row.Cells["Raw"]; ok && !bytes.Equal(raw.Data.([]byte), buf[:n]) {
		t.Fatal("capture raw bytes differ")
	}
}

func TestCallbacksCompletePinnedGenerators(t *testing.T) {
	totalReads, totalRows := 0, 0
	for i, c := range callbacksGeneratorCases(t) {
		t.Run(fmt.Sprintf("%d/%s/vista%t/legacy%t/%s", i, c.Arch, c.Vista, c.Legacy, c.Scenario), func(t *testing.T) {
			env, _ := callbacksGeneratorEnvironment(t, c)
			params := map[string]string{}
			for _, p := range windowsCallbackPlugins()[0].spec.Parameters {
				params[p.Name] = p.Default
			}
			var rows []evidence.Row
			errorDetails := 0
			completed := false
			err := windowsCallbacks(context.Background(), env, params, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "memory_read" {
					verifyCallbackOriginalCapture(t, env, row)
					totalReads++
				}
				if row.Cells["RecordType"].String() == "callback" {
					rows = append(rows, row)
					if row.Cells["Detail"].Error != "" {
						errorDetails++
					}
				}
				if row.Cells["RecordType"].String() == "task_summary" {
					v := row.Cells["Coverage"].Data.(map[string]evidence.Value)
					completed = v["Completed"].Data.(bool)
				}
				return nil
			})
			failed := c.Scenario == "bad-driver" || c.Scenario == "no-name-info" && c.Vista
			if (err != nil) != failed || completed == failed {
				t.Fatal("callback completeness", completed, err)
			}
			totalRows += len(rows)
			original := map[string]int{}
			for _, r := range c.Rows {
				original[callbackGeneratorProjection(t, r)]++
			}
			actual := map[string]int{}
			for _, r := range rows {
				actual[callbackNativeProjection(t, r)]++
			}
			if c.Error == nil {
				if !reflect.DeepEqual(actual, original) {
					t.Fatalf("five-column callback generator differs\nnative=%v\noriginal=%v", actual, original)
				}
			} else {
				if c.Error.Type != "ValueError" || c.Scenario != "no-name-info" || !c.Vista {
					t.Fatal("unreviewed original generator failure", c.Error)
				}
				// Original aborts at the first PnP object's NameInfo. Native preserves
				// all previous rows and all three readable PnP callbacks with typed errors.
				for key, n := range original {
					if actual[key] < n {
						t.Fatal("lost rows before original abort", key)
					}
					actual[key] -= n
					if actual[key] == 0 {
						delete(actual, key)
					}
				}
				extras := 0
				for _, r := range rows {
					if r.Cells["Type"].String() == "EventCategoryDeviceInterfaceChange" {
						address, addressErr := r.Cells["Callback"].Uint()
						if addressErr != nil || address != 0x8800 {
							t.Fatal("lost PnP callback address")
						}
						if r.Cells["Detail"].Reason != "unreadable" || r.Cells["Detail"].Error == "" {
							t.Fatal("lost PnP detail error")
						}
						extras++
					}
				}
				if len(rows) != len(c.Rows)+3 || extras != 3 || errorDetails != 3 {
					t.Fatal("incorrect explicit continuation after baseline abort", len(rows), len(c.Rows), extras, errorDetails)
				}
				for key, n := range actual {
					if n < 0 {
						t.Fatal("negative row difference", key)
					}
				}
			}
		})
	}
	t.Logf("verified %d original reads and %d native callback projections", totalReads, totalRows)
}

func FuzzCallbacksGeneratorPipeline(f *testing.F) {
	cases := callbacksGeneratorCases(f)
	if os.Getenv("GOMEM_BASELINE_DIR") == "" {
		f.Skip("set GOMEM_BASELINE_DIR for pinned callback layouts")
	}
	for _, i := range []int{0, 4, 6, 7, 16, 20, 22, 23, 64, 68, 80, 86, 96, 112, 128, 142} {
		f.Add(uint8(i), uint32(0x30000), []byte{1, 0, 2, 2})
	}
	f.Fuzz(func(t *testing.T, which uint8, offset uint32, mutation []byte) {
		c := cases[int(which)%len(cases)]
		env, data := callbacksGeneratorEnvironment(t, c)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := int(offset % uint32(len(data)))
		copy(data[at:], mutation)
		// All parsers retain the actual hardware translation and fixed source range.
		// Bounds cap malformed lists, callback candidates and captured output.
		params := map[string]string{"max-read-bytes": "1048576", "max-reads": "1024", "max-rows": "2048", "max-nodes": "128"}
		rows := 0
		_ = windowsCallbacks(context.Background(), env, params, func(row evidence.Row) error {
			rows++
			if rows > 2048 {
				t.Fatal("callback output exceeded budget")
			}
			if row.Cells["RecordType"].String() == "callback" {
				if _, err := row.Cells["Callback"].Uint(); err != nil {
					t.Fatal("callback address lost numeric type", err)
				}
			}
			return nil
		})
	})
}
