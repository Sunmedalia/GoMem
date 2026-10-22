package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type callbackMappingCase struct {
	callbacksGeneratorCase
	Version string
	PageMap []struct {
		Virtual, Physical uint64
		Present           bool
	} `json:"page_map"`
}

func callbackMappingCases(t testing.TB) []callbackMappingCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-callbacks-mapping-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []callbackMappingCase
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 90 {
		t.Fatal("callback mapping fixture drift")
	}
	return f.Cases
}
func TestCallbacksPermutedPagesAndHardwareHoles(t *testing.T) {
	reads, callbacks, failures := 0, 0, 0
	for i, c := range callbackMappingCases(t) {
		t.Run(fmt.Sprintf("%d/%s/%s/legacy%t/%s", i, c.Arch, c.Version, c.Legacy, c.Scenario), func(t *testing.T) {
			env, _ := callbacksGeneratorEnvironment(t, c.callbacksGeneratorCase)
			for _, m := range c.PageMap {
				mapping, err := env.Kernel.(*memory.Virtual).Translator.Translate(context.Background(), m.Virtual)
				if m.Present {
					if err != nil || mapping.Physical != m.Physical {
						t.Fatal("hardware mapping differs", m, mapping, err)
					}
				} else if err == nil {
					t.Fatal("missing PTE translated as present", m)
				}
			}
			params := map[string]string{}
			for _, p := range windowsCallbackPlugins()[0].spec.Parameters {
				params[p.Name] = p.Default
			}
			actual := map[string]int{}
			completed := false
			sourceLayers := map[string]int{}
			sourceOffsets := map[uint64]bool{}
			err := windowsCallbacks(context.Background(), env, params, func(row evidence.Row) error {
				switch row.Cells["RecordType"].String() {
				case "callback":
					actual[callbackNativeProjection(t, row)]++
					callbacks++
					if row.Cells["Route"].String() == "pool" {
						sourceLayers[row.Cells["Layer"].String()]++
						at, err := row.Cells["Offset"].Uint()
						if err != nil {
							t.Fatal(err)
						}
						sourceOffsets[at] = true
					}
				case "memory_read":
					verifyCallbackOriginalCapture(t, env, row)
					reads++
					if row.Cells["ReadComplete"].Data == false {
						failures++
					}
				case "task_summary":
					completed = row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data == true
				}
				return nil
			})
			failed := c.Scenario == "driver-hole" || c.Scenario == "component-hole" || c.Scenario == "module-hole"
			if (err != nil) != failed || completed == failed {
				t.Fatal("permuted callback completeness", completed, err)
			}
			if c.Error != nil {
				t.Fatal("unreviewed original mapping failure", c.Error)
			}
			original := map[string]int{}
			for _, row := range c.Rows {
				original[callbackGeneratorProjection(t, row)]++
			}
			if !reflect.DeepEqual(actual, original) {
				t.Fatalf("mapped generator differs\nnative=%v\nreference=%v", actual, original)
			}
			scanLayer := env.Physical.Name()
			if c.Version == "Windows10" {
				scanLayer = env.Kernel.Name()
			}
			if len(sourceLayers) != 1 || sourceLayers[scanLayer] == 0 {
				t.Fatal("pool source layer differs", sourceLayers, scanLayer)
			}
			// The IoFs allocation survives every selected hole. Its source must be
			// physical on older systems, and virtual on Windows 10.
			wanted := uint64(0x30000 + c.Width*2)
			if c.Version != "Windows10" {
				for _, m := range c.PageMap {
					if m.Virtual == 0x30000 {
						wanted = m.Physical + uint64(c.Width*2)
					}
				}
			}
			if !sourceOffsets[wanted] {
				t.Fatal("allocation provenance used the wrong address space", wanted, sourceOffsets)
			}
		})
	}
	t.Logf("verified %d mapped source reads, %d callback projections, %d explicit failed reads", reads, callbacks, failures)
}

func TestCallbackPoolLayoutRequiresOnlyRelevantHeaderFields(t *testing.T) {
	for _, c := range callbackMappingCases(t) {
		if c.Version != "Windows10" || c.Scenario != "normal" || c.Legacy {
			continue
		}
		t.Run(c.Arch, func(t *testing.T) {
			env, _ := callbacksGeneratorEnvironment(t, c.callbacksGeneratorCase)
			if _, err := env.Objects.Field("_OBJECT_HEADER", "InfoMask"); err == nil {
				t.Fatal("regression fixture unexpectedly has executive InfoMask")
			}
			constraints, err := callbackPoolConstraints(c.Width, true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := poolScanLayout(env, constraints); err != nil {
				t.Fatal("nonexecutive callback scan required executive metadata", err)
			}
			file, err := builtinPoolConstraints("File")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := poolScanLayout(env, file); err == nil {
				t.Fatal("executive File scan accepted missing optional header metadata")
			}
		})
	}
}

func FuzzCallbacksPermutedPagePipeline(f *testing.F) {
	if os.Getenv("GOMEM_BASELINE_DIR") == "" {
		f.Skip("set GOMEM_BASELINE_DIR for pinned mapping controls")
	}
	cases := callbackMappingCases(f)
	for _, i := range []int{0, 1, 4, 10, 14, 20, 24, 30, 40, 50, 60, 70, 80, 84, 89} {
		f.Add(uint8(i), uint32(0x9000), []byte{0, 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, which uint8, offset uint32, mutation []byte) {
		c := cases[int(which)%len(cases)]
		env, data := callbacksGeneratorEnvironment(t, c.callbacksGeneratorCase)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := int(offset % uint32(len(data)))
		copy(data[at:], mutation)
		rows := 0
		_ = windowsCallbacks(context.Background(), env, map[string]string{"max-read-bytes": "1048576", "max-reads": "1024", "max-rows": "2048", "max-nodes": "128"}, func(row evidence.Row) error {
			rows++
			if rows > 2048 {
				t.Fatal("mapping fuzz exceeded output budget")
			}
			if row.Cells["RecordType"].String() == "memory_read" {
				verifyCallbackOriginalCapture(t, env, row)
			}
			return nil
		})
	})
}
