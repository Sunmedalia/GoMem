package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type cmdControl struct {
	Scenario string
	Layout   string
	Build    uint64
	Revision uint64
	ISF      json.RawMessage
	Size     int
	Writes   []struct {
		Offset int
		Data   string
	}
	Rows []struct {
		Depth  uint64
		Values []json.RawMessage
	}
	Error *string
}

func cmdControls(t testing.TB) []cmdControl {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-cmdscan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []cmdControl
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 132 {
		t.Fatal("cmdscan fixture drift")
	}
	return fixture.Cases
}
func cmdEnvironment(t testing.TB, c cmdControl) (plugin.Environment, flatMemory) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(flatMemory, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(data) || len(raw) > len(data)-w.Offset {
			t.Fatal("invalid original write")
		}
		copy(data[w.Offset:], raw)
	}
	translator, err := memory.NewIntelForOS(data, 0x8000, "x64", "windows", 256)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: data, Translator: translator, ID: "kernel"}
	cache := t.TempDir()
	var fixture struct{ Catalog map[string]string }
	raw, err := os.ReadFile("../../pkg/winconsole/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	name := c.Layout
	source := []byte(fixture.Catalog[name])
	if len(source) == 0 {
		t.Fatal("unknown original layout", name)
	}
	hash := sha256.Sum256(source)
	if err = os.MkdirAll(filepath.Join(cache, "console-symbols"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "console-symbols", fmt.Sprintf("%s-%x.json", name, hash)), source, 0600); err != nil {
		t.Fatal(err)
	}
	return plugin.Environment{OS: "windows", Architecture: "x64", ImageHash: "fixture", Physical: data, Kernel: kernel, Objects: &object.Reader{Layer: kernel, Symbols: table}, Symbols: table, KernelBase: 0x10000, SymbolCache: cache, Offline: true}, data
}
func TestCmdScanOriginalCompleteGenerators(t *testing.T) {
	for _, c := range cmdControls(t) {
		t.Run(fmt.Sprintf("%d-%d/%s", c.Build, c.Revision, c.Scenario), func(t *testing.T) {
			env, physical := cmdEnvironment(t, c)
			b := windowsCmdScanPlugins()[0]
			p, err := plugin.Parameters(b.spec, map[string]string{"no-registry": "true"})
			if err != nil {
				t.Fatal(err)
			}
			rows := []evidence.Row{}
			var properties []evidence.Row
			selections := 0
			spaces := map[string]memory.MemoryLayer{"flat": physical, "kernel": env.Kernel}
			err = b.run(context.Background(), env, p, func(row evidence.Row) error {
				rows = append(rows, row)
				if row.Cells["RecordType"].String() == "layout_selection" {
					selections++
					if row.Cells["LayoutName"].String() != c.Layout {
						t.Fatal("wrong layout selected", row.Cells["LayoutName"], c.Layout)
					}
				}
				if row.Cells["RecordType"].String() == "history_property" || row.Cells["RecordType"].String() == "history_not_found" {
					properties = append(properties, row)
				}
				return nil
			})
			failed := c.Scenario == "unreadable-command" || c.Scenario == "unreadable-bucket" || c.Scenario == "unreadable-application" || c.Scenario == "missing-vad-page"
			if failed != (err != nil) {
				t.Fatalf("failed=%v error=%v", failed, err)
			}
			if (c.Scenario == "uppercase-process" && selections != 0) || (c.Scenario != "uppercase-process" && selections != 1) {
				t.Fatal("layout selection count", selections)
			}
			if c.Error != nil {
				if *c.Error != "UnboundLocalError" || len(properties) != 1 {
					t.Fatal("unexpected original exception handling", c.Error, properties)
				}
			}
			if c.Error == nil && len(properties) != len(c.Rows) {
				t.Fatalf("properties %d != %d: %v", len(properties), len(c.Rows), err)
			}
			ancestors := map[uint64]string{}
			for i, want := range c.Rows {
				row := properties[i]
				depth, _ := row.Cells["Depth"].Uint()
				if depth != want.Depth {
					t.Fatal("depth", i, depth, want.Depth)
				}
				parent := ""
				if depth > 0 {
					parent = ancestors[depth-1]
					if parent == "" {
						t.Fatal("missing original tree ancestor", i, depth)
					}
				}
				if row.ParentID != parent {
					t.Fatal("parent differs from original tree", i, row.ParentID, parent)
				}
				ancestors[depth] = row.ID
				got := []any{}
				for _, name := range []string{"PID", "Process", "ConsoleInfo", "Property", "Address", "Data"} {
					v := row.Cells[name]
					var value any
					switch v.Kind {
					case "address", "uint64":
						value, _ = v.Uint()
					case "missing":
						value = map[string]any{"missing": "NotApplicableValue"}
					default:
						value = v.String()
					}
					got = append(got, value)
				}
				raw, _ := json.Marshal(got)
				var a, z any
				json.Unmarshal(raw, &a)
				reference, _ := json.Marshal(want.Values)
				json.Unmarshal(reference, &z)
				if !reflect.DeepEqual(a, z) {
					t.Fatalf("row %d got %s want %s", i, raw, reference)
				}
			}
			// Independently verify every captured original read through its own space.
			for _, row := range rows {
				if row.Cells["RecordType"].String() != "memory_read" {
					continue
				}
				layer := row.Cells["Layer"].String()
				original := spaces[layer]
				if original == nil {
					original = env.Kernel
				}
				at, _ := row.Cells["Offset"].Uint()
				n, _ := row.Cells["Captured"].Uint()
				requested, _ := row.Cells["Requested"].Uint()
				buf := make([]byte, requested)
				read, _ := original.ReadAt(context.Background(), buf, at)
				if uint64(read) != n {
					t.Fatal("capture count mismatch", layer, at, read, n)
				}
				hash := sha256.Sum256(buf[:read])
				if row.Cells["SHA256"].String() != hex.EncodeToString(hash[:]) {
					t.Fatal("capture digest mismatch")
				}
				if v, ok := row.Cells["Raw"]; ok && !bytes.Equal(v.Data.([]byte), buf[:read]) {
					t.Fatal("false capture bytes")
				}
			}
		})
	}
}
func TestCmdScanBoundsCancellationAndOutput(t *testing.T) {
	c := cmdControls(t)[0]
	env, _ := cmdEnvironment(t, c)
	b := windowsCmdScanPlugins()[0]
	for _, overrides := range []map[string]string{{"max-reads": "1"}, {"max-read-bytes": "1"}, {"max-rows": "1"}, {"max-slots": "1"}, {"max-candidates": "0"}, {"max-history": "-1"}, {"max-history": "65536"}, {"max-history": ""}, {"max-history": "50,no"}, {"max-map-entries": "1"}} {
		overrides["no-registry"] = "true"
		p, err := plugin.Parameters(b.spec, overrides)
		if err != nil {
			continue
		}
		if err := b.run(context.Background(), env, p, func(evidence.Row) error { return nil }); err == nil {
			t.Fatal("bound ignored", overrides)
		}
	}
	p, _ := plugin.Parameters(b.spec, map[string]string{"no-registry": "true"})
	sentinel := errors.New("output stopped")
	calls := 0
	err := b.run(context.Background(), env, p, func(evidence.Row) error { calls++; return sentinel })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	err = b.run(ctx, env, p, func(evidence.Row) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	v, err := parseCmdHistory("50,0,50,65535")
	if err != nil || !reflect.DeepEqual(v, []uint64{0, 50, 65535}) {
		t.Fatal(v, err)
	}
}

func FuzzCmdScanPipeline(f *testing.F) {
	c := cmdControls(f)[0]
	base, original := cmdEnvironment(f, c)
	f.Add([]byte("cmd.exe"), uint8(0))
	f.Add([]byte{0, 0, 0, 0, 0xff, 0xff}, uint8(1))
	f.Add([]byte{}, uint8(3))
	f.Fuzz(func(t *testing.T, payload []byte, section uint8) {
		if len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x102000, 0x102400, 0x400, 0x1000}[section%4]
		copy(data[at:], payload)
		translator, err := memory.NewIntelForOS(data, 0x8000, "x64", "windows", 32)
		if err != nil {
			t.Fatal(err)
		}
		kernel := &memory.Virtual{Physical: data, Translator: translator, ID: "kernel"}
		env := base
		env.Physical = data
		env.Kernel = kernel
		env.Objects = &object.Reader{Layer: kernel, Symbols: env.Symbols}
		b := windowsCmdScanPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"no-registry": "true", "max-nodes": "8", "max-regions": "8", "max-candidates": "8", "max-slots": "32", "max-reads": "2000", "max-rows": "3000", "max-read-bytes": "1048576", "max-map-tables": "32", "max-map-entries": "8192"})
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		stopped := false
		_ = b.run(context.Background(), env, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("output after stop")
			}
			calls++
			if calls > 1000 {
				stopped = true
				return errors.New("bounded output")
			}
			if row.Cells["RecordType"].String() == "memory_read" {
				n, _ := row.Cells["Captured"].Uint()
				requested, _ := row.Cells["Requested"].Uint()
				if n > requested || requested > memory.MaxRead {
					t.Fatal("invalid capture bounds")
				}
			}
			return nil
		})
	})
}

func TestCmdScanRegistryFailurePreservesIndependentHistory(t *testing.T) {
	env, _ := cmdEnvironment(t, cmdControls(t)[0])
	b := windowsCmdScanPlugins()[0]
	p, err := plugin.Parameters(b.spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	properties, registryFailures := 0, 0
	err = b.run(context.Background(), env, p, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "registry_unavailable":
			registryFailures++
		case "history_property":
			properties++
		}
		return nil
	})
	if err == nil || properties != 9 || registryFailures != 1 {
		t.Fatal("registry error erased or hid independent history", err, properties, registryFailures)
	}
}

func TestCmdScanRevisionFallbackRetainsProbeFailure(t *testing.T) {
	env, data := cmdEnvironment(t, cmdControls(t)[0])
	binary.LittleEndian.PutUint16(data[0x16002:], 17763)
	marker := 0x1a000
	for i, c := range []byte("OriginalFilename\x00CONHOST.EXE") {
		data[marker+2*i] = 0
		data[marker+2*i+1] = c
	}
	copy(data[marker-0x400:], []byte{0xbd, 0x04, 0xef, 0xfe})
	binary.LittleEndian.PutUint32(data[marker-0x3fc:], 0x10000)
	binary.LittleEndian.PutUint16(data[marker-0x3f8:], 0)
	binary.LittleEndian.PutUint16(data[marker-0x3f6:], 10)
	binary.LittleEndian.PutUint16(data[marker-0x3f4:], 1)
	binary.LittleEndian.PutUint16(data[marker-0x3f2:], 17763)
	raw, err := os.ReadFile("../../pkg/winconsole/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Catalog map[string]string }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	name := "consoles-win10-17763-x64"
	source := []byte(fixture.Catalog[name])
	hash := sha256.Sum256(source)
	if err = os.WriteFile(filepath.Join(env.SymbolCache, "console-symbols", fmt.Sprintf("%s-%x.json", name, hash)), source, 0600); err != nil {
		t.Fatal(err)
	}
	b := windowsCmdScanPlugins()[0]
	p, err := plugin.Parameters(b.spec, map[string]string{"no-registry": "true"})
	if err != nil {
		t.Fatal(err)
	}
	probes, properties := 0, 0
	selected := ""
	err = b.run(context.Background(), env, p, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "conhost_version_unavailable":
			probes++
		case "history_property":
			properties++
		case "layout_selection":
			selected = row.Cells["LayoutName"].String()
		}
		return nil
	})
	if err == nil || probes != 1 || properties != 9 || selected != name {
		t.Fatal("failed probe/fallback lost", err, probes, properties, selected)
	}
}
