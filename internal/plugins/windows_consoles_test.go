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
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func consoleControls(t testing.TB) []cmdControl {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-consoles-oracle.json")
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
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 156 {
		t.Fatal("Consoles oracle drift")
	}
	return fixture.Cases
}

func TestConsolesOriginalCompleteGenerators(t *testing.T) {
	for _, c := range consoleControls(t) {
		t.Run(fmt.Sprintf("%d-%d/%s", c.Build, c.Revision, c.Scenario), func(t *testing.T) {
			env, physical := cmdEnvironment(t, c)
			b := windowsConsolesPlugins()[0]
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
				if row.Cells["RecordType"].String() == "console_property" || row.Cells["RecordType"].String() == "console_not_found" {
					properties = append(properties, row)
				}
				return nil
			})
			var catalog struct{ Catalog map[string]string }
			raw, errRead := os.ReadFile("../../pkg/winconsole/testdata/version-oracle.json")
			if errRead != nil {
				t.Fatal(errRead)
			}
			if errRead = json.Unmarshal(raw, &catalog); errRead != nil {
				t.Fatal(errRead)
			}
			var layout struct {
				Types map[string]struct {
					Fields map[string]struct{ Type struct{ Kind string } }
				} `json:"user_types"`
			}
			if errRead = json.Unmarshal([]byte(catalog.Catalog[c.Layout]), &layout); errRead != nil {
				t.Fatal(errRead)
			}
			legacy := layout.Types["_EXE_ALIAS_LIST"].Fields["ExeName"].Type.Kind == "pointer"
			if ((legacy && c.Scenario != "zero-count") || c.Scenario == "command-hole" || c.Scenario == "screen-cells-hole" || c.Scenario == "history-cycle" || c.Scenario == "title-hole") != (err != nil) {
				t.Fatalf("legacy exe name=%v scenario=%s error=%v", legacy, c.Scenario, err)
			}
			if selections != 1 {
				t.Fatal("layout selection count", selections)
			}

			if c.Error == nil && len(properties) != len(c.Rows) {
				t.Fatalf("properties %d != %d: %v", len(properties), len(c.Rows), err)
			}
			summary := rows[len(rows)-1]
			if summary.Cells["RecordType"].String() != "task_summary" {
				t.Fatal("missing task summary")
			}
			coverage := summary.Cells["Coverage"].Data.(map[string]evidence.Value)
			wantConsoles := uint64(1)
			if c.Scenario == "zero-count" || c.Scenario == "title-hole" {
				wantConsoles = 0
			}
			count, countErr := coverage["Consoles"].Uint()
			if countErr != nil || count != wantConsoles || coverage["Completed"].Data != (err == nil) {
				t.Fatal("false coverage summary", coverage, err)
			}
			if _, present := coverage["Histories"]; present {
				t.Fatal("console count mislabeled as command histories")
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
						kind := "NotApplicableValue"
						if v.Reason == "not_available" {
							kind = "NotAvailableValue"
						}
						value = map[string]any{"missing": kind}
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

func consoleModernControl(t testing.TB) cmdControl {
	for _, c := range consoleControls(t) {
		if c.Build == 22621 && c.Scenario == "normal" {
			return c
		}
	}
	t.Fatal("missing modern control")
	return cmdControl{}
}
func TestConsolesBoundsCancellationAndOutput(t *testing.T) {
	c := consoleModernControl(t)
	env, _ := cmdEnvironment(t, c)
	b := windowsConsolesPlugins()[0]
	base, _ := plugin.Parameters(b.spec, map[string]string{"no-registry": "true"})
	if err := b.run(context.Background(), env, base, func(evidence.Row) error { return nil }); err != nil {
		t.Fatal("control must succeed before testing bounds", err)
	}
	for _, overrides := range []map[string]string{{"max-reads": "1"}, {"max-read-bytes": "1"}, {"max-rows": "1"}, {"max-slots": "1"}, {"max-candidates": "0"}, {"max-buffers": "-1"}, {"max-buffers": "65536"}, {"max-screens": "0"}, {"max-screen-rows": "1"}, {"max-screen-cells": "1"}, {"max-screen-bytes": "1"}, {"max-map-entries": "1"}} {
		overrides["no-registry"] = "true"
		p, err := plugin.Parameters(b.spec, overrides)
		if err != nil {
			continue
		}
		if err = b.run(context.Background(), env, p, func(evidence.Row) error { return nil }); err == nil {
			t.Fatal("bound ignored", overrides)
		}
	}
	sentinel := errors.New("consoles output stopped")
	calls := 0
	err := b.run(context.Background(), env, base, func(evidence.Row) error { calls++; return sentinel })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	err = b.run(ctx, env, base, func(evidence.Row) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	p, _ := plugin.Parameters(b.spec, map[string]string{"no-registry": "true", "max-buffers": "0"})
	properties, notFound := 0, 0
	err = b.run(context.Background(), env, p, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "console_property" {
			properties++
		}
		if row.Cells["RecordType"].String() == "console_not_found" {
			notFound++
		}
		return nil
	})
	if err != nil || properties != 0 || notFound != 1 {
		t.Fatal("zero buffer validity bound", err, properties, notFound)
	}
}
func TestConsolesRegistryFailurePreservesIndependentConsole(t *testing.T) {
	c := consoleModernControl(t)
	env, _ := cmdEnvironment(t, c)
	b := windowsConsolesPlugins()[0]
	p, err := plugin.Parameters(b.spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	properties, failures := 0, 0
	err = b.run(context.Background(), env, p, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "console_property":
			properties++
		case "registry_unavailable":
			failures++
		}
		return nil
	})
	if err == nil || failures != 2 || properties != len(c.Rows) {
		t.Fatal("registry failure erased console", err, failures, properties)
	}
}
func FuzzConsolesPipeline(f *testing.F) {
	c := consoleModernControl(f)
	base, original := cmdEnvironment(f, c)
	f.Add([]byte("console"), uint8(0))
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255}, uint8(1))
	f.Add([]byte{}, uint8(3))
	f.Fuzz(func(t *testing.T, payload []byte, section uint8) {
		if len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), original...)
		targets := []int{0x100400, 0x100400 + 2512, 0x105000, 0x10c000, 0x108000, 0x109000, 0x107400, 0x106000}
		copy(data[targets[int(section)%len(targets)]:], payload)
		// Exercise corrupt process page mappings as well as object payloads.
		if section&128 != 0 {
			binary.LittleEndian.PutUint64(data[0xb000+0x100*8:], 0)
		}
		translator, err := memory.NewIntelForOS(data, 0x8000, "x64", "windows", 32)
		if err != nil {
			t.Fatal(err)
		}
		kernel := &memory.Virtual{Physical: data, Translator: translator, ID: "kernel"}
		env := base
		env.Physical = data
		env.Kernel = kernel
		env.Objects = &object.Reader{Layer: kernel, Symbols: env.Symbols}
		b := windowsConsolesPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"no-registry": "true", "max-nodes": "8", "max-regions": "8", "max-candidates": "8", "max-slots": "32", "max-reads": "2000", "max-rows": "3000", "max-read-bytes": "1048576", "max-map-tables": "32", "max-map-entries": "8192", "max-screens": "8", "max-screen-rows": "8", "max-screen-cells": "32", "max-screen-bytes": "1024"})
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
