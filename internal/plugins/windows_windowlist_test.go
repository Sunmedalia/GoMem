package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowListOracle(t testing.TB) []windowStationsCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-windowlist-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []windowStationsCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 16 {
		t.Fatal("window list fixture drift")
	}
	return f.Cases
}
func windowListExpected(t testing.TB, rows [][]json.RawMessage) [][]any {
	t.Helper()
	result := [][]any{}
	for _, r := range rows {
		if len(r) != 8 {
			t.Fatal("invalid windows fixture row")
		}
		row := make([]any, 8)
		for i, v := range r {
			if string(v) == "null" {
				continue
			}
			if i == 0 || i == 2 || i == 5 || i == 7 {
				var n uint64
				if err := json.Unmarshal(v, &n); err != nil {
					t.Fatal(err)
				}
				row[i] = n
			} else {
				var s string
				if err := json.Unmarshal(v, &s); err != nil {
					t.Fatal(err)
				}
				row[i] = s
			}
		}
		result = append(result, row)
	}
	return result
}
func windowListFields(row evidence.Row) []any {
	result := make([]any, 8)
	for i, key := range []string{"Offset", "Station", "Session", "Desktop", "Window", "Procedure", "Process", "PID"} {
		v := row.Cells[key]
		if v.Kind == "missing" {
			continue
		}
		if i == 0 || i == 2 || i == 5 || i == 7 {
			n, _ := v.Uint()
			result[i] = n
		} else {
			result[i] = v.String()
		}
	}
	return result
}
func TestWindowListCompleteOriginalGenerator(t *testing.T) {
	b := windowsWindowsPlugins()[0]
	for _, c := range windowListOracle(t) {
		t.Run(c.Scenario, func(t *testing.T) {
			if c.Error != nil {
				t.Fatal("original generator raised", *c.Error)
			}
			e, _ := windowStationsSetup(t, c)
			p, err := plugin.Parameters(b.spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := [][]any{}
			layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
			reads, summaries := 0, 0
			partialPrefix := false
			err = b.run(context.Background(), e, p, func(row evidence.Row) error {
				switch row.Cells["RecordType"].String() {
				case "window":
					got = append(got, windowListFields(row))
					address, _ := row.Cells["WindowAddress"].Uint()
					at, _ := row.Cells["Offset"].Uint()
					if len(got) == 1 && (address != 0x81000 || at != 0x80018) {
						t.Fatal("lost pointer offset versus target", at, address)
					}
					if c.Scenario == "direct-prefix-gap" {
						raw, ok := row.Cells["WindowNameRaw"].Data.([]byte)
						partialPrefix = ok && len(raw) == 16 && row.Cells["Error"].Kind == "missing"
					}
				case "gui_session":
					coverage := row.Cells["Coverage"].Data.(map[string]evidence.Value)
					cr3, _ := coverage["CR3"].Uint()
					tr, err := memory.NewIntelForOS(e.Physical, cr3, "x64", "windows", 1024)
					if err != nil {
						t.Fatal(err)
					}
					id := row.Cells["Layer"].String()
					layers[id] = &memory.Virtual{Physical: e.Physical, Translator: tr, ID: id}
				case "memory_read":
					reads++
					verifyWindowStationRead(t, row, layers)
				case "task_summary":
					summaries++
				}
				return nil
			})
			if want := windowListExpected(t, c.Rows); !reflect.DeepEqual(got, want) {
				t.Fatalf("window fields got %v want %v: %v", got, want, err)
			}
			if err == nil || summaries != 1 || reads == 0 {
				t.Fatal("lost partial/read failures", err, summaries, reads)
			}
			if c.Scenario == "direct-prefix-gap" && !partialPrefix {
				t.Fatal("lost readable direct prefix or error")
			}
		})
	}
}

func TestWindowListBoundsCancelAndEmitter(t *testing.T) {
	c := windowListOracle(t)[0]
	b := windowsWindowsPlugins()[0]
	for _, key := range []string{"max-windows", "max-window-steps", "max-window-depth", "max-desktops"} {
		e, source := windowStationsSetup(t, c)
		p, _ := plugin.Parameters(b.spec, nil)
		p[key] = "garbage"
		if err := b.run(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil || source.reads != 0 {
			t.Fatal("invalid bound read memory", key, err)
		}
	}
	for _, mid := range []bool{false, true} {
		e, source := windowStationsSetup(t, c)
		p, _ := plugin.Parameters(b.spec, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if !mid {
			cancel()
		}
		rows := 0
		err := b.run(ctx, e, p, func(evidence.Row) error { rows++; cancel(); return nil })
		if !errors.Is(err, context.Canceled) || !mid && (rows != 0 || source.reads != 0) || mid && rows != 1 {
			t.Fatal("cancel", mid, rows, err)
		}
	}
	e, _ := windowStationsSetup(t, c)
	p, _ := plugin.Parameters(b.spec, nil)
	sentinel := errors.New("window emitter")
	if err := b.run(context.Background(), e, p, func(evidence.Row) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("lost emitter failure", err)
	}
	for _, kind := range []string{"memory_read", "window"} {
		for _, cancelTask := range []bool{false, true} {
			e, _ := windowStationsSetup(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			stopped := false
			err := b.run(ctx, e, p, func(row evidence.Row) error {
				if stopped {
					t.Fatal("output after terminal window event")
				}
				if row.Cells["RecordType"].String() == kind {
					stopped = true
					if cancelTask {
						cancel()
						return nil
					}
					return sentinel
				}
				return nil
			})
			cancel()
			cause := sentinel
			if cancelTask {
				cause = context.Canceled
			}
			if !stopped || !errors.Is(err, cause) {
				t.Fatal("mid-stream window stop lost", kind, cancelTask, err)
			}
		}
	}
}

func FuzzWindowListPagedPipeline(f *testing.F) {
	cases := windowListOracle(f)
	cache := windowStationsCache(f)
	f.Add([]byte{}, uint8(0), uint8(0))
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255}, uint8(2), uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, index, region uint8) {
		if len(payload) > 128 {
			payload = payload[:128]
		}
		c := cases[int(index)%len(cases)]
		e, source := windowStationsSetup(t, c)
		e.SymbolCache = cache
		at := []int{0x80018, 0x81058, 0x81070, 0x810b8, 0x84078, 0x81018, 0x57000 + 0x1a0, 0x5b000, 0x20030, 0x40000 + 0x81*8}[int(region)%10]
		copy(source.flatMemory[at:], payload)
		b := windowsWindowsPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"max-reads": "3000", "max-rows": "4000", "max-read-bytes": "8388608", "max-processes": "8", "max-sessions": "4", "max-stations": "4", "max-desktops": "4", "max-windows": "16", "max-window-steps": "128", "max-window-depth": "8"})
		if err != nil {
			t.Fatal(err)
		}
		layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
		calls := 0
		stopped := false
		sentinel := errors.New("window fuzz emitter")
		_ = b.run(context.Background(), e, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("output after emitter failure")
			}
			calls++
			if calls > 4000 {
				t.Fatal("window stream bound")
			}
			switch row.Cells["RecordType"].String() {
			case "gui_session":
				coverage := row.Cells["Coverage"].Data.(map[string]evidence.Value)
				cr3, _ := coverage["CR3"].Uint()
				tr, err := memory.NewIntelForOS(e.Physical, cr3, "x64", "windows", 1024)
				if err != nil {
					t.Fatal(err)
				}
				id := row.Cells["Layer"].String()
				layers[id] = &memory.Virtual{Physical: e.Physical, Translator: tr, ID: id}
			case "memory_read":
				verifyWindowStationRead(t, row, layers)
			}
			if calls == 3500 {
				stopped = true
				return sentinel
			}
			return nil
		})
	})
}
