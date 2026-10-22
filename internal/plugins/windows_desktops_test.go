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

type desktopCase struct {
	windowStationsCase
	Results map[string]struct {
		Rows  [][]json.RawMessage
		Error *string
	}
}

func desktopsOracle(t testing.TB) []desktopCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-desktops-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []desktopCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 16 {
		t.Fatal("desktop oracle drift")
	}
	return f.Cases
}
func desktopExpected(t testing.TB, raw [][]json.RawMessage) [][]any {
	t.Helper()
	want := [][]any{}
	for _, r := range raw {
		var at, sid, pid uint64
		var station, process string
		var desktop any
		if len(r) != 6 {
			t.Fatal("invalid desktop oracle row")
		}
		_ = json.Unmarshal(r[0], &at)
		_ = json.Unmarshal(r[1], &station)
		_ = json.Unmarshal(r[2], &sid)
		_ = json.Unmarshal(r[3], &desktop)
		_ = json.Unmarshal(r[4], &process)
		_ = json.Unmarshal(r[5], &pid)
		want = append(want, []any{at, station, sid, desktop, process, pid})
	}
	return want
}
func desktopFields(row evidence.Row) []any {
	at, _ := row.Cells["Offset"].Uint()
	session, _ := row.Cells["Session"].Uint()
	pid, _ := row.Cells["PID"].Uint()
	var name any
	if row.Cells["Desktop"].Kind != "missing" {
		name = row.Cells["Desktop"].String()
	}
	return []any{at, row.Cells["WindowStation"].String(), session, name, row.Cells["Process"].String(), pid}
}
func TestDesktopsCompleteOriginalGenerators(t *testing.T) {
	for _, c := range desktopsOracle(t) {
		for _, b := range windowsDesktopPlugins() {
			t.Run(b.spec.Name+"/"+c.Scenario, func(t *testing.T) {
				e, _ := windowStationsSetup(t, c.windowStationsCase)
				p, err := plugin.Parameters(b.spec, nil)
				if err != nil {
					t.Fatal(err)
				}
				mode := "desktops"
				if b.spec.Name == "windows.deskscan" {
					mode = "deskscan"
				}
				ref := c.Results[mode]
				if ref.Error != nil {
					t.Fatal("original generator raised unexpected error", *ref.Error)
				}
				got := [][]any{}
				layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
				reads := 0
				summary := 0
				err = b.run(context.Background(), e, p, func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "desktop":
						got = append(got, desktopFields(row))
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
						summary++
					}
					return nil
				})
				want := desktopExpected(t, ref.Rows)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("desktop original/native fields differ", got, want, err)
				}
				failure := c.Scenario == "owner-unmapped" || c.Scenario == "thread-cycle" || c.Scenario == "thread-unmapped" || c.Scenario == "name-unmapped" || mode == "deskscan" && c.Scenario == "parent-unmapped"
				if (err != nil) != failure || summary != 1 || reads == 0 {
					t.Fatal("desktop failure visibility", err, failure, summary, reads)
				}
			})
		}
	}
}

func TestDesktopsBoundsCancellationAndEmitter(t *testing.T) {
	c := desktopsOracle(t)[0]
	for _, b := range windowsDesktopPlugins() {
		t.Run(b.spec.Name, func(t *testing.T) {
			for _, key := range []string{"max-threads", "max-rows", "max-read-bytes", "max-reads", "max-processes", "max-sessions"} {
				e, _ := windowStationsSetup(t, c.windowStationsCase)
				p, _ := plugin.Parameters(b.spec, map[string]string{key: "1"})
				err := b.run(context.Background(), e, p, func(evidence.Row) error { return nil })
				if err == nil {
					t.Fatal("desktop exhausted bound succeeded", key)
				}
			}
			for _, key := range []string{"max-threads", "max-desktops"} {
				for _, value := range []string{"1000001", "garbage"} {
					e, source := windowStationsSetup(t, c.windowStationsCase)
					p, _ := plugin.Parameters(b.spec, nil)
					p[key] = value
					if err := b.run(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil || source.reads != 0 {
						t.Fatal("invalid desktop bound", key, value, err)
					}
				}
			}
			e, _ := windowStationsSetup(t, c.windowStationsCase)
			p, _ := plugin.Parameters(b.spec, map[string]string{"max-desktops": "0"})
			owners := 0
			err := b.run(context.Background(), e, p, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "desktop" {
					owners++
				}
				return nil
			})
			want := 0
			if b.spec.Name == "windows.deskscan" {
				want = 2
			}
			if err != nil || owners != want {
				t.Fatal("desktop zero traversal bound", owners, want, err)
			}
			for _, mid := range []bool{false, true} {
				for _, cancelTask := range []bool{false, true} {
					e, source := windowStationsSetup(t, c.windowStationsCase)
					p, _ := plugin.Parameters(b.spec, nil)
					ctx, cancel := context.WithCancel(context.Background())
					calls := 0
					stopAt := 1
					if mid {
						stopAt = 10
					}
					sentinel := errors.New("desktop emitter stopped")
					if cancelTask && !mid {
						cancel()
					}
					err := b.run(ctx, e, p, func(evidence.Row) error {
						calls++
						if calls > stopAt {
							t.Fatal("desktop output after stop")
						}
						if calls == stopAt {
							if cancelTask {
								cancel()
							} else {
								return sentinel
							}
						}
						return nil
					})
					cancel()
					cause := sentinel
					if cancelTask {
						cause = context.Canceled
					}
					if !errors.Is(err, cause) {
						t.Fatal("desktop stop lost", err)
					}
					if cancelTask && !mid && (calls != 0 || source.reads != 0) {
						t.Fatal("desktop read/output after pre-cancel")
					}
				}
			}
		})
	}
}
func FuzzDesktopsPagedPipeline(f *testing.F) {
	cases := desktopsOracle(f)
	cache := windowStationsCache(f)
	f.Add([]byte{0, 0, 0, 0}, uint8(0), uint8(0), false)
	f.Add([]byte{255, 255, 255, 255}, uint8(3), uint8(5), true)
	f.Fuzz(func(t *testing.T, payload []byte, index, region uint8, scan bool) {
		if len(payload) > 128 {
			return
		}
		c := cases[int(index)%len(cases)]
		e, source := windowStationsSetup(t, c.windowStationsCase)
		e.SymbolCache = cache
		at := []int{0x55108, 0x572e0, 0x5b000, 0x55088, 0x55018, 0x20030, 0x40000 + 0x55*8}[int(region)%7]
		copy(source.flatMemory[at:], payload)
		b := windowsDesktopPlugins()[0]
		if scan {
			b = windowsDesktopPlugins()[1]
		}
		p, err := plugin.Parameters(b.spec, map[string]string{"max-reads": "3000", "max-rows": "4000", "max-read-bytes": "8388608", "max-processes": "8", "max-sessions": "4", "max-stations": "4", "max-desktops": "4", "max-threads": "4"})
		if err != nil {
			t.Fatal(err)
		}
		layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
		calls := 0
		stopped := false
		sentinel := errors.New("desktop fuzz emitter stopped")
		_ = b.run(context.Background(), e, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("desktop output after terminal error")
			}
			calls++
			if calls > 4000 {
				t.Fatal("desktop row budget exceeded")
			}
			switch row.Cells["RecordType"].String() {
			case "gui_session":
				coverage := row.Cells["Coverage"].Data.(map[string]evidence.Value)
				cr3, _ := coverage["CR3"].Uint()
				tr, cause := memory.NewIntelForOS(e.Physical, cr3, "x64", "windows", 32)
				if cause != nil {
					t.Fatal(cause)
				}
				id := row.Cells["Layer"].String()
				layers[id] = &memory.Virtual{Physical: e.Physical, Translator: tr, ID: id}
			case "memory_read":
				verifyWindowStationRead(t, row, layers)
			}
			if region&128 != 0 && calls == 10 {
				stopped = true
				return sentinel
			}
			return nil
		})
	})
}
