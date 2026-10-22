package plugins

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type windowStationsCase struct {
	Scenario   string
	ISF        json.RawMessage
	Size       int
	KernelBase uint64 `json:"kernel_base"`
	KernelDTB  uint64 `json:"kernel_dtb"`
	Holes      [][2]uint64
	Rows       [][]json.RawMessage
	Error      *string
	Writes     []struct {
		Offset int
		Data   string
	}
}

func windowStationsOracle(t testing.TB) []windowStationsCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-windowstations-oracle.json")
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
		t.Fatal("WindowStations oracle drift")
	}
	return f.Cases
}
func windowStationsCache(t testing.TB) string {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/wingui/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Catalog map[string]struct {
			SHA256 string
			Source string `json:"source_gzip_base64"`
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	name := "gui-win10-19041-x64"
	c := f.Catalog[name]
	data, err := base64.StdEncoding.DecodeString(c.Source)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(io.LimitReader(z, (4<<20)+1))
	_ = z.Close()
	if err != nil || len(data) > 4<<20 {
		t.Fatal("GUI source bound", err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != c.SHA256 {
		t.Fatal("GUI digest differs")
	}
	cache := t.TempDir()
	if err = os.MkdirAll(filepath.Join(cache, "gui"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "gui", name+"-"+c.SHA256+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return cache
}
func windowStationsSetup(t testing.TB, c windowStationsCase) (plugin.Environment, *guiPoolMemory) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(flatMemory, c.Size)
	for _, w := range c.Writes {
		b, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(data)-len(b) {
			t.Fatal("invalid station writes", err)
		}
		copy(data[w.Offset:], b)
	}
	physical := &guiPoolMemory{flatMemory: data, holes: c.Holes}
	translator, err := memory.NewIntelForOS(physical, c.KernelDTB, "x64", "windows", 1024)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: physical, Translator: translator, ID: "windowstations:fixture:kernel"}
	return plugin.Environment{OS: "windows", Architecture: "x64", Physical: physical, Kernel: kernel, Symbols: table, Objects: &object.Reader{Layer: kernel, Symbols: table}, KernelBase: c.KernelBase, SymbolCache: windowStationsCache(t), Offline: true}, physical
}
func verifyWindowStationRead(t testing.TB, row evidence.Row, layers map[string]memory.MemoryLayer) {
	t.Helper()
	at, _ := row.Cells["Offset"].Uint()
	n, _ := row.Cells["Captured"].Uint()
	requested, _ := row.Cells["Requested"].Uint()
	layer, ok := layers[row.Cells["Layer"].String()]
	if !ok {
		t.Fatal("capture references unknown layer", row.Cells["Layer"])
	}
	if n > requested || requested > 1<<20 {
		t.Fatal("capture count exceeds request/read bound")
	}
	data := make([]byte, requested)
	count, err := layer.ReadAt(context.Background(), data, at)
	if uint64(count) != n {
		t.Fatal("capture differs from independent source reread", at, n, count, err)
	}
	data = data[:count]
	digest := sha256.Sum256(data)
	if row.Cells["SHA256"].String() != hex.EncodeToString(digest[:]) {
		t.Fatal("capture digest differs from original")
	}
	complete, _ := row.Cells["ReadComplete"].Data.(bool)
	if complete != (err == nil && uint64(count) == requested) {
		t.Fatal("capture completeness differs")
	}
	if raw, ok := row.Cells["Raw"]; ok {
		b, ok := raw.Data.([]byte)
		if !ok || !bytes.Equal(b, data) {
			t.Fatal("raw capture differs from original")
		}
	}
	if row.Provenance.Layer != layer.Name() || row.Provenance.Offset != fmt.Sprintf("0x%x", at) {
		t.Fatal("GUI capture provenance lost")
	}
}
func TestWindowStationsCompleteOriginalGenerator(t *testing.T) {
	for _, c := range windowStationsOracle(t) {
		t.Run(c.Scenario, func(t *testing.T) {
			e, _ := windowStationsSetup(t, c)
			b := windowsWindowStationsPlugins()[0]
			p, err := plugin.Parameters(b.spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := [][]any{}
			layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
			var captures, summary int
			err = b.run(context.Background(), e, p, func(row evidence.Row) error {
				switch row.Cells["RecordType"].String() {
				case "windowstation":
					at, _ := row.Cells["Offset"].Uint()
					sid, _ := row.Cells["SessionId"].Uint()
					got = append(got, []any{at, row.Cells["Name"].String(), sid})
				case "gui_session":
					coverage := row.Cells["Coverage"].Data.(map[string]evidence.Value)
					cr3, _ := coverage["CR3"].Uint()
					tr, cause := memory.NewIntelForOS(e.Physical, cr3, "x64", "windows", 1024)
					if cause != nil {
						t.Fatal(cause)
					}
					id := row.Cells["Layer"].String()
					layers[id] = &memory.Virtual{Physical: e.Physical, Translator: tr, ID: id}
				case "memory_read":
					captures++
					verifyWindowStationRead(t, row, layers)
				case "task_summary":
					summary++
				}
				return nil
			})
			want := [][]any{}
			for _, r := range c.Rows {
				var at, sid uint64
				var name string
				_ = json.Unmarshal(r[0], &at)
				_ = json.Unmarshal(r[1], &name)
				_ = json.Unmarshal(r[2], &sid)
				want = append(want, []any{at, name, sid})
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("WindowStations original rows differ", got, want, err)
			}
			failure := len(c.Holes) > 0 || c.Scenario == "null-next" || c.Scenario == "bad-session-cr3"
			if (err != nil) != failure || summary != 1 || captures == 0 {
				t.Fatal("GUI failure/summary/capture distinction", err, summary, captures)
			}
		})
	}
}
func TestWindowStationsLimitsCancelAndOutput(t *testing.T) {
	c := windowStationsOracle(t)[0]
	b := windowsWindowStationsPlugins()[0]
	for _, key := range []string{"max-reads", "max-read-bytes", "max-rows", "max-processes", "max-sessions"} {
		t.Run(key, func(t *testing.T) {
			e, _ := windowStationsSetup(t, c)
			p, _ := plugin.Parameters(b.spec, map[string]string{key: "1"})
			err := b.run(context.Background(), e, p, func(evidence.Row) error { return nil })
			if err == nil {
				t.Fatal("exhausted GUI bound succeeded")
			}
		})
	}
	for _, key := range []string{"max-reads", "max-read-bytes", "max-rows", "max-processes", "max-sessions", "max-stations"} {
		for _, value := range []string{"-1", "garbage", strconv.FormatUint(^uint64(0), 10)} {
			e, _ := windowStationsSetup(t, c)
			p := map[string]string{key: value}
			if _, err := plugin.Parameters(b.spec, p); err == nil {
				defaults, _ := plugin.Parameters(b.spec, nil)
				defaults[key] = value
				if err = b.run(context.Background(), e, defaults, func(evidence.Row) error { return nil }); err == nil {
					t.Fatal("invalid GUI bound", key, value)
				}
			}
		}
	}
	e, physical := windowStationsSetup(t, c)
	p, _ := plugin.Parameters(b.spec, nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err := b.run(cancelled, e, p, func(evidence.Row) error { t.Fatal("cancelled GUI output"); return nil })
	if !errors.Is(err, context.Canceled) || physical.reads != 0 {
		t.Fatal("cancelled GUI read", err)
	}
	sentinel := fmt.Errorf("GUI emitter failure")
	calls := 0
	err = b.run(context.Background(), e, p, func(evidence.Row) error { calls++; return sentinel })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal("GUI output stop", calls, err)
	}
}

func FuzzWindowStationsPagedPipeline(f *testing.F) {
	cases := windowStationsOracle(f)
	cache := windowStationsCache(f)
	f.Add([]byte{1, 0, 0, 0}, uint8(0), uint8(0))
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255}, uint8(6), uint8(4))
	f.Fuzz(func(t *testing.T, payload []byte, index, region uint8) {
		if len(payload) > 128 {
			return
		}
		c := cases[int(index)%len(cases)]
		e, source := windowStationsSetup(t, c)
		e.SymbolCache = cache
		at := []int{0x18080, 0x20000, 0x50060, 0x50030, 0x40000 + 0x50*8, 0x50800}[int(region)%6]
		copy(source.flatMemory[at:], payload)
		b := windowsWindowStationsPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"max-reads": "2000", "max-rows": "3000", "max-read-bytes": "8388608", "max-processes": "8", "max-sessions": "4", "max-stations": "4"})
		if err != nil {
			t.Fatal(err)
		}
		layers := map[string]memory.MemoryLayer{e.Kernel.Name(): e.Kernel, e.Physical.Name(): e.Physical}
		calls := 0
		stopped := false
		sentinel := errors.New("GUI fuzz output stop")
		_ = b.run(context.Background(), e, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("GUI evidence after emitter failure")
			}
			calls++
			if calls > 3000 {
				t.Fatal("GUI row budget escaped")
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
			if region&0x80 != 0 && calls == 10 {
				stopped = true
				return sentinel
			}
			return nil
		})
	})
}

func TestWindowStationsMidStreamStopsAndRootOnly(t *testing.T) {
	cases := windowStationsOracle(t)
	b := windowsWindowStationsPlugins()[0]
	for _, cancelTask := range []bool{false, true} {
		e, _ := windowStationsSetup(t, cases[0])
		p, _ := plugin.Parameters(b.spec, nil)
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		sentinel := errors.New("GUI midstream output failed")
		err := b.run(ctx, e, p, func(evidence.Row) error {
			calls++
			if calls > 10 {
				t.Fatal("GUI output after terminal signal")
			}
			if calls == 10 {
				if cancelTask {
					cancel()
				} else {
					return sentinel
				}
			}
			return nil
		})
		cancel()
		want := sentinel
		if cancelTask {
			want = context.Canceled
		}
		if !errors.Is(err, want) || calls != 10 {
			t.Fatal("GUI midstream signal lost", calls, err)
		}
	}
	var c windowStationsCase
	for _, candidate := range cases {
		if candidate.Scenario == "root-traversal" {
			c = candidate
			break
		}
	}
	e, _ := windowStationsSetup(t, c)
	p, _ := plugin.Parameters(b.spec, map[string]string{"max-stations": "0"})
	stations := 0
	err := b.run(context.Background(), e, p, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "windowstation" {
			stations++
		}
		return nil
	})
	if err != nil || stations != 1 {
		t.Fatal("GUI root-only traversal", stations, err)
	}
	e, source := windowStationsSetup(t, cases[0])
	e.SymbolCache = t.TempDir()
	p, _ = plugin.Parameters(b.spec, nil)
	err = b.run(context.Background(), e, p, func(evidence.Row) error { t.Fatal("missing offline GUI layout emitted analysis"); return nil })
	if err == nil || source.reads != 0 {
		t.Fatal("missing offline layout became empty scan", err)
	}
	e, source = windowStationsSetup(t, cases[0])
	e.Architecture = "arm64"
	err = b.run(context.Background(), e, p, func(evidence.Row) error { t.Fatal("unsupported architecture emitted analysis"); return nil })
	if err == nil || source.reads != 0 {
		t.Fatal("unsupported GUI architecture accepted", err)
	}
}
