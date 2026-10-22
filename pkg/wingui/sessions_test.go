package wingui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type guiSessionCase struct {
	Layout, Scenario string
	ISF              json.RawMessage
	Size             int
	KernelBase       uint64 `json:"kernel_base"`
	KernelDTB        uint64 `json:"kernel_dtb"`
	PIDs             []uint64
	Holes            [][2]uint64
	Rows             []map[string]any
	Error            string
	Writes           []struct {
		Offset int
		Data   string
	}
}

func guiSessionOracle(t testing.TB) []guiSessionCase {
	t.Helper()
	data, err := os.ReadFile("testdata/sessions-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []guiSessionCase
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 75 {
		t.Fatal("GUI session oracle drift")
	}
	return f.Cases
}
func guiSessionSetup(t testing.TB, c guiSessionCase) (SessionReader, *guiMemory) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	physical := &guiMemory{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(physical.data) || len(raw) > len(physical.data)-w.Offset {
			t.Fatal("invalid session fixture write")
		}
		copy(physical.data[w.Offset:], raw)
	}
	intel, err := memory.NewIntelForOS(physical, c.KernelDTB, "x64", "windows", 1024)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: physical, Translator: intel, ID: "gui-session-kernel"}
	return SessionReader{Kernel: &object.Reader{Layer: kernel, Symbols: table}, Physical: physical, KernelBase: c.KernelBase}, physical
}
func TestGUISessionsActualOriginalTranslatedMaps(t *testing.T) {
	for _, c := range guiSessionOracle(t) {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, physical := guiSessionSetup(t, c)
			rows := []map[string]any{}
			ctx := context.Background()
			err := r.Visit(ctx, SessionOptions{MaxProcesses: 16, MaxSessions: 16, PIDs: c.PIDs}, func(s SessionSpace) error {
				row := map[string]any{"session": s.SessionID, "cr3": s.RawCR3}
				data, err := memory.Read(ctx, s.Layer, 0x400000, 16)
				if err != nil {
					row["probe_error"] = "unavailable"
				} else {
					row["probe"] = hex.EncodeToString(data)
				}
				rows = append(rows, row)
				if s.Process < 0x20000 || s.Process > 0x23000 || (s.Process-0x20000)%0x1000 != 0 {
					t.Fatal("session lost process address", s)
				}
				expectedMethod := "typed"
				if c.Layout == "opaque-type" {
					expectedMethod = "opaque-offset-8"
				}
				if s.Method != expectedMethod {
					t.Fatal("lost session selection provenance", s.Method)
				}
				if s.CR3 != s.RawCR3&^uint64(4095) {
					t.Fatal("CR3 normalization", s)
				}
				if !strings.Contains(s.Layer.Name(), "0x") {
					t.Fatal("layer lost object identity")
				}
				return nil
			})
			a, _ := json.Marshal(rows)
			b, _ := json.Marshal(c.Rows)
			var got, want any
			_ = json.Unmarshal(a, &got)
			_ = json.Unmarshal(b, &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rows got %s want %s; native error %v; original %s", a, b, err, c.Error)
			}
			damaged := c.Error != "" || c.Scenario == "session-unmapped" || c.Scenario == "session-hole" || c.Scenario == "session-pointer-hole" || c.Scenario == "cr3-hole" || c.Scenario == "pid-hole" || c.Scenario == "broken-forward" || c.Scenario == "bad-backlink" || c.Scenario == "first-owner-fault"
			if (err != nil) != damaged {
				t.Fatal("session failure visibility", err, c.Error)
			}
			for _, read := range physical.reads {
				if read.Err == nil && (read.At > uint64(len(physical.data)) || uint64(len(read.Data)) > uint64(len(physical.data))-read.At || !bytes.Equal(read.Data, physical.data[read.At:read.At+uint64(len(read.Data))])) {
					t.Fatal("session original physical capture mismatch")
				}
			}
		})
	}
}
func TestGUISessionsBoundsCancellationAndEmitter(t *testing.T) {
	c := guiSessionOracle(t)[0]
	ctx := context.Background()
	for _, options := range []SessionOptions{{MaxProcesses: 1, MaxSessions: 10}, {MaxProcesses: 10, MaxSessions: 1}} {
		r, _ := guiSessionSetup(t, c)
		count := 0
		err := r.Visit(ctx, options, func(SessionSpace) error { count++; return nil })
		if err == nil || count != 1 {
			t.Fatal("session bound lost prefix", count, err)
		}
	}
	for _, item := range guiSessionOracle(t) {
		if item.Layout != "typed" || (item.Scenario != "normal" && item.Scenario != "duplicate-session") {
			continue
		}
		maxSessions := uint64(3)
		expected := 3
		if item.Scenario == "duplicate-session" {
			maxSessions, expected = 1, 1
		}
		reader, _ := guiSessionSetup(t, item)
		count := 0
		err := reader.Visit(ctx, SessionOptions{MaxProcesses: 4, MaxSessions: maxSessions}, func(SessionSpace) error { count++; return nil })
		if err != nil || count != expected {
			t.Fatal("exact session/process limits rejected", item.Scenario, count, err)
		}
	}
	stop := errors.New("session output failed")
	r, _ := guiSessionSetup(t, c)
	count := 0
	err := r.Visit(ctx, SessionOptions{MaxProcesses: 10, MaxSessions: 10}, func(SessionSpace) error { count++; return stop })
	if !errors.Is(err, stop) || count != 1 {
		t.Fatal("session emitter failure", count, err)
	}
	for _, mid := range []bool{false, true} {
		r, _ := guiSessionSetup(t, c)
		count = 0
		cancelled, cancel := context.WithCancel(ctx)
		if !mid {
			cancel()
		}
		err = r.Visit(cancelled, SessionOptions{MaxProcesses: 10, MaxSessions: 10}, func(SessionSpace) error { count++; cancel(); return nil })
		cancel()
		expected := 0
		if mid {
			expected = 1
		}
		if !errors.Is(err, context.Canceled) || count != expected {
			t.Fatal("session cancellation", count, err)
		}
	}
	for _, options := range []SessionOptions{{}, {MaxProcesses: 1000001, MaxSessions: 1}, {MaxProcesses: 1, MaxSessions: 1000001}} {
		if err = r.Visit(ctx, options, func(SessionSpace) error { return nil }); err == nil {
			t.Fatal("invalid session bounds accepted")
		}
	}
	if err = r.Visit(ctx, SessionOptions{MaxProcesses: 1, MaxSessions: 1}, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	if err = (SessionReader{}).Visit(ctx, SessionOptions{MaxProcesses: 1, MaxSessions: 1}, func(SessionSpace) error { return nil }); err == nil {
		t.Fatal("missing session inputs accepted")
	}
}
func FuzzGUISessions(f *testing.F) {
	c := guiSessionOracle(f)[0]
	seed, source := guiSessionSetup(f, c)
	f.Add(uint64(0x20000), uint64(0), []byte{})
	f.Add(uint64(0x20028), uint64(8), []byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, at, width uint64, patch []byte) {
		r := SessionReader{Kernel: &object.Reader{Symbols: seed.Kernel.Symbols}, KernelBase: c.KernelBase}
		physical := &guiMemory{data: append([]byte(nil), source.data...)}
		at %= uint64(len(physical.data))
		if len(patch) > 16 {
			patch = patch[:16]
		}
		copy(physical.data[at:], patch)
		if width > 0 {
			physical.holes = [][2]uint64{{at, 1 + width%16}}
		}
		translator, err := memory.NewIntelForOS(physical, c.KernelDTB, "x64", "windows", 16)
		if err != nil {
			t.Fatal(err)
		}
		r.Physical = physical
		r.Kernel.Layer = &memory.Virtual{Physical: physical, Translator: translator, ID: "session-fuzz"}
		count := 0
		_ = r.Visit(context.Background(), SessionOptions{MaxProcesses: 8, MaxSessions: 4}, func(s SessionSpace) error {
			count++
			_, _ = memory.Read(context.Background(), s.Layer, 0x400000, 16)
			return nil
		})
		if count > 4 || len(physical.reads) > 256 {
			t.Fatal("session acquisition exceeded bounds", count, len(physical.reads))
		}
	})
}
