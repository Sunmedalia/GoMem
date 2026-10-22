package winconsole

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type consoleControl struct {
	Layout, Scenario string
	Size             int
	Root             uint64
	MaxBuffers       uint64 `json:"max_buffers"`
	Writes           []struct {
		Offset int
		Data   string
	}
	Holes   [][2]uint64
	Results map[string]result
}
type consoleOracle struct {
	Commit  string
	Kernel  json.RawMessage
	Layouts map[string]struct{ Source, SHA256 string }
	Cases   []consoleControl
}

func consoleFixture(t testing.TB) consoleOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/console-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o consoleOracle
	if err = json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	if o.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(o.Cases) != 319 || len(o.Layouts) != 11 {
		t.Fatal("console object oracle drift")
	}
	return o
}
func consoleSetup(t testing.TB, o consoleOracle, c consoleControl) (ConsoleReader, original) {
	t.Helper()
	l, err := ParseConsoleLayout([]byte(o.Layouts[c.Layout].Source))
	if err != nil {
		t.Fatal(err)
	}
	if l.SHA256 != o.Layouts[c.Layout].SHA256 || l.SHA256 != catalogPins[c.Layout].sha256 {
		t.Fatal("console source digest mismatch")
	}
	k, err := symbols.Parse(o.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	m := original{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data) || len(raw) > len(m.data)-w.Offset {
			t.Fatal("invalid console object write")
		}
		copy(m.data[w.Offset:], raw)
	}
	return ConsoleReader{Layer: m, Layout: l, KernelSymbols: k}, m
}
func consoleCompare(t *testing.T, c consoleControl, name string, value any) {
	t.Helper()
	want := c.Results[name]
	if want.Error != "" {
		t.Fatal("cannot compare original aborted result", name, want.Error)
	}
	var a, b any
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(want.Value, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s got %s want %s", name, raw, want.Value)
	}
}
func consoleCapture(t testing.TB, m original, at uint64, raw []byte) {
	t.Helper()
	buf := make([]byte, len(raw))
	n, err := m.ReadAt(context.Background(), buf, at)
	if err != nil || n != len(raw) || !bytes.Equal(buf, raw) {
		t.Fatal("console original capture mismatch", at, n, err)
	}
}
func TestOriginalConsoleObjectMethods(t *testing.T) {
	o := consoleFixture(t)
	for _, c := range o.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := consoleSetup(t, o, c)
			for _, old := range []bool{false, true} {
				name := "title"
				if old {
					name = "original_title"
				}
				title, err := r.Title(context.Background(), c.Root, old)
				failed := c.Scenario == "both-title-hole" || old && c.Scenario == "original-title-hole" || !old && (c.Scenario == "title-hole" || c.Scenario == "zero-count-title-hole" || c.Scenario == "tail-title-hole")
				if failed != (err != nil) {
					t.Fatal(name, err)
				}
				if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("title read cause lost", err)
				}
				consoleCompare(t, c, name, title.Text)
				if err == nil {
					consoleCapture(t, m, title.Pointer.Address, title.Pointer.Raw)
					consoleCapture(t, m, title.Pointer.Value, title.Raw)
				}
			}
			valid, err := r.Valid(context.Background(), c.Root, c.MaxBuffers)
			failed := c.Scenario == "count-hole" || c.Scenario == "title-hole" || c.Scenario == "both-title-hole" || c.Scenario == "tail-title-hole"
			if failed != (err != nil) {
				t.Fatal("validity error lost", err)
			}
			if c.Results["valid"].Error == "" {
				consoleCompare(t, c, "valid", valid)
			}
			if c.Scenario != "count-hole" {
				values := map[string]any{}
				for _, name := range []string{"ScreenX", "ScreenY", "CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax", "ProcessCount"} {
					v, err := r.Scalar(context.Background(), c.Root, "_CONSOLE_INFORMATION."+name)
					if err != nil {
						t.Fatal(err)
					}
					consoleCapture(t, m, v.Address, v.Raw)
					if v.Signed {
						values[name] = int64(v.Value)
					} else {
						values[name] = v.Value
					}
				}
				consoleCompare(t, c, "scalars", values)
			}
			for _, walk := range []struct {
				name, field, node string
				owner             uint64
			}{
				{"histories", "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", c.Root},
				{"processes", "_CONSOLE_INFORMATION.ConsoleProcessList", "_CONSOLE_PROCESS_LIST", c.Root},
				{"exe_aliases", "_CONSOLE_INFORMATION.ExeAliasList", "_EXE_ALIAS_LIST", c.Root},
				{"aliases", "_EXE_ALIAS_LIST.AliasList", "_ALIAS", 0xc000},
			} {
				addresses := []uint64{}
				err := r.WalkList(context.Background(), walk.owner, walk.field, walk.node, 8, func(at uint64) error { addresses = append(addresses, at); return nil })
				failed := walk.name == "histories" && (c.Scenario == "history-cycle" || c.Scenario == "history-link-hole" || c.Scenario == "history-next-hole" || c.Scenario == "null-history-head" || c.Scenario == "sentinel-head-hole") || walk.name == "processes" && c.Scenario == "process-cycle" || walk.name == "aliases" && (c.Scenario == "alias-cycle" || c.Scenario == "alias-node-hole")
				if failed != (err != nil) {
					t.Fatal(walk.name, "list failure mismatch", err)
				}
				if c.Results[walk.name].Error == "" {
					consoleCompare(t, c, walk.name, addresses)
				} else {
					// Original physical-range checks admit an unreadable node and then abort
					// its forward-link read. Native requires a readable container byte first.
					first := uint64(0xb000)
					if walk.name == "aliases" {
						first = 0xd000
					}
					if !reflect.DeepEqual(addresses, []uint64{first}) || !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatal("original abort/native acquired prefix", addresses, err)
					}
				}
			}
			values := []map[string]uint64{}
			err = r.WalkList(context.Background(), c.Root, "_CONSOLE_INFORMATION.ConsoleProcessList", "_CONSOLE_PROCESS_LIST", 8, func(at uint64) error {
				target, err := r.Scalar(context.Background(), at, "_CONSOLE_PROCESS_LIST.ConsoleProcess")
				if err != nil {
					return err
				}
				pid, err := r.Scalar(context.Background(), target.Value, "_CONSOLE_PROCESS.ProcessId")
				if err != nil {
					return err
				}
				handle, err := r.Scalar(context.Background(), target.Value, "_CONSOLE_PROCESS.ProcessHandle")
				if err != nil {
					return err
				}
				for _, v := range []ConsoleScalar{target, pid, handle} {
					consoleCapture(t, m, v.Address, v.Raw)
				}
				values = append(values, map[string]uint64{"pid": pid.Value, "handle": handle.Value})
				return nil
			})
			if (err != nil) != (c.Scenario == "process-cycle" || c.Scenario == "process-node-read-hole") {
				t.Fatal("attached process fields", err)
			}
			if c.Results["process_values"].Error == "" {
				consoleCompare(t, c, "process_values", values)
			}
		})
	}
}
func TestConsoleBoundsOutputCancellationAndPartialBytes(t *testing.T) {
	o := consoleFixture(t)
	c := o.Cases[0]
	r, m := consoleSetup(t, o, c)
	for _, bound := range []uint64{0, 1, 1000001} {
		n := 0
		err := r.WalkList(context.Background(), c.Root, "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", bound, func(uint64) error { n++; return nil })
		if err == nil || n > 1 {
			t.Fatal("list bound ignored", bound, n, err)
		}
	}
	sentinel := errors.New("stop output")
	count := 0
	err := r.WalkList(context.Background(), c.Root, "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", 8, func(uint64) error { count++; return sentinel })
	if !errors.Is(err, sentinel) || count != 1 {
		t.Fatal(err, count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	count = 0
	err = r.WalkList(ctx, c.Root, "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", 8, func(uint64) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatal("cancellation not terminal", err, count)
	}
	if _, err := r.Title(ctx, c.Root, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.Valid(ctx, c.Root, 4); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.Scalar(context.Background(), c.Root, "_EXE_ALIAS_LIST.AliasList"); err == nil {
		t.Fatal("embedded list read as scalar")
	}
	r.Layer = consolePartialLayer{m}
	title, err := r.Title(context.Background(), c.Root, false)
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(title.Raw) != 4 || !bytes.Equal(title.Raw, m.data[0x10000:0x10004]) || title.Text != "" {
		t.Fatal("partial title bytes hidden", title, err)
	}
}

type consolePartialLayer struct{ original }

func (m consolePartialLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x10000 && len(p) > 4 {
		n, _ := m.original.ReadAt(ctx, p[:4], at)
		return n, io.ErrUnexpectedEOF
	}
	return m.original.ReadAt(ctx, p, at)
}
func TestConsoleLayoutRejectsMalformedMetadata(t *testing.T) {
	o := consoleFixture(t)
	raw := []byte(o.Layouts[o.Cases[0].Layout].Source)
	for _, bad := range [][]byte{nil, []byte("{}"), []byte("{"), bytes.Repeat([]byte("x"), 4<<20+1)} {
		if _, err := ParseConsoleLayout(bad); err == nil {
			t.Fatal("invalid layout accepted")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { delete(d["user_types"].(map[string]any), "_CONSOLE_INFORMATION") },
		func(d map[string]any) { d["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4 },
		func(d map[string]any) {
			d["user_types"].(map[string]any)["_CONSOLE_INFORMATION"].(map[string]any)["fields"].(map[string]any)["Title"].(map[string]any)["offset"] = -2000000
		},
	} {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		bad, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseConsoleLayout(bad); err == nil {
			t.Fatal("bad metadata accepted")
		}
	}
}
func FuzzConsoleObjects(f *testing.F) {
	o := consoleFixture(f)
	for _, i := range []uint16{0, 1, 10, 18, 28, 202, 290, 318} {
		f.Add([]byte{}, i, uint32(0))
	}
	f.Fuzz(func(t *testing.T, payload []byte, index uint16, offset uint32) {
		if len(payload) > 256 {
			return
		}
		c := o.Cases[int(index)%len(o.Cases)]
		r, m := consoleSetup(t, o, c)
		copy(m.data[int(offset)%len(m.data):], payload)
		r.Layer = m
		text, _ := r.Title(context.Background(), c.Root, false)
		if len(text.Raw) > 512 {
			t.Fatal("unbounded title")
		}
		_, _ = r.Valid(context.Background(), c.Root, 4)
		count := 0
		err := r.WalkList(context.Background(), c.Root, "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", 4, func(at uint64) error { count++; return nil })
		if count > 4 {
			t.Fatal("unbounded list", err)
		}
	})
}
func FuzzConsoleObjectLayout(f *testing.F) {
	o := consoleFixture(f)
	f.Add([]byte(o.Layouts[o.Cases[0].Layout].Source))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4<<20+1 {
			return
		}
		l, err := ParseConsoleLayout(raw)
		if err != nil {
			return
		}
		r := ConsoleReader{Layer: original{data: make([]byte, 128)}, Layout: l}
		_, _ = r.Title(context.Background(), 0, false)
		_, _ = r.Valid(context.Background(), 0, 4)
		for name := range l.fields {
			_, _ = l.Address(0, name)
		}
	})
}
