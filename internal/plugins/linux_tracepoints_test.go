package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func tracepointsTestFixture(t testing.TB, width int, layout string) (plugin.Environment, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-tracepoints-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Width            int
			Layout, Scenario string
			ISF              json.RawMessage
			Writes           [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, c := range oracle.Cases {
		if c.Width != width || c.Layout != layout || c.Scenario != "normal" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		data := make(flatMemory, 0x20000)
		for _, w := range c.Writes {
			var at int
			var text string
			if err = json.Unmarshal(w[0], &at); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &text); err != nil {
				t.Fatal(err)
			}
			b, err := hex.DecodeString(text)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[at:], b)
		}
		arch := "x64"
		if width == 4 {
			arch = "x86"
		}
		return plugin.Environment{Kernel: data, Physical: data, Objects: &object.Reader{Layer: data, Symbols: table}, Symbols: table, Architecture: arch, OS: "linux"}, data
	}
	t.Fatal("missing fixture")
	return plugin.Environment{}, nil
}
func tracepointsTestParams() map[string]string {
	return map[string]string{"max-nodes": "32", "max-tracepoints": "32", "max-probes": "32", "max-bytes": "65536", "max-scan-bytes": "65536"}
}
func TestLinuxTracepointsEveryOutputBoundary(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, layout := range []string{"absolute", "prel32"} {
			t.Run(fmt.Sprintf("%d/%s", width, layout), func(t *testing.T) {
				e, _ := tracepointsTestFixture(t, width, layout)
				total, selected := 0, 0
				err := linuxTracepoints(context.Background(), e, tracepointsTestParams(), func(row evidence.Row) error {
					total++
					if row.Cells["RecordType"].String() == "tracepoint_probe" {
						selected++
					}
					return nil
				})
				if err == nil || selected != 3 {
					t.Fatal("missing sources must fail but retain parsed probes", selected, err)
				}
				for boundary := 1; boundary <= total; boundary++ {
					stop := errors.New("sink failure")
					calls := 0
					err := linuxTracepoints(context.Background(), e, tracepointsTestParams(), func(evidence.Row) error {
						calls++
						if calls == boundary {
							return stop
						}
						return nil
					})
					if !errors.Is(err, stop) || calls != boundary {
						t.Fatal(boundary, calls, err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					calls = 0
					err = linuxTracepoints(ctx, e, tracepointsTestParams(), func(evidence.Row) error {
						calls++
						if calls == boundary {
							cancel()
						}
						return nil
					})
					cancel()
					if !errors.Is(err, context.Canceled) || calls != boundary {
						t.Fatal(boundary, calls, err)
					}
				}
			})
		}
	}
}
func TestLinuxTracepointsBoundsAndLayouts(t *testing.T) {
	for _, name := range []string{"max-nodes", "max-tracepoints", "max-probes", "max-bytes", "max-scan-bytes"} {
		for _, bad := range []string{"0", "-1", "18446744073709551615", "bad"} {
			e, _ := tracepointsTestFixture(t, 8, "absolute")
			p := tracepointsTestParams()
			p[name] = bad
			if err := linuxTracepoints(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(name, bad)
			}
		}
	}
	for _, name := range []string{"root", "stop", "root-type", "signedness", "stride", "func-type", "funcs-type"} {
		t.Run(name, func(t *testing.T) {
			e, _ := tracepointsTestFixture(t, 8, "prel32")
			table := e.Symbols.(*symbols.ISF)
			expected := ""
			switch name {
			case "root":
				delete(table.Symbols, "__start___tracepoints_ptrs")
				expected = "unsupported tracepoints"
			case "stop":
				delete(table.Symbols, "__stop___tracepoints_ptrs")
				expected = "__stop___tracepoints_ptrs"
			case "root-type":
				s := table.Symbols["__start___tracepoints_ptrs"]
				s.Type = nil
				table.Symbols["__start___tracepoints_ptrs"] = s
				expected = "subtype metadata"
			case "signedness":
				typ := table.Bases["int"]
				typ.Signed = false
				table.Bases["int"] = typ
				expected = "signed four-byte int"
			case "stride":
				typ := table.Types["tracepoint_func"]
				typ.Size = 1 << 21
				table.Types["tracepoint_func"] = typ
				expected = "invalid tracepoint_func extent"
			case "func-type":
				typ := table.Types["tracepoint_func"]
				f := typ.Fields["func"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "int"}
				typ.Fields["func"] = f
				table.Types["tracepoint_func"] = typ
				expected = "must declare a pointer target"
			case "funcs-type":
				typ := table.Types["tracepoint"]
				f := typ.Fields["funcs"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "int"}
				typ.Fields["funcs"] = f
				table.Types["tracepoint"] = typ
				expected = "tracepoint.funcs is not a pointer"
			}
			observed := false
			err := linuxTracepoints(context.Background(), e, tracepointsTestParams(), func(row evidence.Row) error {
				if strings.Contains(row.Cells["Error"].Error, expected) {
					observed = true
				}
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), expected) && !observed {
				t.Fatal(name, expected, err)
			}
		})
	}
}

type tracepointPrefixLayer struct{ memory.MemoryLayer }

func (l tracepointPrefixLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x17400 && len(p) == 512 {
		n, err := l.MemoryLayer.ReadAt(ctx, p[:32], at)
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func TestLinuxTracepointsPartialNameRetainsPrefixAndError(t *testing.T) {
	e, _ := tracepointsTestFixture(t, 8, "absolute")
	layer := tracepointPrefixLayer{e.Kernel}
	e.Kernel = layer
	e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
	prefix := 0
	err := linuxTracepoints(context.Background(), e, tracepointsTestParams(), func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "tracepoint_probe" && row.Cells["tracepoint"].String() == "sched_switch" {
			prefix++
			if row.Cells["NameReadComplete"].Data != false || row.Cells["NameError"].Error == "" || row.Cells["Error"].Reason != "probe_inspection_incomplete" {
				t.Fatal(row)
			}
		}
		return nil
	})
	if err == nil || prefix != 2 {
		t.Fatal(err, prefix)
	}
}
func TestTracepointRelative32Boundaries(t *testing.T) {
	for _, c := range []struct {
		slot, encoded, want uint64
		fail                bool
	}{{0x1000, 0xffffffff, 0xfff, false}, {0x1000, 4, 0x1004, false}, {0, 0xffffffff, 0, true}, {^uint64(0), 1, 0, true}, {0x80000000, 0x80000000, 0, false}} {
		got, err := tracepointRelative32(c.slot, c.encoded)
		if (err != nil) != c.fail || !c.fail && got != c.want {
			t.Fatal(c, got, err)
		}
	}
}
func FuzzLinuxTracepointAcquisition(f *testing.F) {
	e, original := tracepointsTestFixture(f, 8, "prel32")
	f.Add([]byte{1, 2, 3, 4}, uint8(0))
	f.Add([]byte{0, 0, 0, 0}, uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x16f00, 0x17000, 0x17200, 0x17400}[int(region)%4]
		copy(data[at:], payload)
		env := e
		env.Kernel = data
		env.Objects = &object.Reader{Layer: data, Symbols: e.Symbols}
		p := tracepointsTestParams()
		p["max-probes"] = "8"
		p["max-bytes"] = "4096"
		calls := 0
		_ = linuxTracepoints(context.Background(), env, p, func(evidence.Row) error {
			calls++
			if calls > 1000 {
				return errors.New("output bound")
			}
			return nil
		})
		if calls > 1001 {
			t.Fatal("unbounded output")
		}
	})
}
