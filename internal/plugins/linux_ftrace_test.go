package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func ftraceTestFixture(t testing.TB, width int, layout string) (plugin.Environment, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-ftrace-oracle.json")
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
func ftraceTestParams() map[string]string {
	return map[string]string{"show-ftrace-flags": "true", "max-nodes": "32", "max-entries": "32", "max-bytes": "65536", "max-scan-bytes": "65536"}
}
func TestLinuxFtraceEveryOutputBoundary(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, layout := range []string{"legacy", "pointer", "embedded"} {
			t.Run(fmt.Sprintf("%d/%s", width, layout), func(t *testing.T) {
				e, _ := ftraceTestFixture(t, width, layout)
				total, hooks := 0, 0
				err := linuxFtrace(context.Background(), e, ftraceTestParams(), func(row evidence.Row) error {
					total++
					if row.Cells["RecordType"].String() == "ftrace_hook" {
						hooks++
					}
					return nil
				})
				if err == nil || hooks != 3 {
					t.Fatal("missing module sources must fail but preserve hooks", err, hooks)
				}
				for boundary := 1; boundary <= total; boundary++ {
					stop := errors.New("sink stopped")
					calls := 0
					err := linuxFtrace(context.Background(), e, ftraceTestParams(), func(evidence.Row) error {
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
					err = linuxFtrace(ctx, e, ftraceTestParams(), func(evidence.Row) error {
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
func TestLinuxFtraceBoundsAndMissingLayouts(t *testing.T) {
	for _, name := range []string{"max-nodes", "max-entries", "max-bytes", "max-scan-bytes"} {
		for _, bad := range []string{"0", "-1", "18446744073709551615", "bad"} {
			e, _ := ftraceTestFixture(t, 8, "legacy")
			p := ftraceTestParams()
			p[name] = bad
			if err := linuxFtrace(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(name, bad)
			}
		}
	}
	for _, name := range []string{"root", "sentinel"} {
		e, _ := ftraceTestFixture(t, 8, "legacy")
		symbol := "ftrace_ops_list"
		if name == "sentinel" {
			symbol = "ftrace_list_end"
		}
		delete(e.Symbols.(*symbols.ISF).Symbols, symbol)
		calls := 0
		if err := linuxFtrace(context.Background(), e, ftraceTestParams(), func(evidence.Row) error { calls++; return nil }); err == nil || calls != 0 {
			t.Fatal(name, calls, err)
		}
	}
}
func FuzzLinuxFtraceAcquisition(f *testing.F) {
	e, original := ftraceTestFixture(f, 8, "pointer")
	f.Add([]byte{1, 2, 3, 4}, uint8(0))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x16f00, 0x17000, 0x17400, 0x17600, 0x17800, 0x17a00}[int(region)%6]
		copy(data[at:], payload)
		env := e
		env.Kernel = data
		env.Objects = &object.Reader{Layer: data, Symbols: e.Symbols}
		p := ftraceTestParams()
		p["max-nodes"] = "8"
		p["max-entries"] = "8"
		p["max-bytes"] = "4096"
		calls := 0
		_ = linuxFtrace(context.Background(), env, p, func(evidence.Row) error {
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

func TestLinuxFtraceMalformedLayoutsAreExplicit(t *testing.T) {
	for _, name := range []string{"func-hash", "buckets", "first", "ops-extent", "node-extent", "root-type"} {
		t.Run(name, func(t *testing.T) {
			e, _ := ftraceTestFixture(t, 8, "pointer")
			table := e.Symbols.(*symbols.ISF)
			expected := ""
			switch name {
			case "func-hash":
				typ := table.Types["ftrace_ops"]
				f := typ.Fields["func_hash"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "ulong"}
				typ.Fields["func_hash"] = f
				table.Types["ftrace_ops"] = typ
				expected = "unsupported ftrace_ops.func_hash"
			case "buckets":
				typ := table.Types["ftrace_hash"]
				f := typ.Fields["buckets"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "ulong"}
				typ.Fields["buckets"] = f
				table.Types["ftrace_hash"] = typ
				expected = "unsupported ftrace_hash.buckets"
			case "first":
				typ := table.Types["hlist_head"]
				f := typ.Fields["first"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "ulong"}
				typ.Fields["first"] = f
				table.Types["hlist_head"] = typ
				expected = "hlist_head.first is not a pointer"
			case "ops-extent":
				typ := table.Types["ftrace_ops"]
				typ.Size = 1 << 21
				table.Types["ftrace_ops"] = typ
				expected = "invalid ftrace_ops extent"
			case "node-extent":
				typ := table.Types["hlist_node"]
				typ.Size = 1 << 21
				table.Types["hlist_node"] = typ
				expected = "invalid hlist_node extent"
			case "root-type":
				s := table.Symbols["ftrace_ops_list"]
				s.Type = nil
				table.Symbols["ftrace_ops_list"] = s
				expected = "must declare a pointer"
			}
			observed := false
			err := linuxFtrace(context.Background(), e, ftraceTestParams(), func(row evidence.Row) error {
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
