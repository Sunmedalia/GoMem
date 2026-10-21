package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func kallsymsFixture(t testing.TB, layout, bpf string) (plugin.Environment, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-kallsyms-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Width                 int
			Layout, BPF, Scenario string
			ISF                   json.RawMessage
			Writes                [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		if c.Width != 8 || c.Layout != layout || c.BPF != bpf || c.Scenario != "normal" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		data := make(flatMemory, 0x20000)
		for _, w := range c.Writes {
			var at int
			var encoded string
			if err = json.Unmarshal(w[0], &at); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &encoded); err != nil {
				t.Fatal(err)
			}
			raw, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[at:], raw)
		}
		return plugin.Environment{OS: "linux", Architecture: "x64", Symbols: table, Kernel: data, Physical: data, Objects: &object.Reader{Layer: data, Symbols: table}}, data
	}
	t.Fatal("missing fixture")
	return plugin.Environment{}, nil
}
func kallsymsParams(t testing.TB) map[string]string {
	t.Helper()
	p, err := plugin.Parameters(linuxKallsymsPlugins()[0].spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestLinuxKallsymsEveryOutputBoundary(t *testing.T) {
	e, _ := kallsymsFixture(t, "typetab", "pack")
	count := 0
	err := linuxKallsyms(context.Background(), e, kallsymsParams(t), func(evidence.Row) error { count++; return nil })
	if err != nil || count < 10 {
		t.Fatal(count, err)
	}
	for boundary := 1; boundary <= count; boundary++ {
		stop := errors.New("sink failed")
		calls := 0
		err = linuxKallsyms(context.Background(), e, kallsymsParams(t), func(evidence.Row) error {
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
		err = linuxKallsyms(ctx, e, kallsymsParams(t), func(evidence.Row) error {
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
}
func TestLinuxKallsymsSourceFlags(t *testing.T) {
	e, _ := kallsymsFixture(t, "legacy", "modern")
	names := []string{"core", "modules", "ftrace", "bpf"}
	counts := []int{3, 2, 2, 1}
	for mask := 0; mask < 16; mask++ {
		p := kallsymsParams(t)
		want := map[string]int{}
		for i, name := range names {
			if mask == 0 || mask&(1<<i) != 0 {
				want[name] = counts[i]
			}
			if mask&(1<<i) != 0 {
				p[name] = "true"
			}
		}
		got := map[string]int{}
		err := linuxKallsyms(context.Background(), e, p, func(row evidence.Row) error {
			if row.Cells["RecordType"].String() == "symbol" {
				got[row.Cells["SubSystem"].String()]++
			}
			return nil
		})
		// The public flag is modules, while the fixed result subsystem is module.
		want["module"] = want["modules"]
		delete(want, "modules")
		if err != nil {
			t.Fatal(mask, err)
		}
		for _, name := range []string{"core", "module", "ftrace", "bpf"} {
			if got[name] != want[name] {
				t.Fatal(mask, got, want)
			}
		}
	}
}
func TestLinuxKallsymsInvalidParameters(t *testing.T) {
	for _, name := range []string{"max-nodes", "max-symbols", "max-bytes"} {
		for _, value := range []string{"0", "-1", "18446744073709551615", "bad"} {
			e, _ := kallsymsFixture(t, "legacy", "modern")
			p := kallsymsParams(t)
			p[name] = value
			if err := linuxKallsyms(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(name, value)
			}
		}
	}
	for _, name := range []string{"core", "modules", "ftrace", "bpf"} {
		e, _ := kallsymsFixture(t, "legacy", "modern")
		p := kallsymsParams(t)
		p[name] = "bad"
		if err := linuxKallsyms(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
			t.Fatal(name)
		}
	}
}

type kallsymsPartialLayer struct{ flatMemory }

func (l kallsymsPartialLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x18800+512 && len(p) == 512 {
		n, err := l.flatMemory.ReadAt(ctx, p[:12], at)
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	return l.flatMemory.ReadAt(ctx, p, at)
}
func TestLinuxKallsymsPartialReadIsExplicit(t *testing.T) {
	e, data := kallsymsFixture(t, "legacy", "modern")
	layer := kallsymsPartialLayer{data}
	e.Kernel = layer
	e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
	captures, affected := 0, 0
	err := linuxKallsyms(context.Background(), e, kallsymsParams(t), func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "symbol" && row.Cells["Error"].Reason == "symbol_name_acquisition_incomplete" {
			affected++
			if row.Cells["SymbolName"].String() != "entry" || row.Cells["SubSystem"].String() != "module" {
				t.Fatal(row)
			}
			p := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			if len(p["NameReadIssues"].Data.([]map[string]evidence.Value)) != 1 {
				t.Fatal(p)
			}
		}
		if row.Cells["RecordType"].String() == "symbol_read" {
			p := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			if p["ReadComplete"].Data == false {
				captures++
				n, _ := p["CapturedBytes"].Uint()
				if n != 12 || p["Error"].Error == "" {
					t.Fatal(row)
				}
			}
		}
		return nil
	})
	if err == nil || captures != 1 || affected != 1 {
		t.Fatal(captures, err)
	}
}
func FuzzLinuxKallsymsSources(f *testing.F) {
	e, original := kallsymsFixture(f, "typetab", "legacy")
	f.Add([]byte{0xff}, uint8(0))
	f.Add([]byte{0, 0, 0, 0}, uint8(3))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x18000, 0x18200, 0x18400, 0x19400, 0x19d00, 0x1a200, 0x1a400}[int(region)%7]
		copy(data[at:], payload)
		env := e
		env.Kernel = data
		env.Objects = &object.Reader{Layer: data, Symbols: e.Symbols}
		p := kallsymsParams(t)
		p["max-nodes"] = "8"
		p["max-symbols"] = "16"
		p["max-bytes"] = "4096"
		calls := 0
		_ = linuxKallsyms(context.Background(), env, p, func(evidence.Row) error {
			calls++
			if calls > 10000 {
				return errors.New("output bound")
			}
			return nil
		})
		if calls > 10001 {
			t.Fatal("unbounded output")
		}
	})
}

func TestLinuxKallsymsMalformedLayouts(t *testing.T) {
	for _, fault := range []string{"list", "symtab", "container", "name-array", "kernel-symbol-size"} {
		t.Run(fault, func(t *testing.T) {
			e, _ := kallsymsFixture(t, "typetab", "legacy")
			table := e.Symbols.(*symbols.ISF)
			switch fault {
			case "list":
				typ := table.Types["module"]
				f := typ.Fields["list"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
				typ.Fields["list"] = f
				table.Types["module"] = typ
			case "symtab":
				typ := table.Types["mod_kallsyms"]
				f := typ.Fields["symtab"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
				typ.Fields["symtab"] = f
				table.Types["mod_kallsyms"] = typ
			case "container":
				typ := table.Types["module"]
				f := typ.Fields["kallsyms"]
				f.Type = symbols.TypeRef{Kind: "base", Name: "u64"}
				typ.Fields["kallsyms"] = f
				table.Types["module"] = typ
			case "name-array":
				typ := table.Types["module"]
				f := typ.Fields["name"]
				f.Type.Count = 1 << 21
				typ.Fields["name"] = f
				table.Types["module"] = typ
			case "kernel-symbol-size":
				typ := table.Types["kernel_symbol"]
				typ.Size = 1 << 20
				table.Types["kernel_symbol"] = typ
			}
			if err := linuxKallsyms(context.Background(), e, kallsymsParams(t), func(evidence.Row) error { return nil }); err == nil {
				t.Fatal("malformed layout accepted")
			}
		})
	}
}
