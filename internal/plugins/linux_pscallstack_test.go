package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func callStackFuzzFixture(t testing.TB) (*symbols.ISF, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-pscallstack-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Width             int
			Threads, Scenario string
			ISF               json.RawMessage
			Writes            [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		if c.Width != 8 || c.Threads != "legacy" || c.Scenario != "normal" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		data := make(flatMemory, 0x80000)
		for _, w := range c.Writes {
			var at int
			var encoded string
			if err = json.Unmarshal(w[0], &at); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &encoded); err != nil {
				t.Fatal(err)
			}
			v, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[at:], v)
		}
		return table, data
	}
	t.Fatal("missing callstack control")
	return nil, nil
}
func FuzzLinuxPsCallStack(f *testing.F) {
	table, original := callStackFuzzFixture(f)
	f.Add([]byte{0xff}, uint8(0))
	f.Add([]byte{0}, uint8(6))
	params, err := plugin.Parameters(linuxPsCallStackPlugins()[0].spec, map[string]string{"max-nodes": "8", "max-tasks": "8", "max-symbols": "16", "max-words": "64", "max-bytes": "16384"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x30000, 0x30050, 0x30440, 0x43fc0, 0x16000, 0x18200, 0x73000, 0x19d00}[int(region)%8]
		copy(data[at:], payload)
		intel, err := memory.NewIntel(data, 0x70000, "x64", 16)
		if err != nil {
			t.Fatal(err)
		}
		layer := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
		env := plugin.Environment{OS: "linux", Architecture: "x64", Symbols: table, Kernel: layer, Physical: data, Objects: &object.Reader{Layer: layer, Symbols: table}}
		rows := 0
		_ = linuxPsCallStack(context.Background(), env, params, func(r evidence.Row) error {
			rows++
			if rows > 40000 {
				return errors.New("fuzz output limit")
			}
			if r.Cells["RecordType"].String() == "stack_entry" {
				if _, err := r.Cells["Address"].Uint(); err != nil {
					t.Fatal(err)
				}
				if r.Cells["Error"].Error != "" {
					t.Fatal("error presented as normal stack entry")
				}
			}
			return nil
		})
		if rows > 40001 {
			t.Fatal("unbounded output")
		}
	})
}
func TestLinuxPsCallStackConfiguration(t *testing.T) {
	table, data := callStackFuzzFixture(t)
	intel, err := memory.NewIntel(data, 0x70000, "x64", 16)
	if err != nil {
		t.Fatal(err)
	}
	layer := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	env := plugin.Environment{OS: "linux", Architecture: "x64", Symbols: table, Kernel: layer, Physical: data, Objects: &object.Reader{Layer: layer, Symbols: table}}
	for _, name := range []string{"max-tasks", "max-words", "max-bytes", "max-symbols", "max-nodes"} {
		for _, v := range []string{"0", "10000000001", "bad"} {
			params, _ := plugin.Parameters(linuxPsCallStackPlugins()[0].spec, nil)
			params[name] = v
			if err := linuxPsCallStack(context.Background(), env, params, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(name, v)
			}
		}
	}
	for _, field := range []string{"pid", "unresolved"} {
		params, _ := plugin.Parameters(linuxPsCallStackPlugins()[0].spec, nil)
		params[field] = "bad"
		if err := linuxPsCallStack(context.Background(), env, params, func(evidence.Row) error { return nil }); err == nil {
			t.Fatal(field)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	params, _ := plugin.Parameters(linuxPsCallStackPlugins()[0].spec, nil)
	if err := linuxPsCallStack(ctx, env, params, func(evidence.Row) error { t.Fatal("emitted after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	env.Architecture = "arm64"
	if err := linuxPsCallStack(context.Background(), env, params, func(evidence.Row) error { return nil }); err == nil {
		t.Fatal("unsupported architecture")
	}
}
