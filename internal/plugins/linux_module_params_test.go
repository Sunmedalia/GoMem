package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func moduleParamFixture(width int, endian, layout string, charSigned bool) (capabilityLayer, *linuxModuleRead) {
	data := make(capabilityLayer, 65536)
	ref := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: name} }
	ptr := func(kind, name string) symbols.TypeRef {
		sub := symbols.TypeRef{Kind: kind, Name: name}
		return symbols.TypeRef{Kind: "pointer", Subtype: &sub}
	}
	field := func(at uint64, typ symbols.TypeRef) symbols.Field { return symbols.Field{Offset: at, Type: typ} }
	table := &symbols.ISF{Bases: map[string]symbols.Type{}, Types: map[string]symbols.Type{}, Symbols: map[string]symbols.Symbol{}}
	for _, b := range []struct {
		name   string
		size   int
		signed bool
	}{
		{"pointer", width, false}, {"int", 4, true}, {"long unsigned int", width, false}, {"long long unsigned int", 8, false}, {"long int", width, true}, {"unsigned int", 4, false}, {"short unsigned int", 2, false}, {"short int", 2, true}, {"char", 1, charSigned},
	} {
		table.Bases[b.name] = symbols.Type{Kind: "int", Size: uint64(b.size), Signed: b.signed, Endian: endian}
	}
	table.Types["module"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"kp": field(0, ptr("struct", "kernel_param")), "num_kp": field(8, ref("unsigned int"))}}
	fields := map[string]symbols.Field{
		"name": field(0, ptr("base", "char")), "arg": field(16, ptr("base", "char")),
		"arr": field(16, ptr("struct", "kparam_array")), "str": field(16, ptr("struct", "kparam_string")),
	}
	if layout == "get" {
		fields["get"] = field(8, symbols.TypeRef{Kind: "pointer"})
	} else {
		fields["ops"] = field(8, ptr("struct", "kernel_param_ops"))
	}
	table.Types["kernel_param"] = symbols.Type{Kind: "struct", Size: 32, Fields: fields}
	table.Types["kernel_param_ops"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"get": field(8, symbols.TypeRef{Kind: "pointer"})}}
	table.Types["kparam_string"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"maxlen": field(0, ref("unsigned int")), "string": field(8, ptr("base", "char"))}}
	table.Types["kparam_array"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"max": field(0, ref("unsigned int")), "num": field(8, ptr("base", "unsigned int")), "elemsize": field(16, ref("unsigned int")), "elem": field(24, ptr("struct", "kernel_param"))}}
	env := plugin.Environment{Kernel: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}}
	return data, &linuxModuleRead{context.Background(), env, map[string]evidence.Value{}, &pluginFailures{}}
}

func verifyParamCaptures(t *testing.T, data []byte, v evidence.Value) int {
	t.Helper()
	if v.Kind != "structure" {
		return 0
	}
	fields, ok := v.Data.(map[string]evidence.Value)
	if !ok {
		t.Fatal("unrecognized structure", v)
	}
	if address, ok := fields["Address"]; ok {
		at, err := address.Uint()
		if err != nil {
			t.Fatal(err)
		}
		raw, ok := fields["Raw"].Data.([]byte)
		if !ok || len(raw) == 0 || at > uint64(len(data)) || uint64(len(raw)) > uint64(len(data))-at {
			t.Fatal(fields)
		}
		got, err := fields["CapturedBytes"].Uint()
		if err != nil || got != uint64(len(raw)) || fields["ReadComplete"].Data != true || !bytes.Equal(raw, data[at:at+uint64(len(raw))]) {
			t.Fatal(fields, err)
		}
		return 1
	}
	count := 0
	for _, field := range fields {
		count += verifyParamCaptures(t, data, field)
	}
	return count
}

func TestLinuxModuleParamsPinnedByteOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-module-params-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit   string
		Handlers map[string]uint64 `json:"handler_symbols"`
		Cases    []struct {
			Name, Endian, Layout, Expected string
			Width                          int
			CharSigned                     bool              `json:"char_signed"`
			Overrides                      map[string]uint64 `json:"symbol_overrides"`
			Writes                         []struct {
				Address uint64
				Hex     string
			}
			ExpectedKind string `json:"expected_kind"`
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 224 {
		t.Fatal(err, len(oracle.Cases))
	}
	for _, test := range oracle.Cases {
		t.Run(fmt.Sprintf("%d/%s/%s/%s", test.Width, test.Endian, test.Layout, test.Name), func(t *testing.T) {
			data, n := moduleParamFixture(test.Width, test.Endian, test.Layout, test.CharSigned)
			table := n.e.Symbols.(*symbols.ISF)
			for name, at := range oracle.Handlers {
				table.Symbols[name] = symbols.Symbol{Address: at}
			}
			for name, at := range test.Overrides {
				table.Symbols[name] = symbols.Symbol{Address: at}
			}
			for _, write := range test.Writes {
				raw, err := hex.DecodeString(write.Hex)
				if err != nil || write.Address > uint64(len(data)) || uint64(len(raw)) > uint64(len(data))-write.Address {
					t.Fatal(write, err)
				}
				copy(data[write.Address:], raw)
			}
			value, err := newLinuxParamDecoder(n).value(0x100, 0)
			if err != nil || linuxParamDisplay(value) != test.Expected || n.failures.count != 0 {
				t.Fatal(value, err, test.Expected, n.failures)
			}
			if test.ExpectedKind == "integer" && value.Kind != "int64" && value.Kind != "uint64" || test.ExpectedKind == "missing" && value.Kind != "missing" || test.ExpectedKind == "string" && value.Kind != "string" {
				t.Fatal("lost value type", value)
			}
			if test.ExpectedKind == "missing" && (value.Reason == "" || value.Error != "") {
				t.Fatal("lost absence reason", value)
			}
			captures := 0
			for _, v := range n.fields {
				captures += verifyParamCaptures(t, data, v)
			}
			if captures < 1 {
				t.Fatal("no evidence captured")
			}
			// The module-level display must format Python's None explicitly, retain
			// typed values, and use the same getter policy as individual decoding.
			args, err := linuxModuleArguments(n, 0x80)
			if err != nil || args != "test="+test.Expected || n.failures.count != 0 {
				t.Fatal(args, err, n.failures)
			}
		})
	}
}

func TestLinuxModuleParamsMalformedAndPartialReads(t *testing.T) {
	for _, scenario := range []string{"null-ops", "partial-ops", "partial-scalar", "partial-string", "string-limit", "array-count", "array-cycle", "array-overflow", "untyped-num", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			data, n := moduleParamFixture(8, "little", "ops", true)
			table := n.e.Symbols.(*symbols.ISF)
			for i, name := range []string{"param_get_int", "param_get_charp", "param_get_string", "param_array_get"} {
				table.Symbols[name] = symbols.Symbol{Address: uint64(0x8000 + 16*i)}
			}
			put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
			put(0x108, 0x1100)
			put(0x1108, 0x8000)
			put(0x110, 0x5000)
			switch scenario {
			case "null-ops":
				put(0x108, 0)
			case "partial-ops":
				put(0x108, 65524)
			case "partial-scalar":
				put(0x110, 65534)
			case "partial-string":
				put(0x1108, 0x8010)
				put(0x110, 65533)
				copy(data[65533:], "abc")
			case "string-limit":
				put(0x1108, 0x8020)
				put(0x5000, 4097)
			case "array-count", "array-cycle", "array-overflow", "untyped-num":
				put(0x1108, 0x8030)
				put(0x110, 0x800)
				put(0x800, 1)
				put(0x810, 32)
				put(0x818, 0x100)
				switch scenario {
				case "array-count":
					put(0x800, 33)
				case "array-overflow":
					put(0x800, 2)
					put(0x818, ^uint64(0)-16)
				case "untyped-num":
					put(0x808, 0x900)
					f := table.Types["kparam_array"].Fields["num"]
					f.Type.Subtype = nil
					table.Types["kparam_array"].Fields["num"] = f
				}
			case "cancel":
				ctx, cancel := context.WithCancel(n.ctx)
				cancel()
				n.ctx = ctx
			}
			value, err := newLinuxParamDecoder(n).value(0x100, 0)
			if err == nil || value.Kind != "missing" || value.Error == "" {
				t.Fatal(value, err)
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if scenario == "partial-string" || scenario == "partial-scalar" || scenario == "partial-ops" {
				incomplete := false
				for _, field := range n.fields {
					if field.Kind == "structure" {
						c := field.Data.(map[string]evidence.Value)
						if complete, ok := c["ReadComplete"]; ok && complete.Data == false {
							incomplete = true
							count, _ := c["CapturedBytes"].Uint()
							if count == 0 {
								t.Fatal("partial bytes discarded", c)
							}
						}
					}
				}
				if !incomplete {
					t.Fatal("read error has no capture", n.fields)
				}
			}
		})
	}
}

func TestLinuxModuleArgumentBoundsAndIncompleteDisplay(t *testing.T) {
	for _, scenario := range []string{"count", "null-kp", "bad-stride", "overflow", "partial", "missing-scalar-type"} {
		t.Run(scenario, func(t *testing.T) {
			data, n := moduleParamFixture(8, "little", "get", true)
			table := n.e.Symbols.(*symbols.ISF)
			table.Symbols["param_get_int"] = symbols.Symbol{Address: 0x8000}
			put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
			put(0x80, 0x100)
			put(0x88, 2)
			for i := 0; i < 2; i++ {
				at := uint64(0x100 + i*32)
				put(at, 0x6000+uint64(i*32))
				put(at+8, 0x8000)
				put(at+16, 0x5000+uint64(i*4))
				copy(data[0x6000+i*32:], "p"+strconv.Itoa(i)+"\x00")
			}
			binary.LittleEndian.PutUint32(data[0x5000:], 7)
			switch scenario {
			case "count":
				put(0x88, 129)
			case "null-kp":
				put(0x80, 0)
			case "bad-stride":
				typ := table.Types["kernel_param"]
				typ.Size = 0
				table.Types["kernel_param"] = typ
			case "overflow":
				put(0x80, ^uint64(0)-16)
			case "partial":
				put(0x130, 0x30000)
			case "missing-scalar-type":
				delete(table.Bases, "int")
			}
			args, err := linuxModuleArguments(n, 0x80)
			if err == nil {
				t.Fatal("malformed parameters reported complete", args)
			}
			if scenario == "partial" && args != "p0=7" {
				t.Fatal("valid prefix lost or partial value fabricated", args, err)
			}
		})
	}
}

func TestLinuxModuleParameterGraphAndStringBudgets(t *testing.T) {
	for _, mode := range []string{"depth", "visits", "strings"} {
		t.Run(mode, func(t *testing.T) {
			data, n := moduleParamFixture(8, "little", "get", true)
			table := n.e.Symbols.(*symbols.ISF)
			table.Symbols["param_get_int"] = symbols.Symbol{Address: 0x8000}
			table.Symbols["param_array_get"] = symbols.Symbol{Address: 0x8100}
			table.Symbols["param_get_string"] = symbols.Symbol{Address: 0x8200}
			put := func(at, value uint64) { binary.LittleEndian.PutUint64(data[at:], value) }
			param := func(at, get, arg uint64) { put(at+8, get); put(at+16, arg) }
			array := func(at, count, elem uint64) { put(at, count); put(at+8, 0); put(at+16, 32); put(at+24, elem) }
			switch mode {
			case "depth":
				for i := uint64(0); i < 17; i++ {
					param(0x100+i*32, 0x8100, 0x1000+i*32)
					array(0x1000+i*32, 1, 0x100+(i+1)*32)
				}
				param(0x100+17*32, 0x8000, 0x5000)
			case "visits":
				param(0x100, 0x8100, 0x800)
				array(0x800, 32, 0x1000)
				array(0x900, 32, 0x2000)
				array(0xa00, 32, 0x3000)
				for i := uint64(0); i < 32; i++ {
					param(0x1000+i*32, 0x8100, 0x900)
					param(0x2000+i*32, 0x8100, 0xa00)
					param(0x3000+i*32, 0x8000, 0x5000)
				}
			case "strings":
				// Nine roots each visit 32 string parameters. Repeated object addresses
				// are allowed, but repeated bytes still consume the per-module budget.
				put(0x80, 0x100)
				put(0x88, 9)
				array(0x800, 32, 0x1000)
				put(0x5000, 4096)
				for i := uint64(0); i < 9; i++ {
					put(0x100+i*32, 0x6000)
					param(0x100+i*32, 0x8100, 0x800)
				}
				copy(data[0x6000:], "p\x00")
				for i := uint64(0); i < 32; i++ {
					param(0x1000+i*32, 0x8200, 0x5000)
				}
				if _, err := linuxModuleArguments(n, 0x80); err == nil {
					t.Fatal("module string budget ignored")
				}
				return
			}
			d := newLinuxParamDecoder(n)
			if _, err := d.value(0x100, 0); err == nil || d.visits > 4096 {
				t.Fatal("graph bound ignored", mode, d.visits, err)
			}
		})
	}
}

func FuzzLinuxModuleParameterGraph(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5}, uint64(0x100), uint8(0))
	f.Add(make([]byte, 64), ^uint64(0), uint8(1))
	seed := make([]byte, 2048)
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(seed[at:], value) }
	put(0x108, 0x200)
	put(0x208, 0x8100)
	put(0x110, 0x400)
	put(0x400, 1)
	put(0x410, 32)
	put(0x418, 0x100)
	f.Add(seed, uint64(0x100), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, address uint64, mode uint8) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		data, n := moduleParamFixture(8, "little", "ops", true)
		for i, h := range linuxParamIntegers {
			n.e.Symbols.(*symbols.ISF).Symbols[h.getter] = symbols.Symbol{Address: uint64(0x8000 + 16*i)}
		}
		n.e.Symbols.(*symbols.ISF).Symbols["param_array_get"] = symbols.Symbol{Address: 0x8100}
		copy(data, raw)
		if mode&1 != 0 {
			data = data[:len(raw)]
			n.e.Kernel = data
			n.e.Objects.Layer = data
		}
		_, _ = newLinuxParamDecoder(n).value(address, 0)
	})
}

func TestLinuxModuleParameterTableAbsenceHasReason(t *testing.T) {
	_, n := moduleParamFixture(8, "little", "get", true)
	delete(n.e.Symbols.(*symbols.ISF).Types["module"].Fields, "kp")
	args, err := linuxModuleArguments(n, 0x80)
	proof := n.fields["module_parameters"]
	if err != nil || args != "" || proof.Kind != "missing" || proof.Reason != "parameter_table_not_in_layout" || proof.Error != "" {
		t.Fatal(args, proof, err)
	}
}

func TestLinuxModuleParameterInclusiveBounds(t *testing.T) {
	data, n := moduleParamFixture(8, "little", "get", true)
	table := n.e.Symbols.(*symbols.ISF)
	table.Symbols["param_get_int"] = symbols.Symbol{Address: 0x8000}
	table.Symbols["param_array_get"] = symbols.Symbol{Address: 0x8100}
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(data[at:], value) }
	put(0x80, 0x100)
	put(0x88, 128)
	put(0x5000, 7)
	copy(data[0x6000:], "p\x00")
	for i := uint64(0); i < 128; i++ {
		at := 0x100 + i*32
		put(at, 0x6000)
		put(at+8, 0x8000)
		put(at+16, 0x5000)
	}
	expected := make([]string, 128)
	for i := range expected {
		expected[i] = "p=7"
	}
	if got, err := linuxModuleArguments(n, 0x80); err != nil || got != strings.Join(expected, ", ") {
		t.Fatal("128 parameters rejected", got, err)
	}
	put(0x108, 0x8100)
	put(0x110, 0x2000)
	put(0x2000, 32)
	put(0x2008, 0)
	put(0x2010, 32)
	put(0x2018, 0x3000)
	for i := uint64(0); i < 32; i++ {
		at := 0x3000 + i*32
		put(at+8, 0x8000)
		put(at+16, 0x5000)
	}
	value, err := newLinuxParamDecoder(n).value(0x100, 0)
	expected = make([]string, 32)
	for i := range expected {
		expected[i] = "7"
	}
	if err != nil || value.String() != strings.Join(expected, ",") {
		t.Fatal("32 array elements rejected", value, err)
	}
}
