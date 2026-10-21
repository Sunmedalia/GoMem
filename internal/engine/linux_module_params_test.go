package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func moduleParamsEngine(t *testing.T, arch, layout string, broken bool) *engine.Engine {
	t.Helper()
	f := modxFixture(t, arch, "legacy", "")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned int"}
	field := func(at uint64, typ symbols.TypeRef) symbols.Field { return symbols.Field{Offset: at, Type: typ} }
	table.Bases["int"] = symbols.Type{Kind: "int", Size: 4, Signed: true, Endian: "little"}
	table.Bases["unsigned int"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
	module := table.Types["module"]
	module.Fields["kp"] = field(192, ptr)
	module.Fields["num_kp"] = field(200, u32)
	table.Types["module"] = module
	kpFields := map[string]symbols.Field{"name": field(0, ptr), "arg": field(16, ptr), "str": field(16, ptr), "arr": field(16, ptr)}
	if layout == "get" {
		kpFields["get"] = field(8, ptr)
	} else {
		kpFields["ops"] = field(8, ptr)
	}
	table.Types["kernel_param"] = symbols.Type{Kind: "struct", Size: 32, Fields: kpFields}
	table.Types["kernel_param_ops"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"get": field(8, ptr)}}
	arrayNum := ptr
	arrayNum.Subtype = &u32
	table.Types["kparam_array"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"max": field(0, u32), "num": field(8, arrayNum), "elemsize": field(16, u32), "elem": field(24, ptr)}}
	for name, at := range map[string]uint64{"param_get_int": 0x8200, "param_get_bool": 0x8220, "param_get_charp": 0x8240, "param_array_get": 0x8260} {
		table.Symbols[name] = symbols.Symbol{Address: at}
	}
	put32 := func(at uint64, value uint32) { binary.LittleEndian.PutUint32(data[at:], value) }
	pointer := func(at, value uint64) {
		if table.PointerSize() == 4 {
			put32(at, uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[at:], value)
		}
	}
	pointer(0xc4c0, 0x14000)
	put32(0xc4c8, 5)
	param := func(at, getter, arg uint64) {
		if layout == "get" {
			pointer(at+8, getter)
		} else {
			ops := 0x1e000 + at - 0x14000
			pointer(at+8, ops)
			pointer(ops+8, getter)
		}
		pointer(at+16, arg)
	}
	for i, p := range []struct {
		name     string
		get, arg uint64
	}{{"signed", 0x8200, 0x1b000}, {"toggle", 0x8220, 0x1b004}, {"label", 0x8240, 0x1b100}, {"mystery", 0xdead, 0}, {"items", 0x8260, 0x17000}} {
		at := uint64(0x14000 + i*32)
		name := uint64(0x1a000 + i*32)
		pointer(at, name)
		copy(data[name:], p.name+"\x00")
		param(at, p.get, p.arg)
	}
	put32(0x1b000, 0xffffff85)
	put32(0x1b004, 1)
	copy(data[0x1b100:], "hello\x00")
	put32(0x17000, 2)
	pointer(0x17008, 0)
	put32(0x17010, 32)
	pointer(0x17018, 0x15000)
	param(0x15000, 0x8200, 0x1b200)
	param(0x15020, 0x8220, 0x1b204)
	put32(0x1b200, 7)
	if broken {
		pointer(0x14010, 0x300000)
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func verifyModuleParameterWireCaptures(t *testing.T, e *engine.Engine, value evidence.Value) int {
	t.Helper()
	if value.Kind != "structure" {
		return 0
	}
	raw, err := json.Marshal(value.Data)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]evidence.Value
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if proof, ok := fields["Raw"]; ok {
		at, err := fields["Address"].Uint()
		if err != nil {
			t.Fatal(err)
		}
		captured, err := base64.StdEncoding.DecodeString(proof.String())
		if err != nil || len(captured) == 0 || fields["ReadComplete"].Data != true {
			t.Fatal(fields, err)
		}
		count, err := fields["CapturedBytes"].Uint()
		if err != nil || count != uint64(len(captured)) {
			t.Fatal(fields, err)
		}
		actual, err := memory.Read(context.Background(), e.Env.Kernel, at, len(captured))
		if err != nil || !bytes.Equal(captured, actual) {
			t.Fatal("parameter source differs", fields, err)
		}
		return 1
	}
	count := 0
	for _, v := range fields {
		count += verifyModuleParameterWireCaptures(t, e, v)
	}
	return count
}

func TestLinuxModuleParameterEvidenceAndCache(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"get", "ops"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := moduleParamsEngine(t, arch, layout, false)
				hidden, captures := 0, 0
				var fresh, cached bytes.Buffer
				check := func(r evidence.Row) {
					if r.Cells["RecordType"].String() != "kset_only" {
						return
					}
					hidden++
					if got := r.Cells["Load Arguments"].String(); got != "signed=-123, toggle=Y, label=hello, mystery=None, items=7,N" {
						t.Fatal(got, r)
					}
					captures += verifyModuleParameterWireCaptures(t, e, r.Cells["FieldEvidence"])
					fields := bashProofFields(t, r.Cells["FieldEvidence"])
					if fields["param_value@14000"].Kind != "int64" || fields["param_value@14000"].String() != "-123" || fields["param_value@14060"].Kind != "missing" || fields["param_value@14060"].Reason != "parameter_getter_unknown" {
						t.Fatal("parameter types lost", fields)
					}
				}
				result, err := e.Run(context.Background(), "linux.check_modules", nil, engine.RunOptions{Emit: func(r evidence.Row) error { check(r); return json.NewEncoder(&fresh).Encode(r) }})
				if err != nil || result.Task.State != "completed" || hidden != 1 || captures < 20 {
					t.Fatal(result, err, hidden, captures)
				}
				hidden, captures = 0, 0
				replay, err := e.Run(context.Background(), "linux.check_modules", nil, engine.RunOptions{Emit: func(r evidence.Row) error { check(r); return json.NewEncoder(&cached).Encode(r) }})
				if err != nil || !replay.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) || hidden != 1 || captures < 20 {
					t.Fatal(replay, err, hidden, captures)
				}
			})
		}
	}
}

func TestLinuxModuleParameterReadFailureRemainsPartial(t *testing.T) {
	e := moduleParamsEngine(t, "x64", "ops", true)
	seen := false
	result, err := e.Run(context.Background(), "linux.check_modules", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if r.Cells["RecordType"].String() != "kset_only" {
			return nil
		}
		seen = true
		if r.Cells["Load Arguments"].Kind != "missing" || r.Cells["Load Arguments"].Error == "" {
			t.Fatal("read failure displayed as clean arguments", r)
		}
		fields := bashProofFields(t, r.Cells["FieldEvidence"])
		if fields["LoadArgumentsPartial"].String() != "toggle=Y, label=hello, mystery=None, items=7,N" || fields["param_value@14000"].Error == "" {
			t.Fatal("partial evidence lost", fields)
		}
		capture := bashProofFields(t, fields["scalar@300000"])
		if capture["ReadComplete"].Data != false || capture["Error"].Error == "" {
			t.Fatal(capture)
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || !seen {
		t.Fatal(result, err, seen)
	}
	replay, err := e.Run(context.Background(), "linux.check_modules", nil, engine.RunOptions{})
	if err == nil || replay.Reused {
		t.Fatal("partial parameters cached as success", replay, err)
	}
}
