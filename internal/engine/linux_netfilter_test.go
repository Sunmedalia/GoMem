package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func netfilterEngine(t *testing.T, handler uint64, fault string) *engine.Engine {
	t.Helper()
	f := modxFixture(t, "x64", "legacy", "")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 0x23000 {
		data = append(data, make([]byte, 0x23000-len(data))...)
	}
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	word := func(at uint64, v uint32) { binary.LittleEndian.PutUint32(data[at:], v) }
	ptr := symbols.TypeRef{Kind: "pointer"}
	i32 := symbols.TypeRef{Kind: "base", Name: "int"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned int"}
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	table.Bases["int"] = symbols.Type{Kind: "int", Size: 4, Endian: "little", Signed: true}
	table.Bases["unsigned int"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
	table.Bases["unsigned char"] = symbols.Type{Kind: "int", Size: 1, Endian: "little"}
	table.Types["nf_hook_ops"] = symbols.Type{Kind: "struct", Size: 48, Fields: map[string]symbols.Field{
		"list": {Offset: 0, Type: symbols.TypeRef{Kind: "struct", Name: "list_head"}},
		"hook": {Offset: 16, Type: ptr}, "owner": {Offset: 24, Type: ptr},
		"pf": {Offset: 32, Type: u8}, "hooknum": {Offset: 36, Type: u32}, "priority": {Offset: 40, Type: i32},
	}}
	inner := symbols.TypeRef{Kind: "array", Count: 8, Subtype: &symbols.TypeRef{Kind: "struct", Name: "list_head"}}
	table.Symbols["nf_hooks"] = symbols.Symbol{Address: 0x21000, Type: &symbols.TypeRef{Kind: "array", Count: 13, Subtype: &inner}}
	for i := uint64(0); i < 13*8; i++ {
		slot := uint64(0x21000) + i*16
		put(slot, slot)
		put(slot+8, slot)
	}
	// IPV4 is protocol index 2. LOCAL_IN is hook index 1: 2*8+1.
	head := uint64(0x21000 + 17*16)
	put(head, 0x22000)
	put(head+8, 0x22000)
	put(0x22000, head)
	put(0x22008, head)
	put(0x22010, handler)
	word(0x22028, 0xffffffff) // priority -1
	table.Symbols["_text"] = symbols.Symbol{Address: 0x8000}
	table.Symbols["_etext"] = symbols.Symbol{Address: 0x9000}
	table.Symbols["test_kernel_handler"] = symbols.Symbol{Address: 0x8500}
	if fault == "source" {
		delete(table.Symbols, "module_kset")
	}
	if fault == "list" {
		put(head, 0)
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
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: "x64", OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxNetfilterLegacyHooks(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		handler               uint64
		fault, hooked, module string
		failed                bool
	}{
		{"unknown", 0xffffffff81001234, "", "True", "", false},
		{"kernel", 0x8500, "", "False", "__kernel__", false},
		{"incomplete-source", 0xffffffff81001234, "source", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := netfilterEngine(t, tc.handler, tc.fault)
			var rows []evidence.Row
			var fresh, cached bytes.Buffer
			result, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "netfilter_hook" {
					rows = append(rows, row)
				}
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
				return json.NewEncoder(&fresh).Encode(row)
			}})
			if (err != nil) != tc.failed || len(rows) != 1 {
				t.Fatal(result, err, len(rows))
			}
			row := rows[0]
			if row.Cells["Proto"].String() != "IPV4" || row.Cells["Hook"].String() != "LOCAL_IN" || row.Cells["Priority"].String() != "-1" {
				t.Fatal(row)
			}
			if tc.failed {
				if row.Cells["Is Hooked"].Reason != "module_sources_incomplete" {
					t.Fatal(row)
				}
			} else {
				if row.Cells["Is Hooked"].String() != tc.hooked || tc.module != "" && row.Cells["Module"].String() != tc.module {
					t.Fatal(row)
				}
				if tc.module != "" && row.Cells["Symbol"].String() != "test_kernel_handler" {
					t.Fatal(row)
				}
				replay, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !replay.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(replay, err)
				}
			}
		})
	}
}

func TestLinuxNetfilterStopAndCorruptList(t *testing.T) {
	e := netfilterEngine(t, 0x8500, "")
	sentinel := errors.New("stop hook output")
	calls := 0
	_, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "netfilter_hook" {
			calls++
			return sentinel
		}
		return nil
	}})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = e.Run(ctx, "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "netfilter_hook" {
			calls++
			cancel()
		}
		return nil
	}})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	broken := netfilterEngine(t, 0x8500, "list")
	diagnostics := 0
	result, err := broken.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "netfilter_error" {
			diagnostics++
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || diagnostics != 1 {
		t.Fatal(result, err, diagnostics)
	}
}
