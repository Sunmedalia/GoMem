// Package testfixture creates deterministic synthetic memory, never real case data.
package testfixture

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Fixture struct {
	Image, Symbols, OS, DTB string
	KernelBase              uint64
}

func Write(dir, platform string) (Fixture, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Fixture{}, err
	}
	data := make([]byte, 128<<10)
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put(0x1000, 0x2003)
	put(0x2000, 0x3003)
	put(0x3000, 0x83)
	t := symbols.ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`)}, Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}, "u64": {Kind: "int", Size: 8, Endian: "little"}, "u32": {Kind: "int", Size: 4, Endian: "little"}, "u16": {Kind: "int", Size: 2, Endian: "little"}, "char": {Kind: "char", Size: 1, Endian: "little"}}, Types: map[string]symbols.Type{}, Symbols: map[string]symbols.Symbol{}}
	base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
	ptr := symbols.TypeRef{Kind: "pointer"}
	arr := func(n uint64) symbols.TypeRef {
		s := base("char")
		return symbols.TypeRef{Kind: "array", Count: n, Subtype: &s}
	}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: off, Type: ref} }
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	list := func(head uint64, nodes ...uint64) {
		if len(nodes) == 0 {
			put(head, head)
			put(head+8, head)
			return
		}
		put(head, nodes[0])
		put(head+8, nodes[len(nodes)-1])
		for i, a := range nodes {
			next, prev := head, head
			if i+1 < len(nodes) {
				next = nodes[i+1]
			}
			if i > 0 {
				prev = nodes[i-1]
			}
			put(a, next)
			put(a+8, prev)
		}
	}
	fixture := Fixture{Image: filepath.Join(dir, platform+".raw"), Symbols: filepath.Join(dir, platform+".json"), OS: platform, DTB: "0x1000"}
	switch platform {
	case "linux":
		banner := "Linux version 6.1.0-gomem (deterministic synthetic fixture) #1 SMP"
		copy(data[0x8000:], banner)
		t.Meta["linux"] = json.RawMessage(`{}`)
		t.Symbols["linux_banner"] = symbols.Symbol{Address: 0x8000, ConstantData: base64.StdEncoding.EncodeToString(append([]byte(banner), 0))}
		t.Symbols["init_task"] = symbols.Symbol{Address: 0x9000}
		t.Symbols["modules"] = symbols.Symbol{Address: 0xc000}
		t.Types["task_struct"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{"tasks": field(0, strct("list_head")), "pid": field(16, base("u32")), "tgid": field(20, base("u32")), "comm": field(24, arr(16)), "real_parent": field(40, ptr), "start_time": field(48, base("u64")), "mm": field(56, ptr)}}
		t.Types["list_head"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"next": field(0, ptr), "prev": field(8, ptr)}}
		t.Types["mm_struct"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"pgd": field(0, ptr)}}
		t.Types["module_layout"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"base": field(0, ptr), "size": field(8, base("u64"))}}
		t.Types["module"] = symbols.Type{Kind: "struct", Size: 96, Fields: map[string]symbols.Field{"list": field(0, strct("list_head")), "name": field(16, arr(32)), "core_layout": field(48, strct("module_layout"))}}
		list(0x9000, 0xa000, 0xb000)
		for i, a := range []uint64{0xa000, 0xb000} {
			pid := uint64(100 + i)
			binary.LittleEndian.PutUint32(data[a+16:], uint32(pid))
			binary.LittleEndian.PutUint32(data[a+20:], uint32(pid))
			if i == 0 {
				copy(data[a+24:], "init")
				put(a+40, 0x9000)
			} else {
				copy(data[a+24:], "worker")
				put(a+40, 0xa000)
			}
			put(a+48, uint64(i+1)*1000000000)
			put(a+56, 0xe000)
		}
		put(0xe000, 0x1000)
		list(0xc000, 0xd000)
		copy(data[0xd010:], "fixture_module")
		put(0xd030, 0x10000)
		put(0xd038, 4096)
	case "windows":
		fixture.KernelBase = 0x4000
		t.Meta["windows"] = json.RawMessage(`{"pdb":{"database":"ntkrnlmp.pdb","GUID":"112233445566778899AABBCCDDEEFF00","age":1,"machine_type":34404}}`)
		t.Symbols["PsActiveProcessHead"] = symbols.Symbol{Address: 0x2000}
		t.Symbols["PsLoadedModuleList"] = symbols.Symbol{Address: 0x2010}
		t.Types["_EPROCESS"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{"ActiveProcessLinks": field(0, strct("_LIST_ENTRY")), "UniqueProcessId": field(16, ptr), "InheritedFromUniqueProcessId": field(24, ptr), "ImageFileName": field(32, arr(16)), "CreateTime": field(48, base("u64")), "Pcb": field(56, strct("_KPROCESS"))}}
		t.Types["_LIST_ENTRY"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Flink": field(0, ptr), "Blink": field(8, ptr)}}
		t.Types["_KPROCESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DirectoryTableBase": field(0, base("u64"))}}
		t.Types["_KLDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"InLoadOrderLinks": field(0, strct("_LIST_ENTRY")), "DllBase": field(16, ptr), "SizeOfImage": field(24, base("u32")), "BaseDllName": field(32, strct("_UNICODE_STRING"))}}
		t.Types["_UNICODE_STRING"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": field(0, base("u16")), "MaximumLength": field(2, base("u16")), "Buffer": field(8, ptr)}}
		copy(data[0x4000:], "MZ")
		binary.LittleEndian.PutUint32(data[0x403c:], 0x80)
		copy(data[0x4080:], "PE\x00\x00")
		binary.LittleEndian.PutUint16(data[0x4094:], 240)
		binary.LittleEndian.PutUint16(data[0x4098:], 0x20b)
		binary.LittleEndian.PutUint32(data[0x4098+108:], 16)
		binary.LittleEndian.PutUint32(data[0x4098+112+48:], 0x300)
		binary.LittleEndian.PutUint32(data[0x4098+112+52:], 28)
		cv := append([]byte("RSDS"), []byte{0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0}...)
		cv = append(cv, 1, 0, 0, 0)
		cv = append(cv, []byte("ntkrnlmp.pdb\x00")...)
		copy(data[0x4400:], cv)
		binary.LittleEndian.PutUint32(data[0x430c:], 2)
		binary.LittleEndian.PutUint32(data[0x4310:], uint32(len(cv)))
		binary.LittleEndian.PutUint32(data[0x4314:], 0x400)
		list(0x6000, 0x8000, 0x9000)
		for i, a := range []uint64{0x8000, 0x9000} {
			put(a+16, uint64(4+i*100))
			if i == 0 {
				copy(data[a+32:], "System")
			} else {
				copy(data[a+32:], "worker.exe")
				put(a+24, 4)
			}
			put(a+48, 133000000000000000+uint64(i)*10000000)
			put(a+56, 0x1000)
		}
		list(0x6010, 0xa000)
		put(0xa010, 0x4000)
		binary.LittleEndian.PutUint32(data[0xa018:], 0x10000)
		name := "ntoskrnl.exe"
		binary.LittleEndian.PutUint16(data[0xa020:], uint16(len(name)*2))
		binary.LittleEndian.PutUint16(data[0xa022:], uint16(len(name)*2))
		put(0xa028, 0xb000)
		for i, c := range name {
			binary.LittleEndian.PutUint16(data[0xb000+i*2:], uint16(c))
		}
	default:
		return Fixture{}, os.ErrInvalid
	}
	copy(data[0x18000:], "gomem-test-ioc\x00")
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return Fixture{}, err
	}
	if err = os.WriteFile(fixture.Image, data, 0600); err != nil {
		return Fixture{}, err
	}
	if err = os.WriteFile(fixture.Symbols, b, 0600); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}
