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
		t.Bases["i64"] = symbols.Type{Kind: "int", Size: 8, Endian: "little", Signed: true}
		banner := "Linux version 6.1.0-gomem (deterministic synthetic fixture) #1 SMP"
		copy(data[0x8000:], banner)
		t.Meta["linux"] = json.RawMessage(`{}`)
		t.Symbols["linux_banner"] = symbols.Symbol{Address: 0x8000, ConstantData: base64.StdEncoding.EncodeToString(append([]byte(banner), 0))}
		t.Symbols["init_top_pgt"] = symbols.Symbol{Address: 0x1000}
		t.Symbols["init_task"] = symbols.Symbol{Address: 0x9000}
		t.Symbols["modules"] = symbols.Symbol{Address: 0xc000}
		t.Types["task_struct"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{"tasks": field(0, strct("list_head")), "pid": field(16, base("u32")), "tgid": field(20, base("u32")), "comm": field(24, arr(16)), "real_parent": field(40, ptr), "start_time": field(48, base("u64")), "mm": field(56, ptr)}}
		t.Types["list_head"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"next": field(0, ptr), "prev": field(8, ptr)}}
		t.Types["mm_struct"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"pgd": field(0, ptr), "mmap": field(8, ptr), "start_brk": field(16, base("u64")), "brk": field(24, base("u64")), "start_stack": field(32, base("u64")), "context": field(40, strct("mm_context_t"))}}
		t.Types["mm_context_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"vdso": field(0, ptr)}}
		task := t.Types["task_struct"]
		task.Fields["fs"] = field(64, ptr)
		t.Types["task_struct"] = task
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
		t.Symbols["simple_dname"] = symbols.Symbol{Address: 0x8100}
		t.Types["vm_area_struct"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"vm_start": field(0, ptr), "vm_end": field(8, ptr), "vm_next": field(16, ptr), "vm_prev": field(24, ptr), "vm_mm": field(32, ptr), "vm_flags": field(40, base("u64")), "vm_pgoff": field(48, base("u64")), "vm_file": field(56, ptr)}}
		t.Types["path"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"dentry": field(0, ptr), "mnt": field(8, ptr)}}
		t.Types["file"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"f_path": field(0, strct("path"))}}
		t.Types["fs_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"root": field(0, strct("path"))}}
		t.Types["qstr"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"len": field(0, base("u32")), "name": field(8, ptr)}}
		t.Types["dentry"] = symbols.Type{Kind: "struct", Size: 48, Fields: map[string]symbols.Field{"d_parent": field(0, ptr), "d_name": field(8, strct("qstr")), "d_inode": field(24, ptr), "d_op": field(32, ptr)}}
		t.Types["dentry_operations"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"d_dname": field(0, ptr)}}
		t.Types["vfsmount"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"mnt_root": field(0, ptr), "mnt_parent": field(8, ptr), "mnt_mountpoint": field(16, ptr)}}
		t.Types["inode"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"i_ino": field(0, base("u64")), "i_nlink": field(8, base("u32")), "i_sb": field(16, ptr), "i_size": field(24, base("i64"))}}
		t.Types["super_block"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"s_dev": field(0, base("u32"))}}
		put(0xa040, 0x16000)
		put(0xb040, 0x16000)
		put(0xe008, 0x10000)
		put(0xe010, 0x600000)
		put(0xe018, 0x600800)
		put(0xe020, 0x900800)
		put(0xe028, 0xa00000)
		for i, address := range []uint64{0x10000, 0x11000, 0x12000, 0x12100} {
			starts := []uint64{0x400000, 0x600000, 0x700000, 0x800000}
			put(address, starts[i])
			put(address+8, starts[i]+4096)
			put(address+32, 0xe000)
			if i < 3 {
				put(address+16, []uint64{0x11000, 0x12000, 0x12100}[i])
			}
			if i > 0 {
				put(address+24, []uint64{0x10000, 0x11000, 0x12000}[i-1])
			}
			put(address+40, []uint64{5, 7, 1, 1}[i])
			put(address+56, []uint64{0x13000, 0, 0x13100, 0x13100}[i])
		}
		put(0x12100+48, 2)
		put(0x13000, 0x14000)
		put(0x13008, 0x15000)
		put(0x13100, 0x14100)
		put(0x13108, 0x15000)
		put(0x15000, 0x17000)
		put(0x15008, 0x15000)
		put(0x15010, 0x17000)
		put(0x16000, 0x17000)
		put(0x16008, 0x15000)
		for _, entry := range []struct {
			address, parent, inode, buffer uint64
			name                           string
		}{{0x14000, 0x17000, 0x18200, 0x19000, "memfd:payload"}, {0x14100, 0x14200, 0x18100, 0x19040, "libfoo.so"}, {0x14200, 0x17000, 0, 0x19080, "lib"}, {0x17000, 0x17000, 0, 0x190c0, "/"}} {
			put(entry.address, entry.parent)
			binary.LittleEndian.PutUint32(data[entry.address+8:], uint32(len(entry.name)))
			put(entry.address+16, entry.buffer)
			put(entry.address+24, entry.inode)
			copy(data[entry.buffer:], entry.name)
		}
		put(0x14020, 0x1a000)
		put(0x1a000, 0x8100)
		for i, address := range []uint64{0x18200, 0x18100} {
			put(address, 123+uint64(i))
			put(address+8, uint64(i))
			put(address+16, 0x1b000)
			put(address+24, 4096)
		}
		binary.LittleEndian.PutUint32(data[0x1b000:], 8<<20|1)
	case "windows":
		fixture.KernelBase = 0x4000
		t.Meta["windows"] = json.RawMessage(`{"pdb":{"database":"ntkrnlmp.pdb","GUID":"112233445566778899AABBCCDDEEFF00","age":1,"machine_type":34404}}`)
		t.Symbols["PsActiveProcessHead"] = symbols.Symbol{Address: 0x2000}
		t.Symbols["PsLoadedModuleList"] = symbols.Symbol{Address: 0x2010}
		t.Symbols["MmProtectToValue"] = symbols.Symbol{Address: 0x2200}
		for i, protection := range []uint32{1, 2, 16, 32, 4, 8, 64, 128} {
			binary.LittleEndian.PutUint32(data[0x6200+i*4:], protection)
		}
		t.Types["_LARGE_INTEGER"] = symbols.Type{Kind: "union", Size: 8, Fields: map[string]symbols.Field{"QuadPart": field(0, base("u64"))}}
		t.Types["_EPROCESS"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{"ActiveProcessLinks": field(0, strct("_LIST_ENTRY")), "UniqueProcessId": field(16, ptr), "InheritedFromUniqueProcessId": field(24, ptr), "ImageFileName": field(32, arr(16)), "CreateTime": field(48, symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}), "Pcb": field(56, strct("_KPROCESS")), "ThreadListHead": field(64, strct("_LIST_ENTRY")), "VadRoot": field(80, strct("_RTL_AVL_TREE"))}}
		t.Types["_LIST_ENTRY"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Flink": field(0, ptr), "Blink": field(8, ptr)}}
		t.Types["_KPROCESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DirectoryTableBase": field(0, base("u64"))}}
		processType := t.Types["_EPROCESS"]
		processType.Size = 144
		processType.Fields["Peb"] = field(88, ptr)
		processType.Fields["WoW64Process"] = field(96, ptr)
		processType.Fields["ActiveThreads"] = field(104, base("u32"))
		processType.Fields["ExitTime"] = field(112, symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"})
		processType.Fields["ObjectTable"] = field(120, ptr)
		processType.Fields["Session"] = field(128, ptr)
		t.Types["_EPROCESS"] = processType
		t.Types["_PEB"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"Ldr": field(0, ptr), "ImageBaseAddress": field(8, ptr), "ProcessParameters": field(16, ptr)}}
		t.Types["_RTL_USER_PROCESS_PARAMETERS"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"CommandLine": field(0, strct("_UNICODE_STRING"))}}
		t.Types["_HANDLE_TABLE"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"HandleCount": field(0, base("u32"))}}
		t.Types["_MM_SESSION_SPACE"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"SessionId": field(0, base("u32"))}}
		t.Types["_PEB_LDR_DATA"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"InLoadOrderModuleList": field(0, strct("_LIST_ENTRY"))}}
		t.Types["_LDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 96, Fields: map[string]symbols.Field{"InLoadOrderLinks": field(0, strct("_LIST_ENTRY")), "DllBase": field(16, ptr), "SizeOfImage": field(24, base("u32")), "BaseDllName": field(32, strct("_UNICODE_STRING")), "FullDllName": field(48, strct("_UNICODE_STRING")), "ObsoleteLoadCount": field(64, base("u16")), "LoadTime": field(72, symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"})}}
		t.Types["_EWOW64PROCESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Peb": field(0, ptr)}}
		t.Types["_KLDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"InLoadOrderLinks": field(0, strct("_LIST_ENTRY")), "DllBase": field(16, ptr), "SizeOfImage": field(24, base("u32")), "BaseDllName": field(32, strct("_UNICODE_STRING")), "FullDllName": field(48, strct("_UNICODE_STRING"))}}
		t.Types["_UNICODE_STRING"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": field(0, base("u16")), "MaximumLength": field(2, base("u16")), "Buffer": field(8, ptr)}}
		copy(data[0x4000:], "MZ")
		binary.LittleEndian.PutUint32(data[0x403c:], 0x80)
		copy(data[0x4080:], "PE\x00\x00")
		binary.LittleEndian.PutUint16(data[0x4084:], 0x8664)
		binary.LittleEndian.PutUint16(data[0x4094:], 240)
		binary.LittleEndian.PutUint16(data[0x4098:], 0x20b)
		binary.LittleEndian.PutUint32(data[0x4098+32:], 0x1000)
		binary.LittleEndian.PutUint32(data[0x4098+36:], 0x200)
		binary.LittleEndian.PutUint32(data[0x4098+56:], 0x10000)
		binary.LittleEndian.PutUint32(data[0x4098+60:], 0x1000)
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
			binary.LittleEndian.PutUint32(data[a+104:], uint32(2-i))
			put(a+120, 0x1a000+uint64(i)*16)
			binary.LittleEndian.PutUint32(data[0x1a000+i*16:], uint32(10+i*10))
		}
		put(0x9080, 0x1a100)
		binary.LittleEndian.PutUint32(data[0x1a100:], 1)
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
		modulePath := `\SystemRoot\system32\ntoskrnl.exe`
		binary.LittleEndian.PutUint16(data[0xa030:], uint16(len(modulePath)*2))
		binary.LittleEndian.PutUint16(data[0xa032:], uint16(len(modulePath)*2))
		put(0xa038, 0xb100)
		for i, c := range modulePath {
			binary.LittleEndian.PutUint16(data[0xb100+i*2:], uint16(c))
		}
		t.Types["_CLIENT_ID"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"UniqueProcess": field(0, ptr), "UniqueThread": field(8, ptr)}}
		t.Types["_ETHREAD"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{"ThreadListEntry": field(0, strct("_LIST_ENTRY")), "Cid": field(16, strct("_CLIENT_ID")), "StartAddress": field(32, ptr), "Win32StartAddress": field(40, ptr), "CreateTime": field(48, symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}), "ExitTime": field(56, symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"})}}
		list(0x8040, 0x12000, 0x13000)
		list(0x9040, 0x14000)
		for i, a := range []uint64{0x12000, 0x13000, 0x14000} {
			pid, tid, start := uint64(4), uint64(8+i*4), uint64(0x4010)
			if i == 2 {
				pid, tid, start = 104, 108, 0x700010
			}
			put(a+16, pid)
			put(a+24, tid)
			put(a+32, start)
			put(a+40, start+16)
			put(a+48, 133000000000000000+uint64(i)*10000000+1234567)
		}
		t.Types["_RTL_AVL_TREE"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Root": field(0, ptr)}}
		t.Types["_RTL_BALANCED_NODE"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"Left": field(0, ptr), "Right": field(8, ptr), "ParentValue": field(16, base("u64"))}}
		t.Types["_MMVAD_SHORT"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"VadNode": field(0, strct("_RTL_BALANCED_NODE")), "StartingVpn": field(24, base("u32")), "EndingVpn": field(28, base("u32")), "StartingVpnHigh": field(32, base("char")), "EndingVpnHigh": field(33, base("char"))}}
		bitBase := base("u32")
		bits := func(position, length uint64) symbols.TypeRef {
			return symbols.TypeRef{Kind: "bitfield", BitType: &bitBase, BitPosition: position, BitLength: length}
		}
		t.Types["_MMVAD_FLAGS"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"Protection": field(0, bits(7, 5)), "PrivateMemory": field(0, bits(20, 1))}}
		t.Types["_MMVAD_FLAGS1"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"CommitCharge": field(0, bits(0, 31))}}
		t.Types["_VAD_U"] = symbols.Type{Kind: "union", Size: 4, Fields: map[string]symbols.Field{"VadFlags": field(0, strct("_MMVAD_FLAGS"))}}
		t.Types["_VAD_U1"] = symbols.Type{Kind: "union", Size: 4, Fields: map[string]symbols.Field{"VadFlags1": field(0, strct("_MMVAD_FLAGS1"))}}
		short := t.Types["_MMVAD_SHORT"]
		short.Fields["u"] = field(48, symbols.TypeRef{Kind: "union", Name: "_VAD_U"})
		short.Fields["u1"] = field(52, symbols.TypeRef{Kind: "union", Name: "_VAD_U1"})
		short.Fields["CommitChargeHigh"] = field(34, base("char"))
		t.Types["_MMVAD_SHORT"] = short
		t.Types["_MMVAD"] = symbols.Type{Kind: "struct", Size: 80, Fields: map[string]symbols.Field{"Core": field(0, strct("_MMVAD_SHORT")), "Subsection": field(64, ptr)}}
		t.Types["_SUBSECTION"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"ControlArea": field(0, ptr)}}
		t.Types["_EX_FAST_REF"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Value": field(0, base("u64"))}}
		t.Types["_CONTROL_AREA"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"FilePointer": field(0, strct("_EX_FAST_REF"))}}
		t.Types["_FILE_OBJECT"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"FileName": field(0, strct("_UNICODE_STRING"))}}
		put(0x9050, 0x15000)
		put(0x15008, 0x16000)
		put(0x16010, 0x15001)
		binary.LittleEndian.PutUint32(data[0x15018:], 0x700)
		binary.LittleEndian.PutUint32(data[0x1501c:], 0x70f)
		binary.LittleEndian.PutUint32(data[0x16018:], 0x900)
		binary.LittleEndian.PutUint32(data[0x1601c:], 0x90f)
		copy(data[0x15000-12:], "Vad ")
		copy(data[0x16000-12:], "VadS")
		binary.LittleEndian.PutUint32(data[0x15030:], 3<<7)
		binary.LittleEndian.PutUint32(data[0x16030:], 6<<7|1<<20)
		binary.LittleEndian.PutUint32(data[0x15034:], 16)
		binary.LittleEndian.PutUint32(data[0x16034:], 16)
		put(0x15040, 0x17000)
		put(0x17000, 0x17100)
		put(0x17100, 0x17203)
		fileName := `\Device\HarddiskVolume1\worker.exe`
		binary.LittleEndian.PutUint16(data[0x17200:], uint16(len(fileName)*2))
		binary.LittleEndian.PutUint16(data[0x17202:], uint16(len(fileName)*2))
		put(0x17208, 0x17400)
		for i, c := range fileName {
			binary.LittleEndian.PutUint16(data[0x17400+i*2:], uint16(c))
		}
		put(0x9058, 0x1b000)
		put(0x1b000, 0x1b100)
		put(0x1b008, 0x4000)
		put(0x1b010, 0x1e100)
		commandLine := `"C:\Windows\worker.exe" --flag sample`
		binary.LittleEndian.PutUint16(data[0x1e100:], uint16(len(commandLine)*2))
		binary.LittleEndian.PutUint16(data[0x1e102:], uint16(len(commandLine)*2+2))
		put(0x1e108, 0x1e200)
		for i, c := range commandLine {
			binary.LittleEndian.PutUint16(data[0x1e200+i*2:], uint16(c))
		}
		list(0x1b100, 0x1c000, 0x1c100)
		for i, a := range []uint64{0x1c000, 0x1c100} {
			put(a+16, 0x400000+uint64(i)*0x100000)
			binary.LittleEndian.PutUint32(data[a+24:], 4096)
			binary.LittleEndian.PutUint16(data[a+64:], 0xffff)
			put(a+72, 133000000001234567+uint64(i)*10000000)
			name := []string{"worker.exe", "example.dll"}[i]
			full := `C:\Windows\System32\` + name
			for _, text := range []struct {
				offset, buffer uint64
				value          string
			}{{32, 0x1d000 + uint64(i)*0x400, name}, {48, 0x1d100 + uint64(i)*0x400, full}} {
				binary.LittleEndian.PutUint16(data[a+text.offset:], uint16(len(text.value)*2))
				binary.LittleEndian.PutUint16(data[a+text.offset+2:], uint16(len(text.value)*2))
				put(a+text.offset+8, text.buffer)
				for j, c := range text.value {
					binary.LittleEndian.PutUint16(data[text.buffer+uint64(j)*2:], uint16(c))
				}
			}
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
