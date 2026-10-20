package registry

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestKernelMappedHiveAndBigData(t *testing.T) {
	k := newRAM("kernel")
	const (
		hive = 0xffff800000001000
		base = 0xffff800000002000
		dir  = 0xffff800000003000
		tab  = 0xffff800000004000
		bin  = 0xffff800000005000
		vdir = 0xffff800000007000
		vtab = 0xffff800000008000
		vbin = 0xffff800000006000
		bbin = 0xffff80000000a000
		cbin = 0xffff800000020000
	)
	off := testOffsets()
	putU32(k, hive, hiveSignature)
	putU64(k, hive+off.BaseBlock, base)
	putU32(k, hive+off.Version, 5)
	putU32(k, hive+off.Storage+off.Length, 0x10000)
	putU64(k, hive+off.Storage+off.Map, dir)
	putU32(k, hive+off.Storage+off.DualSize+off.Length, 0x10000)
	putU64(k, hive+off.Storage+off.DualSize+off.Map, vdir)
	copyAt(k, base, []byte("regf"))
	putU32(k, base+36, 0x40)
	putU64(k, dir, tab)
	putU64(k, tab+off.Permanent, bin)
	putU64(k, vdir, vtab)
	putU64(k, vtab+off.Permanent, vbin)
	putCell(k, bin, 0x40, nk("ROOT", 0x24, 133000000000000000, 1, 0x100, 1, 0x80000040, 1, 0x180))
	putCell(k, bin, 0x100, lf(0x140))
	putCell(k, bin, 0x140, nk("Run", 0x20, 133000000100000000, 0, 0, 0, 0, 0, 0))
	putCell(k, bin, 0x180, u32s(0x1c0))
	putCell(k, bin, 0x1c0, vk("Version", 4, 0, []byte{2, 0, 0, 0}))
	putCell(k, vbin, 0x40, lf(0x80000080))
	putCell(k, vbin, 0x80, nk("Current", 0x21, 133000000200000000, 0, 0, 0, 0, 0, 0))
	wide := utf16.Encode([]rune("软件"))
	wideBytes := make([]byte, len(wide)*2)
	for i, u := range wide {
		binary.LittleEndian.PutUint16(wideBytes[i*2:], u)
	}
	putCell(k, bin, 0xe00, nkRaw(0, 133000000300000000, wideBytes, 0, 0, 0, 0, 0, 0))

	h, err := Open(context.Background(), k, nil, hive, `\REGISTRY\MACHINE\SYSTEM`, off)
	if err != nil || h.RootFrom != "base_block" || h.Root != 0x40 || h.Version != 5 {
		t.Fatal(h, err)
	}
	root, err := h.RootKey(context.Background())
	if err != nil || root.Name != "ROOT" {
		t.Fatal(root, err)
	}
	subs, err := h.Subkeys(context.Background(), root)
	if err != nil || len(subs) != 2 || subs[0].Name != "Run" || subs[0].Volatile || !subs[1].Volatile || subs[1].Name != "Current" {
		t.Fatal(subs, err)
	}
	values, err := h.Values(context.Background(), root)
	if err != nil || len(values) != 1 || values[0].Name != "Version" || values[0].Type != 4 || string(values[0].Data) != "\x02\x00\x00\x00" || values[0].DataErr != nil || values[0].Volatile {
		t.Fatal(values, err)
	}
	decoded, err := h.key(context.Background(), 0xe00)
	if err != nil || decoded.Name != "软件" {
		t.Fatal(decoded, err)
	}

	raw := bytesRepeat(0x41, 0x4001)
	putU64(k, tab+off.EntrySize+off.Permanent, bbin)
	putU64(k, tab+2*off.EntrySize+off.Permanent, cbin)
	putBig(k, bbin, cbin)
	putCell(k, bin, 0x40, nk("ROOT", 0x24, 133000000000000000, 1, 0x100, 1, 0x80000040, 2, 0x180))
	putCell(k, bin, 0x180, u32s(0x1c0, 0x240))
	putCell(k, bin, 0x240, vk("Blob", 3, 0x4001, nil))
	binary.LittleEndian.PutUint32(k.page(bin)[(0x240+4+8)&0xfff:], 0x1000)
	root, err = h.RootKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values, err = h.Values(context.Background(), root)
	if err != nil || len(values) != 2 || values[1].Name != "Blob" || values[1].DataErr != nil || string(values[1].Data) != string(raw) {
		got := ""
		if len(values) > 1 {
			got = values[1].Name
			if values[1].DataErr != nil {
				t.Fatal(values[1].DataErr)
			}
		}
		t.Fatal(len(values), got, err)
	}
}

func TestUserBinRequiresProcessLayer(t *testing.T) {
	k, proc := newRAM("kernel"), newRAM("registry")
	const (
		hive = 0xffff800000001000
		dir  = 0xffff800000003000
		tab  = 0xffff800000004000
		bin  = 0x2000
	)
	off := testOffsets()
	putU32(k, hive, hiveSignature)
	putU64(k, hive+off.BaseBlock, 0)
	putU32(k, hive+off.Version, 1)
	putU32(k, hive+off.Storage+off.Length, 0x1000)
	putU64(k, hive+off.Storage+off.Map, dir)
	putU64(k, hive+off.Storage+off.DualSize+off.Map, dir)
	putU64(k, dir, tab)
	putU64(k, tab+off.Permanent, bin)
	putCell(proc, bin, 0x20, nk("ROOT", 0x24, 100000000, 0, 0, 0, 0, 0, 0))
	h, err := Open(context.Background(), k, nil, hive, "SYSTEM", off)
	if err != nil || h.RootFrom != "fallback" || h.Root != rootFallback {
		t.Fatal(h, err)
	}
	_, err = h.RootKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "registry process layer is required") {
		t.Fatal(err)
	}
	putCell(k, bin, 0x20, nk("HIDDEN", 0x24, 100000000, 0, 0, 0, 0, 0, 0))
	if _, err = h.RootKey(context.Background()); err == nil {
		t.Fatal("kernel bytes were accepted for a user bin")
	}
	h, err = Open(context.Background(), k, proc, hive, "SYSTEM", off)
	if err != nil {
		t.Fatal(err)
	}
	root, err := h.RootKey(context.Background())
	if err != nil || root.Name != "ROOT" {
		t.Fatal(root, err)
	}
}

func testOffsets() Offsets {
	return Offsets{BaseBlock: 8, Storage: 24, Version: 16, DualSize: 16, Length: 0, Map: 8, EntrySize: 16, BlockOffset: 0, Permanent: 8, BlockWidth: 8, PermanentWidth: 8, PointerSize: 8}
}

type ram struct {
	name  string
	pages map[uint64][]byte
}

func newRAM(name string) *ram { return &ram{name: name, pages: map[uint64][]byte{}} }
func (r *ram) Name() string   { return r.name }
func (r *ram) Ranges() []memory.Range {
	return nil
}
func (r *ram) ReadAt(_ context.Context, p []byte, addr uint64) (int, error) {
	for i := range p {
		a := addr + uint64(i)
		page := r.pages[a&^0xfff]
		if page == nil {
			return i, io.ErrUnexpectedEOF
		}
		p[i] = page[a&0xfff]
	}
	return len(p), nil
}
func (r *ram) page(addr uint64) []byte {
	base := addr &^ 0xfff
	if r.pages[base] == nil {
		r.pages[base] = make([]byte, 4096)
	}
	return r.pages[base]
}
func putU32(r *ram, addr uint64, v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	copyAt(r, addr, buf[:])
}
func putU64(r *ram, addr uint64, v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	copyAt(r, addr, buf[:])
}
func copyAt(r *ram, addr uint64, b []byte) {
	for i, v := range b {
		a := addr + uint64(i)
		r.page(a)[a&0xfff] = v
	}
}
func putCell(r *ram, bin uint64, index int, payload []byte) {
	total := len(payload) + 4
	if total%8 != 0 {
		total += 8 - total%8
	}
	addr := bin + uint64(index)
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(-int32(total)))
	copyAt(r, addr, hdr[:])
	copyAt(r, addr+4, payload)
	if pad := total - 4 - len(payload); pad > 0 {
		copyAt(r, addr+4+uint64(len(payload)), make([]byte, pad))
	}
}
func nk(name string, flags uint16, stamp uint64, stable, stableList, volatile, volatileList, values, valueList uint32) []byte {
	return nkRaw(flags|keyCompressed, stamp, []byte(name), stable, stableList, volatile, volatileList, values, valueList)
}
func nkRaw(flags uint16, stamp uint64, raw []byte, stable, stableList, volatile, volatileList, values, valueList uint32) []byte {
	buf := make([]byte, 76+len(raw))
	copy(buf, "nk")
	binary.LittleEndian.PutUint16(buf[2:], flags)
	binary.LittleEndian.PutUint64(buf[4:], stamp)
	binary.LittleEndian.PutUint32(buf[20:], stable)
	binary.LittleEndian.PutUint32(buf[24:], volatile)
	binary.LittleEndian.PutUint32(buf[28:], stableList)
	binary.LittleEndian.PutUint32(buf[32:], volatileList)
	binary.LittleEndian.PutUint32(buf[36:], values)
	binary.LittleEndian.PutUint32(buf[40:], valueList)
	binary.LittleEndian.PutUint16(buf[72:], uint16(len(raw)))
	copy(buf[76:], raw)
	return buf
}
func lf(child uint32) []byte {
	buf := make([]byte, 12)
	copy(buf, "lf")
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], child)
	return buf
}
func u32s(values ...uint32) []byte {
	buf := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	return buf
}
func vk(name string, typ, dataLen uint32, inline []byte) []byte {
	buf := make([]byte, 20+len(name))
	copy(buf, "vk")
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(name)))
	length := dataLen
	if inline != nil {
		length = 0x80000000 | uint32(len(inline))
		copy(buf[8:12], inline)
	}
	binary.LittleEndian.PutUint32(buf[4:], length)
	binary.LittleEndian.PutUint32(buf[12:], typ)
	binary.LittleEndian.PutUint16(buf[16:], valueCompressed)
	copy(buf[20:], name)
	return buf
}
func putBig(r *ram, block0, block1 uint64) {
	raw := bytesRepeat(0x41, 0x4001)
	db := make([]byte, 8)
	copy(db, "db")
	binary.LittleEndian.PutUint16(db[2:], 2)
	binary.LittleEndian.PutUint32(db[4:], 0x1040)
	putCell(r, block0, 0, db)
	// The db node is cell index 0x1000 (table 1, suboffset 0). Its list field
	// points at 0x1040, still in this bin, and the two payload words name the
	// data blocks 0x1080 and 0x2000.
	list := u32s(0x1080, 0x2000)
	putCell(r, block0, 0x40, list)
	putCell(r, block0, 0x80, raw[:bigDataBlock])
	putCell(r, block1, 0, raw[bigDataBlock:])
}
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
