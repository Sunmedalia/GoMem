package registry

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestSAMVectorsMatchPinnedBaseline(t *testing.T) {
	boot := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	rev2 := mustHex(t, "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101112131415161718191a1b1c1d1e1fd8b83b5b1bec4c13a2cc1707a29c6a95a8d64fb0382cf931228bc83e0e2a589f00000000000000000000000000000000")
	hboot32 := mustHex(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	got, err := hbootFromF(rev2, boot)
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(hboot32) {
		t.Fatal(hex.EncodeToString(got), err)
	}
	nt, err := decryptRC4Hash(500, hboot32, mustHex(t, "56bec0b534daae1664b37e3f9d8a46de"), antpassword)
	if err != nil || hex.EncodeToString(nt) != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatal(hex.EncodeToString(nt), err)
	}
	lm, err := decryptRC4Hash(500, hboot32, mustHex(t, "0c6e751e3e4b2184647f8903940f8f6a"), almpassword)
	if err != nil || hex.EncodeToString(lm) != "e52cac67419a9a224a3b108f3fa6cb6d" {
		t.Fatal(hex.EncodeToString(lm), err)
	}
	rev3 := mustHex(t, "030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303132333435363738393a3b3c3d3e3f954f64f2e4e86e9eee82d2021668489932d99425710d2b63e6232688d7c8945a0000000000000000")
	hboot16 := mustHex(t, "202122232425262728292a2b2c2d2e2f")
	got, err = hbootFromF(rev3, boot)
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(hboot16) {
		t.Fatal(hex.EncodeToString(got), err)
	}
	salted, err := decryptAESHash(500, hboot16, mustHex(t, "d611c3a648b16ccf79ff954020a03bb26bfe30b60fb489d672d469b54fcbc7ca"), mustHex(t, "404142434445464748494a4b4c4d4e4f"))
	if err != nil || hex.EncodeToString(salted) != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatal(hex.EncodeToString(salted), err)
	}
	if _, err = hbootFromF([]byte{9}, boot); err == nil || !strings.Contains(err.Error(), "revision 9") {
		t.Fatal(err)
	}
}

func TestDumpSAMDecryptsSaltedHashAndRejectsMissingClass(t *testing.T) {
	k := newRAM("kernel")
	off := testOffsets()
	rev3 := mustHex(t, "030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303132333435363738393a3b3c3d3e3f954f64f2e4e86e9eee82d2021668489932d99425710d2b63e6232688d7c8945a0000000000000000")
	sys := mountTestHive(k, 0xffff800000001000, 0xffff800000002000, 0xffff800000003000, 0xffff800000004000, 0xffff800000100000)
	jd := sys.addKey("JD", utf16Bytes("080a0307"), nil)
	skew := sys.addKey("Skew1", utf16Bytes("0201090f"), nil)
	gbg := sys.addKey("GBG", utf16Bytes("00050d04"), nil)
	dataKey := sys.addKey("Data", utf16Bytes("0b060c0e"), nil)
	lsa := sys.addKey("Lsa", nil, nil, jd, skew, gbg, dataKey)
	control := sys.addKey("Control", nil, nil, lsa)
	set := sys.addKey("ControlSet001", nil, nil, control)
	sys.finish(sys.addKey("ROOT", nil, nil, set))

	sam := mountTestHive(k, 0xffff800000010000, 0xffff800000011000, 0xffff800000012000, 0xffff800000013000, 0xffff800000200000)
	user := sam.addKey("000001F4", nil, []hiveValue{{"V", saltedUserV()}})
	names := sam.addKey("Names", nil, nil)
	usersKey := sam.addKey("Users", nil, nil, names, user)
	account := sam.addKey("Account", nil, []hiveValue{{"F", rev3}}, usersKey)
	domains := sam.addKey("Domains", nil, nil, account)
	sam.finish(sam.addKey("ROOT", nil, nil, sam.addKey("SAM", nil, nil, domains)))

	system, err := Open(context.Background(), k, nil, 0xffff800000001000, "SYSTEM", off)
	if err != nil {
		t.Fatal(err)
	}
	samHive, err := Open(context.Background(), k, nil, 0xffff800000010000, "SAM", off)
	if err != nil {
		t.Fatal(err)
	}
	usersOut, err := DumpSAM(context.Background(), system, samHive)
	if err != nil || len(usersOut) != 1 {
		t.Fatal(usersOut, err)
	}
	got := usersOut[0]
	if !got.NameKnown || got.Name != "Ada" || got.RID != 500 || got.LM != "aad3b435b51404eeaad3b435b51404ee" || got.NT != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatal(got)
	}
	if _, err = DumpSAM(context.Background(), nil, samHive); err == nil || !strings.Contains(err.Error(), "SYSTEM") {
		t.Fatal(err)
	}

	broken := mountTestHive(k, 0xffff800000030000, 0xffff800000031000, 0xffff800000032000, 0xffff800000033000, 0xffff800000300000)
	dangling := broken.alloc(nkClass("JD", 0, 0, 0, 0, 0, 0, 0x00f000, 16))
	lsa = broken.addKey("Lsa", nil, nil, dangling, broken.addKey("Skew1", utf16Bytes("0201090f"), nil), broken.addKey("GBG", utf16Bytes("00050d04"), nil), broken.addKey("Data", utf16Bytes("0b060c0e"), nil))
	broken.finish(broken.addKey("ROOT", nil, nil, broken.addKey("ControlSet001", nil, nil, broken.addKey("Control", nil, nil, lsa))))
	bad, err := Open(context.Background(), k, nil, 0xffff800000030000, "SYSTEM", off)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DumpSAM(context.Background(), bad, samHive); err == nil || !strings.Contains(err.Error(), "JD") {
		t.Fatal(err)
	}
}

func TestClassCellStaysInsideItsCell(t *testing.T) {
	k := newRAM("kernel")
	h := mountTestHive(k, 0xffff800000001000, 0xffff800000002000, 0xffff800000003000, 0xffff800000004000, 0xffff800000100000)
	class := h.alloc(append([]byte("ABCDEFGH"), []byte("XXXX")...))
	h.finish(h.alloc(nkClass("ROOT", 0, 0, 0, 0, 0, 0, class, 8)))
	hive, err := Open(context.Background(), k, nil, 0xffff800000001000, "SYSTEM", testOffsets())
	if err != nil {
		t.Fatal(err)
	}
	key, err := hive.RootKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := hive.ClassData(context.Background(), key)
	if err != nil || string(got) != "ABCDEFGH" {
		t.Fatal(string(got), err)
	}
	key.ClassLength = 100
	if _, err = hive.ClassData(context.Background(), key); err == nil || !strings.Contains(err.Error(), "declared 100") {
		t.Fatal(err)
	}
	key.ClassLength = 0
	empty, err := hive.ClassData(context.Background(), key)
	if err != nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
}

type hiveValue struct {
	name string
	data []byte
}

type testHive struct {
	r    *ram
	bin  uint64
	base uint64
	tab  uint64
	next int
}

func mountTestHive(r *ram, hive, base, dir, tab, bin uint64) *testHive {
	off := testOffsets()
	putU32(r, hive, hiveSignature)
	putU64(r, hive+off.BaseBlock, base)
	putU32(r, hive+off.Version, 1)
	putU32(r, hive+off.Storage+off.Length, 0x100000)
	putU64(r, hive+off.Storage+off.Map, dir)
	putU32(r, hive+off.Storage+off.DualSize+off.Length, 0x1000)
	putU64(r, hive+off.Storage+off.DualSize+off.Map, dir)
	copyAt(r, base, []byte("regf"))
	putU64(r, dir, tab)
	return &testHive{r: r, bin: bin, base: base, tab: tab, next: 0x20}
}

func (h *testHive) alloc(payload []byte) uint32 {
	index := h.next
	total := len(payload) + 4
	if total%8 != 0 {
		total += 8 - total%8
	}
	putCell(h.r, h.bin, index, payload)
	h.next = index + total
	return uint32(index)
}

func (h *testHive) finish(root uint32) {
	pages := h.next/0x1000 + 1
	for i := 0; i < pages; i++ {
		putU64(h.r, h.tab+uint64(i)*16+8, h.bin+uint64(i)*0x1000)
	}
	putU32(h.r, h.base+36, root)
}

func (h *testHive) addKey(name string, class []byte, values []hiveValue, kids ...uint32) uint32 {
	var classCell uint32
	var classLen uint16
	if class != nil {
		classCell = h.alloc(class)
		classLen = uint16(len(class))
	}
	var list uint32
	if len(kids) > 0 {
		buf := make([]byte, 4+8*len(kids))
		copy(buf, "lf")
		binary.LittleEndian.PutUint16(buf[2:], uint16(len(kids)))
		for i, child := range kids {
			binary.LittleEndian.PutUint32(buf[4+i*8:], child)
		}
		list = h.alloc(buf)
	}
	ids := make([]uint32, 0, len(values))
	for _, value := range values {
		dataCell := h.alloc(value.data)
		ids = append(ids, h.alloc(vkExternal(value.name, dataCell, len(value.data))))
	}
	var valueList uint32
	if len(ids) > 0 {
		valueList = h.alloc(u32s(ids...))
	}
	return h.alloc(nkClass(name, uint32(len(kids)), list, 0, 0, uint32(len(ids)), valueList, classCell, classLen))
}

func nkClass(name string, stable, stableList, volatile, volatileList, values, valueList, class uint32, classLen uint16) []byte {
	buf := make([]byte, 76+len(name))
	copy(buf, "nk")
	binary.LittleEndian.PutUint16(buf[2:], keyCompressed)
	binary.LittleEndian.PutUint32(buf[20:], stable)
	binary.LittleEndian.PutUint32(buf[24:], volatile)
	binary.LittleEndian.PutUint32(buf[28:], stableList)
	binary.LittleEndian.PutUint32(buf[32:], volatileList)
	binary.LittleEndian.PutUint32(buf[36:], values)
	binary.LittleEndian.PutUint32(buf[40:], valueList)
	binary.LittleEndian.PutUint32(buf[0x30:], class)
	binary.LittleEndian.PutUint16(buf[0x4a:], classLen)
	binary.LittleEndian.PutUint16(buf[72:], uint16(len(name)))
	copy(buf[76:], name)
	return buf
}

func vkExternal(name string, dataCell uint32, n int) []byte {
	buf := make([]byte, 20+len(name))
	copy(buf, "vk")
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(n))
	binary.LittleEndian.PutUint32(buf[8:], dataCell)
	binary.LittleEndian.PutUint32(buf[12:], 3)
	binary.LittleEndian.PutUint16(buf[16:], valueCompressed)
	copy(buf[20:], name)
	return buf
}

func saltedUserV() []byte {
	name := utf16Bytes("Ada")
	const ntRel = 32
	const lmRel = 32 + 56
	buf := make([]byte, 0xCC+lmRel+8)
	binary.LittleEndian.PutUint32(buf[0x0C:], 0)
	binary.LittleEndian.PutUint32(buf[0x10:], uint32(len(name)))
	copy(buf[0xCC:], name)
	binary.LittleEndian.PutUint32(buf[0xA8:], ntRel)
	binary.LittleEndian.PutUint32(buf[0xAC:], 56)
	nt := buf[0xCC+ntRel:]
	nt[2] = 2
	copy(nt[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(nt[8:24], mustHex(nil, "404142434445464748494a4b4c4d4e4f"))
	copy(nt[24:56], mustHex(nil, "d611c3a648b16ccf79ff954020a03bb26bfe30b60fb489d672d469b54fcbc7ca"))
	binary.LittleEndian.PutUint32(buf[0x9C:], lmRel)
	binary.LittleEndian.PutUint32(buf[0xA0:], 4)
	return buf
}

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	if t != nil {
		t.Helper()
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatal(err)
	}
	return b
}
