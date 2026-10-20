package symbols

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMSFDirectoryAndCodeViewFailures(t *testing.T) {
	data, err := os.ReadFile("testdata/native-x64.pdb")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"block-size", func(b []byte) { binary.LittleEndian.PutUint32(b[32:], 0x300) }},
		{"block-map", func(b []byte) { binary.LittleEndian.PutUint32(b[52:], 0xffffffff) }},
		{"directory-budget", func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 64<<20) }},
		{"directory-block-reuse", func(b []byte) {
			bs := binary.LittleEndian.Uint32(b[32:])
			mp := binary.LittleEndian.Uint32(b[52:])
			binary.LittleEndian.PutUint32(b[bs*mp:], 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := bytes.Clone(data)
			tc.mutate(broken)
			if _, err := openMSF(ctx, bytes.NewReader(broken), uint64(len(broken)), 1<<20); err == nil {
				t.Fatal("invalid MSF accepted")
			}
		})
	}
	msf, err := openMSF(ctx, bytes.NewReader(data), uint64(len(data)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	tpi, err := msf.stream(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"index-range", func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 0xffffffff) }},
		{"record-size", func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 0xffff) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := bytes.Clone(tpi)
			tc.mutate(broken)
			if _, err := newCodeView(ctx, broken, &ISF{}, 4096); err == nil {
				t.Fatal("invalid TPI accepted")
			}
		})
	}
	for _, raw := range [][]byte{{0x80}, {0x04, 0x80, 1}, {0xff, 0xff}} {
		c := cvCursor{data: raw}
		c.number()
		if c.err == nil {
			t.Fatal("invalid numeric leaf accepted")
		}
	}
	c := cvCursor{data: []byte{0x18, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	if n := c.number(); string(n) != "340282366920938463463374607431768211455" || c.err != nil {
		t.Fatal(n, c.err)
	}
	// Standard ISF can express pointers with a different ABI width, such as
	// pointer32 members in a 64-bit PDB. The object layer honors that base.
	table := &ISF{Bases: map[string]Type{"pointer": {Kind: "int", Size: 8}}}
	b := &codeView{table: table}
	ref, err := b.primitive(0x403)
	if err != nil || ref.Base != "pointer32" {
		t.Fatal(ref, err)
	}
	if width, err := table.refSize(ref, 0); err != nil || width != 4 {
		t.Fatal(width, err)
	}
}

func TestPDBInfoAgeMayDifferFromImageAge(t *testing.T) {
	data, err := os.ReadFile("testdata/native-x64.pdb")
	if err != nil {
		t.Fatal(err)
	}
	m, err := openMSF(context.Background(), bytes.NewReader(data), uint64(len(data)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	position := uint64(m.streams[1].blocks[0])*m.blockSize + 8
	binary.LittleEndian.PutUint32(data[position:], 5)
	path := filepath.Join(t.TempDir(), "native-x64.pdb")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	table, report, err := ConvertPDB(context.Background(), path, PDBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pdb, err := table.PDBIdentity()
	if err != nil || pdb.Age != 1 || len(report.Warnings) != 1 {
		t.Fatal(pdb, report, err)
	}
}

func TestCodeViewRetainsSameNameVariants(t *testing.T) {
	// Two modules provide different layouts of D, and each declaration has a
	// self pointer via a common forward reference. The earlier layout remains
	// addressable instead of being silently replaced by the later definition.
	ctx := context.Background()
	table := &ISF{Bases: map[string]Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}}, Types: map[string]Type{}, Enums: map[string]Enumeration{}}
	var data bytes.Buffer
	header := make([]byte, 56)
	binary.LittleEndian.PutUint32(header, 20040203)
	binary.LittleEndian.PutUint32(header[4:], 56)
	binary.LittleEndian.PutUint32(header[8:], 0x1000)
	data.Write(header)
	count := uint32(0)
	record := func(leaf uint16, body []byte) {
		binary.Write(&data, binary.LittleEndian, uint16(len(body)+2))
		binary.Write(&data, binary.LittleEndian, leaf)
		data.Write(body)
		count++
	}
	structure := func(size uint16, fields uint32, forward bool) []byte {
		var x bytes.Buffer
		binary.Write(&x, binary.LittleEndian, uint16(1))
		props := uint16(0)
		if forward {
			props = 0x80
		}
		binary.Write(&x, binary.LittleEndian, props)
		binary.Write(&x, binary.LittleEndian, fields)
		binary.Write(&x, binary.LittleEndian, uint64(0))
		binary.Write(&x, binary.LittleEndian, size)
		x.WriteString("D\x00")
		return x.Bytes()
	}
	record(0x1505, structure(0, 0, true)) // 1000 forward
	var pointer bytes.Buffer
	binary.Write(&pointer, binary.LittleEndian, uint32(0x1000))
	binary.Write(&pointer, binary.LittleEndian, uint32(12|8<<13))
	record(0x1002, pointer.Bytes()) // 1001
	field := func(name string) []byte {
		var x bytes.Buffer
		binary.Write(&x, binary.LittleEndian, uint16(0x150d))
		binary.Write(&x, binary.LittleEndian, uint16(3))
		binary.Write(&x, binary.LittleEndian, uint32(0x1001))
		binary.Write(&x, binary.LittleEndian, uint16(0))
		x.WriteString(name + "\x00")
		return x.Bytes()
	}
	record(0x1203, field("a"))                  //1002
	record(0x1505, structure(8, 0x1002, false)) //1003 variant
	record(0x1203, field("b"))                  //1004
	record(0x1505, structure(8, 0x1004, false)) //1005 canonical
	bytes := data.Bytes()
	binary.LittleEndian.PutUint32(bytes[12:], 0x1000+count)
	binary.LittleEndian.PutUint32(bytes[16:], uint32(len(bytes)-56))
	b, err := newCodeView(ctx, bytes, table, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.convert(); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Types["D"].Fields["b"]; !ok {
		t.Fatal("canonical definition missing")
	}
	if _, ok := table.Types["D@0x1003"].Fields["a"]; !ok {
		t.Fatal("earlier definition lost")
	}
	if b.variants != 1 {
		t.Fatal(b.variants)
	}
}

func TestPDBSectionAndOMAPAddresses(t *testing.T) {
	sections := []pdbSection{{rva: 0x1000, size: 0x100}, {rva: 0x3000, size: 0x100}}
	omap := []omapEntry{{from: 0x1000, to: 0x8000}, {from: 0x1080, to: 0}, {from: 0x3000, to: 0x9000}}
	if address, err := pdbRVA(sections, omap, 1, 0x40); err != nil || address != 0x8040 {
		t.Fatal(address, err)
	}
	if address, err := pdbRVA(sections, omap, 2, 0x10); err != nil || address != 0x9010 {
		t.Fatal("last PE section lost", address, err)
	}
	if address, err := pdbRVA(sections, omap, 1, 0x80); !errors.Is(err, errOMAPRemoved) || address != 0x1080 {
		t.Fatal("removed symbol must retain its original RVA and reason", address, err)
	}
	if _, err := pdbRVA(sections, nil, 0, 0); err == nil {
		t.Fatal("segment zero accepted")
	}
	if _, err := pdbRVA(sections, nil, 2, 0x101); err == nil {
		t.Fatal("section overflow accepted")
	}
	if _, err := pdbRVA([]pdbSection{{rva: 0xfffffff0, size: 0x100}}, nil, 1, 0x20); err == nil {
		t.Fatal("RVA wrap accepted")
	}
	if _, err := pdbRVA(sections, []omapEntry{{from: 0x1000, to: 0xfffffff0}}, 1, 0x20); err == nil {
		t.Fatal("OMAP wrap accepted")
	}
}

func FuzzMSF(f *testing.F) {
	data, err := os.ReadFile("testdata/native-x64.pdb")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		m, err := openMSF(context.Background(), bytes.NewReader(data), uint64(len(data)), 512<<10)
		if err == nil {
			for _, id := range []uint16{1, 2, 3} {
				if _, err = m.stream(id); err != nil {
					return
				}
			}
		}
	})
}

func FuzzCodeView(f *testing.F) {
	data, err := os.ReadFile("testdata/native-x64.pdb")
	if err != nil {
		f.Fatal(err)
	}
	m, err := openMSF(context.Background(), bytes.NewReader(data), uint64(len(data)), 512<<10)
	if err != nil {
		f.Fatal(err)
	}
	tpi, err := m.stream(2)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tpi)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		table := &ISF{Bases: map[string]Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}}, Types: map[string]Type{}, Enums: map[string]Enumeration{}, Symbols: map[string]Symbol{}}
		b, err := newCodeView(context.Background(), data, table, 4096)
		if err == nil {
			if b.convert() != nil {
				return
			}
			b.validateLayouts()
		}
	})
}
