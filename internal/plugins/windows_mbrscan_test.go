package plugins

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func TestMBRScanParsesEntriesAndSkipsZeroBootcode(t *testing.T) {
	primary := syntheticMBR(0x11)
	primary[440] = 0x01
	primary[441] = 0x02
	primary[442] = 0x03
	primary[443] = 0x04
	writePartition(primary[446:], 0x80, []byte{0x3f, 0xc1, 0x0a}, 7, []byte{0xfe, 0xff, 0xff}, 2048, 1048576)
	writePartition(primary[462:], 0x00, []byte{0, 0, 0}, 0xff, []byte{0, 0, 0}, 0, 1)
	writePartition(primary[478:], 0x00, []byte{0, 0, 0}, 0, []byte{0, 0, 0}, 0, 0)
	writePartition(primary[494:], 0x7f, []byte{0, 1, 0}, 0xee, []byte{0, 0, 0}, 9, 8)
	zero := syntheticMBR(0)
	image := append(append([]byte(nil), primary...), make([]byte, 0x1000-len(primary))...)
	image = append(image, zero...)
	layer := mbrLayer(t, 0, image, nil)
	rows := runMBR(t, layer, map[string]string{"full": "true"})
	if len(rows) != 6 || rows[5].Cells["RecordType"].String() != "summary" {
		t.Fatalf("rows %d last %s", len(rows), rows[len(rows)-1].Cells["RecordType"])
	}
	parent, parts := rows[0], rows[1:5]
	if parent.Cells["RecordType"].String() != "mbr" || parent.Cells["Depth"].String() != "0" || parent.Cells["DiskSignature"].String() != "01-02-03-04" {
		t.Fatal(parent.Cells)
	}
	if parent.Cells["PartitionIndex"].Reason != "not_applicable" || parent.Cells["Bootable"].Reason != "not_applicable" || parent.Cells["Disasm"].String() != quotedHex(primary[:mbrBootcodeLength]) {
		t.Fatal(parent.Cells["PartitionIndex"], parent.Cells["Bootable"], parent.Cells["Disasm"].String()[:40])
	}
	if parent.Cells["BootcodeMD5"].String() != md5Hex(primary[:mbrBootcodeLength]) || parent.Cells["FullMBRMD5"].String() != md5Hex(primary) || parent.Cells["Bootcode"].String() != hexSpaces(primary[:mbrBootcodeLength]) {
		t.Fatal(parent.Cells["BootcodeMD5"], parent.Cells["FullMBRMD5"])
	}
	if parts[0].ParentID != parent.ID || parts[0].Cells["PartitionIndex"].String() != "1" || parts[0].Cells["Bootable"].String() != "true" || parts[0].Cells["PartitionType"].String() != "NTFS" || parts[0].Cells["SectorInSize"].String() != "1048576" {
		t.Fatal(parts[0].ParentID, parent.ID, parts[0].Cells)
	}
	if parts[0].Cells["BootFlag"].String() != "128" || parts[0].Cells["PartitionTypeRaw"].String() != "7" || parts[0].Cells["StartingLBA"].String() != "2048" || parts[0].Cells["StartingCHS"].String() != "63" || parts[0].Cells["StartingSector"].String() != "1" || parts[0].Cells["StartingCylinder"].String() != "778" {
		t.Fatal(parts[0].Cells)
	}
	if parts[0].Cells["EndingCHS"].String() != "254" || parts[0].Cells["EndingSector"].String() != "63" || parts[0].Cells["EndingCylinder"].String() != "1023" || parts[0].Cells["Disasm"].String() != "" || parts[0].Cells["Bootcode"].String() != "N/A" || parts[0].Cells["Depth"].String() != "1" {
		t.Fatal(parts[0].Cells)
	}
	if parts[1].Cells["PartitionType"].String() != "Not Defined PartitionType" || parts[1].Cells["Bootable"].String() != "false" || parts[2].Cells["PartitionType"].String() != "Empty" || parts[3].Cells["PartitionType"].String() != "EFI GPT Disk" || parts[3].Cells["Bootable"].String() != "false" {
		t.Fatal(parts[1].Cells["PartitionType"], parts[2].Cells["PartitionType"], parts[3].Cells["PartitionType"], parts[3].Cells["Bootable"])
	}
	coverage := rows[5].Cells["Coverage"].Data.(map[string]any)
	if coverage["signatures"] != "2" || coverage["zero_bootcode"] != "1" || coverage["rows"] != "5" || coverage["full"] != "true" || coverage["architecture"] != "intel64" {
		t.Fatal(coverage)
	}
	if len(mbrPartitionTypes) != 50 {
		t.Fatal(len(mbrPartitionTypes))
	}
}

func TestMBRScanShortColumnsAndNegativePadding(t *testing.T) {
	body := make([]byte, 82)
	body[0] = 0xab
	body[80] = 0x55
	body[81] = 0xaa
	body[10] = 0x0a
	body[11] = 0x0b
	body[12] = 0x0c
	body[13] = 0x0d
	layer := mbrLayer(t, 0, body, nil)
	rows := runMBR(t, layer, nil)
	if len(rows) != 6 {
		t.Fatalf("rows %d", len(rows))
	}
	start := int64(80) - mbrSignatureOffset
	padded := make([]byte, mbrLength)
	copy(padded[int(-start):], body[:80])
	padded[510] = 0x55
	padded[511] = 0xaa
	parent := rows[0]
	if parent.Cells["BootcodeMD5"].String() != md5Hex(padded[:mbrBootcodeLength]) || parent.Cells["FullMBRMD5"].String() != md5Hex(padded) || parent.Cells["DiskSignature"].String() != "0a-0b-0c-0d" {
		t.Fatal(parent.Cells["BootcodeMD5"], parent.Cells["FullMBRMD5"], parent.Cells["DiskSignature"], md5Hex(padded))
	}
	if parent.Cells["Bootcode"].Reason != "not_applicable" || parent.Cells["BootFlag"].Reason != "not_applicable" || rows[1].Cells["Bootcode"].Reason != "not_applicable" || rows[1].Cells["Disasm"].String() != "" {
		t.Fatal(parent.Cells["Bootcode"], rows[1].Cells["Bootcode"], rows[1].Cells["Disasm"])
	}
	if !strings.HasPrefix(parent.Cells["Disasm"].String(), `"00 `) || !strings.Contains(parent.Cells["Disasm"].String(), " ab ") {
		t.Fatal(parent.Cells["Disasm"])
	}
}

func TestMBRScanHoleInBootcodeIsPaddedAndFieldHoleFails(t *testing.T) {
	boot := make([]byte, 0x1B8)
	boot[0] = 0x22
	sig := []byte{0x55, 0xaa}
	// Bootcode occupies [0x100, 0x2B8). Fields occupy [0x2B8, 0x2FE). Signature is at 0x2FE.
	data := append(append([]byte(nil), boot...), make([]byte, 0x46)...)
	data = append(data, sig...)
	ranges := []memory.Range{{Start: 0x100, Length: uint64(len(boot))}, {Start: 0x2FE, Length: 2, FileOffset: uint64(len(boot) + 0x46)}}
	layer := mbrLayer(t, 0, data, ranges)
	var rows []evidence.Row
	err := windowsMBRScan(context.Background(), plugin.Environment{Physical: layer, Architecture: "x64"}, map[string]string{}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "unmapped") || len(rows) != 0 {
		t.Fatal(err, len(rows))
	}

	// Same bootcode, but the field bytes are present and only an interior bootcode hole is padded.
	whole := syntheticMBR(0x33)
	whole[0x100] = 0
	store := append([]byte(nil), whole[:0x100]...)
	store = append(store, whole[0x110:]...)
	ranges = []memory.Range{{Start: 0, Length: 0x100}, {Start: 0x110, Length: uint64(len(whole) - 0x110), FileOffset: 0x100}}
	layer = mbrLayer(t, 0, store, ranges)
	rows = runMBR(t, layer, nil)
	padded := append([]byte(nil), whole...)
	for i := 0x100; i < 0x110; i++ {
		padded[i] = 0
	}
	if rows[0].Cells["BootcodeMD5"].String() != md5Hex(padded[:mbrBootcodeLength]) || rows[0].Cells["FullMBRMD5"].String() != md5Hex(padded) {
		t.Fatal(rows[0].Cells["BootcodeMD5"], rows[0].Cells["FullMBRMD5"])
	}
}

func TestMBRScanRejectsNonIntelArchitecture(t *testing.T) {
	layer := mbrLayer(t, 0, []byte{0x55, 0xaa}, nil)
	err := windowsMBRScan(context.Background(), plugin.Environment{Physical: layer, Architecture: "arm64"}, nil, func(evidence.Row) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "Intel") {
		t.Fatal(err)
	}
}

func syntheticMBR(fill byte) []byte {
	mbr := make([]byte, mbrLength)
	for i := 0; i < mbrBootcodeLength; i++ {
		mbr[i] = fill
	}
	mbr[mbrSignatureOffset] = 0x55
	mbr[mbrSignatureOffset+1] = 0xaa
	return mbr
}

func writePartition(entry []byte, flag byte, start []byte, kind byte, end []byte, lba, size uint32) {
	entry[0] = flag
	copy(entry[1:4], start)
	entry[4] = kind
	copy(entry[5:8], end)
	binary.LittleEndian.PutUint32(entry[8:12], lba)
	binary.LittleEndian.PutUint32(entry[12:16], size)
}

func mbrLayer(t *testing.T, base uint64, data []byte, ranges []memory.Range) memory.MemoryLayer {
	t.Helper()
	if ranges == nil {
		ranges = []memory.Range{{Start: base, Length: uint64(len(data))}}
	}
	layer, err := memory.NewMapped(rangeScanSource(data), "physical:test", ranges)
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func runMBR(t *testing.T, layer memory.MemoryLayer, params map[string]string) []evidence.Row {
	t.Helper()
	var rows []evidence.Row
	if err := windowsMBRScan(context.Background(), plugin.Environment{Physical: layer, Architecture: "x64"}, params, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}
