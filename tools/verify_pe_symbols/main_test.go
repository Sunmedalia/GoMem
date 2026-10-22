package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"io"
	"testing"
)

func TestGroupedAcquisitionBoundaries(t *testing.T) {
	valid := map[string]any{"method": "exports", "grouped": true, "acquisitions": []map[string]any{{"offset": "0x1000", "requested": uint64(1), "captured": uint64(1)}, {"offset": "0x1001", "requested": uint64(2), "captured": uint64(2)}}}
	calls, method, err := readCalls(valid, 0x1000, 3, 3, true)
	if err != nil || method != "exports" || len(calls) != 2 || calls[1].Offset != 0x1001 || calls[1].Requested != 2 {
		t.Fatal(calls, method, err)
	}
	for _, mode := range []string{"gap", "missing-bytes", "failed", "partial", "too-many", "wrong-method", "unmarked"} {
		detail := map[string]any{"method": "exports", "grouped": true, "acquisitions": []map[string]any{{"offset": "0x1000", "requested": uint64(1), "captured": uint64(1)}, {"offset": "0x1001", "requested": uint64(2), "captured": uint64(2)}}}
		success := true
		switch mode {
		case "gap":
			detail["acquisitions"].([]map[string]any)[1]["offset"] = "0x1002"
		case "missing-bytes":
			detail["acquisitions"].([]map[string]any)[1]["captured"] = uint64(1)
			detail["acquisitions"].([]map[string]any)[1]["requested"] = uint64(1)
		case "failed":
			success = false
		case "partial":
			detail["acquisitions"].([]map[string]any)[1]["captured"] = uint64(0)
		case "too-many":
			detail["acquisitions"] = make([]map[string]any, 65)
		case "wrong-method":
			detail["method"] = "opcode"
		case "unmarked":
			detail["grouped"] = false
		}
		if _, _, err := readCalls(detail, 0x1000, 3, 3, success); err == nil {
			t.Fatal("accepted damaged boundary list", mode)
		}
	}
}

type iatVerificationMemory []byte

func (m iatVerificationMemory) Name() string           { return "process:test" }
func (m iatVerificationMemory) Ranges() []memory.Range { return nil }
func (m iatVerificationMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at >= uint64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[at:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func TestIndependentIATCoordinatesAndPointers(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, mode := range []string{"valid", "null", "wrong-pointer", "wrong-address", "wrong-provenance", "wrong-machine", "unavailable"} {
			t.Run(fmt.Sprintf("%d/%s", width, mode), func(t *testing.T) {
				raw := iatVerificationMemory(make([]byte, 0x3000))
				copy(raw[0x1000:], "MZ")
				binary.LittleEndian.PutUint32(raw[0x103c:], 0x80)
				copy(raw[0x1080:], "PE\x00\x00")
				machine, magic := uint16(0x14c), uint16(0x10b)
				if width == 8 {
					machine, magic = 0x8664, 0x20b
				}
				binary.LittleEndian.PutUint16(raw[0x1084:], machine)
				binary.LittleEndian.PutUint16(raw[0x1098:], magic)
				value := uint64(0x70001234)
				if mode == "null" {
					value = 0
				}
				if width == 8 {
					binary.LittleEndian.PutUint64(raw[0x1200:], value)
				} else {
					binary.LittleEndian.PutUint32(raw[0x1200:], uint32(value))
				}
				row := evidence.Row{Cells: map[string]evidence.Value{"ImageBase": evidence.Address(0x1000), "IATSlot": evidence.Address(0x1200), "Address": evidence.Address(0x2200), "ResolvedPointer": evidence.Address(value)}, Provenance: evidence.Provenance{Layer: raw.Name(), Offset: "0x1200"}}
				switch mode {
				case "wrong-pointer":
					row.Cells["ResolvedPointer"] = evidence.Address(value + 1)
				case "wrong-address":
					row.Cells["Address"] = evidence.Address(0x1200)
				case "wrong-provenance":
					row.Provenance.Offset = "0x1201"
				case "wrong-machine":
					raw[0x1084] = 0
				case "unavailable":
					row.Cells["ResolvedPointer"] = evidence.Missing("iat_entry_unavailable", nil)
				}
				err := verifyImportRow(context.Background(), row, map[string]memory.MemoryLayer{raw.Name(): raw}, map[string]int{})
				valid := mode == "valid" || mode == "null" || mode == "unavailable"
				if (err == nil) != valid {
					t.Fatal(mode, err)
				}
			})
		}
	}
}
