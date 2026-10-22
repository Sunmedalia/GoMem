package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type testSource []byte

func (m testSource) Name() string           { return "physical" }
func (m testSource) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(m))}} }
func (m testSource) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at >= uint64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[at:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func testLayout() *symbols.ISF {
	table := &symbols.ISF{Bases: map[string]symbols.Type{}, Types: map[string]symbols.Type{}, Enums: map[string]symbols.Enumeration{}}
	for n, size := range map[string]uint64{"u8": 1, "u16": 2, "u32": 4, "u64": 8} {
		table.Bases[n] = symbols.Type{Kind: "int", Size: size, Endian: "little"}
	}
	field := func(offset uint64, name string) symbols.Field {
		return symbols.Field{Offset: offset, Type: symbols.TypeRef{Kind: "base", Name: name}}
	}
	table.Enums["MFTFlagsEnum"] = symbols.Enumeration{Base: "u8", Size: 1, Constants: map[string]json.Number{"File": "1"}}
	table.Enums["AttrTypeEnum"] = symbols.Enumeration{Base: "u8", Size: 1, Constants: map[string]json.Number{"STANDARD_INFORMATION": "16", "FILE_NAME": "48", "DATA": "128"}}
	table.Enums["PermissionFlagEnum"] = symbols.Enumeration{Base: "u8", Size: 1, Constants: map[string]json.Number{"Archive": "32"}}
	enum := func(offset uint64, name string) symbols.Field {
		f := field(offset, name)
		f.Type.Kind = "enum"
		return f
	}
	table.Types["MFT_ENTRY"] = symbols.Type{Kind: "struct", Size: 1024, Fields: map[string]symbols.Field{"FirstAttrOffset": field(20, "u16"), "Flags": enum(22, "MFTFlagsEnum"), "RecordNumber": field(44, "u32"), "LinkCount": field(18, "u16")}}
	table.Types["ATTR_HEADER"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"AttrType": enum(0, "AttrTypeEnum"), "Length": field(4, "u32"), "NonResidentFlag": field(8, "u8"), "NameLength": field(9, "u8"), "NameOffset": field(10, "u16"), "ContentLength": field(16, "u32"), "ContentOffset": field(20, "u16")}}
	for _, name := range []string{"STANDARD_INFORMATION_ENTRY", "FILE_NAME_ENTRY"} {
		fields := map[string]symbols.Field{}
		base := uint64(0)
		if name == "FILE_NAME_ENTRY" {
			base = 8
			fields["Flags"] = enum(56, "PermissionFlagEnum")
			fields["NameLength"] = field(64, "u8")
			fields["Name"] = symbols.Field{Offset: 66, Type: symbols.TypeRef{Kind: "array", Count: 10, Subtype: &symbols.TypeRef{Kind: "base", Name: "u16"}}}
		}
		for i, path := range []string{"CreationTime", "ModifiedTime", "UpdatedTime", "AccessedTime"} {
			fields[path] = field(base+uint64(i)*8, "u64")
		}
		table.Types[name] = symbols.Type{Kind: "struct", Size: 1024, Fields: fields}
	}
	return table
}
func TestIndependentTypedMFTResultsRejectTampering(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/windows-mft-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name   string
			Size   int
			Writes []struct {
				Offset int
				Data   string
			}
			Expected map[string]struct {
				Rows []struct{ Values []json.RawMessage }
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		if c.Name != "FILE-normal" {
			continue
		}
		original := make(testSource, c.Size)
		for _, w := range c.Writes {
			data, _ := hex.DecodeString(w.Data)
			copy(original[w.Offset:], data)
		}
		for _, mode := range []string{"mftscan", "ads", "residentdata"} {
			cols := []string{"Offset", "RecordSignature", "RecordNumber", "LinkCount", "MFTType", "Permissions", "AttributeType", "Created", "Modified", "Updated", "Accessed", "Filename"}
			index := 1
			if mode != "mftscan" {
				index = 0
				cols = []string{"Offset", "RecordSignature", "RecordNumber", "AttributeType", "Filename"}
				if mode == "ads" {
					cols = append(cols, "ADSFilename")
				}
				cols = append(cols, "Hexdump")
			}
			for _, tamper := range []string{"valid", "RecordNumber", "Offset", "RecordSignature", "MFTType", "Filename", "source", "payload"} {
				t.Run(mode+"/"+tamper, func(t *testing.T) {
					data := append(testSource(nil), original...)
					table := testLayout()
					v := verifier{ctx: context.Background(), objects: &object.Reader{Layer: data, Symbols: table}, layout: table, plugin: "windows." + mode, records: map[uint64]sourceRecord{}}
					cells := map[string]evidence.Value{"RecordOffset": evidence.Address(0x1000), "LinkCount": evidence.Number(2), "MFTType": evidence.Text("File")}
					for i, key := range cols {
						var value any
						json.Unmarshal(c.Expected[mode].Rows[index].Values[i], &value)
						switch value := value.(type) {
						case string:
							cells[key] = evidence.Text(value)
						case float64:
							cells[key] = evidence.Number(uint64(value))
						case map[string]any:
							if value["missing"] != nil {
								cells[key] = evidence.Missing(map[string]string{"NotApplicableValue": "not_applicable", "NotAvailableValue": "not_available"}[value["missing"].(string)], nil)
							} else {
								bytes, _ := hex.DecodeString(value["raw"].(string))
								cells[key] = evidence.Bytes(bytes)
								cells["ContentOffset"] = evidence.Address(uint64(value["offset"].(float64)))
								cells["ContentLength"] = evidence.Number(uint64(value["length"].(float64)))
							}
						}
					}
					switch tamper {
					case "RecordNumber":
						cells[tamper] = evidence.Number(99)
					case "Offset":
						cells[tamper] = evidence.Address(0x1000)
					case "RecordSignature":
						cells[tamper] = evidence.Text("BAAD")
					case "MFTType":
						cells[tamper] = evidence.Text("Directory")
					case "Filename":
						cells[tamper] = evidence.Text("invented")
					case "source":
						data[0x102c] ^= 1
					case "payload":
						if mode == "mftscan" {
							cells["Created"] = evidence.Text("2030-01-01T00:00:00+00:00")
						} else {
							cells["Hexdump"] = evidence.Bytes([]byte("invented"))
						}
					}
					err := v.result(evidence.Row{Cells: cells})
					if (err == nil) != (tamper == "valid") {
						t.Fatal(tamper, err)
					}
				})
			}
		}
	}
}
