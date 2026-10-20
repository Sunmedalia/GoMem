package plugins

import (
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func TestAmcacheDecoding(t *testing.T) {
	if got := amUTF16([]byte{'A', 0, 0, 0}); got != "A" {
		t.Fatal(got)
	}
	if got := amUTF16([]byte{'A', 0, 'B', 0, 0, 0}); got != "AB" {
		t.Fatal(got)
	}
	if got := amUTF16([]byte{'A', 0, 0x41}); got != "A\uFFFD" {
		t.Fatal(got)
	}
	values := map[string]registry.Value{
		"FileId":   {Type: regSZ, Data: utf16Bytes("0000ab")},
		"LinkDate": {Type: regSZ, Data: utf16Bytes("01/01/2020 00:00:00")},
	}
	if hash := amStripHash(amString(values, "FileId"), false); hash.String() != "ab" {
		t.Fatal(hash)
	}
	if amStripHash(evidence.Text("0000abcd"), true).String() != "abcd" || amStripHash(evidence.Text("0abc"), false).String() != "abc" {
		t.Fatal("hash strip")
	}
	if amDateString(values, "LinkDate").Reason != "unparsable" || amDateString(values, "Missing").Reason != "not_available" {
		t.Fatal("date string")
	}
	if amString(map[string]registry.Value{"Name": {Type: regDWORD, Data: []byte{1, 0, 0, 0}}}, "Name").Reason != "unparsable" {
		t.Fatal("dword string")
	}
	if amProgramKey("  abc\x00") != "abc" {
		t.Fatal(amProgramKey("  abc\x00"))
	}
	epoch := amEpoch(map[string]registry.Value{"DriverTimeStamp": {Type: regQWORD, Data: []byte{0, 0, 0, 0, 0, 0, 0, 0}}}, "DriverTimeStamp")
	if epoch.String() != "1970-01-01T00:00:00Z" {
		t.Fatal(epoch)
	}
	if amFiletime(0).Reason != "not_set" {
		t.Fatal(amFiletime(0))
	}
}

func TestAmcacheGrouping(t *testing.T) {
	programs := newAmPrograms()
	programs.put("one", amRecord{kind: "Program", path: evidence.Text(`C:\One`), layer: "kernel", offset: 1})
	programs.put("one", amRecord{kind: "Program", path: evidence.Text(`C:\One-last`), layer: "kernel", offset: 2})
	programs.put("empty", amRecord{kind: "Program", path: evidence.Text(`C:\Empty`), layer: "kernel", offset: 3})
	files := []amRecord{
		{kind: "File", id: evidence.Text("one"), path: evidence.Text(`c:\a`), layer: "kernel", offset: 4},
		{kind: "File", id: evidence.Missing("not_available", nil), path: evidence.Text(`c:\orphan`), layer: "kernel", offset: 5},
		{kind: "File", id: evidence.Text("one"), path: evidence.Text(`c:\b`), layer: "kernel", offset: 6},
	}
	var rows []evidence.Row
	if err := (&amState{}).grouped(plugin.Environment{}, programs, files, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatal(len(rows))
	}
	if rows[0].Cells["Path"].String() != `c:\orphan` || rows[0].ParentID != "" || rows[0].Cells["Depth"].String() != "0" {
		t.Fatal("orphan", rows[0].Cells, rows[0].ParentID)
	}
	if rows[1].Cells["Path"].String() != `C:\One-last` || rows[1].ID == "" || rows[1].Cells["EntryType"].String() != "Program" {
		t.Fatal("program", rows[1].Cells, rows[1].ID)
	}
	if rows[2].ParentID != rows[1].ID || rows[2].Cells["Path"].String() != `c:\a` || rows[3].Cells["Path"].String() != `c:\b` || rows[3].Cells["Depth"].String() != "1" {
		t.Fatal("children", rows[2].ParentID, rows[2].Cells["Path"], rows[3].Cells["Path"])
	}
	if rows[4].Cells["Path"].String() != `C:\Empty` || rows[4].ParentID != "" {
		t.Fatal("leftover", rows[4].Cells, rows[4].ParentID)
	}
}

func utf16Bytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), 0)
	}
	return out
}
