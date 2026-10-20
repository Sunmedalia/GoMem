package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const (
	hiveHead = 0x1f000
	hiveA    = 0x1f100
	hiveB    = 0x1f200
	hiveC    = 0x1f300
	hiveStr  = 0x1f600
)

func hiveFixture(t *testing.T) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(b, &table); err != nil {
		t.Fatal(err)
	}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(off uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: off, Type: ref} }
	table.Types["_HHIVE"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Signature": field(0, u32)}}
	table.Types["_CMHIVE"] = symbols.Type{Kind: "struct", Size: 80, Fields: map[string]symbols.Field{
		"Hive": field(0, strct("_HHIVE")), "HiveList": field(16, strct("_LIST_ENTRY")),
		"FileFullPath": field(32, strct("_UNICODE_STRING")), "FileUserName": field(48, strct("_UNICODE_STRING")), "HiveRootPath": field(64, strct("_UNICODE_STRING")),
	}}
	table.Symbols["CmpHiveListHead"] = symbols.Symbol{Address: hiveHead - 0x4000}
	b, err = json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func putUnicode(data []byte, desc, buf uint64, value string) {
	encoded := utf16.Encode([]rune(value))
	binary.LittleEndian.PutUint16(data[desc:], uint16(len(encoded)*2))
	binary.LittleEndian.PutUint16(data[desc+2:], uint16(len(encoded)*2))
	if len(encoded) == 0 {
		return
	}
	binary.LittleEndian.PutUint64(data[desc+8:], buf)
	for i, unit := range encoded {
		binary.LittleEndian.PutUint16(data[buf+uint64(i)*2:], unit)
	}
}

func linkHives(data []byte, head uint64, nodes ...uint64) {
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
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

func putHive(data []byte, base uint64, signature uint32, full, user, root string, buffers uint64) {
	binary.LittleEndian.PutUint32(data[base:], signature)
	putUnicode(data, base+32, buffers, full)
	putUnicode(data, base+48, buffers+0x80, user)
	putUnicode(data, base+64, buffers+0x100, root)
}

func hiveRows(t *testing.T, f testfixture.Fixture, params map[string]string) (rows []evidence.Row, state string, runErr error) {
	t.Helper()
	e := openWindowsImage(t, f)
	result, runErr := e.Run(context.Background(), "windows.hivelist", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	if result.Task.Rows != int64(len(rows)) {
		t.Fatal(result.Task.Rows, len(rows), runErr)
	}
	return rows, result.Task.State, runErr
}

func engineRun(t *testing.T, rows *[]evidence.Row) func(evidence.Row) error {
	t.Helper()
	return func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			t.Fatal(err)
		}
		*rows = append(*rows, row)
		return nil
	}
}

func hiveNames(rows []evidence.Row) []string {
	var names []string
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "hive" && row.Cells["Name"].Kind == "string" {
			names = append(names, row.Cells["Name"].String())
		}
	}
	return names
}

func TestWindowsHiveListNamesFallbackAndFilter(t *testing.T) {
	f := hiveFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		putHive(data, hiveA, 0xBEE0BEE0, `\SystemRoot\System32\Config\SYSTEM`, "", `\REGISTRY\MACHINE\SYSTEM`, hiveStr)
		putHive(data, hiveB, 0xBEE0BEE0, "", `NTUSER.DAT`, `\REGISTRY\USER\S-1-5-21`, hiveStr+0x300)
		putHive(data, hiveC, 0xBEE0BEE0, "", "", `\REGISTRY\MACHINE\SOFTWARE`, hiveStr+0x600)
		linkHives(data, hiveHead, hiveA+16, hiveB+16, hiveC+16)
	})
	rows, state, err := hiveRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 4 {
		t.Fatal(state, rows, err)
	}
	if got := hiveNames(rows); len(got) != 3 || got[0] != `\SystemRoot\System32\Config\SYSTEM` || got[1] != `NTUSER.DAT` || got[2] != `\REGISTRY\MACHINE\SOFTWARE` {
		t.Fatal(got)
	}
	if rows[0].Cells["NameSource"].String() != "FileFullPath" || rows[1].Cells["NameSource"].String() != "FileUserName" || rows[2].Cells["NameSource"].String() != "HiveRootPath" {
		t.Fatal(rows[0].Cells["NameSource"], rows[1].Cells["NameSource"], rows[2].Cells["NameSource"])
	}
	signature, sigErr := rows[0].Cells["Signature"].Uint()
	if rows[0].Cells["FileUserName"].String() != "" || rows[1].Cells["FileFullPath"].String() != "" || rows[0].Cells["FileOutput"].String() != "disabled" || sigErr != nil || signature != 0xBEE0BEE0 {
		t.Fatal(rows[0].Cells, rows[1].Cells, sigErr)
	}
	summary := rows[3]
	if summary.Cells["RecordType"].String() != "summary" || summary.Cells["Error"].Reason != "not_applicable" || summary.Cells["Coverage"].Kind != "structure" {
		t.Fatal(summary)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["hives"] != "3" || coverage["diagnostics"] != "0" {
		t.Fatal(coverage)
	}
	filtered, state, err := hiveRows(t, f, map[string]string{"filter": "ntuser"})
	if err != nil || state != "completed" || hiveNames(filtered) == nil || hiveNames(filtered)[0] != "NTUSER.DAT" || len(hiveNames(filtered)) != 1 || len(filtered) != 2 {
		t.Fatal(state, hiveNames(filtered), len(filtered), err)
	}
	none, state, err := hiveRows(t, f, map[string]string{"filter": "absent"})
	if err != nil || state != "completed" || len(hiveNames(none)) != 0 || len(none) != 1 {
		t.Fatal(state, none, err)
	}
	for _, params := range []map[string]string{{"max-nodes": "0"}, {"max-nodes": "1000001"}, {"dump": "maybe"}} {
		if _, err := openWindowsImage(t, f).Run(context.Background(), "windows.hivelist", params, engine.RunOptions{}); err == nil {
			t.Fatal("invalid parameter accepted", params)
		}
	}
}

func TestWindowsHiveListEmptyNameAndUnreadableSiblingField(t *testing.T) {
	f := hiveFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		putHive(data, hiveA, 0xBEE0BEE0, "", "", "", hiveStr)
		putHive(data, hiveB, 0xBEE0BEE0, "", `SAM`, "", hiveStr+0x300)
		binary.LittleEndian.PutUint16(data[hiveB+32:], 8)
		binary.LittleEndian.PutUint64(data[hiveB+40:], 0x300000)
		linkHives(data, hiveHead, hiveA+16, hiveB+16)
	})
	rows, state, err := hiveRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 3 {
		t.Fatal(state, len(rows), err)
	}
	if rows[0].Cells["Name"].String() != "" || rows[0].Cells["NameSource"].String() != "none" || rows[0].Cells["Error"].Reason != "not_applicable" {
		t.Fatal(rows[0].Cells)
	}
	if rows[1].Cells["Name"].String() != "SAM" || rows[1].Cells["NameSource"].String() != "FileUserName" || rows[1].Cells["FileFullPath"].Reason != "hive_name_unreadable" || rows[1].Cells["Error"].Reason != "not_applicable" {
		t.Fatal(rows[1].Cells)
	}
}

func TestWindowsHiveListInvalidSignatureRecoversOtherDirection(t *testing.T) {
	f := hiveFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		putHive(data, hiveA, 0xBEE0BEE0, `\SYSTEM`, "", "", hiveStr)
		putHive(data, hiveB, 0xDEAD, `\BROKEN`, "", "", hiveStr+0x300)
		putHive(data, hiveC, 0xBEE0BEE0, `\SOFTWARE`, "", "", hiveStr+0x600)
		linkHives(data, hiveHead, hiveA+16, hiveB+16, hiveC+16)
	})
	rows, state, err := hiveRows(t, f, nil)
	if err == nil || state != "failed" || len(rows) != 4 || hiveNames(rows)[0] != `\SYSTEM` || hiveNames(rows)[1] != `\SOFTWARE` {
		t.Fatal(state, hiveNames(rows), len(rows), err)
	}
	bad, badErr := rows[1].Cells["Signature"].Uint()
	if rows[1].Cells["RecordType"].String() != "diagnostic" || rows[1].Cells["Error"].Reason != "hive_signature_invalid" || badErr != nil || bad != 0xDEAD {
		t.Fatal(rows[1].Cells, badErr)
	}
	if !strings.Contains(err.Error(), "Windows registry hives") || rows[3].Cells["Error"].Reason != "hive_list_incomplete" {
		t.Fatal(err, rows[3].Cells)
	}
	coverage := rows[3].Cells["Coverage"].Data.(map[string]any)
	if coverage["hives"] != "2" || coverage["diagnostics"] != "1" {
		t.Fatal(coverage)
	}
}

func TestWindowsHiveListBrokenForwardLinkWalksBackward(t *testing.T) {
	f := hiveFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		putHive(data, hiveA, 0xBEE0BEE0, `\SYSTEM`, "", "", hiveStr)
		putHive(data, hiveC, 0xBEE0BEE0, `\SOFTWARE`, "", "", hiveStr+0x300)
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put(hiveHead, hiveA+16)
		put(hiveHead+8, hiveC+16)
		put(hiveA+16, 0)
		put(hiveA+24, hiveHead)
		put(hiveC+16, hiveHead)
		put(hiveC+24, hiveHead)
	})
	rows, state, err := hiveRows(t, f, nil)
	if err == nil || state != "failed" || hiveNames(rows)[0] != `\SYSTEM` || hiveNames(rows)[1] != `\SOFTWARE` {
		t.Fatal(state, hiveNames(rows), len(rows), err)
	}
	if rows[1].Cells["RecordType"].String() != "diagnostic" || rows[1].Cells["Error"].Reason != "hive_list_forward_failed" {
		t.Fatal(rows[1].Cells)
	}
}

func TestWindowsHiveDumpWithoutMapLayoutWritesNothing(t *testing.T) {
	f := hiveFixture(t)
	e := openWindowsImage(t, f)
	result, err := e.Run(context.Background(), "windows.hivelist", map[string]string{"dump": "true"}, engine.RunOptions{})
	if err == nil || result.Task.State != "failed" || result.Task.Rows != 0 || !strings.Contains(err.Error(), "BaseBlock") {
		t.Fatal(result, err)
	}
	if err = hiveFiles(t, e.Store.Dir); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsHiveDumpReconstructsStableStore(t *testing.T) {
	f := printKeyFixture(t, true)
	image, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	e := openWindowsImage(t, f)
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "windows.hivelist", map[string]string{"dump": "true"}, engine.RunOptions{Emit: engineRun(t, &rows)})
	if err != nil || result.Task.State != "completed" || len(rows) != 2 {
		t.Fatal(result.Task.State, len(rows), err)
	}
	file, ok := rows[0].Cells["FileOutput"].Data.(evidence.Artifact)
	if !ok || rows[0].Cells["FileOutput"].Kind != "artifact" || file.State != "completed" || file.Name != "registry.SYSTEM.30000.hive" || file.MissingBytes != "0" {
		t.Fatal(rows[0].Cells["FileOutput"])
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
		t.Fatal(err)
	}
	member, err := e.Store.OpenArtifactMember(context.Background(), file, false)
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()
	got, err := io.ReadAll(member)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, image[0x31000:0x32000]...), image[0x36000:0x37000]...)
	if len(got) != len(want) || string(got) != string(want) || string(got[:4]) != "regf" {
		t.Fatal(len(got), len(want), string(got[:4]))
	}
	coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
	if coverage["hives"] != "1" || coverage["dump_failures"] != "0" || rows[1].Cells["Error"].Reason != "not_applicable" {
		t.Fatal(rows[1].Cells)
	}
	limited := openWindowsImage(t, f)
	limitedRows := []evidence.Row{}
	limitedResult, err := limited.Run(context.Background(), "windows.hivelist", map[string]string{"dump": "true", "max-hive": "4096"}, engine.RunOptions{Emit: engineRun(t, &limitedRows)})
	if err == nil || limitedResult.Task.State != "failed" || len(limitedRows) != 2 || limitedRows[0].Cells["FileOutput"].Reason != "hive_too_large" || limitedRows[1].Cells["Error"].Reason != "hive_reconstruction_incomplete" {
		t.Fatal(limitedResult.Task.State, len(limitedRows), err)
	}
	if err = hiveFiles(t, limited.Store.Dir); err != nil {
		t.Fatal(err)
	}
}

func hiveFiles(t *testing.T, dir string) error {
	t.Helper()
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(entry.Name(), ".hive") {
			return fmt.Errorf("unexpected hive file %s", path)
		}
		return nil
	})
}
