package engine_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsUserAssistSynthetic(t *testing.T) {
	f := printKeyFixture(t, true)
	addCookiePad(t, f)
	editWindowsImage(t, f, func(data []byte) {
		putUnicode(data, 0x30000+96, 0x34100, `\??\C:\Users\generic-user\ntuser.dat`)
		binary.LittleEndian.PutUint32(data[0x3a000:], 0xBEE0BEE0)
		putUnicode(data, 0x3a000+80, 0x3b000, "")
		putUnicode(data, 0x3a000+96, 0x3b100, `\REGISTRY\MACHINE\SYSTEM`)
		putUnicode(data, 0x3a000+112, 0x3b200, "")
		linkHives(data, hiveHead, 0x30000+64, 0x3a000+64)
		writeUserAssistCells(data)
	})
	rows, state, err := userAssistRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 6 {
		t.Fatal(state, len(rows), err, assistSummary(rows))
	}
	var key evidence.Row
	var children []evidence.Row
	for _, row := range rows {
		if row.Cells["HiveName"].String() != `\??\C:\Users\generic-user\ntuser.dat` {
			t.Fatal(row.Cells["HiveName"])
		}
		if row.Cells["RecordType"].String() == "key" {
			key = row
			continue
		}
		children = append(children, row)
	}
	if key.ID == "" || key.ParentID != "" || key.Cells["Type"].String() != "Key" || key.Cells["Name"].Reason != "not_applicable" || key.Cells["RawData"].String() != "N/A" || key.Cells["Depth"].String() != "0" {
		t.Fatal(key.Cells)
	}
	wantPath := `ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Count`
	if key.Cells["Path"].String() != wantPath || key.Cells["LastWriteTime"].String() != "2022-06-18T04:26:40Z" {
		t.Fatal(key.Cells["Path"], key.Cells["LastWriteTime"])
	}
	if key.Cells["RawLastWrite"].String() != "133000000000000000" {
		t.Fatal(key.Cells["RawLastWrite"])
	}
	byName := map[string]evidence.Row{}
	for _, row := range children {
		if err := row.Verify(); err != nil {
			t.Fatal(err)
		}
		if row.ParentID != key.ID || row.Cells["Path"].String() != wantPath || row.Cells["LastWriteTime"].String() != key.Cells["LastWriteTime"].String() || row.Cells["Depth"].String() != "1" {
			t.Fatal(row.Cells["RecordType"], row.Cells["Name"], row.ParentID, row.Cells["Path"], row.Cells["LastWriteTime"])
		}
		byName[row.Cells["Name"].String()] = row
	}
	sub := byName["Sessions"]
	if sub.Cells["RecordType"].String() != "subkey" || sub.Cells["Type"].String() != "Subkey" || sub.Cells["RawData"].String() != "N/A" || sub.Cells["Count"].Reason != "not_applicable" {
		t.Fatal(sub.Cells)
	}
	folder := byName[`%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\notepad.exe`]
	if folder.Cells["RecordType"].String() != "value" || folder.Cells["Count"].String() != "9" || folder.Cells["FocusCount"].String() != "4" || folder.Cells["TimeFocused"].String() != "0:00:02" || folder.Cells["ID"].Reason != "not_applicable" || folder.Cells["LastUpdated"].String() != "2022-06-18T04:26:50Z" {
		t.Fatal(folder.Cells)
	}
	if !strings.Contains(folder.Cells["RawData"].String(), "09 00 00 00") || folder.Cells["RawBytes"].Kind != "bytes" {
		t.Fatal(folder.Cells["RawData"], folder.Cells["RawBytes"].Kind)
	}
	session := byName["UEME_CTLSESSION"]
	if session.Cells["Count"].String() != "6" || session.Cells["TimeFocused"].String() != "0:00:00.501000" {
		t.Fatal(session.Cells)
	}
	short := byName["short"]
	if short.Cells["Count"].Reason != "unparsable" || short.Cells["Count"].Error != "" || short.Cells["RawData"].String() == "" || strings.Count(short.Cells["RawData"].String(), " ") != 7 {
		t.Fatal(short.Cells["Count"], short.Cells["RawData"])
	}
	bad := byName["bad"]
	if bad.Cells["Count"].Reason != "unparsable" || bad.Cells["RawData"].Reason != "registry_value_unreadable" || bad.Cells["Error"].Reason != "registry_value_unreadable" || bad.Cells["Error"].Error == "" || strings.Contains(bad.Cells["RawData"].String(), "00 00 00 00") {
		t.Fatal(bad.Cells["Count"], bad.Cells["RawData"], bad.Cells["Error"])
	}
	filtered, state, err := userAssistRows(t, f, map[string]string{"offset": "0x30000"})
	if err != nil || state != "completed" || len(filtered) != 6 {
		t.Fatal(state, len(filtered), err)
	}
	none, state, err := userAssistRows(t, f, map[string]string{"offset": "0x1111"})
	if err != nil || state != "completed" || len(none) != 0 {
		t.Fatal(state, len(none), err)
	}
}

func TestWindowsUserAssistMissingKeyIsSkipped(t *testing.T) {
	f := printKeyFixture(t, true)
	addCookiePad(t, f)
	editWindowsImage(t, f, func(data []byte) {
		putUnicode(data, 0x30000+96, 0x34100, `\??\C:\Users\missing\NTUSER.DAT`)
	})
	rows, state, err := userAssistRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 0 {
		t.Fatal(state, len(rows), err, assistSummary(rows))
	}
}

func addCookiePad(t *testing.T, f testfixture.Fixture) {
	t.Helper()
	raw, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	table.Types["_KUSER_SHARED_DATA"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{
		"CookiePad": {Offset: 0, Type: symbols.TypeRef{Kind: "base", Name: "u32"}},
	}}
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeUserAssistCells(data []byte) {
	const (
		root                     = 0x40
		software, softwareList   = 0x100, 0x80
		microsoft, microsoftList = 0x200, 0x180
		windows, windowsList     = 0x300, 0x280
		current, currentList     = 0x400, 0x380
		explorer, explorerList   = 0x500, 0x480
		assist, assistList       = 0x600, 0x580
		guid, guidList           = 0x700, 0x680
		count, countList         = 0x800, 0x780
		sessions                 = 0x900
		valueList                = 0x980
		folderVK, folderData     = 0xa00, 0xa80
		sessionVK, sessionData   = 0xb00, 0xb80
		shortVK, shortData       = 0xc00, 0xc80
		badVK                    = 0xd00
	)
	stamp := uint64(133000000000000000)
	putCell(data, 0x36000, root, nkCell("ROOT", 0x20, stamp, 1, softwareList, 0, 0, 0, 0))
	putCell(data, 0x36000, softwareList, lfCell(software))
	putCell(data, 0x36000, software, nkCell("Software", 0x20, stamp, 1, microsoftList, 0, 0, 0, 0))
	putCell(data, 0x36000, microsoftList, lfCell(microsoft))
	putCell(data, 0x36000, microsoft, nkCell("Microsoft", 0x20, stamp, 1, windowsList, 0, 0, 0, 0))
	putCell(data, 0x36000, windowsList, lfCell(windows))
	putCell(data, 0x36000, windows, nkCell("Windows", 0x20, stamp, 1, currentList, 0, 0, 0, 0))
	putCell(data, 0x36000, currentList, lfCell(current))
	putCell(data, 0x36000, current, nkCell("CurrentVersion", 0x20, stamp, 1, explorerList, 0, 0, 0, 0))
	putCell(data, 0x36000, explorerList, lfCell(explorer))
	putCell(data, 0x36000, explorer, nkCell("Explorer", 0x20, stamp, 1, assistList, 0, 0, 0, 0))
	putCell(data, 0x36000, assistList, lfCell(assist))
	putCell(data, 0x36000, assist, nkCell("UserAssist", 0x20, stamp, 1, guidList, 0, 0, 0, 0))
	putCell(data, 0x36000, guidList, lfCell(guid))
	putCell(data, 0x36000, guid, nkCell("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", 0x20, stamp, 1, countList, 0, 0, 0, 0))
	putCell(data, 0x36000, countList, lfCell(count))
	putCell(data, 0x36000, count, nkCell("Count", 0x20, stamp, 1, sessions-0x80, 0, 0, 4, valueList))
	putCell(data, 0x36000, sessions-0x80, lfCell(sessions))
	putCell(data, 0x36000, sessions, nkCell("Sessions", 0x20, 99, 0, 0, 0, 0, 0, 0))
	putCell(data, 0x36000, valueList, u32List(folderVK, sessionVK, shortVK, badVK))
	folder := make([]byte, 72)
	binary.LittleEndian.PutUint32(folder[4:], 9)
	binary.LittleEndian.PutUint32(folder[8:], 4)
	binary.LittleEndian.PutUint32(folder[12:], 1500)
	binary.LittleEndian.PutUint64(folder[60:], 133000000100000000)
	putCell(data, 0x36000, folderVK, vkExternal("{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\\abgrcnq.rkr", 3, folderData, len(folder)))
	putCell(data, 0x36000, folderData, folder)
	session := make([]byte, 72)
	binary.LittleEndian.PutUint32(session[4:], 6)
	binary.LittleEndian.PutUint32(session[8:], 2)
	binary.LittleEndian.PutUint32(session[12:], 1)
	putCell(data, 0x36000, sessionVK, vkExternal("HRZR_PGYFRFFVBA", 3, sessionData, len(session)))
	putCell(data, 0x36000, sessionData, session)
	short := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	putCell(data, 0x36000, shortVK, vkExternal("fubeg", 3, shortData, len(short)))
	putCell(data, 0x36000, shortData, short)
	putCell(data, 0x36000, badVK, vkExternal("onq", 3, 0x7ff0, 72))
}

func vkExternal(name string, typ uint32, dataCell uint32, n int) []byte {
	buf := make([]byte, 20+len(name))
	copy(buf, "vk")
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(n))
	binary.LittleEndian.PutUint32(buf[8:], dataCell)
	binary.LittleEndian.PutUint32(buf[12:], typ)
	binary.LittleEndian.PutUint16(buf[16:], 1)
	copy(buf[20:], name)
	return buf
}

func u32List(values ...uint32) []byte {
	buf := make([]byte, 4*len(values))
	for i, value := range values {
		binary.LittleEndian.PutUint32(buf[i*4:], value)
	}
	return buf
}

func userAssistRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(t.Context(), "windows.userassist", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func assistSummary(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Type"].String()+" "+row.Cells["Name"].String()+" "+row.Cells["Error"].String())
	}
	return out
}
