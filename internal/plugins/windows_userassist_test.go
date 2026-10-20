package plugins

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestUserAssistFoldersAndROT13(t *testing.T) {
	if len(userAssistFolders) != 101 {
		t.Fatal(len(userAssistFolders))
	}
	guid := "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}"
	stored := rot13(guid + `\notepad.exe`)
	if stored != `{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\abgrcnq.rkr` {
		t.Fatal(stored)
	}
	got := userAssistValueName(stored, true)
	want := `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\notepad.exe`
	if got != want {
		t.Fatal(got)
	}
	again := userAssistValueName(rot13(guid+`\x\`+guid), true)
	folder := userAssistFolders[guid]
	if again != folder+`\x\`+folder {
		t.Fatal(again)
	}
	if got := userAssistValueName(rot13(`plain\`+guid), true); got != `plain\`+guid {
		t.Fatal(got)
	}
	if userAssistValueName(stored, false) != rot13(stored) {
		t.Fatal("xp keeps the decoded name")
	}
	if userAssistValueName("HRZR_PGYFRFFVBA", true) != "UEME_CTLSESSION" {
		t.Fatal(userAssistValueName("HRZR_PGYFRFFVBA", true))
	}
}

func TestUserAssistLayouts(t *testing.T) {
	if known, win7 := userAssistWin7(nil); known || win7 {
		t.Fatal("nil symbols")
	}
	if known, win7 := userAssistWin7(&symbols.ISF{}); known || win7 {
		t.Fatal("missing type")
	}
	xp := &symbols.ISF{Types: map[string]symbols.Type{"_KUSER_SHARED_DATA": {Kind: "struct", Fields: map[string]symbols.Field{}}}}
	if known, win7 := userAssistWin7(xp); !known || win7 {
		t.Fatal("xp", known, win7)
	}
	win7 := &symbols.ISF{Types: map[string]symbols.Type{"_KUSER_SHARED_DATA": {Kind: "struct", Fields: map[string]symbols.Field{"CookiePad": {}}}}}
	if known, modern := userAssistWin7(win7); !known || !modern {
		t.Fatal("win7")
	}

	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[4:], 9)
	binary.LittleEndian.PutUint32(blob[8:], 4)
	binary.LittleEndian.PutUint32(blob[12:], 1500)
	binary.LittleEndian.PutUint64(blob[60:], 133000000100000000)
	parsed := parseUserAssist(blob, nil, true, true)
	if parsed.count.String() != "9" || parsed.focus.String() != "4" || parsed.focused.String() != "0:00:02" || parsed.id.Reason != "not_applicable" {
		t.Fatal(parsed)
	}
	if parsed.updated.String() != "2022-06-18T04:26:50Z" || parsed.raw.String() != spaceHex(blob) {
		t.Fatal(parsed.updated, parsed.raw)
	}
	short := parseUserAssist(blob[:8], nil, true, true)
	if short.count.Reason != "unparsable" || short.count.String() == "0" || short.raw.String() != spaceHex(blob[:8]) {
		t.Fatal(short)
	}
	failed := parseUserAssist(nil, fmt.Errorf("page missing"), true, true)
	if failed.count.Reason != "unparsable" || failed.raw.Reason != "registry_value_unreadable" || failed.cause.Error != "page missing" {
		t.Fatal(failed)
	}
	unknown := parseUserAssist(blob, nil, false, false)
	if unknown.raw.String() != spaceHex(blob) || unknown.count.Reason != "unparsable" {
		t.Fatal(unknown)
	}

	old := make([]byte, 16)
	binary.LittleEndian.PutUint32(old[0:], 7)
	binary.LittleEndian.PutUint32(old[4:], 4)
	binary.LittleEndian.PutUint64(old[8:], 0)
	xpParsed := parseUserAssist(old, nil, true, false)
	if xpParsed.id.String() != "7" || xpParsed.count.String() != "4" || xpParsed.focus.Reason != "not_applicable" || xpParsed.updated.Reason != "not_set" {
		t.Fatal(xpParsed)
	}
	binary.LittleEndian.PutUint32(old[4:], 6)
	if parseUserAssist(old, nil, true, false).count.String() != "1" {
		t.Fatal("xp count")
	}
}

func TestFocusDurationMatchesPinnedTimedelta(t *testing.T) {
	want := map[uint32]string{
		0:          "0:00:00.500000",
		1:          "0:00:00.501000",
		499:        "0:00:00.999000",
		500:        "0:00:01",
		501:        "0:00:01.001000",
		999:        "0:00:01.499000",
		1000:       "0:00:01.500000",
		1500:       "0:00:02",
		420000:     "0:07:00.500000",
		3600000:    "1:00:00.500000",
		86400000:   "1 day, 0:00:00.500000",
		4294967295: "49 days, 17:02:47.795000",
		4294966795: "49 days, 17:02:47.295000",
		123456789:  "1 day, 10:17:37.289000",
		333:        "0:00:00.833000",
		999999:     "0:16:40.499000",
		65535:      "0:01:06.035000",
		3280387012: "37 days, 23:13:07.512000",
		1095513148: "12 days, 16:18:33.648000",
		1930549411: "22 days, 8:15:49.911000",
		2798570523: "32 days, 9:22:51.023000",
		3387541014: "39 days, 4:59:01.514000",
		403123852:  "4 days, 15:58:44.352000",
		3589583794: "41 days, 13:06:24.294000",
		1912923437: "22 days, 3:22:03.937000",
		4059906722: "46 days, 23:45:07.222000",
		3871601465: "44 days, 19:26:41.965000",
		131383004:  "1 day, 12:29:43.504000",
		2325348894: "26 days, 21:55:49.394000",
		1001090105: "11 days, 14:04:50.605000",
		92297589:   "1 day, 1:38:18.089000",
		2758633299: "31 days, 22:17:13.799000",
		3693442237: "42 days, 17:57:22.737000",
		2878940490: "33 days, 7:42:20.990000",
		1302957853: "15 days, 1:55:58.353000",
		3790218436: "43 days, 20:50:18.936000",
		2170177477: "25 days, 2:49:37.977000",
	}
	for focus, text := range want {
		if got := focusDuration(focus); got != text {
			t.Fatalf("focus %d got %s want %s", focus, got, text)
		}
	}
}

func FuzzUserAssistBlob(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, 72))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, known := range []bool{false, true} {
			for _, win7 := range []bool{false, true} {
				parseUserAssist(data, nil, known, win7)
				parseUserAssist(data, fmt.Errorf("short"), known, win7)
			}
		}
		rot13(string(data))
		if len(data) >= 4 {
			focusDuration(binary.LittleEndian.Uint32(data))
		}
	})
}
