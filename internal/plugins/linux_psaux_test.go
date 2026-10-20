package plugins

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLinuxArgumentPythonReference(t *testing.T) {
	data, err := os.ReadFile("testdata/linux-arguments.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Hex, Decoded, Display string
		Arguments             []string
	}
	if err = json.Unmarshal(data, &cases); err != nil || len(cases) < 400 {
		t.Fatal("reference fixture drift", len(cases), err)
	}
	for _, tc := range cases {
		raw, err := hex.DecodeString(tc.Hex)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := replaceInvalidUTF8(raw)
		display, vector, _ := linuxArgumentDisplay(raw)
		if decoded != tc.Decoded || display != tc.Display || !reflect.DeepEqual(vector, tc.Arguments) {
			t.Fatal(tc.Hex, decoded, tc.Decoded, display, tc.Display, vector, tc.Arguments)
		}
	}
}

func TestLinuxArgumentReplacementAndDisplay(t *testing.T) {
	for _, tc := range []struct {
		raw     []byte
		decoded string
		valid   bool
	}{{[]byte("取证🔎"), "取证🔎", true}, {[]byte{0xff, 0xff}, "��", false}, {[]byte{0xe2, 0x82}, "�", false}, {[]byte{0xe2, 0x82, 'A'}, "�A", false}, {[]byte{0xed, 0xa0, 0x80}, "���", false}, {[]byte{0xf4, 0x90, 0x80, 0x80}, "����", false}, {[]byte{0xf0, 0x90, 0x80}, "�", false}, {[]byte{0xef, 0xbf, 0xbd}, "�", true}} {
		decoded, valid := replaceInvalidUTF8(tc.raw)
		if decoded != tc.decoded || valid != tc.valid {
			t.Fatal(tc.raw, decoded, valid)
		}
	}
	large := bytes.Repeat([]byte{0}, maxLinuxArgumentVector+1)
	display, vector, warnings := linuxArgumentDisplay(large)
	if len(display) != len(large)-1 || vector != nil || len(warnings) != 1 || warnings[0] != "argument_count_limit" {
		t.Fatal("large vector was allocated or raw display was discarded")
	}
	for _, tc := range []struct{ raw, display, vector string }{{"a\x00b\x00", "a b", "a|b"}, {"a\x00\x00", "a ", "a|"}, {"\x00", " ", ""}, {"a ", "a", "a "}, {"a", "a", "a"}, {"a\x00 \x00", "a  ", "a| "}} {
		display, vector, _ := linuxArgumentDisplay([]byte(tc.raw))
		if display != tc.display || strings.Join(vector, "|") != tc.vector {
			t.Fatal(tc, display, vector)
		}
	}
}

func FuzzLinuxArgumentDisplay(f *testing.F) {
	for _, seed := range [][]byte{{}, {'a', 0}, {0xff, 0xff}, {0xe2, 0x82}, {0xed, 0xa0, 0x80}, {0, 0}, []byte("取证🔎\x00--flag\x00")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		before := append([]byte(nil), raw...)
		display, vector, warnings := linuxArgumentDisplay(raw)
		decoded, valid := replaceInvalidUTF8(raw)
		if !bytes.Equal(raw, before) || !utf8.ValidString(display) || !utf8.ValidString(decoded) || len(vector) > len(raw)+1 || utf8.RuneCountInString(decoded) > len(raw) || valid != utf8.Valid(raw) {
			t.Fatal("argument display violated bounds or raw capture invariants")
		}
		if valid && decoded != string(raw) {
			t.Fatal("valid UTF-8 was altered")
		}
		seen := map[string]bool{}
		for _, warning := range warnings {
			if seen[warning] || warning != "invalid_utf8" && warning != "missing_terminal_nul" && warning != "argument_count_limit" {
				t.Fatal("invalid warning set")
			}
			seen[warning] = true
		}
		if seen["invalid_utf8"] == valid {
			t.Fatal("invalid UTF-8 not identified")
		}
	})
}
