package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestIndependentStringsParserPinnedOracle(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/windows-strings-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Parser []struct {
			Raw, Offset, Text string
			Error             bool
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Parser) != 1038 {
		t.Fatal("oracle drift")
	}
	for _, c := range fixture.Parser {
		data, _ := hex.DecodeString(c.Raw)
		match := windowsStringsPattern.FindSubmatch(data)
		_, overflow := strconv.ParseUint(c.Offset, 10, 64)
		if c.Error {
			if match != nil {
				t.Fatalf("accepted %q", data)
			}
			continue
		}
		if len(match) != 3 || hex.EncodeToString(match[2]) != c.Text {
			t.Fatalf("%q: %q", data, match)
		}
		if overflow != nil {
			continue
		}
		got, err := strconv.ParseUint(string(match[1]), 10, 64)
		want, _ := strconv.ParseUint(c.Offset, 10, 64)
		if err != nil || got != want {
			t.Fatalf("offset %q: %s != %s", data, match[1], c.Offset)
		}
	}
}

func TestIndependentStringsInputTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strings.txt")
	if err := os.WriteFile(path, []byte("123 hello\ninvalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "raw", "offset", "number", "text", "verified", "digest", "duplicate", "candidate"} {
		t.Run(mode, func(t *testing.T) {
			v, err := openStringsInput(path)
			if err != nil {
				t.Fatal(err)
			}
			row := evidence.Row{Cells: map[string]evidence.Value{
				"InputOffset": evidence.Address(0), "RawLine": evidence.Bytes([]byte("123 hello\n")),
				"PhysicalAddress": evidence.Address(123), "InputLine": evidence.Number(1),
				"String": evidence.Text("hello\n"), "InputSHA256": evidence.Text(v.hash), "StringVerified": evidence.Bool(false),
				"PhysicalAssociations": {Kind: "structure", Data: []map[string]evidence.Value{}},
			}}
			switch mode {
			case "raw":
				row.Cells["RawLine"] = evidence.Bytes([]byte("123 other\n"))
			case "offset":
				row.Cells["PhysicalAddress"] = evidence.Address(124)
			case "number":
				row.Cells["InputLine"] = evidence.Number(2)
			case "text":
				row.Cells["String"] = evidence.Text("other\n")
			case "verified":
				row.Cells["StringVerified"] = evidence.Bool(true)
			case "digest":
				row.Cells["InputSHA256"] = evidence.Text("wrong")
			case "duplicate":
				v.seen[0] = true
			case "candidate":
				row.Cells["PhysicalAssociations"] = evidence.Value{Kind: "structure", Data: []map[string]evidence.Value{{"Name": evidence.Text("Process 4"), "Identity": evidence.Text("invented")}}}
			}
			err = v.stringRow(context.Background(), row, map[string]memory.MemoryLayer{}, map[string]stringsOwner{}, nil, "x64")
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
	v, err := openStringsInput(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := evidence.Row{Cells: map[string]evidence.Value{"InputOffset": evidence.Address(10), "RawLine": evidence.Bytes([]byte("invalid\n")), "Error": evidence.Missing("input_line_unrecognized", os.ErrInvalid)}}
	if err = v.invalidLine(bad); err != nil {
		t.Fatal(err)
	}
	if err = v.invalidLine(bad); err == nil {
		t.Fatal("accepted repeated diagnostic")
	}
}

func TestIndependentStringsTranslationProofTampering(t *testing.T) {
	raw := iatVerificationMemory(make([]byte, 0x5000))
	binary.LittleEndian.PutUint32(raw[0x1000:], 0x2001)
	binary.LittleEndian.PutUint32(raw[0x2000:], 0x3001)
	translator, err := memory.NewIntelForOS(raw, 0x1000, "x86", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: raw, Translator: translator, ID: "kernel"}
	for _, mode := range []string{"valid", "root", "physical", "leaf", "owner", "baseline"} {
		t.Run(mode, func(t *testing.T) {
			proof := map[string]evidence.Value{"Virtual": evidence.Address(0), "Physical": evidence.Address(0x3000), "PhysicalEntry": evidence.Address(0x2000), "Entry": evidence.Address(0x3001), "EntryWidth": evidence.Number(4), "PageSize": evidence.Number(4096)}
			mapping := map[string]evidence.Value{"Name": evidence.Text("kernel"), "Identity": evidence.Missing("kernel_address_space", nil), "PID": evidence.Missing("kernel_address_space", nil), "ProcessOffset": evidence.Missing("kernel_address_space", nil), "Root": evidence.Address(0x1000), "Virtual": evidence.Address(0), "Physical": evidence.Address(0x3000), "Length": evidence.Number(4096), "Baseline": evidence.Bool(true), "BaselineAddress": evidence.Address(0), "PhysicalMatch": evidence.Bool(true), "Translation": {Kind: "structure", Data: proof}}
			switch mode {
			case "root":
				mapping["Root"] = evidence.Address(0x2000)
			case "physical":
				mapping["Physical"] = evidence.Address(0x4000)
			case "leaf":
				proof["Entry"] = evidence.Address(0x3003)
			case "owner":
				mapping["PID"] = evidence.Number(4)
			case "baseline":
				mapping["BaselineAddress"] = evidence.Address(0x3000)
			}
			row := evidence.Row{Cells: map[string]evidence.Value{"InputPage": evidence.Address(0x3000), "Mapping": {Kind: "structure", Data: mapping}}}
			err := verifyStringsAssociation(context.Background(), row, nil, nil, kernel, "x86")
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}

func TestIndependentStringsHierarchy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strings")
	if err := os.WriteFile(path, []byte("123 hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "unknown-page", "wrong-input-parent", "wrong-result-parent", "duplicate-page"} {
		t.Run(mode, func(t *testing.T) {
			v, err := openStringsInput(path)
			if err != nil {
				t.Fatal(err)
			}
			input := evidence.Row{ID: "input", Cells: map[string]evidence.Value{"RecordType": evidence.Text("input")}}
			page := evidence.Row{ID: "page", ParentID: "input", Cells: map[string]evidence.Value{"RecordType": evidence.Text("query_page"), "InputPage": evidence.Address(0)}}
			child := evidence.Row{ID: "string", ParentID: "page", Cells: map[string]evidence.Value{"RecordType": evidence.Text("string"), "PhysicalAddress": evidence.Address(123)}}
			if err = v.hierarchy(input); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unknown-page":
				page.Cells["InputPage"] = evidence.Address(4096)
			case "wrong-input-parent":
				page.ParentID = "absent"
			case "wrong-result-parent":
				child.ParentID = "input"
			}
			err = v.hierarchy(page)
			if err == nil && mode == "duplicate-page" {
				err = v.hierarchy(page)
			}
			if err == nil {
				err = v.hierarchy(child)
			}
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}
