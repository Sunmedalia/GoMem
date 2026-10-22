package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

var windowsStringsPattern = regexp.MustCompile(`(?s)^(?:[^0-9A-Za-z_]*)([0-9]+)(?:[^0-9A-Za-z_]*)([0-9A-Za-z_].+)\n?`)

type stringsVerifiedLine struct {
	number, physical uint64
	raw, text        []byte
}
type stringsInputVerifier struct {
	hash        string
	data        []byte
	lines       map[uint64]stringsVerifiedLine
	seen        map[uint64]bool
	invalid     map[uint64][]byte
	seenInvalid map[uint64]bool
	inputID     string
	pages       map[uint64]string
	queryPages  map[uint64]bool
}

func openStringsInput(path string) (*stringsInputVerifier, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("strings input is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("strings input exceeds snapshot bound")
	}
	hash := sha256.Sum256(data)
	v := &stringsInputVerifier{hash: hex.EncodeToString(hash[:]), data: data, lines: map[uint64]stringsVerifiedLine{}, seen: map[uint64]bool{}, invalid: map[uint64][]byte{}, seenInvalid: map[uint64]bool{}, pages: map[uint64]string{}, queryPages: map[uint64]bool{}}
	position, number := 0, uint64(0)
	for position < len(data) {
		end := bytes.IndexByte(data[position:], '\n')
		if end < 0 {
			end = len(data) - position
		} else {
			end++
		}
		line := data[position : position+end]
		number++
		match := windowsStringsPattern.FindSubmatch(line)
		var offset uint64
		if len(match) == 3 {
			offset, err = strconv.ParseUint(string(match[1]), 10, 64)
		} else {
			err = fmt.Errorf("invalid line")
		}
		if err != nil {
			v.invalid[uint64(position)] = line
		} else {
			v.lines[uint64(position)] = stringsVerifiedLine{number, offset, line, match[2]}
			v.queryPages[offset&^uint64(4095)] = true
		}
		position += end
	}
	return v, nil
}

// hierarchy verifies retained native evidence independently of flat baseline rows.
func (v *stringsInputVerifier) hierarchy(row evidence.Row) error {
	kind := row.Cells["RecordType"].String()
	switch kind {
	case "input":
		if v.inputID != "" || row.ID == "" || row.ParentID != "" {
			return fmt.Errorf("invalid input evidence root")
		}
		v.inputID = row.ID
	case "input_error", "query_page":
		if v.inputID == "" || row.ParentID != v.inputID {
			return fmt.Errorf("input evidence parent differs")
		}
		if kind == "query_page" {
			page, err := row.Cells["InputPage"].Uint()
			if err != nil || page&4095 != 0 || row.ID == "" || v.pages[page] != "" {
				return fmt.Errorf("invalid or repeated query page")
			}
			if !v.queryPages[page] {
				return fmt.Errorf("query page absent from original input")
			}
			v.pages[page] = row.ID
		}
	case "association", "string":
		key := "InputPage"
		if kind == "string" {
			key = "PhysicalAddress"
		}
		page, err := row.Cells[key].Uint()
		if err != nil || v.pages[page&^uint64(4095)] == "" || row.ParentID != v.pages[page&^uint64(4095)] {
			return fmt.Errorf("query evidence parent differs")
		}
	}
	return nil
}

func (v *stringsInputVerifier) provenance(row evidence.Row) error {
	if row.Provenance.Parameters["engine.input.strings_file.sha256"] != v.hash || row.Provenance.Parameters["engine.input.strings_file.size"] != strconv.Itoa(len(v.data)) {
		return fmt.Errorf("strings input snapshot provenance differs")
	}
	return nil
}
func (v *stringsInputVerifier) input(row evidence.Row) error {
	if row.Cells["InputSHA256"].String() != v.hash {
		return fmt.Errorf("input record digest differs")
	}
	n, err := row.Cells["Captured"].Uint()
	if err != nil || n != uint64(len(v.data)) {
		return fmt.Errorf("input record size differs")
	}
	return nil
}
func (v *stringsInputVerifier) raw(row evidence.Row) (uint64, []byte, error) {
	at, err := row.Cells["InputOffset"].Uint()
	if err != nil {
		return 0, nil, err
	}
	raw, err := evidenceBytes(row.Cells["RawLine"])
	if err != nil {
		return 0, nil, err
	}
	if at > uint64(len(v.data)) || uint64(len(raw)) > uint64(len(v.data))-at || !bytes.Equal(raw, v.data[at:at+uint64(len(raw))]) {
		return 0, nil, fmt.Errorf("original strings input line differs")
	}
	return at, raw, nil
}
func (v *stringsInputVerifier) invalidLine(row evidence.Row) error {
	at, raw, err := v.raw(row)
	if err != nil {
		return err
	}
	expected, ok := v.invalid[at]
	if !ok || v.seenInvalid[at] || !bytes.Equal(raw, expected) || row.Cells["Error"].Kind != "missing" || row.Cells["Error"].Error == "" {
		return fmt.Errorf("invalid input diagnostic differs")
	}
	v.seenInvalid[at] = true
	return nil
}

type stringsOwner struct{ pid, offset uint64 }

func verifyStringOwner(m map[string]evidence.Value, owners map[string]stringsOwner) error {
	if m["Name"].String() == "kernel" {
		for _, key := range []string{"PID", "ProcessOffset", "Identity"} {
			if m[key].Kind != "missing" || m[key].Reason != "kernel_address_space" || m[key].Error != "" {
				return fmt.Errorf("kernel owner metadata is not typed missing")
			}
		}
		return nil
	}
	owner, ok := owners[m["Identity"].String()]
	if !ok {
		return fmt.Errorf("unknown original process identity")
	}
	pid, err := m["PID"].Uint()
	if err != nil || pid != owner.pid || m["Name"].String() != fmt.Sprintf("Process %d", pid) {
		return fmt.Errorf("process association PID differs")
	}
	offset, err := m["ProcessOffset"].Uint()
	if err != nil || offset != owner.offset {
		return fmt.Errorf("process association object differs")
	}
	return nil
}

func stringOwnerLayer(name, identity string, layers map[string]memory.MemoryLayer, kernel memory.MemoryLayer) (*memory.Virtual, error) {
	layer := kernel
	if name != "kernel" {
		layer = layers["process:"+identity]
	}
	space, ok := layer.(*memory.Virtual)
	if !ok {
		return nil, fmt.Errorf("unknown original strings owner")
	}
	return space, nil
}
func canonicalStringAddress(at uint64, architecture string) uint64 {
	if architecture == "x64" {
		at &= 0x0000ffffffffffff
		if at&(1<<47) != 0 {
			at |= 0xffff000000000000
		}
	}
	return at
}
func (v *stringsInputVerifier) stringRow(ctx context.Context, row evidence.Row, layers map[string]memory.MemoryLayer, owners map[string]stringsOwner, kernel memory.MemoryLayer, architecture string) error {
	at, raw, err := v.raw(row)
	if err != nil {
		return err
	}
	expected, ok := v.lines[at]
	if !ok || v.seen[at] || !bytes.Equal(raw, expected.raw) {
		return fmt.Errorf("unexpected or repeated strings input line")
	}
	physical, err := row.Cells["PhysicalAddress"].Uint()
	if err != nil || physical != expected.physical {
		return fmt.Errorf("strings source physical offset differs")
	}
	line, err := row.Cells["InputLine"].Uint()
	if err != nil || line != expected.number {
		return fmt.Errorf("strings source line number differs")
	}
	text := make([]rune, len(expected.text))
	for i, b := range expected.text {
		text[i] = rune(b)
	}
	if row.Cells["String"].String() != string(text) || row.Cells["InputSHA256"].String() != v.hash || row.Cells["StringVerified"].Data != false {
		return fmt.Errorf("external string bytes or verification claim differs")
	}
	var candidates []map[string]evidence.Value
	data, err := json.Marshal(row.Cells["PhysicalAssociations"].Data)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &candidates); err != nil {
		return err
	}
	for _, m := range candidates {
		if err := verifyStringOwner(m, owners); err != nil {
			return err
		}
		space, err := stringOwnerLayer(m["Name"].String(), m["Identity"].String(), layers, kernel)
		if err != nil {
			return err
		}
		address, err := m["VirtualAddress"].Uint()
		if err != nil {
			return err
		}
		reported, err := m["PhysicalAddress"].Uint()
		if err != nil || reported != physical {
			return fmt.Errorf("physical association source differs")
		}
		base, err := m["RunPhysical"].Uint()
		if err != nil {
			return err
		}
		size, err := m["RunLength"].Uint()
		if err != nil || physical < base || physical-base >= size {
			return fmt.Errorf("physical association outside source run")
		}
		virtual, err := m["RunVirtual"].Uint()
		if err != nil || canonicalStringAddress(virtual+(physical-base), architecture) != address {
			return fmt.Errorf("physical association displacement differs")
		}
		tr, err := space.Translator.Translate(ctx, address)
		if err != nil || tr.Physical != physical {
			return fmt.Errorf("original physical association not supported: %v", err)
		}
	}
	v.seen[at] = true
	return nil
}
func verifyStringsAssociation(ctx context.Context, row evidence.Row, layers map[string]memory.MemoryLayer, owners map[string]stringsOwner, kernel memory.MemoryLayer, architecture string) error {
	var m map[string]evidence.Value
	data, err := json.Marshal(row.Cells["Mapping"].Data)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	if err := verifyStringOwner(m, owners); err != nil {
		return err
	}
	space, err := stringOwnerLayer(m["Name"].String(), m["Identity"].String(), layers, kernel)
	if err != nil {
		return err
	}
	rooted, ok := space.Translator.(memory.RootedTranslator)
	if !ok {
		return fmt.Errorf("original strings root unavailable")
	}
	root, err := m["Root"].Uint()
	if err != nil || root != rooted.Root() {
		return fmt.Errorf("strings owner root differs")
	}
	page, err := row.Cells["InputPage"].Uint()
	if err != nil || page&4095 != 0 {
		return fmt.Errorf("invalid strings query page")
	}
	virtual, err := m["Virtual"].Uint()
	if err != nil {
		return err
	}
	physical, err := m["Physical"].Uint()
	if err != nil {
		return err
	}
	size, err := m["Length"].Uint()
	if err != nil || size == 0 || size-1 > ^uint64(0)-physical {
		return fmt.Errorf("invalid strings mapping extent")
	}
	if m["Baseline"].Data == true {
		want := physical
		if m["Name"].String() == "kernel" {
			if page>>12 < physical>>12 || page>>12 > (physical+size-1)>>12 {
				return fmt.Errorf("kernel baseline page outside mapping")
			}
			want = virtual
			if architecture == "x64" {
				want &= 0x0000ffffffffffff
			}
		} else {
			base := virtual
			if architecture == "x64" {
				base &= 0x0000ffffffffffff
			}
			if page != base&^uint64(4095) {
				return fmt.Errorf("process baseline query is not virtual run base")
			}
		}
		got, err := m["BaselineAddress"].Uint()
		if err != nil || got != want {
			return fmt.Errorf("baseline coordinate differs")
		}
	}
	if m["PhysicalMatch"].Data == true {
		if page < physical || page-physical >= size {
			return fmt.Errorf("physical page outside claimed mapping")
		}
		address := canonicalStringAddress(virtual+(page-physical), architecture)
		tr, err := space.Translator.Translate(ctx, address)
		if err != nil || tr.Physical != page {
			return fmt.Errorf("original association translation differs")
		}
		var proof map[string]evidence.Value
		data, err := json.Marshal(m["Translation"].Data)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &proof); err != nil {
			return err
		}
		for key, want := range map[string]uint64{"Virtual": address, "Physical": page, "PhysicalEntry": tr.EntryAddress, "Entry": tr.Entry, "EntryWidth": uint64(tr.EntryWidth), "PageSize": tr.PageSize} {
			got, err := proof[key].Uint()
			if err != nil || got != want {
				return fmt.Errorf("original association leaf differs at %s", key)
			}
		}
	}
	return nil
}

func verifyUnavailableStringMapping(row evidence.Row, physical memory.MemoryLayer) error {
	var m map[string]evidence.Value
	data, err := json.Marshal(row.Cells["Mapping"].Data)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	at, err := m["Physical"].Uint()
	if err != nil {
		return err
	}
	length, err := m["Length"].Uint()
	if err != nil || length == 0 || length > ^uint64(0)-at {
		return fmt.Errorf("invalid unavailable mapping")
	}
	end, cursor := at+length, at
	for _, span := range physical.Ranges() {
		if span.Length > ^uint64(0)-span.Start {
			return fmt.Errorf("invalid original physical range")
		}
		if span.Start+span.Length <= cursor {
			continue
		}
		if span.Start > cursor {
			break
		}
		cursor = span.Start + span.Length
		if cursor >= end {
			return fmt.Errorf("unavailable mapping asserted over captured ranges")
		}
	}
	if row.Cells["Error"].Kind != "missing" || row.Cells["Error"].Error == "" {
		return fmt.Errorf("mapping diagnostic lacks original error")
	}
	return nil
}
