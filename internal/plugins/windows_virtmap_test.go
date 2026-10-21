package plugins

import (
	"encoding/json"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestSystemVaCoalesceMatchesPinnedMachine(t *testing.T) {
	page := uint64(0x10)
	start := uint64(0x1000)
	one, err := coalesceSystemVa(start, page, []string{"A", "A", "B"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one["A"]) != 1 || one["A"][0].start != 0x1000 || one["A"][0].size != 0x10 || len(one["B"]) != 1 || one["B"][0].start != 0x1010 || one["B"][0].size != 0x20 {
		t.Fatalf("%+v", one)
	}
	same, err := coalesceSystemVa(start, page, []string{"A", "A", "A"})
	if err != nil || len(same) != 1 || len(same["A"]) != 1 || same["A"][0].size != page {
		t.Fatalf("%+v %v", same, err)
	}
	tail, err := coalesceSystemVa(start, page, []string{"A", "B", "B"})
	if err != nil || tail["A"][0] != (vaSpan{start: 0x1000, size: 0x10}) || tail["B"][0] != (vaSpan{start: 0x1010, size: 0x10}) {
		t.Fatalf("%+v %v", tail, err)
	}
	again, err := coalesceSystemVa(start, page, []string{"A", "B", "A"})
	if err != nil || len(again["A"]) != 2 || again["A"][1].start != 0x1020 || again["B"][0].start != 0x1010 {
		t.Fatalf("%+v %v", again, err)
	}
	if _, err = coalesceSystemVa(start, 0, []string{"A"}); err == nil {
		t.Fatal("zero page")
	}
}

func TestSystemVaNameAndLegacyCount(t *testing.T) {
	enum := symbols.Enumeration{Size: 4, Constants: map[string]json.Number{
		"MiVaUnused": "0", "MiVaSessionSpace": "1", "MiVaZed": "-1", "MiVaAlpha": "1",
	}}
	name, err := systemVaName(enum, 0, false, 8)
	if err != nil || name != "MiVaUnused" {
		t.Fatal(name, err)
	}
	name, err = systemVaName(enum, 1, false, 8)
	if err != nil || name != "MiVaAlpha" {
		t.Fatal(name, err)
	}
	name, err = systemVaName(enum, 0xff, true, 1)
	if err != nil || name != "MiVaZed" {
		t.Fatal(name, err)
	}
	if _, err = systemVaName(enum, 0xff, false, 1); err == nil {
		t.Fatal("unsigned 255 matched a negative constant")
	}
	count, err := legacyVaCount(0x80000000, 0x200000)
	if err != nil || count != 1024 {
		t.Fatal(count, err)
	}
	count, err = legacyVaCount(0, 0x200000)
	if err != nil || count != 2048 {
		t.Fatal(count, err)
	}
	count, err = legacyVaCount(0x800000000000, 0x200000)
	if err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if _, err = legacyVaCount(0x1000, 0); err == nil {
		t.Fatal("zero page")
	}
}

func TestVirtStartCanonicalizesMaskedKernelPointer(t *testing.T) {
	got := virtStart(0xd90000000000, 8)
	if got.String() != "0xffffd90000000000" {
		t.Fatal(got)
	}
	low := virtStart(0x1000, 8)
	if low.String() != "0x0000000000001000" {
		t.Fatal(low)
	}
}
