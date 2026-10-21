package plugins

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func TestLinuxSyscallPinnedTableSizing(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-syscall-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Sizes []struct {
			Width, Metadata, Following, Selected uint64
			Error                                bool
			Symbols                              []struct {
				Name    string
				Address uint64
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Sizes) != 16 {
		t.Fatal(err, len(oracle.Sizes))
	}
	for _, tc := range oracle.Sizes {
		symbols := make([]linuxSyscallSymbol, 0, len(tc.Symbols))
		for _, s := range tc.Symbols {
			symbols = append(symbols, linuxSyscallSymbol{s.Address, s.Name})
		}
		sort.Slice(symbols, func(i, j int) bool {
			if symbols[i].address != symbols[j].address {
				return symbols[i].address < symbols[j].address
			}
			return symbols[i].name < symbols[j].name
		})
		got, err := linuxSyscallTableSize(symbols, tc.Metadata, 0x18000, tc.Width)
		if tc.Error {
			if err == nil {
				t.Fatal("empty size accepted", tc)
			}
			continue
		}
		if err != nil || got.entries != tc.Selected {
			t.Fatal(tc, got, err)
		}
	}
}

func FuzzLinuxSyscallTableSize(f *testing.F) {
	f.Add(uint64(0x18000), uint64(8), uint64(0), []byte{0x00, 0x80, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, table, width, metadata uint64, raw []byte) {
		if width != 4 && width != 8 {
			width = 8
		}
		if metadata > 10000 {
			metadata = 10000
		}
		var symbols []linuxSyscallSymbol
		for i := 0; i+7 < len(raw) && i < 64; i += 8 {
			address := uint64(raw[i]) | uint64(raw[i+1])<<8 | uint64(raw[i+2])<<16 | uint64(raw[i+3])<<24
			symbols = append(symbols, linuxSyscallSymbol{address, string(raw[i+4 : i+8])})
		}
		sort.Slice(symbols, func(i, j int) bool {
			if symbols[i].address != symbols[j].address {
				return symbols[i].address < symbols[j].address
			}
			return symbols[i].name < symbols[j].name
		})
		got, err := linuxSyscallTableSize(symbols, metadata, table, width)
		if err != nil {
			if got.entries != 0 {
				t.Fatal(got)
			}
			return
		}
		if got.entries == 0 || (got.next != 0 && got.entries > got.next && got.entries != metadata) {
			t.Fatal(got)
		}
	})
}
