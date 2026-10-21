package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Expected values come from the pinned Python object's decoder, not this reader.
func TestServiceLayoutOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-service-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Layouts int
		Cases   []struct {
			Layout, Scenario string
			Address          uint64
			Size             int
			Segments         []struct {
				Offset int
				Hex    string
			}
			Valid    bool
			Expected []json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Layouts != len(serviceLayouts) || len(fixture.Cases) != 224 {
		t.Fatal("incomplete service oracle")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			mem := make(flatMemory, c.Size)
			for _, seg := range c.Segments {
				b, err := hex.DecodeString(seg.Hex)
				if err != nil {
					t.Fatal(err)
				}
				copy(mem[seg.Offset:], b)
			}
			layout, ok := serviceLayouts[c.Layout]
			if !ok {
				t.Fatal("missing layout", c.Layout)
			}
			row, valid, _, err := (serviceReader{mem, layout}).readRecord(context.Background(), c.Address, c.Address, map[string]svcBinary{"example": {path: "registry.exe", dll: "example.dll", pathOK: true, dllOK: true}})
			if err != nil || valid != c.Valid {
				t.Fatal(valid, c.Valid, err)
			}
			if !valid {
				return
			}
			for i, name := range []string{"Offset", "Order", "PID", "Start", "State", "Type", "Name", "Display", "Binary", "BinaryRegistry", "Dll"} {
				cell := row.Cells[name]
				if string(c.Expected[i]) == "null" {
					if cell.Kind != "missing" {
						t.Errorf("%s: %v, want missing", name, cell)
					}
					continue
				}
				var expected any
				if err := json.Unmarshal(c.Expected[i], &expected); err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprint(expected)
				if name == "Offset" {
					want = evidence.Address(uint64(expected.(float64))).String()
				}
				if cell.String() != want {
					t.Errorf("%s = %s; want %s", name, cell.String(), want)
				}
			}
		})
	}
}

func TestServiceVersionOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-service-versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Width         int
			PE            json.RawMessage
			Types         map[string][]string
			Symbols       []string
			Layout        string
			ListSupported bool `json:"list_supported"`
			Vista         bool
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 136 {
		t.Fatal(len(fixture.Cases))
	}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			table := &symbols.ISF{Meta: map[string]json.RawMessage{"windows": json.RawMessage(`{"pe":` + string(c.PE) + `}`)}, Bases: map[string]symbols.Type{"pointer": {Size: uint64(c.Width)}}, Types: map[string]symbols.Type{}, Symbols: map[string]symbols.Symbol{}}
			for name, members := range c.Types {
				fields := map[string]symbols.Field{}
				for _, member := range members {
					fields[member] = symbols.Field{}
				}
				table.Types[name] = symbols.Type{Fields: fields}
			}
			for _, name := range c.Symbols {
				table.Symbols[name] = symbols.Symbol{}
			}
			layout, err := selectServiceLayout(table)
			if c.Layout == "" {
				if err == nil {
					t.Fatal("unsupported version accepted", layout.name)
				}
			} else if err != nil || layout.name != c.Layout {
				t.Fatal(layout.name, c.Layout, err)
			}
			if got := serviceListSupported(plugin.Environment{Symbols: table}); got != c.ListSupported {
				t.Fatal("list gate", got, c.ListSupported)
			}
			if got := matchServiceVersion(table, serviceVersion{minimum: [3]int{6, 0, 0}, checks: []serviceCheck{{"KdCopyDataBlock", "", true}}}); got != c.Vista {
				t.Fatal("Vista tag", got, c.Vista)
			}
		})
	}
}

func TestServiceLegacyTagIsDirectAndUnaligned(t *testing.T) {
	for _, name := range []string{"services-xp-x86", "services-xp-2003-x64"} {
		t.Run(name, func(t *testing.T) {
			layout := serviceLayouts[name]
			mem := make(flatMemory, 0x3000)
			reader := serviceReader{mem, layout}
			const record = 0x404
			putU32(mem, record+layout.order, 9)
			putU32(mem, record+layout.start, 2)
			putU32(mem, record+layout.state, 1)
			// An apparent linked record must not cause XP's direct-scan branch to walk it.
			if layout.pointerSize == 8 {
				putU64(mem, record, record)
			} else {
				putU32(mem, record, record)
			}
			stats := svcStats{}
			count := 0
			for i := 0; i < 2; i++ {
				err := reader.scanHit(context.Background(), record+layout.tag, true, nil, map[string]bool{}, &stats, func(row evidence.Row) error {
					count++
					if row.Provenance.Offset != "0x404" {
						t.Fatal(row.Provenance)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if count != 2 || stats.records != 2 || stats.headers != 0 {
				t.Fatal(count, stats)
			}
			if err := reader.scanHit(context.Background(), layout.tag-1, true, nil, nil, &stats, func(evidence.Row) error { t.Fatal("underflow emitted"); return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}
