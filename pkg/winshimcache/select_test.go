package winshimcache

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type selectionOracleFixture struct {
	Commit string          `json:"commit"`
	Scope  string          `json:"scope"`
	Cases  []selectionCase `json:"cases"`
}

type selectionCase struct {
	Name        string          `json:"name"`
	Width       int             `json:"width"`
	ISF         json.RawMessage `json:"isf"`
	Checks      map[string]bool `json:"checks"`
	Selected    *string         `json:"selected"`
	Route       string          `json:"route"`
	Is81OrLater bool            `json:"is_8_1_or_later"`
}

func selectionOracle(t testing.TB) selectionOracleFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/selection-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture selectionOracleFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 34 {
		t.Fatalf("selection oracle has %d cases", len(fixture.Cases))
	}
	return fixture
}

func selectionTable(t *testing.T, width int, version string, fields map[string]map[string]bool) *symbols.ISF {
	t.Helper()
	bases := map[string]symbols.Type{
		"pointer": {Kind: "int", Size: uint64(width), Endian: "little"},
	}
	types := map[string]symbols.Type{}
	for typ, members := range fields {
		fields := map[string]symbols.Field{}
		for name, present := range members {
			if present {
				fields[name] = symbols.Field{Type: symbols.TypeRef{Kind: "base", Name: "pointer"}}
			}
		}
		types[typ] = symbols.Type{Kind: "struct", Size: 8, Fields: fields}
	}
	table := &symbols.ISF{Bases: bases, Types: types, Symbols: map[string]symbols.Symbol{}}
	if version != "" {
		table.Meta = map[string]json.RawMessage{"windows": json.RawMessage(fmt.Sprintf(`{"pe":%s}`, version))}
	} else {
		table.Meta = map[string]json.RawMessage{}
	}
	return table
}

func TestShimcacheLayoutSelectionPinnedOrder(t *testing.T) {
	tests := []struct {
		name, version, layout string
		width                 int
		fields                map[string]map[string]bool
		family                Family
		is81                  bool
	}{
		{"win10-x64", `{"major":10,"minor":0,"revision":19041,"build":1}`, "shimcache-win10-x64", 8, nil, Family8OrLater, true},
		{"win10-x86", `{"major":10,"minor":0,"revision":19041,"build":1}`, "shimcache-win10-x86", 4, nil, Family8OrLater, true},
		{"win8.1-x64", `{"major":6,"minor":3,"revision":9600,"build":1}`, "shimcache-win8-x64", 8, nil, Family8OrLater, true},
		{"win8.1-x86", `{"major":6,"minor":3,"revision":9600,"build":1}`, "shimcache-win8-x86", 4, nil, Family8OrLater, true},
		{"win8-x64", `{"major":6,"minor":2,"revision":9200,"build":1}`, "shimcache-win8-x64", 8, nil, Family8OrLater, false},
		{"win8-x86", `{"major":6,"minor":2,"revision":9200,"build":1}`, "shimcache-win8-x86", 4, nil, Family8OrLater, false},
		{"win7-x64", `{"major":6,"minor":1,"revision":7601,"build":1}`, "shimcache-vista-x64", 8, nil, Family2003To7, false},
		{"win7-x86", `{"major":6,"minor":1,"revision":7600,"build":1}`, "shimcache-vista-x86", 4, nil, Family2003To7, false},
		{"vista-x64", `{"major":6,"minor":0,"revision":6002,"build":1}`, "shimcache-vista-x64", 8, nil, Family2003To7, false},
		{"vista-x86", `{"major":6,"minor":0,"revision":6002,"build":1}`, "shimcache-vista-x86", 4, nil, Family2003To7, false},
		{"2003-x64", `{"major":5,"minor":2,"revision":3790,"build":1}`, "shimcache-2003-x64", 8, nil, Family2003To7, false},
		{"2003-x86", `{"major":5,"minor":2,"revision":3790,"build":1}`, "shimcache-2003-x86", 4, nil, Family2003To7, false},
		{"xp-sp3", `{"major":5,"minor":1,"revision":2600,"build":1}`, "shimcache-xp-sp3-x86", 4,
			map[string]map[string]bool{"_MMFREE_POOL_ENTRY": {}, "_HANDLE_TABLE": {"HandleCount": true}}, FamilyXP, false},
		{"xp-sp2", `{"major":5,"minor":1,"revision":2600}`, "shimcache-xp-sp2-x86", 4,
			map[string]map[string]bool{"_HANDLE_TABLE": {"HandleCount": true}}, FamilyXP, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := selectionTable(t, test.width, test.version, test.fields)
			got, err := SelectLayout(table)
			if err != nil {
				t.Fatal(err)
			}
			if got.Layout != test.layout || got.Family != test.family || got.Is64Bit != (test.width == 8) || got.Is81OrLater != test.is81 || got.Versioned != (test.name != "xp-sp2") {
				t.Fatalf("selection = %+v", got)
			}
		})
	}
}

func TestShimcacheSelectionOriginal(t *testing.T) {
	fixture := selectionOracle(t)
	for _, original := range fixture.Cases {
		t.Run(original.Name, func(t *testing.T) {
			table, err := symbols.Parse(original.ISF)
			if err != nil {
				t.Fatal(err)
			}
			if table.PointerSize() != original.Width {
				t.Fatalf("oracle pointer width %d != %d", table.PointerSize(), original.Width)
			}
			checks := SymbolVersionChecks(table)
			for name, want := range original.Checks {
				if got := checks[name].Value; got != want {
					t.Errorf("%s = %t, want %t", name, got, want)
				}
			}
			if original.Selected == nil {
				if _, err := SelectLayout(table); err == nil {
					t.Fatal("unsupported version selected a layout")
				}
				return
			}
			selection, err := SelectLayout(table)
			if err != nil {
				t.Fatal(err)
			}
			if selection.Layout != *original.Selected {
				t.Fatalf("layout = %q, want %q", selection.Layout, *original.Selected)
			}
			wantFamily := map[string]Family{
				"modern": Family8OrLater, "2003-to-7": Family2003To7,
				"xp": FamilyXP, "unsupported": FamilyUnsupported,
			}[original.Route]
			if selection.Family != wantFamily {
				t.Fatalf("family = %v, want %v", selection.Family, wantFamily)
			}
			if selection.Is81OrLater != original.Is81OrLater {
				t.Fatalf("8.1+ = %t, want %t", selection.Is81OrLater, original.Is81OrLater)
			}
		})
	}
}

func TestShimcacheLayoutSelectionFallbacks(t *testing.T) {
	tests := []struct {
		name, layout string
		width        int
		symbols      []string
		fields       map[string]map[string]bool
	}{
		{"win10", "shimcache-win10-x64", 8, []string{"ObHeaderCookie"}, map[string]map[string]bool{"_HANDLE_TABLE": {"HandleCount": false}}},
		{"win8", "shimcache-win8-x86", 4, []string{"KdCopyDataBlock"}, map[string]map[string]bool{
			"_OBJECT_HEADER": {"TypeIndex": false}, "_HANDLE_TABLE": {"HandleCount": false},
			"_KPRCB": {"PendingTickFlags": false}}},
		{"win7", "shimcache-win7-x64", 8, nil, map[string]map[string]bool{"_OBJECT_HEADER": {"TypeIndex": true}, "_HANDLE_TABLE": {"HandleCount": true}}},
		{"vista", "shimcache-vista-x86", 4, []string{"KdCopyDataBlock"}, map[string]map[string]bool{
			"_OBJECT_HEADER": {"TypeIndex": false}, "_HANDLE_TABLE": {"HandleCount": true}}},
		{"2003", "shimcache-2003-x64", 8, []string{"_MM_AVL_TABLE"}, map[string]map[string]bool{"_HANDLE_TABLE": {"HandleCount": true}}},
		{"xp-sp3", "shimcache-xp-sp3-x86", 4, []string{"_MMFREE_POOL_ENTRY"}, map[string]map[string]bool{"_HANDLE_TABLE": {"HandleCount": true}}},
		{"xp-sp2", "shimcache-xp-sp2-x86", 4, nil, map[string]map[string]bool{"_HANDLE_TABLE": {"HandleCount": true}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := selectionTable(t, test.width, "", test.fields)
			for _, name := range test.symbols {
				table.Symbols[name] = symbols.Symbol{Address: 0x1000}
			}
			got, err := SelectLayout(table)
			if err != nil {
				t.Fatal(err)
			}
			if got.Layout != test.layout || got.Versioned || len(got.FallbackChecks) == 0 {
				t.Fatalf("selection = %+v", got)
			}
		})
	}
}

func TestShimcacheModernHeadChoice(t *testing.T) {
	heads := []uint64{0x1000, 0x2000}
	for _, test := range []struct {
		name string
		sel  Selection
		want uint64
	}{
		{"win8-x64", Selection{Is64Bit: true, Is81OrLater: false}, 0x1000},
		{"win8-x86", Selection{Is64Bit: false, Is81OrLater: false}, 0x2000},
		{"win81-x64", Selection{Is64Bit: true, Is81OrLater: true}, 0x2000},
		{"win10-x86", Selection{Is64Bit: false, Is81OrLater: true}, 0x2000},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ChooseModernHead(test.sel, heads)
			if err != nil || got != test.want {
				t.Fatal(got, err)
			}
		})
	}
	if _, err := ChooseModernHead(Selection{}, heads[:1]); err == nil {
		t.Fatal("accepted one handle")
	}
}

func TestShimcacheVersionMismatchAndBounds(t *testing.T) {
	table := selectionTable(t, 8, `{"major":4,"minor":0,"revision":0,"build":1}`, nil)
	if _, err := SelectLayout(table); err == nil {
		t.Fatal("unsupported version accepted")
	}
	if _, err := SelectLayout(selectionTable(t, 2, "", nil)); err == nil {
		t.Fatal("unsupported pointer width accepted")
	}
	if _, ok := WindowsVersion(selectionTable(t, 8, `{"major":70000,"minor":0,"revision":0,"build":1}`, nil)); ok {
		t.Fatal("out-of-range version accepted")
	}
}
