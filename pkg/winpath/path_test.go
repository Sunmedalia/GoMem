package winpath

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPinnedWindowsPathAndCandidateOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/path-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Path, Name string
			Candidates []string
		}
		Casing []struct {
			Input, Lower string
			Upper        string `json:"upper_initial"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 1109 || len(fixture.Casing) != 87 {
		t.Fatal("reference drift")
	}
	for _, c := range fixture.Cases {
		name := ModuleName(c.Path)
		if name != c.Name {
			t.Fatalf("%q: name %q expected %q", c.Path, name, c.Name)
		}
		if got := PDBCandidates(name); !reflect.DeepEqual(got, c.Candidates) {
			t.Fatalf("%q: candidates %q expected %q", c.Path, got, c.Candidates)
		}
	}
	for _, c := range fixture.Casing {
		if Lower(c.Input) != c.Lower || UpperInitial(c.Input) != c.Upper {
			t.Fatalf("%q: casing %q/%q expected %q/%q", c.Input, Lower(c.Input), UpperInitial(c.Input), c.Lower, c.Upper)
		}
	}
}
func TestUnicode16AllScalarValues(t *testing.T) {
	raw, err := os.ReadFile("testdata/unicode16-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version string `json:"unicode_version"`
		Scalars int    `json:"scalar_values"`
		Rows    []struct {
			Code         rune
			Lower, Upper string
			Ignored      bool
			Cased        bool `json:"effective_cased"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != UnicodeVersion || fixture.Scalars != 1112064 {
		t.Fatal("Unicode reference drift")
	}
	index := 0
	for code := rune(0); code <= utf8.MaxRune; code++ {
		if code >= 0xd800 && code <= 0xdfff {
			continue
		}
		lower, upper := string(code), string(code)
		ignored, cased := false, false
		if index < len(fixture.Rows) && fixture.Rows[index].Code == code {
			r := fixture.Rows[index]
			index++
			lower, upper, ignored, cased = r.Lower, r.Upper, r.Ignored, r.Cased
		}
		if got := Lower(string(code)); got != lower {
			t.Fatalf("%U lower %q expected %q", code, got, lower)
		}
		if got := UpperInitial(string(code)); got != upper {
			t.Fatalf("%U upper %q expected %q", code, got, upper)
		}
		if got := inRanges(ignorableRanges[:], code); got != ignored {
			t.Fatalf("%U ignored %v expected %v", code, got, ignored)
		}
		if got := inRanges(casedRanges[:], code) && !ignored; got != cased {
			t.Fatalf("%U effective cased %v expected %v", code, got, cased)
		}
	}
	if index != len(fixture.Rows) {
		t.Fatal("unordered/unconsumed Unicode cases")
	}
}
func TestCasingTablesAndLinearContexts(t *testing.T) {
	for _, table := range [][]caseMapping{lowerMappings[:], upperMappings[:]} {
		previous := rune(-1)
		for _, item := range table {
			if item.code <= previous || !utf8.ValidString(item.text) || item.text == "" {
				t.Fatal(item)
			}
			previous = item.code
		}
	}
	for _, table := range [][]runeRange{casedRanges[:], ignorableRanges[:]} {
		previous := rune(-1)
		for _, item := range table {
			if item.first <= previous || item.last < item.first {
				t.Fatal(item)
			}
			previous = item.last
		}
	}
	text := "AΣ" + strings.Repeat("\u0301", 65536) + "A"
	if got := Lower(text); !strings.HasPrefix(got, "aσ") || len(got) != len(text) {
		t.Fatal("long context handling")
	}
}
func FuzzWindowsModulePath(f *testing.F) {
	for _, s := range []string{`C:\Windows\İΣ.dll`, `\\server\share`, `\\?\UNC\host\share\ß.DLL`, `C:abc`, "AΣ\u0301A"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 65536 {
			return
		}
		name := ModuleName(path)
		if !utf8.ValidString(name) || strings.ContainsAny(name, `\/`) {
			t.Fatal("invalid basename")
		}
		if len(name) > 4*len(path)+16 {
			t.Fatal("unbounded case expansion")
		}
		candidates := PDBCandidates(name)
		if len(candidates) < 2 || len(candidates) > 4 {
			t.Fatal("candidate bound")
		}
		for _, c := range candidates {
			if !utf8.ValidString(c) || len(c) > 4*len(name)+32 {
				t.Fatal("invalid candidate")
			}
		}
	})
}
func BenchmarkWindowsModulePath(b *testing.B) {
	for b.Loop() {
		ModuleName(`\Device\HarddiskVolume2\Windows\System32\İΣßFixture.DLL`)
	}
}
