// Package winpath implements Windows module names and Unicode casing independent
// of the host OS and Go's Unicode version. Its Unicode data version is explicit.
package winpath

import (
	"sort"
	"strings"
	"unicode/utf8"
)

type caseMapping struct {
	code rune
	text string
}
type runeRange struct{ first, last rune }

func mapped(table []caseMapping, r rune) string {
	i := sort.Search(len(table), func(i int) bool { return table[i].code >= r })
	if i < len(table) && table[i].code == r {
		return table[i].text
	}
	return string(r)
}
func inRanges(table []runeRange, r rune) bool {
	i := sort.Search(len(table), func(i int) bool { return table[i].last >= r })
	return i < len(table) && table[i].first <= r
}

// Lower applies Unicode 16 default full lowercase mappings. Final Sigma uses
// original-string contexts; language-specific Turkish/Azeri/Lithuanian rules
// are excluded, matching Python's locale-independent str.lower.
func Lower(s string) string {
	runes := []rune(s)
	after := make([]bool, len(runes))
	state := false
	for i := len(runes) - 1; i >= 0; i-- {
		after[i] = state
		if !inRanges(ignorableRanges[:], runes[i]) {
			state = inRanges(casedRanges[:], runes[i])
		}
	}
	var out strings.Builder
	out.Grow(len(s))
	before := false
	for i, r := range runes {
		if r == 0x3a3 {
			if before && !after[i] {
				out.WriteRune(0x3c2)
			} else {
				out.WriteRune(0x3c3)
			}
		} else {
			out.WriteString(mapped(lowerMappings[:], r))
		}
		if !inRanges(ignorableRanges[:], r) {
			before = inRanges(casedRanges[:], r)
		}
	}
	return out.String()
}

// UpperInitial uppercases the first Unicode character, including expansions,
// leaving subsequent characters unchanged.
func UpperInitial(s string) string {
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)
	return mapped(upperMappings[:], r) + s[n:]
}

// Basename follows Windows drive, UNC/device and separator rules on every host.
// A drive/share-only path or trailing separator has an empty basename.
func Basename(path string) string {
	r := []rune(strings.ReplaceAll(path, "/", `\`))
	if len(r) >= 2 && r[0] == '\\' && r[1] == '\\' {
		start := 2
		if len(r) >= 8 && strings.EqualFold(string(r[:8]), `\\?\UNC\`) {
			start = 8
		}
		first := -1
		for i := start; i < len(r); i++ {
			if r[i] == '\\' {
				first = i
				break
			}
		}
		if first < 0 {
			return ""
		}
		second := -1
		for i := first + 1; i < len(r); i++ {
			if r[i] == '\\' {
				second = i
				break
			}
		}
		if second < 0 {
			return ""
		}
		r = r[second+1:]
	} else if len(r) >= 2 && r[1] == ':' {
		r = r[2:]
	}
	for i := len(r) - 1; i >= 0; i-- {
		if r[i] == '\\' {
			return string(r[i+1:])
		}
	}
	return string(r)
}
func ModuleName(path string) string { return Lower(Basename(path)) }

// PDBCandidates reproduces the pinned helper's last-three-character replacement
// and first-character uppercase variant. Input is a normalized module basename.
func PDBCandidates(name string) []string {
	if name == "ntoskrnl.exe" {
		return []string{"ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "ntoskrnl.pdb"}
	}
	r := []rune(name)
	name = string(r[:max(0, len(r)-3)]) + "pdb"
	return []string{name, UpperInitial(name)}
}
