package winshimcache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// OSVersion is the Windows PE version returned by metadata.pe_version. The
// upstream metadata object permits either three or four components, while
// OsDistinguisher only accepts the four-component form.
type OSVersion struct {
	Major, Minor, Revision, Build uint16
	Components                    uint8
}

func (v OSVersion) atLeast(major, minor, revision uint16) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Revision >= revision
}

func (v OSVersion) exact(major, minor, revision uint16) bool {
	return v.Major == major && v.Minor == minor && v.Revision == revision
}

// WindowsVersion returns metadata.windows.pe when major, minor and revision
// exist. Components distinguishes the three- and four-component forms. The
// pinned OsDistinguisher unpack requests four entries, so a three-component
// tuple deliberately falls back to symbol checks.
func WindowsVersion(table symbols.SymbolTable) (OSVersion, bool) {
	if table == nil {
		return OSVersion{}, false
	}
	raw, ok := table.Metadata()["windows"]
	if !ok || len(raw) == 0 {
		return OSVersion{}, false
	}
	values, ok := peTuple(raw)
	if !ok {
		return OSVersion{}, false
	}
	var out [4]uint16
	components := uint8(3)
	for i, value := range values {
		if value == nil {
			if i == 3 {
				continue
			}
			return OSVersion{}, false
		}
		number, ok := numeric(value)
		if !ok || !number.IsInt() || !number.Num().IsUint64() || number.Num().Uint64() > 0xffff {
			return OSVersion{}, false
		}
		out[i] = uint16(number.Num().Uint64())
	}
	if values[3] != nil {
		components = 4
	}
	return OSVersion{out[0], out[1], out[2], out[3], components}, true
}

func peTuple(raw json.RawMessage) ([]any, bool) {
	var metadata struct {
		PE map[string]json.RawMessage `json:"pe"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.PE == nil {
		return nil, false
	}
	values := make([]any, 4)
	for i, name := range []string{"major", "minor", "revision", "build"} {
		raw, ok := metadata.PE[name]
		if !ok {
			if name == "build" {
				continue
			}
			return nil, false
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&values[i]) != nil || values[i] == nil {
			return nil, false
		}
	}
	return values, true
}

func numeric(value any) (*big.Rat, bool) {
	switch v := value.(type) {
	case json.Number:
		n, ok := new(big.Rat).SetString(string(v))
		return n, ok
	case bool:
		if v {
			return big.NewRat(1, 1), true
		}
		return big.NewRat(0, 1), true
	default:
		return nil, false
	}
}

func versionFour(table symbols.SymbolTable) (OSVersion, bool) {
	if table == nil {
		return OSVersion{}, false
	}
	raw, ok := table.Metadata()["windows"]
	if !ok {
		return OSVersion{}, false
	}
	var metadata struct {
		PE map[string]json.RawMessage `json:"pe"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.PE == nil || len(metadata.PE["build"]) == 0 {
		return OSVersion{}, false
	}
	version, ok := WindowsVersion(table)
	return version, ok && version.Components == 4
}

type presenceState int

const (
	presenceUnknown presenceState = iota
	presenceAbsent
	presencePresent
)

func tablePresence(table symbols.SymbolTable, name string) presenceState {
	if table == nil {
		return presenceUnknown
	}
	if _, err := table.Lookup(name); err == nil {
		return presencePresent
	}
	if _, err := table.Type(name); err == nil {
		return presencePresent
	}
	return presenceAbsent
}

func symbolPresence(table symbols.SymbolTable, name string) presenceState {
	if table == nil {
		return presenceUnknown
	}
	if _, err := table.Lookup(name); err == nil {
		return presencePresent
	}
	return presenceAbsent
}

func memberPresence(table symbols.SymbolTable, typ, member string) presenceState {
	if table == nil {
		return presenceUnknown
	}
	t, err := table.Type(typ)
	if err != nil {
		return presenceAbsent
	}
	if _, ok := t.Fields[member]; ok {
		return presencePresent
	}
	return presenceAbsent
}

// Family is the discovery algorithm selected by WindowsVersion.
type Family uint8

const (
	FamilyUnsupported Family = iota
	FamilyXP
	Family2003To7
	Family8OrLater
)

// VersionMatch mirrors a fixed Windows OsDistinguisher. Versioned reports
// whether complete PE metadata selected the result. FallbackChecks retains the
// pinned presence checks that established a metadata-free result.
type VersionMatch struct {
	Value          bool
	Versioned      bool
	FallbackChecks []string
}

func (m VersionMatch) or(other VersionMatch) VersionMatch {
	return VersionMatch{Value: m.Value || other.Value, Versioned: m.Versioned || other.Versioned,
		FallbackChecks: append(append([]string(nil), m.FallbackChecks...), other.FallbackChecks...)}
}

type versionRule struct {
	test     func(OSVersion) bool
	fallback func(symbols.SymbolTable) (bool, []string)
}

func versionedRule(test func(OSVersion) bool, fallback func(symbols.SymbolTable) (bool, []string)) versionRule {
	return versionRule{test: test, fallback: fallback}
}

func (r versionRule) match(table symbols.SymbolTable) VersionMatch {
	if version, ok := versionFour(table); ok {
		return VersionMatch{Value: r.test(version), Versioned: true}
	}
	value, checks := r.fallback(table)
	return VersionMatch{Value: value, FallbackChecks: checks}
}

func presenceRule(name string, want bool) func(symbols.SymbolTable) (bool, []string) {
	return func(table symbols.SymbolTable) (bool, []string) {
		got := tablePresence(table, name)
		return (got == presencePresent) == want, []string{fmt.Sprintf("%s=%t", name, want)}
	}
}

func symbolPresenceRule(name string, want bool) func(symbols.SymbolTable) (bool, []string) {
	return func(table symbols.SymbolTable) (bool, []string) {
		got := symbolPresence(table, name)
		return (got == presencePresent) == want, []string{fmt.Sprintf("symbol:%s=%t", name, want)}
	}
}

func memberRule(typ, member string, want bool) func(symbols.SymbolTable) (bool, []string) {
	return func(table symbols.SymbolTable) (bool, []string) {
		got := memberPresence(table, typ, member)
		return (got == presencePresent) == want, []string{fmt.Sprintf("%s.%s=%t", typ, member, want)}
	}
}

// SymbolVersionChecks implements the fixed fallback list in order. Checks
// short-circuit exactly as OsDistinguisher does.
func SymbolVersionChecks(table symbols.SymbolTable) map[string]VersionMatch {
	rules := map[string]versionRule{
		"is_win10": versionedRule(
			func(v OSVersion) bool { return v.atLeast(10, 0, 0) },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := presenceRule("ObHeaderCookie", true)(t)
				if !value {
					return value, checks
				}
				v, more := memberRule("_HANDLE_TABLE", "HandleCount", false)(t)
				return v, append(checks, more...)
			}),
		"is_windows_8_or_later": versionedRule(
			func(v OSVersion) bool { return v.atLeast(6, 2, 0) },
			func(t symbols.SymbolTable) (bool, []string) {
				return memberRule("_HANDLE_TABLE", "HandleCount", false)(t)
			}),
		"is_windows_8_1_or_later": versionedRule(
			func(v OSVersion) bool { return v.atLeast(6, 3, 0) },
			func(t symbols.SymbolTable) (bool, []string) {
				return memberRule("_KPRCB", "PendingTickFlags", true)(t)
			}),
		"is_windows_7": versionedRule(
			// The pinned distinguisher compares the complete tuple with
			// (6, 1), so four-component Win7 metadata falls back to symbols.
			func(v OSVersion) bool { return v.Components == 4 && v.exact(6, 1, 0) },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := memberRule("_OBJECT_HEADER", "TypeIndex", true)(t)
				if !value {
					return value, checks
				}
				v, more := memberRule("_HANDLE_TABLE", "HandleCount", true)(t)
				return v, append(checks, more...)
			}),
		"is_vista_or_later": versionedRule(
			func(v OSVersion) bool { return v.atLeast(6, 0, 0) },
			func(t symbols.SymbolTable) (bool, []string) {
				return symbolPresenceRule("KdCopyDataBlock", true)(t)
			}),
		"is_2003": versionedRule(
			func(v OSVersion) bool { return v.Major == 5 && v.Minor == 2 },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := symbolPresenceRule("KdCopyDataBlock", false)(t)
				if !value {
					return value, checks
				}
				v, more := memberRule("_HANDLE_TABLE", "HandleCount", true)(t)
				if !v {
					return v, append(checks, more...)
				}
				v, more = presenceRule("_MM_AVL_TABLE", true)(t)
				return v, append(checks, more...)
			}),
		"is_windows_xp_sp3": versionedRule(
			func(v OSVersion) bool { return v.Major == 5 && v.Minor == 1 },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := symbolPresenceRule("KdCopyDataBlock", false)(t)
				if !value {
					return value, checks
				}
				v, more := presenceRule("_MMFREE_POOL_ENTRY", true)(t)
				if !v {
					return v, append(checks, more...)
				}
				value, more = memberRule("_HANDLE_TABLE", "HandleCount", true)(t)
				if !value {
					return value, append(checks, more...)
				}
				return true, append(checks, more...)
			}),
		"is_windows_xp_sp2": versionedRule(
			func(v OSVersion) bool { return v.Major == 5 && v.Minor == 1 },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := symbolPresenceRule("KdCopyDataBlock", false)(t)
				if !value {
					return value, checks
				}
				v, more := presenceRule("_MMFREE_POOL_ENTRY", false)(t)
				if !v {
					return v, append(checks, more...)
				}
				v, more = memberRule("_HANDLE_TABLE", "HandleCount", true)(t)
				return v, append(checks, more...)
			}),
		"is_xp_or_2003": versionedRule(
			func(v OSVersion) bool { return v.atLeast(5, 1, 0) && v.Major < 6 },
			func(t symbols.SymbolTable) (bool, []string) {
				value, checks := symbolPresenceRule("KdCopyDataBlock", false)(t)
				if !value {
					return value, checks
				}
				v, more := memberRule("_HANDLE_TABLE", "HandleCount", true)(t)
				return v, append(checks, more...)
			}),
	}
	out := make(map[string]VersionMatch, len(rules))
	for name, rule := range rules {
		out[name] = rule.match(table)
	}
	return out
}

// Selection records the exact layout and route used by the original plugin.
// XP SP3 intentionally precedes SP2 because the original version table is
// ordered newest to oldest.
type Selection struct {
	Layout         string
	Family         Family
	Is64Bit        bool
	Is81OrLater    bool
	Version        OSVersion
	Versioned      bool
	FallbackChecks []string
}

// SelectLayout applies the pinned 14-entry newest-to-oldest table and then
// chooses the discovery algorithm from the same version predicates.
func SelectLayout(table symbols.SymbolTable) (Selection, error) {
	if table == nil {
		return Selection{}, fmt.Errorf("Shimcache layout selection requires symbols")
	}
	width := table.PointerSize()
	if width != 4 && width != 8 {
		return Selection{}, fmt.Errorf("unsupported Shimcache pointer width %d", width)
	}
	version, _ := WindowsVersion(table)
	checks := SymbolVersionChecks(table)
	versioned := checks["is_win10"].Versioned || checks["is_windows_8_or_later"].Versioned ||
		checks["is_windows_7"].Versioned || checks["is_vista_or_later"].Versioned ||
		checks["is_2003"].Versioned || checks["is_windows_xp_sp3"].Versioned ||
		checks["is_windows_xp_sp2"].Versioned || checks["is_xp_or_2003"].Versioned
	var fallback []string
	match := func(name string) bool {
		value := checks[name]
		fallback = append(fallback, value.FallbackChecks...)
		return value.Value
	}
	is64 := width == 8
	type entry struct {
		ok     bool
		for64  bool
		layout string
	}
	entries := []entry{
		{match("is_win10"), true, "shimcache-win10-x64"},
		{match("is_win10"), false, "shimcache-win10-x86"},
		{checks["is_windows_8_or_later"].Value, true, "shimcache-win8-x64"},
		{checks["is_windows_8_or_later"].Value, false, "shimcache-win8-x86"},
		{checks["is_windows_7"].Value, true, "shimcache-win7-x64"},
		{checks["is_windows_7"].Value, false, "shimcache-win7-x86"},
		{checks["is_vista_or_later"].Value, true, "shimcache-vista-x64"},
		{checks["is_vista_or_later"].Value, false, "shimcache-vista-x86"},
		{checks["is_2003"].Value, false, "shimcache-2003-x86"},
		{checks["is_2003"].Value, true, "shimcache-2003-x64"},
		{checks["is_windows_xp_sp3"].Value, false, "shimcache-xp-sp3-x86"},
		{checks["is_windows_xp_sp2"].Value, false, "shimcache-xp-sp2-x86"},
		{checks["is_xp_or_2003"].Value, true, "shimcache-xp-2003-x64"},
		{checks["is_xp_or_2003"].Value, false, "shimcache-xp-2003-x86"},
	}
	for _, entry := range entries {
		if entry.ok && entry.for64 == is64 {
			family := FamilyUnsupported
			switch entry.layout {
			case "shimcache-xp-sp2-x86", "shimcache-xp-sp3-x86", "shimcache-xp-2003-x64", "shimcache-xp-2003-x86":
				family = FamilyXP
			case "shimcache-2003-x64", "shimcache-2003-x86", "shimcache-vista-x64", "shimcache-vista-x86", "shimcache-win7-x64", "shimcache-win7-x86":
				family = Family2003To7
			case "shimcache-win8-x64", "shimcache-win8-x86", "shimcache-win10-x64", "shimcache-win10-x86":
				family = Family8OrLater
			}
			return Selection{Layout: entry.layout, Family: family, Is64Bit: is64,
				Is81OrLater: checks["is_windows_8_1_or_later"].Value || checks["is_win10"].Value,
				Version:     version, Versioned: versioned, FallbackChecks: uniqueStrings(fallback)}, nil
		}
	}
	return Selection{}, fmt.Errorf("this version of Windows is not supported by Shimcache: %#v", version)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// ModernModuleNames returns the first module list searched by the original
// Windows 8+ path. Only Windows 8.1 and later use ahcache.sys.
func ModernModuleNames(selection Selection) []string {
	if selection.Is81OrLater {
		return []string{"ahcache.sys"}
	}
	return []string{"ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"}
}

// ChooseModernHead preserves the original x86 Windows 8 versus later cache
// choice after exactly two handles have been found.
func ChooseModernHead(selection Selection, heads []uint64) (uint64, error) {
	if len(heads) != 2 {
		return 0, fmt.Errorf("Shimcache requires exactly two handles, found %d", len(heads))
	}
	if !selection.Is64Bit && !selection.Is81OrLater {
		return heads[1], nil
	}
	if !selection.Is81OrLater {
		return heads[0], nil
	}
	return heads[1], nil
}

// ModuleSection is a loaded module's PE section in kernel virtual memory.
type ModuleSection struct {
	ModuleOffset, ModuleBase, Address, VirtualSize uint64
	Name                                           string
}
