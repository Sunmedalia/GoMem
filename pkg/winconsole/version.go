package winconsole

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

// Version uses measured KUSER/debug values. Revision is the conhost product
// revision when available; the baseline's physical fallback reads file revision.
// It is ignored unless the exact OS build requires further inspection.
type Version struct {
	Width                         int
	Major, Minor, Build, Revision uint64
}
type Selection struct {
	Name                                             string
	Exact, Windows10X64                              bool
	MatchedBuild, MatchedRevision, EffectiveRevision uint64
}
type versionKey struct{ major, minor, build, revision uint64 }

// VersionFromMemory reads KUSER and KdVersionBlock from a caller-supplied Intel
// kernel address space. It never substitutes ISF PE metadata for image bytes.
// Conhost revision acquisition remains the caller's responsibility when needed.
func VersionFromMemory(ctx context.Context, reader *object.Reader, kernelBase uint64) (Version, error) {
	v := Version{Width: reader.Symbols.PointerSize()}
	if v.Width != 4 && v.Width != 8 {
		return v, fmt.Errorf("conhost version reads require 4/8-byte pointers")
	}
	debug, err := reader.Symbols.Lookup("KdVersionBlock")
	if err != nil {
		return v, err
	}
	at, err := memory.Add(kernelBase, debug.Address)
	if err != nil {
		return v, err
	}
	v.Build, err = reader.Uint(ctx, at, "_DBGKD_GET_VERSION64", "MinorVersion")
	if err != nil {
		return v, err
	}
	kuser := uint64(0xffdf0000)
	if v.Width == 8 {
		kuser = 0xfffff78000000000
	}
	v.Major, err = reader.Uint(ctx, kuser, "_KUSER_SHARED_DATA", "NtMajorVersion")
	if err != nil {
		return v, err
	}
	v.Minor, err = reader.Uint(ctx, kuser, "_KUSER_SHARED_DATA", "NtMinorVersion")
	return v, err
}

var versionLayouts = map[versionKey]string{
	{10, 0, 17763, 1}:    "consoles-win10-17763-x64",
	{10, 0, 17763, 3232}: "consoles-win10-17763-3232-x64",
	{10, 0, 18362, 0}:    "consoles-win10-18362-x64",
	{10, 0, 19041, 0}:    "consoles-win10-19041-x64",
	{10, 0, 20348, 1}:    "consoles-win10-20348-x64",
	{10, 0, 20348, 1970}: "consoles-win10-20348-1970-x64",
	{10, 0, 20348, 2461}: "consoles-win10-20348-2461-x64",
	{10, 0, 20348, 2520}: "consoles-win10-20348-2461-x64",
	{10, 0, 22000, 0}:    "consoles-win10-22000-x64",
	{10, 0, 22621, 1}:    "consoles-win10-22621-x64",
	{10, 0, 22621, 3527}: "consoles-win10-22621-3527-x64",
	// The baseline maps this build to 22000 despite bundling a 25398 file.
	{10, 0, 25398, 0}: "consoles-win10-22000-x64",
}

func (v Version) NeedsRevision() bool {
	if v.Width != 8 {
		return false
	}
	for k := range versionLayouts {
		if k.major == v.Major && k.minor == v.Minor && k.build == v.Build && k.revision != 0 {
			return true
		}
	}
	return false
}
func Select(v Version) (Selection, error) {
	if v.Width != 4 && v.Width != 8 {
		return Selection{}, fmt.Errorf("conhost selection requires 4/8-byte pointers")
	}
	if v.Width == 4 {
		return Selection{}, fmt.Errorf("baseline has no x86 conhost layouts")
	}
	if !v.NeedsRevision() {
		v.Revision = 0
	}
	k := versionKey{v.Major, v.Minor, v.Build, v.Revision}
	name, exact := versionLayouts[k]
	if !exact {
		found := false
		for candidate, value := range versionLayouts {
			if candidate.major != v.Major || candidate.minor != v.Minor || candidate.build > v.Build || candidate.revision > v.Revision {
				continue
			}
			if !found || candidate.build > k.build || candidate.build == k.build && candidate.revision > k.revision {
				k, name, found = candidate, value, true
			}
		}
		if !found {
			return Selection{}, fmt.Errorf("unsupported conhost version %d.%d.%d revision %d", v.Major, v.Minor, v.Build, v.Revision)
		}
	}
	return Selection{Name: name, Exact: exact, Windows10X64: v.Major == 10, MatchedBuild: k.build, MatchedRevision: k.revision, EffectiveRevision: v.Revision}, nil
}
