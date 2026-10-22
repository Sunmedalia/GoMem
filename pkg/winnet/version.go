package winnet

import "fmt"

// Version is measured from kernel/KUSER structures. TCPIPRevision is needed
// only for the ambiguous Windows 8.1 x64 layout. Is18363 is the kernel symbol
// metadata/type distinguisher, independent of the debug structure's build.
type Version struct {
	Width                              int
	Major, Minor, Build, TCPIPRevision uint64
	Is18363                            bool
}

type Selection struct {
	Name                                  string
	EffectiveBuild                        uint64
	Exact, Windows10X64, AdditionalTCPTag bool
}

type versionKey struct{ major, minor, build, revision uint64 }

// These are version/layout facts from the fixed baseline. Fallback deliberately
// selects the latest same-NT-version entry, not the nearest lower build.
var versionLayouts = map[int]map[versionKey]string{
	4: {
		{6, 0, 6000, 0}: "netscan-vista-x86", {6, 0, 6001, 0}: "netscan-vista-x86", {6, 0, 6002, 0}: "netscan-vista-x86", {6, 0, 6003, 0}: "netscan-vista-x86",
		{6, 1, 7600, 0}: "netscan-win7-x86", {6, 1, 7601, 0}: "netscan-win7-x86", {6, 1, 8400, 0}: "netscan-win7-x86",
		{6, 2, 9200, 0}: "netscan-win8-x86", {6, 3, 9600, 0}: "netscan-win81-x86",
		{10, 0, 10240, 0}: "netscan-win10-10240-x86", {10, 0, 10586, 0}: "netscan-win10-10586-x86",
		{10, 0, 14393, 0}: "netscan-win10-14393-x86", {10, 0, 15063, 0}: "netscan-win10-15063-x86",
		{10, 0, 16299, 0}: "netscan-win10-15063-x86", {10, 0, 17134, 0}: "netscan-win10-17134-x86",
		{10, 0, 17763, 0}: "netscan-win10-17134-x86", {10, 0, 18362, 0}: "netscan-win10-17134-x86", {10, 0, 18363, 0}: "netscan-win10-17134-x86",
	},
	8: {
		{6, 0, 6000, 0}: "netscan-vista-x64", {6, 0, 6001, 0}: "netscan-vista-sp12-x64", {6, 0, 6002, 0}: "netscan-vista-sp12-x64", {6, 0, 6003, 0}: "netscan-vista-sp12-x64",
		{6, 1, 7600, 0}: "netscan-win7-x64", {6, 1, 7601, 0}: "netscan-win7-x64", {6, 1, 8400, 0}: "netscan-win7-x64",
		{6, 2, 9200, 0}: "netscan-win8-x64", {6, 3, 9600, 0}: "netscan-win81-x64", {6, 3, 9600, 19935}: "netscan-win81-19935-x64",
		{10, 0, 10240, 0}: "netscan-win10-x64", {10, 0, 10586, 0}: "netscan-win10-x64", {10, 0, 14393, 0}: "netscan-win10-x64",
		{10, 0, 15063, 0}: "netscan-win10-15063-x64", {10, 0, 16299, 0}: "netscan-win10-16299-x64",
		{10, 0, 17134, 0}: "netscan-win10-17134-x64", {10, 0, 17763, 0}: "netscan-win10-17763-x64",
		{10, 0, 18362, 0}: "netscan-win10-18362-x64", {10, 0, 18363, 0}: "netscan-win10-18363-x64",
		{10, 0, 19041, 0}: "netscan-win10-19041-x64", {10, 0, 20348, 0}: "netscan-win10-20348-x64",
	},
}

func (v Version) NeedsTCPIPRevision() bool {
	return v.Width == 8 && v.Major == 6 && v.Minor == 3 && v.Build == 9600
}

func Select(v Version) (Selection, error) {
	versions, ok := versionLayouts[v.Width]
	if !ok {
		return Selection{}, fmt.Errorf("network version selection requires 4/8-byte pointers")
	}
	if v.Build == 18362 && v.Is18363 {
		v.Build = 18363
	}
	if !v.NeedsTCPIPRevision() {
		v.TCPIPRevision = 0
	}
	key := versionKey{v.Major, v.Minor, v.Build, v.TCPIPRevision}
	name, exact := versions[key]
	if !exact {
		var latest versionKey
		found := false
		for candidate, value := range versions {
			if candidate.major != v.Major || candidate.minor != v.Minor || candidate.revision > v.TCPIPRevision {
				continue
			}
			if !found || candidate.build > latest.build || candidate.build == latest.build && candidate.revision > latest.revision {
				latest, name, found = candidate, value, true
			}
		}
		if !found {
			return Selection{}, fmt.Errorf("unsupported Windows network version %d.%d.%d", v.Major, v.Minor, v.Build)
		}
	}
	return Selection{Name: name, EffectiveBuild: v.Build, Exact: exact, Windows10X64: v.Width == 8 && v.Major == 10, AdditionalTCPTag: name == "netscan-win10-20348-x64"}, nil
}
