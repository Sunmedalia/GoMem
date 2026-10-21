package plugins

import (
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Offsets are facts extracted from the pinned service ISFs by
// tools/build_service_oracle.py. Some upstream fields extend past their declared
// structure size, so service records use bounded primitive reads directly.
type serviceLayout struct {
	name                                                                   string
	pointerSize                                                            int
	headerPtr, prev, order, start, namePtr, displayPtr, serviceType, state uint64
	processPtr, driverPtr, binaryPtr, pid, tag                             uint64
	legacy                                                                 bool
}
type serviceReader struct {
	layer  memory.MemoryLayer
	layout serviceLayout
}
type serviceCheck struct {
	name, member string
	present      bool
}
type serviceVersion struct {
	minimum [3]int
	exact   bool
	maximum [3]int
	checks  []serviceCheck
}

func serviceWin10Checks(keepAlive bool) []serviceCheck {
	return []serviceCheck{{"ObHeaderCookie", "", true}, {"_HANDLE_TABLE", "HandleCount", false}, {"_EPROCESS", "KeepAliveCounter", keepAlive}}
}

// A three-component PE version cannot be unpacked by the pinned distinguisher;
// it falls back to symbol/type checks. Complete metadata takes precedence.
func matchServiceVersion(table symbols.SymbolTable, version serviceVersion) bool {
	var meta struct {
		PE struct{ Major, Minor, Revision, Build *int } `json:"pe"`
	}
	if json.Unmarshal(table.Metadata()["windows"], &meta) == nil && meta.PE.Major != nil && meta.PE.Minor != nil && meta.PE.Revision != nil && meta.PE.Build != nil {
		if version.exact {
			return false
		} // pinned comparison: four-tuple == three-tuple
		actual := [4]int{*meta.PE.Major, *meta.PE.Minor, *meta.PE.Revision, *meta.PE.Build}
		compare := func(bound [3]int) int {
			for i := 0; i < 3; i++ {
				if actual[i] < bound[i] {
					return -1
				}
				if actual[i] > bound[i] {
					return 1
				}
			}
			return 1 // equal prefix: a four-tuple is greater than a three-tuple
		}
		return compare(version.minimum) >= 0 && (version.maximum == [3]int{} || compare(version.maximum) < 0)
	}
	for _, check := range version.checks {
		typ, typeErr := table.Type(check.name)
		if check.member == "" {
			_, symbolErr := table.Lookup(check.name)
			if (typeErr == nil || symbolErr == nil) != check.present {
				return false
			}
		} else if typeErr != nil {
			// Preserve the pinned missing-type behavior, including its positive case.
			if !check.present {
				return false
			}
		} else if _, found := typ.Fields[check.member]; found != check.present {
			return false
		}
	}
	return true
}

type serviceLayoutRule struct {
	version serviceVersion
	width   int
	name    string
}

func selectServiceLayout(table symbols.SymbolTable) (serviceLayout, error) {
	if table.PointerSize() != 4 && table.PointerSize() != 8 {
		return serviceLayout{}, fmt.Errorf("unsupported service pointer size %d", table.PointerSize())
	}
	win10 := func(cfg bool) []serviceCheck {
		return append(serviceWin10Checks(false), serviceCheck{"_EPROCESS", "ControlFlowGuardEnabled", cfg})
	}
	rules := []serviceLayoutRule{
		{serviceVersion{minimum: [3]int{10, 0, 25398}, checks: []serviceCheck{{"_EPROCESS", "MmSlabIdentity", true}, {"_EPROCESS", "EnableProcessImpersonationLogging", true}}}, 8, "services-win10-25398-x64"},
	}
	add := func(minimum [3]int, checks []serviceCheck, x64, x86 string) {
		if x64 != "" {
			rules = append(rules, serviceLayoutRule{serviceVersion{minimum: minimum, checks: checks}, 8, x64})
		}
		if x86 != "" {
			rules = append(rules, serviceLayoutRule{serviceVersion{minimum: minimum, checks: checks}, 4, x86})
		}
	}
	add([3]int{10, 0, 19041}, []serviceCheck{{"_EPROCESS", "TimerResolutionIgnore", true}, {"_EPROCESS", "VmProcessorHostTransition", true}, {"_KQOS_GROUPING_SETS", "", true}}, "services-win10-19041-x64", "services-win10-19041-x86")
	add([3]int{10, 0, 18362}, []serviceCheck{{"ObHeaderCookie", "", true}, {"_CM_CACHED_VALUE_INDEX", "", false}, {"_WNF_PROCESS_CONTEXT", "", true}}, "services-win10-18362-x64", "services-win10-18362-x86")
	add([3]int{10, 0, 17763}, []serviceCheck{{"_EPROCESS", "TrustletIdentity", false}, {"ParentSecurityDomain", "", true}}, "", "services-win10-17763-x86")
	add([3]int{10, 0, 16299}, win10(false), "services-win10-16299-x64", "services-win10-16299-x86")
	for _, item := range []struct {
		width  int
		suffix string
	}{{8, "x64"}, {4, "x86"}} {
		rules = append(rules, serviceLayoutRule{serviceVersion{exact: true, checks: win10(true)}, item.width, "services-win10-15063-" + item.suffix})
	}
	for _, item := range []struct {
		width  int
		suffix string
	}{{8, "x64"}, {4, "x86"}} {
		rules = append(rules, serviceLayoutRule{serviceVersion{minimum: [3]int{10, 0, 0}, maximum: [3]int{10, 0, 15063}, checks: serviceWin10Checks(true)}, item.width, "services-win8-" + item.suffix})
	}
	// The second Windows 8 entry is also marked x64 in the pinned map. It is
	// unreachable; x86 Windows 8 therefore falls through to the Vista layout.
	add([3]int{6, 2, 0}, []serviceCheck{{"_HANDLE_TABLE", "HandleCount", false}}, "services-win8-x64", "")
	add([3]int{6, 0, 0}, []serviceCheck{{"KdCopyDataBlock", "", true}}, "services-vista-x64", "services-vista-x86")
	xpChecks := []serviceCheck{{"KdCopyDataBlock", "", false}, {"_HANDLE_TABLE", "HandleCount", true}}
	rules = append(rules,
		serviceLayoutRule{serviceVersion{minimum: [3]int{5, 1, 0}, maximum: [3]int{5, 2, 0}, checks: xpChecks}, 4, "services-xp-x86"},
		serviceLayoutRule{serviceVersion{minimum: [3]int{5, 1, 0}, maximum: [3]int{6, 0, 0}, checks: xpChecks}, 8, "services-xp-2003-x64"})
	for _, rule := range rules {
		if rule.width == table.PointerSize() && matchServiceVersion(table, rule.version) {
			return serviceLayouts[rule.name], nil
		}
	}
	return serviceLayout{}, fmt.Errorf("no service layout matches the kernel symbols and PE version")
}
