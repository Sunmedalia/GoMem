// Package wingui reads data-only GUI layouts used by the pinned Windows plugins.
package wingui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Selection struct{ Name, Method string }
type feature struct {
	name, member string
	present      bool
}
type versionRule struct {
	name   string
	lower  []int64
	exact  bool
	checks []feature
}

// Facts from WindowStations._win_version_file_map and OsDistinguisher at the
// locked baseline. Order matters; a later predicate must not override a match.
var versionRules = []versionRule{
	{"gui-win10-19577-x64", []int64{10, 0, 19577}, false, []feature{{"_EPROCESS", "PaeTop", false}, {"_EPROCESS", "IdealProcessorAssignmentBlock", true}}},
	{"gui-win10-19041-x64", []int64{10, 0, 19041}, false, []feature{{"_EPROCESS", "TimerResolutionIgnore", true}, {"_EPROCESS", "VmProcessorHostTransition", true}, {"_KQOS_GROUPING_SETS", "", true}}},
	{"gui-win10-18362-x64", []int64{10, 0, 18362}, false, []feature{{"ObHeaderCookie", "", true}, {"_CM_CACHED_VALUE_INDEX", "", false}, {"_WNF_PROCESS_CONTEXT", "", true}}},
	{"gui-win10-17763-x64", []int64{10, 0, 17763}, false, []feature{{"_EPROCESS", "TrustletIdentity", false}, {"ParentSecurityDomain", "", true}}},
	{"gui-win10-17134-x64", []int64{10, 0, 17134}, false, []feature{{"_EPROCESS", "ProcessFirstResume", true}, {"_EPROCESS", "HighMemoryPriority", true}}},
	{"gui-win10-16299-x64", []int64{10, 0, 16299}, false, []feature{{"ObHeaderCookie", "", true}, {"_HANDLE_TABLE", "HandleCount", false}, {"_EPROCESS", "KeepAliveCounter", false}, {"_EPROCESS", "ControlFlowGuardEnabled", false}}},
	{"gui-win10-15063-x64", []int64{10, 0, 15063}, false, []feature{{"ObHeaderCookie", "", true}, {"_HANDLE_TABLE", "HandleCount", false}, {"_EPROCESS", "KeepAliveCounter", false}}},
	{"gui-win10-10586-x64", []int64{10, 0, 10586}, false, []feature{{"_UNLOADED_DRIVERS", "", false}, {"ObHeaderCookie", "", true}}},
	{"gui-win8-x64", []int64{6, 2}, false, []feature{{"_HANDLE_TABLE", "HandleCount", false}}},
	{"gui-win7sp1-x64", []int64{6, 1, 7601}, true, []feature{{"_EPROCESS", "VdmObjects", false}, {"_EPROCESS", "UmsScheduledThreads", true}, {"_EPROCESS", "QuotaUsage", false}, {"_EPROCESS", "WnfContext", false}}},
	{"gui-win7sp0-x64", []int64{6, 1, 7600}, true, []feature{{"_EPROCESS", "VdmObjects", true}, {"_EPROCESS", "UmsScheduledThreads", false}, {"_EPROCESS", "QuotaUsage", false}, {"_EPROCESS", "WnfContext", false}}},
}

// Select preserves the original PE tuple order: major, minor, revision, build.
// OsDistinguisher unpacks four elements before comparing; three-element metadata
// therefore falls back to symbol features. Its exact Win7 checks compare a
// four-element tuple to a three-element tuple and cannot succeed via metadata.
func Select(table symbols.SymbolTable) (Selection, error) {
	if table == nil || table.PointerSize() != 8 {
		return Selection{}, fmt.Errorf("GUI layouts require x64 kernel symbols")
	}
	values, metadata := peTuple(table.Metadata()["windows"])
	for _, rule := range versionRules {
		matched, usable := false, metadata
		if metadata {
			if !rule.exact {
				matched, usable = tupleLower(values, rule.lower)
			}
		}
		method := "metadata"
		if !usable {
			matched = matchFeatures(table, rule.checks)
			method = "symbol-fallback"
		}
		if matched {
			return Selection{Name: rule.name, Method: method}, nil
		}
	}
	return Selection{}, fmt.Errorf("unsupported Windows GUI layout")
}
func peTuple(raw json.RawMessage) ([]any, bool) {
	var metadata struct {
		PE map[string]json.RawMessage `json:"pe"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return nil, false
	}
	values := make([]any, 4)
	for i, name := range []string{"major", "minor", "revision", "build"} {
		raw := metadata.PE[name]
		if len(raw) == 0 {
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
func tupleLower(values []any, lower []int64) (bool, bool) {
	for i, want := range lower {
		value, ok := numeric(values[i])
		if !ok {
			return false, false
		}
		cmp := value.Cmp(big.NewRat(want, 1))
		if cmp != 0 {
			return cmp > 0, true
		}
	}
	// The original PE tuple has four elements and every lower bound has 2/3.
	return true, true
}
func matchFeatures(table symbols.SymbolTable, checks []feature) bool {
	for _, check := range checks {
		typ, err := table.Type(check.name)
		if check.member == "" {
			_, symErr := table.Lookup(check.name)
			if (err == nil || symErr == nil) != check.present {
				return false
			}
		} else if err != nil {
			// Original OsDistinguisher treats a missing type differently from a
			// missing field: expected-true checks survive SymbolError; false do not.
			if !check.present {
				return false
			}
		} else {
			_, exists := typ.Fields[check.member]
			if exists != check.present {
				return false
			}
		}
	}
	return true
}
