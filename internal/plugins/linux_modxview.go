package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxModxviewPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.modxview", Upstream: "linux.malware.modxview.Modxview", Platform: "linux", NeedsKernel: true, Description: "Correlate kernel modules across the active list, sysfs and bounded allocation scanning", Parameters: []plugin.Parameter{{Name: "plain-taints", Kind: "bool", Default: "false", Description: "Display pinned plain taint characters instead of descriptions"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Shared list/candidate visit bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}}, Columns: []evidence.Column{{Name: "Name", Kind: "string"}, {Name: "Address", Kind: "address"}, {Name: "In procfs", Kind: "bool"}, {Name: "In sysfs", Kind: "bool"}, {Name: "In scan", Kind: "bool"}, {Name: "Taints", Kind: "string"}, {Name: "TaintsRaw", Kind: "uint64"}, {Name: "Source", Kind: "string"}, {Name: "SourceOffset", Kind: "address"}, {Name: "KObjectName", Kind: "string"}, {Name: "RefCount", Kind: "int64"}, {Name: "Selected", Kind: "bool"}, {Name: "Gatherers", Kind: "structure"}, {Name: "Base", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Size", Kind: "uint64"}, {Name: "CoreTextSize", Kind: "uint64"}, {Name: "InitSize", Kind: "uint64"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Status", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}}}, linuxModxview}}
}

type linuxTaintFlag struct {
	char            rune
	bit             uint
	description     string
	present, module bool
}

var linuxTaintFlags = []linuxTaintFlag{
	{'P', 0, "PROPRIETARY_MODULE", true, true}, {'G', 0, "PROPRIETARY_MODULE", false, true}, {'F', 1, "FORCED_MODULE", true, false}, {'S', 2, "CPU_OUT_OF_SPEC", true, false}, {'R', 3, "FORCED_RMMOD", true, false}, {'M', 4, "MACHINE_CHECK", true, false}, {'B', 5, "BAD_PAGE", true, false}, {'U', 6, "USER", true, false}, {'D', 7, "DIE", true, false}, {'A', 8, "OVERRIDDEN_ACPI_TABLE", true, false}, {'W', 9, "WARN", true, false}, {'C', 10, "CRAP", true, true}, {'I', 11, "FIRMWARE_WORKAROUND", true, false}, {'O', 12, "OOT_MODULE", true, true}, {'E', 13, "UNSIGNED_MODULE", true, true}, {'L', 14, "SOFTLOCKUP", true, false}, {'K', 15, "LIVEPATCH", true, true}, {'X', 16, "AUX", true, true}, {'T', 17, "RANDSTRUCT", true, true}, {'N', 18, "TEST", true, true},
}

func linuxTaintPlain(taints uint64, module bool) string {
	var out strings.Builder
	for _, f := range linuxTaintFlags {
		if module && !f.module {
			continue
		}
		if taints&(uint64(1)<<f.bit) != 0 {
			out.WriteRune(f.char)
		}
	}
	return out.String()
}
func linuxTaintParsed(plain string) string {
	labels := []string{}
	for _, char := range plain {
		found := false
		for _, f := range linuxTaintFlags {
			if f.char == char {
				found = true
				if f.present {
					labels = append(labels, f.description)
				}
				break
			}
		}
		if !found {
			labels = append(labels, fmt.Sprintf("<UNKNOWN_TAINT_CHAR_%c>", char))
		}
	}
	return strings.Join(labels, ",")
}
func linuxModuleTaints(n *linuxModuleRead, taints uint64) (string, error) {
	symbol, err := n.e.Symbols.Lookup("taint_flags")
	if err != nil {
		return linuxTaintPlain(taints, true), nil
	}
	if symbol.Type == nil || symbol.Type.Kind != "array" || symbol.Type.Underlying() == nil {
		return "", fmt.Errorf("taint_flags must declare an array type")
	}
	count := symbol.Type.Count
	if count == 0 {
		return linuxTaintPlain(taints, true), nil
	}
	if count > 256 {
		return "", fmt.Errorf("taint_flags exceeds 256 entries")
	}
	subtype := *symbol.Type.Underlying()
	if subtype.Kind != "struct" {
		return "", fmt.Errorf("taint_flags element is not a structure")
	}
	stride, err := n.e.Objects.Size(subtype)
	if err != nil || stride == 0 {
		return "", fmt.Errorf("invalid taint_flag stride %d: %v", stride, err)
	}
	start, err := n.e.Symbol("taint_flags")
	if err != nil {
		return "", err
	}
	var plain strings.Builder
	for bit := uint64(0); bit < count; bit++ {
		if stride > (^uint64(0)-start)/count {
			return "", fmt.Errorf("taint_flags address overflow")
		}
		at, err := memory.Add(start, bit*stride)
		if err != nil {
			return "", err
		}
		module, err := n.uint(at, subtype.Name, "module")
		if err != nil {
			return "", err
		}
		if module == 0 {
			continue
		}
		yes, yesErr := n.uint(at, subtype.Name, "c_true")
		no, noErr := n.uint(at, subtype.Name, "c_false")
		if yesErr != nil {
			return "", yesErr
		}
		if noErr != nil {
			return "", noErr
		}
		if yes >= 0xd800 && yes <= 0xdfff || no >= 0xd800 && no <= 0xdfff {
			return "", fmt.Errorf("taint character is a Unicode surrogate")
		}
		if yes > 0x10ffff || no > 0x10ffff {
			continue
		}
		if bit < 64 && taints&(uint64(1)<<bit) != 0 {
			plain.WriteRune(rune(yes))
		} else if no != 32 {
			plain.WriteRune(rune(no))
		}
	}
	return plain.String(), nil
}

func linuxModxview(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("module correlation requires kernel memory and symbols")
	}
	plain, err := strconv.ParseBool(p["plain-taints"])
	if err != nil {
		return err
	}
	sources, err := linuxGatherModuleSources(ctx, e, p, out)
	if err != nil {
		return err
	}
	modules := linuxAggregateModuleSources(sources.results)
	for _, a := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := linuxModuleRow(e, a.offset, "module", "")
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		n := sources.reader(fields)
		before := sources.failures.count
		name, nameErr := n.text(a.offset, "module", "name")
		if nameErr != nil {
			r.Cells["Name"] = evidence.Missing("module_name_unreadable", nameErr)
		} else if name == "" {
			r.Cells["Name"] = evidence.Missing("module_name_empty", nil)
		} else {
			r.Cells["Name"] = evidence.Text(name)
		}
		r.Cells["Gatherers"] = evidence.Value{Kind: "structure", Data: map[string]any{"sources": append([]string(nil), a.gatherers...)}}
		has := func(want string) bool {
			for _, got := range a.gatherers {
				if got == want {
					return true
				}
			}
			return false
		}
		r.Cells["In procfs"], r.Cells["In sysfs"], r.Cells["In scan"] = evidence.Bool(has("Lsmod")), evidence.Bool(has("SysFs")), evidence.Bool(has("Scanner"))
		taints, taintErr := n.uint(a.offset, "module", "taints")
		if taintErr != nil {
			r.Cells["TaintsRaw"], r.Cells["Taints"] = evidence.Missing("module_taints_unreadable", taintErr), evidence.Missing("module_taints_unreadable", taintErr)
		} else {
			r.Cells["TaintsRaw"] = evidence.Number(taints)
			value, err := linuxModuleTaints(n, taints)
			if err != nil {
				sources.failures.add(err)
				r.Cells["Taints"] = evidence.Missing("module_taints_unavailable", err)
			} else {
				if !plain {
					value = linuxTaintParsed(value)
				}
				if value == "" {
					r.Cells["Taints"] = evidence.Missing("module_taints_empty", nil)
				} else {
					r.Cells["Taints"] = evidence.Text(value)
				}
			}
		}
		if sources.failures.count > before {
			r.Cells["Error"] = evidence.Missing("module_fields_incomplete", fmt.Errorf("%d module errors", sources.failures.count-before))
		}
		if err := sources.out(r); err != nil {
			return err
		}
	}
	r := linuxModuleRow(e, 0, "summary", "")
	r.Cells["Address"] = evidence.Missing("not_applicable", nil)
	r.Provenance.Offset = ""
	r.Cells["Coverage"] = poolCoverage(map[string]string{"modules": strconv.Itoa(len(modules)), "lsmod": strconv.Itoa(len(sources.results["Lsmod"])), "sysfs": strconv.Itoa(len(sources.results["SysFs"])), "scanner": strconv.Itoa(len(sources.results["Scanner"])), "source_visits": strconv.FormatUint(sources.nodes, 10), "scan_positions": strconv.FormatUint(sources.positions, 10), "scan_unreadable": strconv.FormatUint(sources.unreadable, 10), "scan_self_matches": strconv.FormatUint(sources.selfMatches, 10), "scan_rejected": strconv.FormatUint(sources.rejected, 10), "diagnostics": strconv.FormatUint(sources.diagnostics, 10), "read_layout_errors": strconv.Itoa(sources.failures.count), "scope": "three module sources; missing reads are not evidence of absence"})
	if err := sources.out(r); err != nil {
		return err
	}
	return sources.failures.err("Linux module correlation")
}
