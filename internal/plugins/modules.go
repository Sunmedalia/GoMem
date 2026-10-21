package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func modulePlugins() []builtin {
	var out []builtin
	for _, os := range []string{"windows", "linux"} {
		name, up := os+".modules", os+".modules.Modules"
		fn := windowsModules
		if os == "linux" {
			name, up = "linux.lsmod", "linux.lsmod.Lsmod"
			fn = linuxModules
		}
		s := plugin.Spec{Name: name, Upstream: up, Platform: os, NeedsKernel: true, Description: "Enumerate loaded kernel modules from the kernel list", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "65536", Description: "Traversal safety limit"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "Size", Kind: "uint64"}}}
		if os == "linux" {
			s.Parameters = append(s.Parameters, plugin.Parameter{Name: "plain-taints", Kind: "bool", Default: "false", Description: "Display pinned plain taint characters instead of descriptions"})
			s.Columns = append(s.Columns, []evidence.Column{{Name: "Module Name", Kind: "string"}, {Name: "Code Size", Kind: "address"}, {Name: "Taints", Kind: "string"}, {Name: "Load Arguments", Kind: "string"}, {Name: "File Output", Kind: "string"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "Error", Kind: "missing"}}...)
		}
		if os == "windows" {
			s.Parameters = append(s.Parameters, plugin.Parameter{Name: "base", Kind: "string", Description: "Optional exact module base; zero disables filtering"}, plugin.Parameter{Name: "name", Kind: "string", Description: "Case-sensitive substring of the base module name"}, plugin.Parameter{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct listed PE modules, using typed session layers when needed"}, plugin.Parameter{Name: "max-session-layers", Kind: "uint", Default: "256", Description: "Maximum unique session roots cached for extraction (1..4096)"})
			s.Columns = append(s.Columns, []evidence.Column{{Name: "Path", Kind: "string"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "Patches", Kind: "structure"}, {Name: "ExtractionAttempts", Kind: "structure"}}...)
		}
		out = append(out, builtin{s, fn})
	}
	return out
}
func linuxModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	head, err := e.Symbol("modules")
	if err != nil {
		return err
	}
	f, err := e.Objects.Field("module", "list")
	if err != nil {
		return err
	}
	plain, err := strconv.ParseBool(p["plain-taints"])
	if err != nil {
		return err
	}
	s := &linuxModuleSources{ctx: ctx, e: e, emit: out}
	err = e.Objects.WalkList(ctx, head, f.Offset, max, func(a uint64) error {
		row, err := linuxModuleDisplayRow(s, linuxModuleInfo{offset: a}, plain)
		if err != nil {
			return err
		}
		row.Cells["RecordType"] = evidence.Text("module")
		row.Cells["Source"] = evidence.Text("Lsmod")
		row.Cells["Status"] = evidence.Text("listed")
		return s.out(row)
	})
	if err != nil {
		return err
	}
	return s.failures.err("Linux module enumeration")
}
func unicodeString(ctx context.Context, e plugin.Environment, a uint64, t, field string) (string, error) {
	f, err := e.Objects.Field(t, field)
	if err != nil {
		return "", err
	}
	base, err := memory.Add(a, f.Offset)
	if err != nil {
		return "", err
	}
	n, err := e.Objects.Uint(ctx, base, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	if n > 65534 || n%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16 length")
	}
	ptr, err := e.Objects.Uint(ctx, base, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return "", err
	}
	b, err := memory.Read(ctx, e.Kernel, ptr, int(n))
	if err != nil {
		return "", err
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u)), nil
}
func windowsModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	var base uint64
	if p["base"] != "" {
		base, err = strconv.ParseUint(p["base"], 0, 64)
		if err != nil {
			return fmt.Errorf("base: %w", err)
		}
	}
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	f, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		f, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return err
	}
	maxLayers, err := strconv.ParseUint(p["max-session-layers"], 0, 32)
	if err != nil || maxLayers == 0 || maxLayers > 4096 {
		return fmt.Errorf("max-session-layers must be 1..4096")
	}
	layers := windowsModuleLayers{env: e, max: max, maxLayers: int(maxLayers)}
	var failures pluginFailures
	err = e.Objects.WalkList(ctx, head, f.Offset, max, func(a uint64) error {
		moduleBase := optionalUint(ctx, e, a, typ, "DllBase", true)
		value, baseErr := moduleBase.Uint()
		if base != 0 && baseErr == nil && base != value {
			return nil
		}
		name, nameErr := unicodeString(ctx, e, a, typ, "BaseDllName")
		if p["name"] != "" && nameErr == nil && !strings.Contains(name, p["name"]) {
			return nil
		}
		path, pathErr := unicodeString(ctx, e, a, typ, "FullDllName")
		row := evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Name": evidence.Text(name), "Path": evidence.Text(path), "Base": moduleBase, "Size": optionalUint(ctx, e, a, typ, "SizeOfImage", false), "FileOutput": evidence.Missing("not_requested", nil), "Patches": evidence.Missing("not_requested", nil), "ExtractionAttempts": evidence.Missing("not_requested", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", a)}}
		if nameErr != nil {
			row.Cells["Name"] = evidence.Missing("unreadable_or_unavailable", nameErr)
		}
		if pathErr != nil {
			row.Cells["Path"] = evidence.Missing("unreadable_or_unavailable", pathErr)
		}
		// An unreadable filter field cannot establish that a row is excluded.
		if base != 0 && baseErr != nil || p["name"] != "" && nameErr != nil {
			cause := fmt.Errorf("cannot evaluate module filter at %#x: base=%v name=%v", a, baseErr, nameErr)
			failures.add(cause)
			row.Cells["FileOutput"] = evidence.Missing("module_filter_unresolved", cause)
		} else if dump {
			var dumpErr error
			if baseErr != nil {
				dumpErr = baseErr
				row.Cells["FileOutput"] = evidence.Missing("module_base_unreadable", baseErr)
				row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", baseErr)
				row.Cells["ExtractionAttempts"] = evidence.Missing("module_base_unreadable", baseErr)
			} else {
				layer, attempts, er := layers.find(ctx, value)
				row.Cells["ExtractionAttempts"] = evidence.Value{Kind: "structure", Data: attempts}
				dumpErr = er
				if er != nil {
					row.Cells["FileOutput"] = evidence.Missing("module_address_space_unavailable", er)
					row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", er)
				} else {
					leaf := "UnreadableDLLName"
					if pathErr == nil {
						leaf = path
						if i := strings.LastIndexAny(leaf, "/\\"); i >= 0 {
							leaf = leaf[i+1:]
						}
					}
					file, image, er := dumpPE(ctx, e, layer, fmt.Sprintf("%s.%#x.%#x.dmp", leaf, a, value), value)
					row.Cells["FileOutput"], dumpErr = file, er
					if image != nil {
						row.Cells["Patches"] = evidence.Value{Kind: "structure", Data: image.Patches}
					} else {
						row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", er)
					}
				}
			}
			failures.add(dumpErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(row)
	})
	if err != nil {
		return err
	}
	return failures.err("module analysis")
}
