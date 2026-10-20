package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func dllPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.dlllist", Upstream: "windows.dlllist.DllList", Platform: "windows", NeedsKernel: true,
		Description: "Enumerate native and WoW64 PEB load-order DLLs in each process address space",
		Parameters:  []plugin.Parameter{{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct selected DLL PE files into the case"}, {Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "base", Kind: "string", Description: "Optional exact DLL base address"}, {Name: "name", Kind: "string", Description: "RE2 expression matching DLL name or full path"}, {Name: "ignore-case", Kind: "bool", Default: "false", Description: "Case-insensitive name expression"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-PEB list bound"}, {Name: "max-modules", Kind: "uint", Default: "1000000", Description: "Total DLL traversal limit, including filtered entries"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "Size", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "Path", Kind: "string"}, {Name: "LoadCount", Kind: "int64"}, {Name: "LoadTime", Kind: "string"}, {Name: "LoadTimeRaw", Kind: "uint64"}, {Name: "Offset", Kind: "address"}, {Name: "PEB", Kind: "address"}, {Name: "Architecture", Kind: "string"}, {Name: "LayoutSHA256", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "Patches", Kind: "structure"}}}, windowsDLLList}}
}

var wowLoader struct {
	sync.Once
	table *symbols.ISF
	err   error
}

// Only stable loader-list fields are declared for the separate 32-bit PEB.
// These offsets are checked against the locked baseline's wow64.json. Its
// out-of-bounds LoadTime declaration is deliberately not interpreted here.
func wowLoaderSymbols() (*symbols.ISF, error) {
	wowLoader.Do(func() {
		ptr := symbols.TypeRef{Kind: "pointer"}
		u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
		u16 := symbols.TypeRef{Kind: "base", Name: "u16"}
		embedded := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
		field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
			return symbols.Field{Offset: offset, Type: ref}
		}
		t := symbols.ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`)}, Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 4, Endian: "little"}, "u32": {Kind: "int", Size: 4, Endian: "little"}, "u16": {Kind: "int", Size: 2, Endian: "little"}}, Types: map[string]symbols.Type{
			"_PEB":                  {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Ldr": field(12, ptr)}},
			"_PEB_LDR_DATA":         {Kind: "struct", Size: 48, Fields: map[string]symbols.Field{"InLoadOrderModuleList": field(12, embedded("_LIST_ENTRY"))}},
			"_LIST_ENTRY":           {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Flink": field(0, ptr), "Blink": field(4, ptr)}},
			"_UNICODE_STRING":       {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Length": field(0, u16), "MaximumLength": field(2, u16), "Buffer": field(4, ptr)}},
			"_LDR_DATA_TABLE_ENTRY": {Kind: "struct", Size: 160, Fields: map[string]symbols.Field{"InLoadOrderLinks": field(0, embedded("_LIST_ENTRY")), "DllBase": field(24, ptr), "SizeOfImage": field(32, u32), "FullDllName": field(36, embedded("_UNICODE_STRING")), "BaseDllName": field(44, embedded("_UNICODE_STRING"))}},
		}}
		b, err := t.Encode()
		if err == nil {
			wowLoader.table, err = symbols.Parse(b)
		}
		wowLoader.err = err
	})
	return wowLoader.table, wowLoader.err
}

func dllLoadCount(ctx context.Context, e plugin.Environment, address uint64) evidence.Value {
	for _, path := range []string{"LoadCount", "ObsoleteLoadCount"} {
		if _, err := e.Objects.Field("_LDR_DATA_TABLE_ENTRY", path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return evidence.Missing("unreadable_or_unavailable", err)
		}
		n, err := e.Objects.Uint(ctx, address, "_LDR_DATA_TABLE_ENTRY", path)
		if err != nil {
			return evidence.Missing("unreadable_or_unavailable", err)
		}
		return evidence.Integer(int64(int16(n)))
	}
	return evidence.Missing("unsupported_loader_field", nil)
}

func windowsDLLList(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	limit, err := strconv.ParseUint(p["max-modules"], 0, 32)
	if err != nil || limit < 1 || limit > 1000000 {
		return fmt.Errorf("max-modules must be 1..1000000")
	}
	ignore, err := strconv.ParseBool(p["ignore-case"])
	if err != nil {
		return err
	}
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	var expression *regexp.Regexp
	if p["name"] != "" {
		pattern := p["name"]
		if ignore {
			pattern = "(?i:" + pattern + ")"
		}
		expression, err = regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("DLL name expression: %w", err)
		}
	}
	var base uint64
	filterBase := p["base"] != ""
	if filterBase {
		base, err = strconv.ParseUint(p["base"], 0, 64)
		if err != nil {
			return fmt.Errorf("base: %w", err)
		}
		filterBase = base != 0
	}
	var count uint64
	var failureCount int
	var firstFailure error
	var outputErr error
	emit := func(row evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		outputErr = out(row)
		return outputErr
	}
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		var layer memory.MemoryLayer
		diagnostic := func(stage string, cause error) error {
			failureCount++
			if firstFailure == nil {
				firstFailure = cause
			}
			cells := map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "RecordType": evidence.Text("diagnostic"), "Error": evidence.Missing(stage, cause)}
			for _, field := range []string{"Base", "Size", "Name", "Path", "LoadCount", "LoadTime", "LoadTimeRaw", "Offset", "PEB", "Architecture", "LayoutSHA256", "FileOutput", "Patches"} {
				cells[field] = evidence.Missing(stage, cause)
			}
			layerName := e.Kernel.Name()
			if layer != nil {
				layerName = layer.Name()
			}
			return emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: layerName, Offset: fmt.Sprintf("0x%x", process)}})
		}
		peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
		if err != nil {
			return diagnostic("peb_pointer_unreadable", err)
		}
		var wow uint64
		if e.Symbols.PointerSize() == 8 {
			for _, path := range []string{"WoW64Process", "Wow64Process"} {
				if _, err := e.Objects.Field("_EPROCESS", path); err != nil {
					if errors.Is(err, object.ErrFieldAbsent) {
						continue
					}
					return diagnostic("wow64_pointer_layout", err)
				}
				wow, err = e.Objects.Uint(ctx, process, "_EPROCESS", path)
				if err != nil {
					return diagnostic("wow64_pointer_unreadable", err)
				}
				break
			}
		}
		if peb == 0 && wow == 0 {
			return nil
		}
		layer, err = processMemory(ctx, e, process, 0, identity)
		if err != nil {
			return diagnostic("process_space_unavailable", err)
		}
		type target struct {
			peb  uint64
			env  plugin.Environment
			arch string
		}
		native := e
		native.Kernel = layer
		native.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
		arch := "x64"
		if e.Symbols.PointerSize() == 4 {
			arch = "x86"
		}
		var targets []target
		if peb != 0 {
			targets = append(targets, target{peb, native, arch})
		}
		if wow != 0 {
			peb32 := wow
			for _, candidate := range []struct{ typ, path string }{{"_EWOW64PROCESS", "Peb"}, {"_WOW64_PROCESS", "Wow64"}} {
				if _, err := e.Symbols.Type(candidate.typ); err == nil {
					peb32, err = e.Objects.Uint(ctx, wow, candidate.typ, candidate.path)
					if err != nil {
						if err = diagnostic("wow64_peb_unreadable", err); err != nil {
							return err
						}
						peb32 = 0
					}
					break
				}
			}
			if peb32 != 0 {
				table, err := wowLoaderSymbols()
				if err != nil {
					return err
				}
				user32 := native
				user32.Symbols = table
				user32.Objects = &object.Reader{Layer: layer, Symbols: table}
				targets = append(targets, target{peb32, user32, "wow64-x86"})
			}
		}
		for _, target := range targets {
			user := target.env
			ldr, err := user.Objects.Uint(ctx, target.peb, "_PEB", "Ldr")
			if err != nil {
				if err = diagnostic("peb_unreadable", err); err != nil {
					return err
				}
				continue
			}
			if ldr == 0 {
				if err = diagnostic("loader_unavailable", fmt.Errorf("nonzero PEB has no loader pointer")); err != nil {
					return err
				}
				continue
			}
			head, err := user.Objects.Field("_PEB_LDR_DATA", "InLoadOrderModuleList")
			if err != nil {
				return err
			}
			list, err := memory.Add(ldr, head.Offset)
			if err != nil {
				return err
			}
			link, err := user.Objects.Field("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
			if err != nil {
				return err
			}
			err = user.Objects.WalkList(ctx, list, link.Offset, max, func(address uint64) error {
				if count >= limit {
					return fmt.Errorf("total DLL traversal exceeds max-modules")
				}
				count++
				moduleBase := optionalUint(ctx, user, address, "_LDR_DATA_TABLE_ENTRY", "DllBase", true)
				moduleName, er := unicodeString(ctx, user, address, "_LDR_DATA_TABLE_ENTRY", "BaseDllName")
				short := evidence.Text(moduleName)
				if er != nil {
					short = evidence.Missing("unreadable_or_unavailable", er)
				}
				fullName, er := unicodeString(ctx, user, address, "_LDR_DATA_TABLE_ENTRY", "FullDllName")
				full := evidence.Text(fullName)
				if er != nil {
					full = evidence.Missing("unreadable_or_unavailable", er)
				}
				if filterBase {
					v, err := moduleBase.Uint()
					if err != nil {
						return err
					}
					if v != base {
						return nil
					}
				}
				if expression != nil {
					if short.Kind == "missing" || full.Kind == "missing" {
						return fmt.Errorf("cannot apply name filter to unreadable loader names at %#x", address)
					}
					if !expression.MatchString(moduleName) && !expression.MatchString(fullName) {
						return nil
					}
				}
				time, raw := evidence.Missing("unsupported_loader_field", nil), evidence.Missing("unsupported_loader_field", nil)
				if _, er := user.Objects.Field("_LDR_DATA_TABLE_ENTRY", "LoadTime"); er == nil {
					time, raw = windowsTime(ctx, user, address, "_LDR_DATA_TABLE_ENTRY", "LoadTime")
				} else if !errors.Is(er, object.ErrFieldAbsent) {
					time, raw = evidence.Missing("invalid_loader_time_layout", er), evidence.Missing("invalid_loader_time_layout", er)
				}
				row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "Base": moduleBase, "Size": optionalUint(ctx, user, address, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage", false), "Name": short, "Path": full, "LoadCount": dllLoadCount(ctx, user, address), "LoadTime": time, "LoadTimeRaw": raw, "Offset": evidence.Address(address), "PEB": evidence.Address(target.peb), "Architecture": evidence.Text(target.arch), "LayoutSHA256": evidence.Text(user.Symbols.Digest()), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "RecordType": evidence.Text("module"), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", address)}}
				row.Cells["FileOutput"] = evidence.Missing("not_requested", nil)
				row.Cells["Patches"] = evidence.Missing("not_requested", nil)
				var dumpErr error
				if dump {
					value, err := moduleBase.Uint()
					dumpErr = err
					if err != nil {
						row.Cells["FileOutput"] = evidence.Missing("dll_base_unreadable", err)
					} else {
						leaf := "UnreadableDLLName"
						if full.Kind != "missing" {
							leaf = fullName
							if i := strings.LastIndexAny(leaf, "/\\"); i >= 0 {
								leaf = leaf[i+1:]
							}
						}
						file, image, err := dumpPE(ctx, e, layer, fmt.Sprintf("pid.%d.%s.%#x.%#x.dmp", pid, leaf, address, value), value)
						row.Cells["FileOutput"] = file
						dumpErr = err
						if image != nil {
							row.Cells["Patches"] = evidence.Value{Kind: "structure", Data: image.Patches}
						} else {
							row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", err)
						}
					}
				}
				if err := emit(row); err != nil {
					return err
				}
				return dumpErr
			})
			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if er := diagnostic("loader_list_incomplete", err); er != nil {
					return er
				}
				if count >= limit {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if failureCount > 0 {
		return fmt.Errorf("%d process loader diagnostics; first error: %w", failureCount, firstFailure)
	}
	return nil
}
