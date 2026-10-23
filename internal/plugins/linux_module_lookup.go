package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxModuleAddressMask(e plugin.Environment) (uint64, error) {
	switch e.Architecture {
	case "x64", "arm64":
		return 0xffffffffffff, nil
	case "x86", "pae":
		return 0xffffffff, nil
	default:
		return 0, fmt.Errorf("module pointer lookup does not support architecture %q", e.Architecture)
	}
}

func (s *linuxModuleSources) kernel() error {
	start, err := s.e.Symbol("_text")
	if err != nil {
		return err
	}
	end, err := s.e.Symbol("_etext")
	if err != nil {
		return err
	}
	mask, err := linuxModuleAddressMask(s.e)
	if err != nil {
		return err
	}
	if end&mask < start&mask {
		return fmt.Errorf("inverted kernel text bounds")
	}
	r := linuxModuleRow(s.e, start, "module_observation", "kernel")
	r.Cells["Name"], r.Cells["Base"], r.Cells["End"], r.Cells["Size"] = evidence.Text("__kernel__"), evidence.Address(start), evidence.Address(end), evidence.Number((end&mask)-(start&mask))
	r.Cells["Status"] = evidence.Text("symbol_bounds")
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{
		"_text":  evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Symbol": evidence.Text("_text"), "Address": evidence.Address(start), "SymbolDigest": evidence.Text(s.e.Symbols.Digest())}},
		"_etext": evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Symbol": evidence.Text("_etext"), "Address": evidence.Address(end), "SymbolDigest": evidence.Text(s.e.Symbols.Digest())}},
	}}
	s.results["kernel"] = []linuxModuleInfo{{start, start, (end & mask) - (start & mask), "__kernel__", "kernel"}}
	return s.out(r)
}

// Pinned range lookup uses the first matching gathered module, even where
// ranges overlap. Keep every matching range as evidence for the caller.
func linuxModuleMatches(modules []linuxModuleInfo, mask, address uint64) ([]linuxModuleInfo, error) {
	target := address & mask
	var matches []linuxModuleInfo
	for _, m := range modules {
		start := m.base & mask
		end, err := memory.Add(start, m.size)
		if err != nil || end > mask {
			return nil, fmt.Errorf("masked module extent overflows address space")
		}
		if start <= target && target < end {
			matches = append(matches, m)
		}
	}
	return matches, nil
}

func linuxUnqualifiedSymbol(name string) string {
	if parts := strings.Split(name, "!"); len(parts) > 1 {
		return parts[1]
	}
	return name
}

// Exact symbol addresses only: a nearby function or a symbol's size must not
// turn an interior instruction into an asserted function entry.
func linuxModuleLookup(n *linuxModuleRead, modules []linuxModuleInfo, kernelSymbols map[uint64]string, address uint64) (*linuxModuleInfo, string, []linuxModuleInfo, error) {
	mask, err := linuxModuleAddressMask(n.e)
	if err != nil {
		return nil, "", nil, err
	}
	matches, err := linuxModuleMatches(modules, mask, address)
	if err != nil || len(matches) == 0 {
		return nil, "", matches, err
	}
	match := matches[0]
	target := address & mask
	if match.name == "__kernel__" {
		if name, ok := kernelSymbols[target]; ok {
			at, err := n.e.Symbol(name)
			if err != nil {
				return &match, "", matches, err
			}
			n.fields["resolved_kernel_symbol"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Symbol": evidence.Text(name), "Address": evidence.Address(at), "SymbolDigest": evidence.Text(n.e.Symbols.Digest())}}
			return &match, linuxUnqualifiedSymbol(name), matches, nil
		}
		return &match, "", matches, nil
	}
	n.fields["symbol_owner_policy"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Policy": evidence.Text("selected_matching_module"), "SelectedObject": evidence.Address(match.offset), "PinnedFinalRangeObject": evidence.Address(modules[len(modules)-1].offset), "DiffersFromPinnedOwner": evidence.Bool(match.offset != modules[len(modules)-1].offset)}}
	name, err := linuxModuleELFSymbol(n, match.offset, target, mask)
	return &match, linuxUnqualifiedSymbol(name), matches, err
}

func linuxModuleELFSymbol(n *linuxModuleRead, module, target, mask uint64) (string, error) {
	base, typ := module, "module"
	modern, err := n.has("module", "kallsyms")
	if err != nil {
		return "", err
	}
	if modern {
		f, err := n.e.Objects.Field("module", "kallsyms")
		if err != nil {
			return "", err
		}
		if f.Type.Kind == "pointer" {
			base, err = n.uint(module, "module", "kallsyms")
			if err != nil {
				return "", err
			}
			if base == 0 {
				return "", fmt.Errorf("module kallsyms pointer is null")
			}
			if f.Type.Underlying() == nil || f.Type.Underlying().Name == "" {
				return "", fmt.Errorf("module kallsyms lacks a target type")
			}
			typ = f.Type.Underlying().Name
		} else if f.Type.Kind == "struct" {
			base, err = memory.Add(module, f.Offset)
			if err != nil {
				return "", err
			}
			typ = f.Type.Name
		} else {
			return "", fmt.Errorf("module kallsyms is not a structure/pointer")
		}
	}
	strtab, err := n.uint(base, typ, "strtab")
	if err != nil {
		return "", err
	}
	count, err := n.uint(base, typ, "num_symtab")
	if err != nil {
		return "", err
	}
	if strtab == 0 || count == 0 {
		return "", nil
	}
	symtab, err := n.uint(base, typ, "symtab")
	if err != nil {
		return "", err
	}
	if symtab == 0 {
		return "", fmt.Errorf("nonempty module symbol table has a null pointer")
	}
	width := n.e.Symbols.PointerSize()
	stride := uint64(16)
	if width == 8 {
		stride = 24
	} else if width != 4 {
		return "", fmt.Errorf("unsupported ELF symbol width")
	}
	pointer, err := n.e.Symbols.Type("pointer")
	if err != nil {
		return "", err
	}
	var order binary.ByteOrder = binary.LittleEndian
	if pointer.Endian == "big" {
		order = binary.BigEndian
	} else if pointer.Endian != "little" && pointer.Endian != "" {
		return "", fmt.Errorf("unknown ELF symbol byte order")
	}
	n.fields["module_symbol_window"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"DeclaredEntries": evidence.Number(count), "PinnedEntryLimit": evidence.Number(4097), "CompleteTableWithinWindow": evidence.Bool(count <= 4097)}}
	// The fixed helper tests iteration_counter > 4096: entries 0..4096.
	if count > 4097 {
		count = 4097
	}
	for i := uint64(0); i < count; i++ {
		if err := n.ctx.Err(); err != nil {
			return "", err
		}
		at, err := memory.Add(symtab, i*stride)
		if err != nil {
			return "", err
		}
		raw, proof, err := linuxCaptureRange(n.ctx, n.e.Kernel, at, int(stride))
		n.fields[fmt.Sprintf("elf_sym_%d", i)] = proof
		if err != nil {
			return "", err
		}
		offset := uint64(order.Uint32(raw))
		value := uint64(order.Uint32(raw[4:]))
		if width == 8 {
			value = order.Uint64(raw[8:])
		}
		at, err = memory.Add(strtab, offset)
		if err != nil {
			return "", err
		}
		raw, proof, err = linuxCaptureRange(n.ctx, n.e.Kernel, at, 512)
		n.fields[fmt.Sprintf("elf_name_%d", i)] = proof
		if err != nil {
			return "", err
		}
		name := spoofDecoded(raw)
		if name != "" && value&mask == target {
			return name, nil
		}
	}
	return "", nil
}

func linuxKernelSymbolIndex(ctx context.Context, e plugin.Environment, mask uint64) (map[uint64]string, error) {
	result := map[uint64]string{}
	for _, name := range e.Symbols.Names() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at, err := e.Symbol(name)
		if err != nil {
			return nil, err
		}
		if _, ok := result[at&mask]; !ok {
			result[at&mask] = name
		}
	}
	return result, nil
}
