package kallsyms

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// FtraceConfig describes optional resident list roots. A configured root may
// have address zero; HasMaps/HasTrampolines distinguish it from an absent source.
type FtraceConfig struct {
	Maps, Trampolines, AddressMask uint64
	HasMaps, HasTrampolines        bool
	MaxNodes                       int
}

// FtraceFromSymbols applies the fixed optional-type/symbol gates. Maps require
// both map and function types and a root symbol; the trampoline root is optional.
func FtraceFromSymbols(table symbols.SymbolTable, slide, mask uint64, maxNodes int) (FtraceConfig, error) {
	c := FtraceConfig{AddressMask: mask, MaxNodes: maxNodes}
	if table == nil || mask == 0 || maxNodes < 1 || maxNodes > 1000000 {
		return c, fmt.Errorf("invalid ftrace symbol configuration")
	}
	has := func(name string) (bool, error) {
		typ, err := table.Type(name)
		if err != nil {
			return false, nil
		}
		if typ.Kind != "struct" {
			return false, fmt.Errorf("%s is not a structure", name)
		}
		return true, nil
	}
	maps, err := has("ftrace_mod_map")
	if err != nil {
		return c, err
	}
	functions, err := has("ftrace_mod_func")
	if err != nil {
		return c, err
	}
	if maps && functions {
		symbol, err := table.Lookup("ftrace_mod_maps")
		if err != nil {
			return c, err
		}
		c.Maps, err = memory.Add(symbol.Address, slide)
		if err != nil {
			return c, err
		}
		c.HasMaps = true
	}
	ops, err := has("ftrace_ops")
	if err != nil {
		return c, err
	}
	if ops {
		for _, name := range table.Names() {
			if name == "ftrace_ops_trampoline_list" {
				symbol, err := table.Lookup(name)
				if err != nil {
					return c, err
				}
				c.Trampolines, err = memory.Add(symbol.Address, slide)
				if err != nil {
					return c, err
				}
				c.HasTrampolines = true
				break
			}
		}
	}
	return c, nil
}

type FtraceMatch struct {
	Symbol                                          Symbol
	Module, Kind, Subsystem                         string
	Object, Map, ModuleObject, NameAddress, Visited uint64
}

// LookupFtrace selects the first matching module function, then the first
// matching trampoline. Both intervals are half-open. Module function values
// are masked; trampoline pointer values follow the layer address mask. Scalar
// trampoline fields retain their captured value, matching the declared type.
// Every list node across both sources consumes the shared per-query node bound.
func LookupFtrace(ctx context.Context, r *object.Reader, c FtraceConfig, address uint64) (*FtraceMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.Symbols == nil || r.Layer == nil || c.AddressMask == 0 || c.MaxNodes < 1 || c.MaxNodes > 1000000 {
		return nil, fmt.Errorf("invalid ftrace lookup configuration")
	}
	if width := r.Symbols.PointerSize(); width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported ftrace pointer width")
	}
	address &= c.AddressMask
	nodes := uint64(0)
	var result *FtraceMatch
	found := errors.New("ftrace lookup matched")
	walk := func(head uint64, typ, member string, visit func(uint64) error) error {
		field, err := r.Field(typ, member)
		if err != nil {
			return err
		}
		if field.Type.Kind != "struct" || field.Type.Name != "list_head" {
			return fmt.Errorf("%s.%s is not embedded list_head", typ, member)
		}
		return r.WalkList(ctx, head, field.Offset, c.MaxNodes, func(at uint64) error {
			if nodes >= uint64(c.MaxNodes) {
				return fmt.Errorf("ftrace lookup global node bound exhausted")
			}
			nodes++
			return visit(at)
		})
	}
	match := func(at, mapAt, moduleAt, nameAt, start, size uint64, name, typ, module, kind string) error {
		exported := typ == "T"
		result = &FtraceMatch{Object: at, Map: mapAt, ModuleObject: moduleAt, NameAddress: nameAt, Module: module, Kind: kind, Subsystem: "ftrace", Visited: nodes, Symbol: Symbol{Name: name, Type: typ, Address: start, Size: size, SizeAvailable: size != 0, SizeStart: start, Exported: &exported}}
		result.Symbol.SizeEnd = start + size // The interval was checked before this call.
		return found
	}
	interval := func(start, size uint64) (bool, error) {
		end, err := memory.Add(start, size)
		if err != nil {
			return false, err
		}
		return start <= address && address < end, nil
	}
	if c.HasMaps {
		err := walk(c.Maps, "ftrace_mod_map", "list", func(mapAt uint64) error {
			field, err := r.Field("ftrace_mod_map", "funcs")
			if err != nil {
				return err
			}
			if field.Type.Kind != "struct" || field.Type.Name != "list_head" {
				return fmt.Errorf("ftrace map funcs is not embedded list_head")
			}
			head, err := memory.Add(mapAt, field.Offset)
			if err != nil {
				return err
			}
			return walk(head, "ftrace_mod_func", "list", func(at uint64) error {
				// The fixed generator acquires every name before testing the interval, but
				// only reads the owning module's name after finding a matching function.
				nameAt, err := readPointer(ctx, r, at, "ftrace_mod_func", "name")
				if err != nil {
					return err
				}
				name, err := readName(ctx, r, nameAt, 512)
				if err != nil {
					return err
				}
				start, err := r.Uint(ctx, at, "ftrace_mod_func", "ip")
				if err != nil {
					return err
				}
				start &= c.AddressMask
				size, err := readNonnegativeSize(ctx, r, at, "ftrace_mod_func", "size")
				if err != nil {
					return err
				}
				inside, err := interval(start, size)
				if err != nil || !inside {
					return err
				}
				moduleAt, err := readPointer(ctx, r, mapAt, "ftrace_mod_map", "mod")
				if err != nil {
					return err
				}
				module, _, err := readArrayName(ctx, r, moduleAt, "module", "name")
				if err != nil {
					return err
				}
				return match(at, mapAt, moduleAt, nameAt, start, size, name, "T", module, "module")
			})
		})
		if errors.Is(err, found) {
			if cause := ctx.Err(); cause != nil {
				return nil, cause
			}
			return result, nil
		}
		if err != nil {
			return nil, err
		}
	}
	if c.HasTrampolines {
		err := walk(c.Trampolines, "ftrace_ops", "list", func(at uint64) error {
			start, err := r.Uint(ctx, at, "ftrace_ops", "trampoline")
			if err != nil {
				return err
			}
			field, err := r.Field("ftrace_ops", "trampoline")
			if err != nil {
				return err
			}
			if field.Type.Kind == "pointer" {
				start &= c.AddressMask
			}
			size, err := readNonnegativeSize(ctx, r, at, "ftrace_ops", "trampoline_size")
			if err != nil {
				return err
			}
			inside, err := interval(start, size)
			if err != nil || !inside {
				return err
			}
			return match(at, 0, 0, 0, start, size, "ftrace_trampoline", "t", "__builtin__ftrace", "trampoline")
		})
		if errors.Is(err, found) {
			if cause := ctx.Err(); cause != nil {
				return nil, cause
			}
			return result, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, ctx.Err()
}
