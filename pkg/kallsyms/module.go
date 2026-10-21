package kallsyms

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ModuleConfig retains the fixed global symbol-address gate. Tree bounds, when
// present, are acquired from mod_tree_root instead. List is only needed on a
// tree miss without an explicitly supplied module.
type ModuleConfig struct {
	Tree, List, AddressMin, AddressMax, AddressMask uint64
	HasTree, HasList                                bool
	MaxNodes, MaxSymbols                            int
}

func ModuleFromSymbols(table symbols.SymbolTable, slide, mask uint64, maxNodes, maxSymbols int) (ModuleConfig, error) {
	c := ModuleConfig{AddressMask: mask, MaxNodes: maxNodes, MaxSymbols: maxSymbols}
	if table == nil || mask == 0 || maxNodes < 1 || maxNodes > 1000000 || maxSymbols < 1 || maxSymbols > 10000000 {
		return c, fmt.Errorf("invalid module lookup configuration")
	}
	lookup := func(name string) (uint64, bool, error) {
		for _, n := range table.Names() {
			if n == name {
				s, err := table.Lookup(name)
				if err != nil {
					return 0, true, err
				}
				at, err := memory.Add(s.Address, slide)
				return at, true, err
			}
		}
		return 0, false, nil
	}
	var err error
	c.Tree, c.HasTree, err = lookup("mod_tree")
	if err != nil {
		return c, err
	}
	c.List, c.HasList, err = lookup("modules")
	if err != nil {
		return c, err
	}
	if !c.HasTree {
		var lo, hi bool
		c.AddressMin, lo, err = lookup("module_addr_min")
		if err != nil {
			return c, err
		}
		c.AddressMax, hi, err = lookup("module_addr_max")
		if err != nil {
			return c, err
		}
		if !lo || !hi {
			return c, fmt.Errorf("missing module allocation boundary symbols")
		}
		c.AddressMin &= mask
		c.AddressMax &= mask
	}
	return c, nil
}

// ModuleRange exposes the fixed raw-value sort and expression value &
// (address_mask + size). End may precede Start even with valid ELF bytes.
// Such bounds must not be mistaken for ABI-correct allocation boundaries.
type ModuleRange struct {
	Object, Start, End, FirstRawValue, LastRawValue, LastRawSize uint64
	Available, Reversed                                          bool
}
type ModuleMatch struct {
	Symbol                                                      Symbol
	Module, Subsystem                                           string
	Object, Entry, Index, SymbolTable, StringTable, NameAddress uint64
	RawABIValue, RawABISize                                     uint64
}

// ModuleLookup retains selection evidence even on no match or error. Match is
// always nil on failure. Acquisition capture and byte limits belong to Layer.
type ModuleLookup struct {
	ListReused               bool
	TablesReused             uint64
	TreeModule               *uint64
	Match                    *ModuleMatch
	GlobalMin, GlobalMax     uint64
	Ranges                   []ModuleRange
	Search                   object.LatchMatch
	ListVisited, SymbolsRead uint64
}
type moduleEntry struct {
	slot, index, name, value, size, abiValue, abiSize uint64
	info                                              byte
}
type moduleTable struct {
	at, base, symtab, strtab uint64
	typ                      string
	entries                  []moduleEntry
	span                     ModuleRange
}

type moduleCache struct {
	tables    map[uint64]*moduleTable
	symbols   uint64
	list      []ModuleRange
	listReady bool
}

// LookupModule follows the locked global gate, optional latch tree, then module
// list fallback. An explicit module still passes both global and ELF-range
// gates. It selects the first containing nonempty ELF symbol, never nearest.
// The locked Elf32 eight-byte value/size and boundary-expression quirks are
// retained, with separate ABI values in the result and explicit range evidence.
func LookupModule(ctx context.Context, r *object.Reader, c ModuleConfig, address uint64, module *uint64) (ModuleLookup, error) {
	return lookupModule(ctx, r, c, address, module, &moduleCache{})
}

func lookupModule(ctx context.Context, r *object.Reader, c ModuleConfig, address uint64, module *uint64, cache *moduleCache) (out ModuleLookup, err error) {
	defer func() {
		if err != nil {
			out.Match = nil
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if r == nil || r.Layer == nil || r.Symbols == nil || c.AddressMask == 0 || c.MaxNodes < 1 || c.MaxNodes > 1000000 || c.MaxSymbols < 1 || c.MaxSymbols > 10000000 {
		return out, fmt.Errorf("invalid module lookup reader or limits")
	}
	width := r.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return out, fmt.Errorf("unsupported module pointer width")
	}
	address &= c.AddressMask
	out.GlobalMin, out.GlobalMax = c.AddressMin, c.AddressMax
	if c.HasTree {
		out.GlobalMin, err = r.Uint(ctx, c.Tree, "mod_tree_root", "addr_min")
		if err != nil {
			return
		}
		out.GlobalMax, err = r.Uint(ctx, c.Tree, "mod_tree_root", "addr_max")
		if err != nil {
			return
		}
		out.GlobalMin &= c.AddressMask
		out.GlobalMax &= c.AddressMask
	}
	if address < out.GlobalMin || address > out.GlobalMax {
		return out, ctx.Err()
	}
	if cache.tables == nil {
		cache.tables = map[uint64]*moduleTable{}
	}
	usedTables := map[uint64]bool{}
	load := func(at uint64) (*moduleTable, error) {
		t, reused := cache.tables[at]
		if !reused {
			if len(cache.tables) >= c.MaxNodes {
				return nil, fmt.Errorf("module cache object bound exhausted")
			}
			used := cache.symbols
			var cause error
			t, cause = readModuleTable(ctx, r, c, at, &used)
			out.SymbolsRead += used - cache.symbols
			if cause != nil {
				return nil, cause
			}
			cache.symbols = used
			cache.tables[at] = t
		}
		if !usedTables[at] {
			if reused {
				out.TablesReused++
			}
			out.Ranges = append(out.Ranges, t.span)
			usedTables[at] = true
		}
		return t, nil
	}
	selected := module
	if selected == nil && c.HasTree {
		root, cause := r.Field("mod_tree_root", "root")
		if cause != nil {
			return out, cause
		}
		if root.Type.Kind != "struct" || root.Type.Name != "latch_tree_root" {
			return out, fmt.Errorf("module tree root is not embedded latch_tree_root")
		}
		at, cause := memory.Add(c.Tree, root.Offset)
		if cause != nil {
			return out, cause
		}
		out.Search, err = r.FindLatchTree(ctx, at, address, c.MaxNodes, func(ctx context.Context, key, node uint64) (int, error) {
			mtn, cause := r.Field("module_memory", "mtn")
			if cause != nil {
				return 0, cause
			}
			mod, cause := r.Field("mod_tree_node", "mod")
			if cause != nil {
				return 0, cause
			}
			// Preserve the fixed comparator's additions, not a container_of subtraction.
			at, cause := memory.Add(node, mtn.Offset)
			if cause != nil {
				return 0, cause
			}
			at, cause = memory.Add(at, mod.Offset)
			if cause != nil {
				return 0, cause
			}
			start, cause := r.Uint(ctx, at, "module_memory", "base")
			if cause != nil {
				return 0, cause
			}
			f, cause := r.Field("module_memory", "base")
			if cause != nil {
				return 0, cause
			}
			if f.Type.Kind == "pointer" {
				start &= c.AddressMask
			}
			size, cause := readNonnegativeSize(ctx, r, at, "module_memory", "size")
			if cause != nil {
				return 0, cause
			}
			end, cause := memory.Add(start, size)
			if cause != nil {
				return 0, cause
			}
			if key < start {
				return -1, nil
			}
			if key >= end {
				return 1, nil
			}
			return 0, nil
		})
		if err != nil {
			return
		}
		if out.Search.Found {
			field, cause := r.Field("mod_tree_node", "node")
			if cause != nil {
				return out, cause
			}
			if field.Type.Kind != "struct" || field.Type.Name != "latch_tree_node" || out.Search.Node < field.Offset {
				return out, fmt.Errorf("invalid module tree node container")
			}
			ptr, cause := readPointer(ctx, r, out.Search.Node-field.Offset, "mod_tree_node", "mod")
			if cause != nil {
				return out, cause
			}
			typ, cause := r.Symbols.Type("module")
			if cause != nil {
				return out, cause
			}
			if typ.Size == 0 || typ.Size > memory.MaxRead {
				return out, fmt.Errorf("invalid module extent")
			}
			if _, cause = memory.Read(ctx, r.Layer, ptr, int(typ.Size)); cause != nil {
				return out, cause
			}
			selected = &ptr
			out.TreeModule = &ptr
		}
	}
	if selected == nil {
		if !c.HasList {
			return out, fmt.Errorf("module list unavailable after tree miss")
		}
		if cache.listReady {
			out.Ranges = append(out.Ranges, cache.list...)
			out.ListReused = true
			for _, span := range cache.list {
				out.TablesReused++
				usedTables[span.Object] = true
			}
		} else {
			field, cause := r.Field("module", "list")
			if cause != nil {
				return out, cause
			}
			if field.Type.Kind != "struct" || field.Type.Name != "list_head" {
				return out, fmt.Errorf("module list is not embedded list_head")
			}
			// The baseline materializes the complete list/range cache before selection.
			err = r.WalkList(ctx, c.List, field.Offset, c.MaxNodes, func(at uint64) error {
				if out.Search.Visited+out.ListVisited >= uint64(c.MaxNodes) {
					return fmt.Errorf("module lookup global node bound exhausted")
				}
				out.ListVisited++
				t, cause := load(at)
				if cause != nil {
					return cause
				}
				if !t.span.Available {
					return fmt.Errorf("listed module has no ELF bounds")
				}
				return nil
			})
			if err != nil {
				return
			}
			cache.list = append([]ModuleRange(nil), out.Ranges...)
			cache.listReady = true
		}
		for _, span := range out.Ranges {
			if span.Start <= address && address < span.End {
				at := span.Object
				selected = &at
				break
			}
		}
	}
	if selected == nil {
		return out, ctx.Err()
	}
	t, cause := load(*selected)
	if cause != nil {
		return out, cause
	}
	if !t.span.Available || address < t.span.Start || address >= t.span.End {
		return out, ctx.Err()
	}
	for _, entry := range t.entries {
		if err = ctx.Err(); err != nil {
			return
		}
		nameAt, cause := memory.Add(t.strtab, entry.name)
		if cause != nil {
			return out, cause
		}
		name, cause := readName(ctx, r, nameAt, 512)
		if cause != nil {
			return out, cause
		}
		if name == "" {
			continue
		}
		start := entry.value & c.AddressMask
		end, cause := memory.Add(start, entry.size)
		if cause != nil {
			return out, cause
		}
		if address < start || address >= end {
			continue
		}
		typ := string(rune(entry.info))
		if t.typ != "module" {
			f, cause := r.Field(t.typ, "typetab")
			if cause == nil {
				if f.Type.Kind != "pointer" {
					return out, fmt.Errorf("module typetab is not a pointer")
				}
				ptr, cause := readPointer(ctx, r, t.base, t.typ, "typetab")
				if cause != nil {
					return out, cause
				}
				ptr, cause = memory.Add(ptr, entry.index)
				if cause != nil {
					return out, cause
				}
				raw, cause := memory.Read(ctx, r.Layer, ptr, 1)
				if cause != nil {
					return out, cause
				}
				typ = ""
				if utf8.Valid(raw) {
					typ = string(raw)
				}
			} else if !errors.Is(cause, object.ErrFieldAbsent) {
				return out, cause
			}
		}
		moduleName, _, cause := readArrayName(ctx, r, t.at, "module", "name")
		if cause != nil {
			return out, cause
		}
		var exported *bool
		if typ != "" {
			upper := strings.IndexFunc(typ, unicode.IsUpper) >= 0 && strings.IndexFunc(typ, unicode.IsLower) < 0
			value := upper || typ == "u" || typ == "v" || typ == "w"
			exported = &value
		}
		out.Match = &ModuleMatch{Symbol: Symbol{Name: name, Type: typ, Address: start, Size: entry.size, SizeAvailable: entry.size != 0, SizeStart: start, SizeEnd: end, Exported: exported}, Module: moduleName, Subsystem: "module", Object: t.at, Entry: entry.slot, Index: entry.index, SymbolTable: t.symtab, StringTable: t.strtab, NameAddress: nameAt, RawABIValue: entry.abiValue, RawABISize: entry.abiSize}
		return out, ctx.Err()
	}
	return out, ctx.Err()
}

func readModuleTable(ctx context.Context, r *object.Reader, c ModuleConfig, at uint64, used *uint64) (*moduleTable, error) {
	t := &moduleTable{at: at, base: at, typ: "module", span: ModuleRange{Object: at}}
	f, err := r.Field("module", "kallsyms")
	if err == nil {
		switch f.Type.Kind {
		case "struct":
			t.base, err = memory.Add(at, f.Offset)
			t.typ = f.Type.Name
		case "pointer":
			if f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" {
				return nil, fmt.Errorf("invalid module kallsyms pointer target")
			}
			t.base, err = readPointer(ctx, r, at, "module", "kallsyms")
			t.typ = f.Type.Subtype.Name
		default:
			return nil, fmt.Errorf("invalid module kallsyms container")
		}
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return nil, err
	}
	t.strtab, err = readPointer(ctx, r, t.base, t.typ, "strtab")
	if err != nil {
		return nil, err
	}
	count, err := r.Uint(ctx, t.base, t.typ, "num_symtab")
	if err != nil {
		return nil, err
	}
	if count > uint64(c.MaxSymbols)-*used {
		return nil, fmt.Errorf("module lookup global symbol bound exhausted")
	}
	if t.strtab == 0 || count == 0 {
		return t, nil
	}
	if count < 2 {
		return nil, fmt.Errorf("module ELF bounds require at least two symbols")
	}
	t.symtab, err = readPointer(ctx, r, t.base, t.typ, "symtab")
	if err != nil {
		return nil, err
	}
	if t.symtab == 0 {
		return nil, fmt.Errorf("null nonempty module symbol table")
	}
	pointer, err := r.Symbols.Type("pointer")
	if err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch pointer.Endian {
	case "little":
		order = binary.LittleEndian
	case "big":
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported ELF byte order")
	}
	stride := uint64(24)
	if r.Symbols.PointerSize() == 4 {
		stride = 16
	}
	first, second, last := -1, -1, -1
	for i := uint64(0); i < count; i++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		slot, cause := memory.Add(t.symtab, i*stride)
		if cause != nil {
			return nil, cause
		}
		raw, cause := memory.Read(ctx, r.Layer, slot, int(stride))
		if cause != nil {
			return nil, cause
		}
		e := moduleEntry{slot: slot, index: i, name: uint64(order.Uint32(raw[:4]))}
		if stride == 24 {
			e.value = order.Uint64(raw[8:16])
			e.size = order.Uint64(raw[16:24])
			e.abiValue = e.value
			e.abiSize = e.size
			e.info = raw[4]
		} else {
			e.value = order.Uint64(raw[4:12])
			e.size = order.Uint64(raw[8:16])
			e.abiValue = uint64(order.Uint32(raw[4:8]))
			e.abiSize = uint64(order.Uint32(raw[8:12]))
			e.info = raw[12]
		}
		t.entries = append(t.entries, e)
		*used += 1
		idx := len(t.entries) - 1
		if first < 0 || e.value < t.entries[first].value {
			second = first
			first = idx
		} else if second < 0 || e.value < t.entries[second].value {
			second = idx
		}
		if last < 0 || e.value >= t.entries[last].value {
			last = idx
		}
	}
	a, b := t.entries[second], t.entries[last]
	// Uint64 wrap is intentional: Python's unbounded sum is ANDed with an
	// at-most-64-bit value, so its higher bits cannot affect the captured result.
	t.span = ModuleRange{Object: at, Start: a.value & c.AddressMask, End: b.value & (c.AddressMask + b.size), FirstRawValue: a.value, LastRawValue: b.value, LastRawSize: b.size, Available: true}
	t.span.Reversed = t.span.End < t.span.Start
	return t, nil
}
