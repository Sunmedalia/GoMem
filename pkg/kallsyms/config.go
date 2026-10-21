package kallsyms

import (
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// FromSymbols resolves resident table coordinates using the kernel slide. It
// deliberately does not use the external table's symbol names as output rows.
// The caller supplies the architecture's address mask explicitly.
func FromSymbols(table symbols.SymbolTable, slide, mask uint64) (Config, error) {
	var c Config
	if table == nil {
		return c, fmt.Errorf("kallsyms requires symbols")
	}
	c.Width = table.PointerSize()
	c.AddressMask = mask
	pointer, err := table.Type("pointer")
	if err != nil {
		return c, err
	}
	c.Endian = pointer.Endian
	if c.Endian == "" {
		c.Endian = "little"
	}
	names := map[string]bool{}
	for _, name := range table.Names() {
		names[name] = true
	}
	resolve := func(name string, required bool) (uint64, bool, error) {
		if !names[name] {
			if required {
				return 0, false, fmt.Errorf("unsupported kallsyms: missing %s", name)
			}
			return 0, false, nil
		}
		symbol, err := table.Lookup(name)
		if err != nil {
			return 0, true, err
		}
		address := symbol.Address
		// Fixed ISF lookup masks addresses before adding kernel relocation.
		// Keep acquisition pointers canonical, but use the fixed coordinates
		// for interval boundaries compared to normalized symbol values.
		if name == "_stext" || name == "_sinittext" || name == "_einittext" || name == "_etext" || name == "_end" {
			address &= mask
		}
		value, err := memory.Add(address, slide)
		return value, true, err
	}
	for _, field := range []struct {
		name     string
		target   *uint64
		required bool
	}{
		{"kallsyms_num_syms", &c.Count, true}, {"kallsyms_names", &c.Names, true}, {"kallsyms_token_table", &c.TokenTable, true}, {"kallsyms_token_index", &c.TokenIndex, true},
		{"kallsyms_markers", &c.Markers, false}, {"_stext", &c.TextStart, false}, {"kallsyms_addresses", &c.Addresses, false}, {"kallsyms_offsets", &c.Offsets, false}, {"kallsyms_relative_base", &c.RelativeBase, false},
		{"_sinittext", &c.InitStart, false}, {"_einittext", &c.InitEnd, false}, {"_etext", &c.TextEnd, true}, {"_end", &c.End, false},
	} {
		value, exists, err := resolve(field.name, field.required)
		if err != nil {
			return c, err
		}
		*field.target = value
		if field.name == "_end" {
			c.HasEnd = exists
		}
	}
	c.HasText = names["_stext"]
	c.HasInit = names["_sinittext"] && names["_einittext"] && c.InitStart != 0 && c.InitEnd != 0
	// Boundaries use the fixed masked-then-relocated ISF coordinates. Read
	// locations remain valid canonical coordinates in the native layer.
	count, err := table.Lookup("kallsyms_num_syms")
	if err != nil {
		return c, err
	}
	if count.Type == nil || count.Type.Kind != "base" {
		return c, fmt.Errorf("kallsyms count lacks integer type metadata")
	}
	r := &object.Reader{Symbols: table}
	size, err := r.Size(*count.Type)
	if err != nil {
		return c, err
	}
	if size != 4 && size != 8 {
		return c, fmt.Errorf("invalid kallsyms count width %d", size)
	}
	c.CountSize = int(size)
	c.MarkerSize = int(size)
	return c, nil
}
