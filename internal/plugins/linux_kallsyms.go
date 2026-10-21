package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxKallsymsPlugins() []builtin {
	columns := []evidence.Column{{Name: "Addr", Kind: "address"}, {Name: "Type", Kind: "string"}, {Name: "Size", Kind: "uint64"}, {Name: "Exported", Kind: "bool"}, {Name: "SubSystem", Kind: "string"}, {Name: "ModuleName", Kind: "string"}, {Name: "SymbolName", Kind: "string"}, {Name: "Description", Kind: "string"}}
	columns = append(columns, evidence.Column{Name: "RecordType", Kind: "string"}, evidence.Column{Name: "Offset", Kind: "address"}, evidence.Column{Name: "FieldEvidence", Kind: "structure"}, evidence.Column{Name: "Coverage", Kind: "structure"}, evidence.Column{Name: "Error", Kind: "missing"})
	params := []plugin.Parameter{}
	for _, name := range []string{"core", "modules", "ftrace", "bpf"} {
		params = append(params, plugin.Parameter{Name: name, Kind: "bool", Default: "false", Description: "Include this symbol source; all sources when no source flag is enabled"})
	}
	params = append(params, plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Global source list bound, 1..1000000"}, plugin.Parameter{Name: "max-symbols", Kind: "uint", Default: "1000000", Description: "Global emitted symbol bound, 1..10000000"}, plugin.Parameter{Name: "max-bytes", Kind: "uint", Default: "536870912", Description: "Cumulative actual acquisition bound, 1..1073741824"})
	return []builtin{{plugin.Spec{Name: "linux.kallsyms", Upstream: "linux.kallsyms.Kallsyms", Platform: "linux", NeedsKernel: true, Description: "Recover resident core, module, ftrace and BPF symbols with acquisition evidence", Parameters: params, Columns: columns}, linuxKallsyms}}
}

type kallsymsReadBudget struct {
	memory.MemoryLayer
	remaining func() uint64
}

func (l *kallsymsReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.remaining() {
		return 0, fmt.Errorf("kallsyms acquisition byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

type linuxKallsymsReader struct {
	ctx                                  context.Context
	e                                    plugin.Environment
	send                                 plugin.Emit
	mask, maxNodes, maxSymbols, maxBytes uint64
	nodes, selected, reads, acquired     uint64
	outputErr                            error
	failures                             pluginFailures
	nameIssues                           []map[string]evidence.Value
}

func (s *linuxKallsymsReader) row(at uint64, kind string) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at)}, Provenance: evidence.Provenance{Layer: s.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
}
func (s *linuxKallsymsReader) emit(row evidence.Row) error {
	if s.outputErr != nil {
		return s.outputErr
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.outputErr = s.send(row)
	if s.outputErr == nil {
		s.outputErr = s.ctx.Err()
	}
	return s.outputErr
}
func (s *linuxKallsymsReader) issue(at uint64, source string, cause error) error {
	if s.outputErr != nil {
		return s.outputErr
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	s.failures.add(cause)
	row := s.row(at, "symbol_source")
	row.Cells["SubSystem"] = evidence.Text(source)
	if cause != nil {
		row.Cells["Error"] = evidence.Missing("symbol_source_incomplete", cause)
	} else {
		row.Cells["Error"] = evidence.Missing("not_applicable", nil)
	}
	return s.emit(row)
}
func linuxKallsyms(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("kallsyms requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	s := &linuxKallsymsReader{ctx: ctx, e: e, send: out, mask: mask}
	for _, v := range []struct {
		name   string
		max    uint64
		target *uint64
	}{{"max-nodes", 1000000, &s.maxNodes}, {"max-symbols", 10000000, &s.maxSymbols}, {"max-bytes", 1 << 30, &s.maxBytes}} {
		n, err := strconv.ParseUint(p[v.name], 0, 64)
		if err != nil || n == 0 || n > v.max {
			return fmt.Errorf("%s must be 1..%d", v.name, v.max)
		}
		*v.target = n
	}
	flags := map[string]bool{}
	any := false
	for _, name := range []string{"core", "modules", "ftrace", "bpf"} {
		value, err := strconv.ParseBool(p[name])
		if err != nil {
			return err
		}
		flags[name] = value
		any = any || value
	}
	if !any {
		for name := range flags {
			flags[name] = true
		}
	}
	trace := &linuxIDRLayer{MemoryLayer: &kallsymsReadBudget{MemoryLayer: e.Kernel, remaining: func() uint64 { return s.maxBytes - s.acquired }}}
	trace.observe = func(at uint64, raw []byte, want int, cause error) error {
		s.reads++
		s.acquired += uint64(len(raw))
		row := s.row(at, "symbol_read")
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil)}
		if cause != nil {
			proof["Error"] = evidence.Missing("read_failed", cause)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return s.emit(row)
	}
	s.e.Kernel = trace
	s.e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	for _, source := range []struct {
		name string
		run  func() error
	}{{"core", s.core}, {"modules", s.modules}, {"ftrace", s.ftrace}, {"bpf", s.bpf}} {
		if !flags[source.name] {
			continue
		}
		if err := source.run(); err != nil {
			if err = s.issue(0, source.name, err); err != nil {
				return err
			}
		} else if err := s.issue(0, source.name, nil); err != nil {
			return err
		}
	}
	row := s.row(0, "symbols_summary")
	row.Cells["Coverage"] = poolCoverage(map[string]string{"symbols": formatCount(s.selected), "nodes": formatCount(s.nodes), "reads": formatCount(s.reads), "acquired_bytes": formatCount(s.acquired), "source_errors": strconv.Itoa(s.failures.count), "scope": "resident symbols; source availability and explicit errors do not establish completeness"})
	failure := s.failures.err("Linux kallsyms")
	if failure != nil {
		row.Cells["Error"] = evidence.Missing("symbols_incomplete", failure)
	}
	if err := s.emit(row); err != nil {
		return err
	}
	return failure
}
func (s *linuxKallsymsReader) core() error {
	config, err := kallsyms.FromSymbols(s.e.Symbols, s.e.KernelSlide, s.mask)
	if err != nil {
		return err
	}
	core, err := kallsyms.Open(s.ctx, s.e.Kernel, config, kallsyms.Limits{Symbols: s.maxSymbols, Bytes: s.maxBytes, TokenBytes: 65536, NameBytes: 1 << 20})
	if err != nil {
		return err
	}
	return core.Stream(s.ctx, func(symbol kallsyms.Symbol) error {
		proof := map[string]evidence.Value{"Index": evidence.Number(symbol.Index), "NameOffset": evidence.Number(symbol.NameOffset), "NextOffset": evidence.Number(symbol.NextOffset), "HeaderBytes": evidence.Number(symbol.HeaderBytes), "CompressedLength": evidence.Number(symbol.CompressedLength), "SizeStart": evidence.Address(symbol.SizeStart), "SizeEnd": evidence.Address(symbol.SizeEnd)}
		at, err := memory.Add(config.Names, symbol.NameOffset)
		if err != nil {
			return err
		}
		return s.symbol(at, symbol.Address, symbol.Size, symbol.SizeAvailable, symbol.Name, symbol.Type, "kernel", "core", symbol.Exported, proof)
	})
}
func (s *linuxKallsymsReader) symbol(at, address, size uint64, available bool, name, typ, module, subsystem string, exported *bool, proof map[string]evidence.Value) error {
	if s.selected >= s.maxSymbols {
		return fmt.Errorf("kallsyms exceeds max-symbols %d", s.maxSymbols)
	}
	row := s.row(at, "symbol")
	row.Cells["Addr"] = evidence.Address(address)
	row.Cells["Type"] = evidence.Missing("not_available", nil)
	if typ != "" {
		row.Cells["Type"] = evidence.Text(typ)
	}
	row.Cells["Size"] = evidence.Missing("not_available", nil)
	if available && size != 0 {
		row.Cells["Size"] = evidence.Number(size)
	}
	row.Cells["Exported"] = evidence.Missing("not_available", nil)
	if exported != nil {
		row.Cells["Exported"] = evidence.Bool(*exported)
	}
	row.Cells["SymbolName"] = evidence.Text(name)
	if flag, ok := proof["NameAvailable"]; ok && flag.Data == false {
		row.Cells["SymbolName"] = evidence.Missing("name_not_in_layout", nil)
	}
	row.Cells["ModuleName"] = evidence.Text(module)
	row.Cells["SubSystem"] = evidence.Text(subsystem)
	row.Cells["Description"] = evidence.Missing("not_available", nil)
	if description := kallsymsTypeDescription(typ); description != "" {
		row.Cells["Description"] = evidence.Text(description)
	}
	if len(s.nameIssues) != 0 {
		if proof == nil {
			proof = map[string]evidence.Value{}
		}
		proof["NameReadIssues"] = evidence.Value{Kind: "structure", Data: append([]map[string]evidence.Value(nil), s.nameIssues...)}
		row.Cells["Error"] = evidence.Missing("symbol_name_acquisition_incomplete", fmt.Errorf("%d partial symbol-name reads", len(s.nameIssues)))
		s.nameIssues = nil
	}
	row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
	if err := s.emit(row); err != nil {
		return err
	}
	s.selected++
	return nil
}
func (s *linuxKallsymsReader) uint(at uint64, typ, field string) (uint64, error) {
	switch field {
	case "symtab", "strtab", "typetab", "syms", "mod", "prog", "aux", "bpf_func", "name":
		f, err := s.e.Objects.Field(typ, field)
		if err != nil {
			return 0, err
		}
		if f.Type.Kind != "pointer" {
			return 0, fmt.Errorf("%s.%s must be a pointer", typ, field)
		}
	}
	return s.e.Objects.Uint(s.ctx, at, typ, field)
}
func (s *linuxKallsymsReader) has(typ, field string) (bool, error) {
	_, err := s.e.Objects.Field(typ, field)
	if errors.Is(err, object.ErrFieldAbsent) {
		return false, nil
	}
	return err == nil, err
}
func (s *linuxKallsymsReader) text(at uint64, size int, ignore bool) (string, error) {
	if size < 0 || size > 1<<20 {
		return "", fmt.Errorf("invalid symbol string extent")
	}

	raw := make([]byte, size)
	n, cause := s.e.Kernel.ReadAt(s.ctx, raw, at)
	if n < 0 || n > len(raw) {
		return "", fmt.Errorf("invalid symbol name read count")
	}
	if cause == nil && n != len(raw) {
		cause = io.ErrUnexpectedEOF
	}
	if cause != nil {
		if s.outputErr != nil {
			return "", s.outputErr
		}
		if s.ctx.Err() != nil {
			return "", s.ctx.Err()
		}
		if n == 0 {
			return "", cause
		}
		s.nameIssues = append(s.nameIssues, map[string]evidence.Value{"Address": evidence.Address(at), "RequestedBytes": evidence.Number(uint64(size)), "CapturedBytes": evidence.Number(uint64(n)), "Error": evidence.Missing("name_prefix_only", cause)})
		if err := s.issue(at, "name-prefix", cause); err != nil {
			return "", err
		}
	}
	raw = raw[:n]
	if end := strings.IndexByte(string(raw), 0); end >= 0 {
		raw = raw[:end]
	}
	if ignore {
		return spoofDecoded(raw), nil
	}
	decoded, _ := replaceInvalidUTF8(raw)
	return decoded, nil
}
func (s *linuxKallsymsReader) array(at uint64, typ, field string) (string, error) {
	f, err := s.e.Objects.Field(typ, field)
	if err != nil {
		return "", err
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil {
		return "", fmt.Errorf("%s.%s not an array", typ, field)
	}
	width, err := s.e.Objects.Size(*f.Type.Subtype)
	if err != nil || width != 1 || f.Type.Count > 1<<20 {
		return "", fmt.Errorf("invalid name array extent")
	}
	base, err := memory.Add(at, f.Offset)
	if err != nil {
		return "", err
	}
	// array_to_string uses replacement decoding, then stops at U+FFFD.
	raw, err := memory.Read(s.ctx, s.e.Kernel, base, int(f.Type.Count))
	if err != nil {
		return "", err
	}
	return spoofDecoded(raw), nil
}
func (s *linuxKallsymsReader) walk(head uint64, typ, member string, visit func(uint64) error) error {
	f, err := s.e.Objects.Field(typ, member)
	if err != nil {
		return err
	}
	if f.Type.Kind != "struct" || f.Type.Name != "list_head" {
		return fmt.Errorf("%s.%s must be an embedded list_head", typ, member)
	}
	return s.e.Objects.WalkList(s.ctx, head, f.Offset, int(s.maxNodes), func(at uint64) error {
		if s.nodes >= s.maxNodes {
			return fmt.Errorf("kallsyms global node bound exhausted")
		}
		s.nodes++
		return visit(at)
	})
}
func (s *linuxKallsymsReader) container(at uint64, typ, field string) (uint64, string, error) {
	f, err := s.e.Objects.Field(typ, field)
	if err != nil {
		return 0, "", err
	}
	if f.Type.Kind == "struct" || f.Type.Kind == "union" {
		value, err := memory.Add(at, f.Offset)
		return value, f.Type.Name, err
	}
	if f.Type.Kind != "pointer" || f.Type.Subtype == nil || (f.Type.Subtype.Kind != "struct" && f.Type.Subtype.Kind != "union") {
		return 0, "", fmt.Errorf("invalid %s.%s container", typ, field)
	}
	value, err := s.uint(at, typ, field)
	if err == nil && value == 0 {
		err = fmt.Errorf("null %s.%s", typ, field)
	}
	return value, f.Type.Subtype.Name, err
}
func (s *linuxKallsymsReader) modules() error {
	head, err := s.e.Symbol("modules")
	if err != nil {
		return err
	}
	return s.walk(head, "module", "list", func(at uint64) error {
		if err := s.module(at); err != nil {
			return s.issue(at, "modules", err)
		}
		return nil
	})
}
func (s *linuxKallsymsReader) module(at uint64) error {
	name, err := s.array(at, "module", "name")
	if err != nil {
		return err
	}
	base, typ := at, "module"
	modern, err := s.has("module", "kallsyms")
	if err != nil {
		return err
	}
	if modern {
		base, typ, err = s.container(at, "module", "kallsyms")
		if err != nil {
			return err
		}
	}
	count, err := s.uint(base, typ, "num_symtab")
	if err != nil {
		return err
	}
	if count > s.maxSymbols {
		return fmt.Errorf("module symbol table exceeds max-symbols")
	}
	strtab, err := s.uint(base, typ, "strtab")
	if err != nil {
		return err
	}
	if strtab == 0 || count == 0 {
		return nil
	}
	symtab, err := s.uint(base, typ, "symtab")
	if err != nil {
		return err
	}
	if symtab == 0 {
		return fmt.Errorf("null nonempty module symbol table")
	}
	typetab := uint64(0)
	if modern {
		present, err := s.has(typ, "typetab")
		if err != nil {
			return err
		}
		if present {
			typetab, err = s.uint(base, typ, "typetab")
			if err != nil {
				return err
			}
			if typetab == 0 {
				return fmt.Errorf("null module typetab")
			}
		}
	}
	symtype, stride := "Elf64_Sym", uint64(24)
	if s.e.Symbols.PointerSize() == 4 {
		symtype, stride = "Elf32_Sym", 16
	}
	// Use the fixed ELF ABI even when a kernel ISF omits standalone Elf types.
	for index := uint64(0); index < count; index++ {
		s.nameIssues = nil
		slot, err := memory.Add(symtab, index*stride)
		if err != nil {
			return err
		}
		raw, err := memory.Read(s.ctx, s.e.Kernel, slot, int(stride))
		if err != nil {
			return err
		}
		order, err := s.order()
		if err != nil {
			return err
		}
		nameoff := uint64(order.Uint32(raw[:4]))
		value, size := uint64(0), uint64(0)
		info := byte(0)
		if stride == 24 {
			value, size, info = order.Uint64(raw[8:16]), order.Uint64(raw[16:24]), raw[4]
		} else {
			value, size, info = uint64(order.Uint32(raw[4:8])), order.Uint64(raw[8:16]), raw[12]
		}
		nameptr, err := memory.Add(strtab, nameoff)
		if err != nil {
			return err
		}
		symbolname, err := s.text(nameptr, 512, true)
		if err != nil {
			return err
		}
		if symbolname == "" {
			continue
		}
		symboltype := string(rune(info))
		if typetab != 0 {
			addr, err := memory.Add(typetab, index)
			if err != nil {
				return err
			}
			raw, err := memory.Read(s.ctx, s.e.Kernel, addr, 1)
			if err != nil {
				return err
			}
			symboltype = strings.ToValidUTF8(string(raw), "")
		}
		value &= s.mask
		exported, err := s.exported(at, symbolname, value)
		if err != nil {
			return err
		}
		if exported != nil && *exported {
			symboltype = strings.ToUpper(symboltype)
		} else {
			symboltype = strings.ToLower(symboltype)
		}
		proof := map[string]evidence.Value{"ModuleObject": evidence.Address(at), "SymbolTable": evidence.Address(symtab), "StringTable": evidence.Address(strtab), "TypeTable": evidence.Address(typetab), "Index": evidence.Number(index), "ELFType": evidence.Text(symtype)}
		if stride == 16 {
			proof["RawELFSize"] = evidence.Number(uint64(order.Uint32(raw[8:12])))
		} else {
			proof["RawELFSize"] = evidence.Number(size)
		}
		if err = s.symbol(slot, value, size, size != 0, symbolname, symboltype, name, "module", exported, proof); err != nil {
			return err
		}
	}
	return nil
}
func (s *linuxKallsymsReader) exported(module uint64, name string, address uint64) (*bool, error) {
	count, err := s.uint(module, "module", "num_syms")
	if err != nil {
		return nil, err
	}
	if count == 0 {
		v := false
		return &v, nil
	}
	if count > s.maxSymbols {
		return nil, fmt.Errorf("module export table exceeds symbol bound")
	}
	base, err := s.uint(module, "module", "syms")
	if err != nil {
		return nil, err
	}
	if base == 0 {
		return nil, fmt.Errorf("null module export table")
	}
	typ, err := s.e.Symbols.Type("kernel_symbol")
	if err != nil {
		return nil, err
	}
	if typ.Size == 0 || typ.Size > 4096 {
		return nil, fmt.Errorf("invalid kernel_symbol extent")
	}
	for count > 0 {
		slot, err := memory.Add(base, (count/2)*typ.Size)
		if err != nil {
			return nil, err
		}
		ptr, err := s.exportPointer(slot, "name_offset", "name")
		if err != nil {
			return nil, err
		}
		other, err := s.text(ptr, 512, true)
		if err != nil {
			return nil, err
		}
		compare := strings.Compare(name, other)
		if compare == 0 {
			value, err := s.exportPointer(slot, "value_offset", "value")
			if err != nil {
				return nil, err
			}
			v := value == address
			return &v, nil
		}
		if compare > 0 {
			base, err = memory.Add(slot, typ.Size)
			if err != nil {
				return nil, err
			}
			count--
		}
		count /= 2
	}
	// The fixed helper returns None rather than false for an absent export.
	return nil, nil
}
func (s *linuxKallsymsReader) exportPointer(at uint64, relative, absolute string) (uint64, error) {
	present, err := s.has("kernel_symbol", relative)
	if err != nil {
		return 0, err
	}
	if !present {
		return s.uint(at, "kernel_symbol", absolute)
	}
	delta, err := s.e.Objects.Int(s.ctx, at, "kernel_symbol", relative)
	if err != nil {
		return 0, err
	}
	// kernel_symbol's helper uses the struct base, even for nonzero member offset.
	return addKallsymsSigned(at, delta, s.e.Symbols.PointerSize())
}
func addKallsymsSigned(at uint64, delta int64, width int) (uint64, error) {
	var value uint64
	var err error
	if delta >= 0 {
		value, err = memory.Add(at, uint64(delta))
	} else {
		n := uint64(-(delta + 1)) + 1
		if n > at {
			return 0, fmt.Errorf("relative symbol pointer underflow")
		}
		value = at - n
	}
	if err == nil && width == 4 && value > 0xffffffff {
		err = fmt.Errorf("relative symbol pointer exceeds 32 bits")
	}
	return value, err
}
func (s *linuxKallsymsReader) ftrace() error {
	var failures pluginFailures
	if _, err := s.e.Symbols.Type("ftrace_mod_map"); err == nil {
		if _, err := s.e.Symbols.Type("ftrace_mod_func"); err != nil {
			return err
		}
		head, err := s.e.Symbol("ftrace_mod_maps")
		if err != nil {
			return err
		}
		err = s.walk(head, "ftrace_mod_map", "list", func(at uint64) error {
			ptr, err := s.uint(at, "ftrace_mod_map", "mod")
			if err != nil {
				return err
			}
			module, err := s.array(ptr, "module", "name")
			if err != nil {
				return err
			}
			f, err := s.e.Objects.Field("ftrace_mod_map", "funcs")
			if err != nil {
				return err
			}
			head, err := memory.Add(at, f.Offset)
			if err != nil {
				return err
			}
			return s.walk(head, "ftrace_mod_func", "list", func(fn uint64) error {
				s.nameIssues = nil
				nameptr, err := s.uint(fn, "ftrace_mod_func", "name")
				if err != nil {
					return err
				}
				name, err := s.text(nameptr, 512, true)
				if err != nil {
					return err
				}
				address, err := s.uint(fn, "ftrace_mod_func", "ip")
				if err != nil {
					return err
				}
				size, err := s.uint(fn, "ftrace_mod_func", "size")
				if err != nil {
					return err
				}
				v := true
				return s.symbol(fn, address&s.mask, size, size != 0, name, "T", module, "ftrace", &v, map[string]evidence.Value{"MapObject": evidence.Address(at)})
			})
		})
		failures.add(err)
	}
	// Both structures and symbol are optional in the pinned kernel-version gates.
	if _, err := s.e.Symbols.Type("ftrace_ops"); err == nil {
		if _, err := s.e.Symbols.Lookup("ftrace_ops_trampoline_list"); err == nil {
			head, err := s.e.Symbol("ftrace_ops_trampoline_list")
			if err != nil {
				return err
			}
			err = s.walk(head, "ftrace_ops", "list", func(at uint64) error {
				address, err := s.uint(at, "ftrace_ops", "trampoline")
				if err != nil {
					return err
				}
				size, err := s.uint(at, "ftrace_ops", "trampoline_size")
				if err != nil {
					return err
				}
				field, err := s.e.Objects.Field("ftrace_ops", "trampoline")
				if err != nil {
					return err
				}
				// The fixed method does not apply an explicit mask, but its
				// Pointer object normalizes to the layer's address width.
				// Integer fields retain their captured high bits.
				if field.Type.Kind == "pointer" {
					address &= s.mask
				}
				v := false
				return s.symbol(at, address, size, size != 0, "ftrace_trampoline", "t", "__builtin__ftrace", "ftrace", &v, nil)
			})
			failures.add(err)
		}
	}
	return failures.err("ftrace symbols")
}
func (s *linuxKallsymsReader) bpf() error {
	typ, member := "bpf_ksym", "lnode"
	if _, err := s.e.Symbols.Type(typ); err != nil {
		typ, member = "bpf_prog_aux", "ksym_lnode"
		if _, err := s.e.Symbols.Type(typ); err != nil {
			return nil
		}
	}
	if _, err := s.e.Symbols.Lookup("bpf_kallsyms"); err != nil {
		return nil
	}
	head, err := s.e.Symbol("bpf_kallsyms")
	if err != nil {
		return err
	}
	return s.walk(head, typ, member, func(at uint64) error {
		s.nameIssues = nil
		proof := map[string]evidence.Value{}
		name, address, size, available, err := s.bpfSymbol(at, typ, proof)
		if err != nil {
			return s.issue(at, "bpf", err)
		}
		v := false
		return s.symbol(at, address&s.mask, size, available, name, "t", "bpf", "bpf", &v, proof)
	})
}
func (s *linuxKallsymsReader) bpfSymbol(at uint64, typ string, proof map[string]evidence.Value) (name string, address, size uint64, available bool, err error) {
	if typ == "bpf_ksym" {
		name, err = s.array(at, typ, "name")
		if err != nil {
			return
		}
		address, err = s.uint(at, typ, "start")
		if err != nil {
			return
		}
		var end uint64
		end, err = s.uint(at, typ, "end")
		if err != nil {
			return
		}
		proof["RegionStart"] = evidence.Address(address)
		proof["RegionEnd"] = evidence.Address(end)
		if end < address {
			return name, address, 0, false, nil
		}
		size = end - address
		return name, address, size, size != 0, nil
	}
	prog, err := s.uint(at, typ, "prog")
	if err != nil {
		return "", 0, 0, false, err
	}
	if prog == 0 {
		return "", 0, 0, false, fmt.Errorf("null BPF program")
	}

	info, err := kallsyms.ReadBPFProgram(s.ctx, s.e.Objects, prog)
	if err != nil {
		return "", 0, 0, false, err
	}
	proof["NameAvailable"] = evidence.Bool(info.NameAvailable)
	proof["ProgramObject"] = evidence.Address(info.Object)
	proof["AuxObject"] = evidence.Address(info.Aux)
	proof["RegionStart"] = evidence.Address(info.RegionStart)
	proof["RegionPages"] = evidence.Number(info.Pages)
	proof["Alignment"] = evidence.Number(info.Alignment)
	return info.Name, info.Function, info.RegionEnd - info.RegionStart, info.RegionEnd > info.RegionStart, nil
}

// Keep the fixed nm descriptions, including case-specific weak/undefined types.
var linuxKallsymsTypeDescriptions = map[string]string{
	"a": "Symbol is absolute and doesn't change during linking", "b": "Symbol in the BSS section, typically holding zero-initialized or uninitialized data", "c": "Symbol is common, typically holding uninitialized data", "d": "Symbol is in the initialized data section", "g": "Symbol is in an initialized data section for small objects", "i": "Symbol is an indirect reference to another symbol", "N": "Symbol is a debugging symbol", "n": "Symbol is in a non-data, non-code, non-debug read-only section", "p": "Symbol is in a stack unwind section", "r": "Symbol is in a read only data section", "s": "Symbol is in an uninitialized or zero-initialized data section for small objects", "t": "Symbol is in the text (code) section", "U": "Symbol is undefined", "u": "Symbol is a unique global symbol", "V": "Symbol is a weak object, with a default value", "v": "Symbol is a weak object", "W": "Symbol is a weak symbol but not marked as a weak object symbol, with a default value", "w": "Symbol is a weak symbol but not marked as a weak object symbol", "?": "Symbol type is unknown"}

func kallsymsTypeDescription(typ string) string {
	if description, ok := linuxKallsymsTypeDescriptions[typ]; ok {
		return description
	}
	return linuxKallsymsTypeDescriptions[strings.ToLower(typ)]
}

func (s *linuxKallsymsReader) order() (binary.ByteOrder, error) {
	pointer, err := s.e.Symbols.Type("pointer")
	if err != nil {
		return nil, err
	}
	switch pointer.Endian {
	case "little", "":
		return binary.LittleEndian, nil
	case "big":
		return binary.BigEndian, nil
	}
	return nil, fmt.Errorf("unknown pointer endianness")
}
