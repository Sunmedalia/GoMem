package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type linuxModuleInfo struct {
	offset, base, size uint64
	name, source       string
}
type linuxModuleRead struct {
	ctx      context.Context
	e        plugin.Environment
	fields   map[string]evidence.Value
	failures *pluginFailures
}

func (n *linuxModuleRead) capture(base uint64, typ, field string) ([]byte, error) {
	raw, value, err := linuxCaptureField(n.ctx, n.e, base, typ, field)
	n.fields[fmt.Sprintf("%s@%x.%s", typ, base, field)] = value
	n.failures.add(err)
	return raw, err
}
func (n *linuxModuleRead) uint(base uint64, typ, field string) (uint64, error) {
	if _, err := n.capture(base, typ, field); err != nil {
		return 0, err
	}
	v, err := n.e.Objects.Uint(n.ctx, base, typ, field)
	n.failures.add(err)
	return v, err
}
func (n *linuxModuleRead) sint(base uint64, typ, field string) (int64, error) {
	if _, err := n.capture(base, typ, field); err != nil {
		return 0, err
	}
	v, err := n.e.Objects.Int(n.ctx, base, typ, field)
	n.failures.add(err)
	return v, err
}
func (n *linuxModuleRead) scalar(address uint64, ref symbols.TypeRef) (uint64, error) {
	size, err := n.e.Objects.Size(ref)
	if err != nil || size < 1 || size > 8 {
		err = fmt.Errorf("invalid module global scalar extent %d: %v", size, err)
		n.failures.add(err)
		return 0, err
	}
	_, proof, err := linuxCaptureRange(n.ctx, n.e.Kernel, address, int(size))
	n.fields[fmt.Sprintf("scalar@%x", address)] = proof
	n.failures.add(err)
	if err != nil {
		return 0, err
	}
	value, err := n.e.Objects.Scalar(n.ctx, address, ref)
	n.failures.add(err)
	return value, err
}
func (n *linuxModuleRead) text(base uint64, typ, field string) (string, error) {
	raw, err := n.capture(base, typ, field)
	return spoofDecoded(raw), err
}
func (n *linuxModuleRead) has(typ, field string) (bool, error) {
	_, err := n.e.Objects.Field(typ, field)
	if errors.Is(err, object.ErrFieldAbsent) {
		return false, nil
	}
	return err == nil, err
}

// New kernels sum discontiguous module_memory sizes. Preserve that pinned
// range model rather than pretending each byte in [base,base+size) is mapped.
func (n *linuxModuleRead) layout(module uint64, kind string) (uint64, error) {
	modern, err := n.has("module", "mem")
	if err != nil {
		n.failures.add(err)
		return 0, err
	}
	if modern {
		names := map[string][]string{"base": {"MOD_TEXT"}, "core": {"MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT"}, "text": {"MOD_TEXT"}, "init": {"MOD_INIT_TEXT", "MOD_INIT_DATA", "MOD_INIT_RODATA"}}[kind]
		enum, err := linuxEnumChoices(n.e, "mod_mem_type", nil)
		if err != nil {
			n.failures.add(err)
			return 0, err
		}
		array, err := n.e.Objects.Field("module", "mem")
		if err != nil {
			return 0, err
		}
		if array.Type.Kind != "array" || array.Type.Underlying() == nil {
			return 0, fmt.Errorf("module.mem is not an array")
		}
		subtype := *array.Type.Underlying()
		if subtype.Kind != "struct" {
			return 0, fmt.Errorf("module.mem elements are not structures")
		}
		stride, err := n.e.Objects.Size(subtype)
		if err != nil {
			return 0, err
		}
		var sum uint64
		for _, name := range names {
			index, ok := enum[name]
			if !ok || index >= array.Type.Count {
				return 0, fmt.Errorf("missing/out-of-range mod_mem_type.%s", name)
			}
			if stride == 0 || index > (^uint64(0)-array.Offset)/stride {
				return 0, fmt.Errorf("module memory array offset overflow")
			}
			address, err := memory.Add(module, array.Offset+index*stride)
			if err != nil {
				return 0, err
			}
			field := "size"
			if kind == "base" {
				field = "base"
			}
			value, err := n.uint(address, subtype.Name, field)
			if err != nil {
				return 0, err
			}
			sum, err = memory.Add(sum, value)
			if err != nil {
				return 0, err
			}
		}
		return sum, nil
	}
	container := "core_layout"
	member := map[string]string{"base": "base", "core": "size", "text": "text_size"}[kind]
	if kind == "init" {
		container, member = "init_layout", "size"
	}
	present, err := n.has("module", container)
	if err != nil {
		return 0, err
	}
	if present {
		return n.uint(module, "module", container+"."+member)
	}
	legacy := map[string]string{"base": "module_core", "core": "core_size", "text": "core_text_size", "init": "init_size"}[kind]
	if legacy == "" {
		return 0, fmt.Errorf("unknown module extent %s", kind)
	}
	return n.uint(module, "module", legacy)
}

func linuxModuleRow(e plugin.Environment, address uint64, kind, source string) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	for _, c := range linuxModxviewPlugins()[0].spec.Columns {
		r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
	}
	r.Cells["Address"], r.Cells["RecordType"], r.Cells["Source"] = evidence.Address(address), evidence.Text(kind), evidence.Text(source)
	return r
}

type linuxModuleSources struct {
	ctx                                                              context.Context
	e                                                                plugin.Environment
	emit                                                             plugin.Emit
	emitErr                                                          error
	failures                                                         pluginFailures
	maxNodes                                                         int
	maxScan                                                          uint64
	nodes, positions, unreadable, selfMatches, rejected, diagnostics uint64
	results                                                          map[string][]linuxModuleInfo
	comparisonOnly                                                   bool
	quietBounds                                                      bool
	ksetModules                                                      map[string]uint64
	ksetOrder                                                        []string
}

func (s *linuxModuleSources) out(r evidence.Row) error {
	if s.emitErr != nil {
		return s.emitErr
	}
	s.emitErr = s.emit(r)
	return s.emitErr
}
func (s *linuxModuleSources) issue(address uint64, source, reason string, cause error) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if s.emitErr != nil {
		return s.emitErr
	}
	s.failures.add(cause)
	s.diagnostics++
	r := linuxModuleRow(s.e, address, "diagnostic", source)
	if address == 0 {
		r.Cells["Address"] = evidence.Missing("source_address_unavailable", nil)
		r.Provenance.Offset = ""
	}
	r.Cells["Error"] = evidence.Missing(reason, cause)
	r.Cells["Status"] = evidence.Text(reason)
	return s.out(r)
}
func (s *linuxModuleSources) visit() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.nodes >= uint64(s.maxNodes) {
		return fmt.Errorf("module source visits exceed max-nodes %d", s.maxNodes)
	}
	s.nodes++
	return nil
}
func (s *linuxModuleSources) reader(fields map[string]evidence.Value) *linuxModuleRead {
	return &linuxModuleRead{s.ctx, s.e, fields, &s.failures}
}
func (s *linuxModuleSources) info(address uint64, source string) (*linuxModuleInfo, error) {
	r := linuxModuleRow(s.e, address, "module_observation", source)
	fields := map[string]evidence.Value{}
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	n := s.reader(fields)
	before := s.failures.count
	if source == "Lsmod" {
		n.capture(address, "module", "list")
	}
	name, nameErr := n.text(address, "module", "name")
	if s.comparisonOnly && source == "Lsmod" {
		if nameErr != nil {
			r.Cells["Name"] = evidence.Missing("module_name_unreadable", nameErr)
		} else {
			r.Cells["Name"] = evidence.Text(name)
		}
		if err := s.out(r); err != nil {
			return nil, err
		}
		if nameErr != nil {
			return nil, nil
		}
		return &linuxModuleInfo{offset: address, name: name, source: source}, nil
	}
	base, baseErr := n.layout(address, "base")
	size, sizeErr := n.layout(address, "core")
	if nameErr == nil {
		r.Cells["Name"] = evidence.Text(name)
	} else {
		r.Cells["Name"] = evidence.Missing("module_name_unreadable", nameErr)
	}
	if baseErr == nil {
		r.Cells["Base"] = evidence.Address(base)
	} else {
		r.Cells["Base"] = evidence.Missing("module_base_unavailable", baseErr)
		s.failures.add(baseErr)
	}
	if sizeErr == nil {
		r.Cells["Size"] = evidence.Number(size)
	} else {
		r.Cells["Size"] = evidence.Missing("module_size_unavailable", sizeErr)
		s.failures.add(sizeErr)
	}
	var info *linuxModuleInfo
	if nameErr == nil && baseErr == nil && sizeErr == nil {
		end, err := memory.Add(base, size)
		if err != nil {
			s.failures.add(err)
			r.Cells["End"] = evidence.Missing("module_range_overflow", err)
		} else {
			r.Cells["End"] = evidence.Address(end)
			info = &linuxModuleInfo{address, base, size, name, source}
		}
	}
	if s.failures.count > before {
		r.Cells["Error"] = evidence.Missing("module_fields_incomplete", fmt.Errorf("%d module errors", s.failures.count-before))
		r.Cells["Status"] = evidence.Text("excluded")
	} else {
		r.Cells["Status"] = evidence.Text("included")
	}
	if err := s.out(r); err != nil {
		return nil, err
	}
	return info, nil
}
func (s *linuxModuleSources) lsmod() error {
	root, err := s.e.Symbol("modules")
	if err != nil {
		return err
	}
	link, err := s.e.Objects.Field("module", "list")
	if err != nil {
		return err
	}
	fields := map[string]evidence.Value{}
	s.reader(fields).capture(root, "list_head", "")
	r := linuxModuleRow(s.e, root, "source_observation", "Lsmod")
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	r.Cells["Status"] = evidence.Text("root")
	if err := s.out(r); err != nil {
		return err
	}
	return s.e.Objects.WalkList(s.ctx, root, link.Offset, s.maxNodes, func(module uint64) error {
		if err := s.visit(); err != nil {
			return err
		}
		info, err := s.info(module, "Lsmod")
		if err != nil {
			return err
		}
		if info != nil {
			s.results["Lsmod"] = append(s.results["Lsmod"], *info)
		}
		return nil
	})
}
func (s *linuxModuleSources) sysfs() error {
	symbol, err := s.e.Symbols.Lookup("module_kset")
	if err != nil {
		return err
	}
	at, err := s.e.Symbol("module_kset")
	if err != nil {
		return err
	}
	if symbol.Type == nil {
		return fmt.Errorf("module_kset symbol lacks type information")
	}
	root := at
	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	if symbol.Type.Kind == "pointer" {
		root, err = n.scalar(at, *symbol.Type)
		if err != nil {
			return err
		}
	} else if symbol.Type.Kind != "struct" {
		return fmt.Errorf("module_kset is not a pointer/structure")
	}
	if root == 0 {
		return fmt.Errorf("module_kset is null")
	}
	headField, err := s.e.Objects.Field("kset", "list")
	if err != nil {
		return err
	}
	head, err := memory.Add(root, headField.Offset)
	if err != nil {
		return err
	}
	entry, err := s.e.Objects.Field("kobject", "entry")
	if err != nil {
		return err
	}
	kobj, err := s.e.Objects.Field("module_kobject", "kobj")
	if err != nil {
		return err
	}
	n.capture(root, "kset", "list")
	r := linuxModuleRow(s.e, root, "source_observation", "SysFs")
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	r.Cells["Status"] = evidence.Text("root")
	if err := s.out(r); err != nil {
		return err
	}
	type candidate struct {
		name            string
		module, kobject uint64
		included        bool
	}
	candidates := []candidate{}
	selected := map[string]int{}
	order := []string{}
	err = s.e.Objects.WalkList(s.ctx, head, entry.Offset, s.maxNodes, func(address uint64) error {
		if err := s.visit(); err != nil {
			return err
		}
		r := linuxModuleRow(s.e, address, "sysfs_candidate", "SysFs")
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		n := s.reader(fields)
		before := s.failures.count
		n.capture(address, "kobject", "entry")
		if address < kobj.Offset {
			return s.issue(address, "SysFs", "module_kobject_underflow", fmt.Errorf("kobject container underflow"))
		}
		module, modErr := n.uint(address-kobj.Offset, "module_kobject", "mod")
		if modErr == nil {
			r.Cells["Address"] = evidence.Address(module)
		}
		namePointer, nameErr := n.uint(address, "kobject", "name")
		name := ""
		if nameErr == nil {
			raw, proof, err := linuxCaptureRange(s.ctx, s.e.Kernel, namePointer, 32)
			fields["name_bytes"] = proof
			s.failures.add(err)
			nameErr = err
			if err == nil {
				name = spoofDecoded(raw)
			}
		}
		r.Cells["SourceOffset"], r.Cells["KObjectName"] = evidence.Address(address), evidence.Text(name)
		refPath := "kref.refcount.counter"
		if _, err := s.e.Objects.Field("kobject", refPath); errors.Is(err, object.ErrFieldAbsent) {
			refPath = "kref.refcount.refs.counter"
		}
		var refs int64
		var refErr error
		if nameErr == nil && namePointer != 0 {
			refs, refErr = n.sint(address, "kobject", refPath)
			if refErr == nil {
				r.Cells["RefCount"] = evidence.Integer(refs)
			} else {
				r.Cells["RefCount"] = evidence.Missing("kobject_refcount_unreadable", refErr)
			}
		}
		included := modErr == nil && nameErr == nil && refErr == nil && namePointer != 0 && refs > 2
		if included {
			if _, ok := selected[name]; !ok {
				order = append(order, name)
			}
			selected[name] = len(candidates)
		}
		candidates = append(candidates, candidate{name, module, address, included})
		r.Cells["Selected"] = evidence.Bool(included)
		r.Cells["Status"] = evidence.Text("candidate")
		if s.failures.count > before {
			r.Cells["Error"] = evidence.Missing("sysfs_fields_incomplete", fmt.Errorf("%d sysfs errors", s.failures.count-before))
		}
		return s.out(r)
	})
	if err != nil {
		if err := s.issue(head, "SysFs", "sysfs_list_incomplete", err); err != nil {
			return err
		}
	}
	for i, c := range candidates {
		r := linuxModuleRow(s.e, c.module, "source_selection", "SysFs")
		r.Cells["SourceOffset"], r.Cells["KObjectName"] = evidence.Address(c.kobject), evidence.Text(c.name)
		included := c.included && selected[c.name] == i
		r.Cells["Selected"] = evidence.Bool(included)
		status := "excluded"
		if included {
			status = "included"
		} else if c.included {
			status = "replaced_duplicate_name"
		}
		r.Cells["Status"] = evidence.Text(status)
		if err := s.out(r); err != nil {
			return err
		}
	}
	s.ksetModules = map[string]uint64{}
	s.ksetOrder = append([]string(nil), order...)
	for _, name := range order {
		c := candidates[selected[name]]
		s.ksetModules[name] = c.module
		if s.comparisonOnly {
			s.results["SysFs"] = append(s.results["SysFs"], linuxModuleInfo{offset: c.module, source: "SysFs"})
			continue
		}
		info, err := s.info(c.module, "SysFs")
		if err != nil {
			return err
		}
		if info != nil {
			s.results["SysFs"] = append(s.results["SysFs"], *info)
		}
	}
	return nil
}
func (s *linuxModuleSources) boundaries() (uint64, uint64, error) {
	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	var low, high, at uint64
	var err error
	if symbol, lookupErr := s.e.Symbols.Lookup("mod_tree"); lookupErr == nil {
		at, err = s.e.Symbol("mod_tree")
		if err == nil {
			if symbol.Type == nil || symbol.Type.Kind != "struct" {
				err = fmt.Errorf("mod_tree symbol must declare its structure type")
			} else {
				low, err = n.uint(at, symbol.Type.Name, "addr_min")
				if err == nil {
					high, err = n.uint(at, symbol.Type.Name, "addr_max")
				}
			}
		}
	} else {
		for i, name := range []string{"module_addr_min", "module_addr_max"} {
			symbol, lookupErr := s.e.Symbols.Lookup(name)
			if lookupErr != nil {
				err = lookupErr
				break
			}
			at, err = s.e.Symbol(name)
			if err != nil {
				break
			}
			if symbol.Type == nil || symbol.Type.Kind == "void" {
				err = fmt.Errorf("%s lacks typed scalar metadata", name)
				break
			}
			value, readErr := n.scalar(at, *symbol.Type)
			if readErr != nil {
				err = readErr
				break
			}
			if i == 0 {
				low = value
			} else {
				high = value
			}
		}
	}
	r := linuxModuleRow(s.e, at, "source_observation", "Scanner")
	r.Cells["Base"], r.Cells["End"], r.Cells["FieldEvidence"] = evidence.Address(low), evidence.Address(high), evidence.Value{Kind: "structure", Data: fields}
	r.Cells["Status"] = evidence.Text("allocation_bounds")
	if err != nil {
		r.Cells["Error"] = evidence.Missing("allocation_bounds_unavailable", err)
	}
	if !s.quietBounds {
		if emitErr := s.out(r); emitErr != nil {
			return 0, 0, emitErr
		}
	}
	if err != nil {
		return 0, 0, err
	}
	if high < low {
		return 0, 0, fmt.Errorf("inverted module allocation bounds")
	}
	if high-low > s.maxScan {
		return 0, 0, fmt.Errorf("module allocation span %d exceeds max-scan-bytes %d", high-low, s.maxScan)
	}
	return low, high, nil
}

// Prefilters scan allocation holes by available page prefixes. A partial page
// does not erase candidates whose pointer bytes were completely captured.
func (s *linuxModuleSources) scanner() error {
	low, high, err := s.boundaries()
	if err != nil {
		return err
	}
	self, err := s.e.Objects.Field("module", "mkobj.mod")
	if err != nil {
		return err
	}
	if self.Type.Kind != "pointer" {
		return fmt.Errorf("module.mkobj.mod must be a pointer")
	}
	width, err := s.e.Objects.Size(self.Type)
	if err != nil || width < 1 || width > 8 {
		return fmt.Errorf("invalid module self-pointer extent %d: %v", width, err)
	}
	step := uint64(s.e.Symbols.PointerSize())
	if step != 4 && step != 8 {
		return fmt.Errorf("invalid module pointer width")
	}
	pointerType, err := s.e.Symbols.Type("pointer")
	if err != nil {
		return err
	}
	var pageBase uint64
	var page []byte
	pageSet := false
	read := func(address uint64) (uint64, bool) {
		base := address &^ uint64(4095)
		offset := address - base
		if !pageSet || pageBase != base {
			buf := make([]byte, 4096)
			got, err := s.e.Kernel.ReadAt(s.ctx, buf, base)
			if got < 0 || got > len(buf) {
				got = 0
			}
			if err == nil && got != len(buf) {
				err = io.ErrUnexpectedEOF
			}
			_ = err
			page = buf[:got]
			pageBase = base
			pageSet = true
		}
		var raw []byte
		if offset+width <= uint64(len(page)) {
			raw = page[offset : offset+width]
		} else if offset+width > 4096 {
			data, err := memory.Read(s.ctx, s.e.Kernel, address, int(width))
			if err != nil {
				return 0, false
			}
			raw = data
		} else {
			return 0, false
		}
		// Follow the symbol pointer format rather than host byte order.
		var value uint64
		if pointerType.Endian == "big" {
			for _, b := range raw {
				value = value<<8 | uint64(b)
			}
		} else {
			for i, b := range raw {
				value |= uint64(b) << uint(i*8)
			}
		}
		return value, true
	}
	for address := low; address < high; {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		s.positions++
		at, err := memory.Add(address, self.Offset)
		if err != nil {
			return err
		}
		value, ok := read(at)
		if !ok {
			s.unreadable++
		} else if value == address {
			s.selfMatches++
			if err := s.visit(); err != nil {
				return err
			}
			r := linuxModuleRow(s.e, address, "scan_candidate", "Scanner")
			fields := map[string]evidence.Value{}
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			n := s.reader(fields)
			before := s.failures.count
			_, wholeErr := n.capture(address, "module", "")
			core, coreErr := n.layout(address, "core")
			text, textErr := n.layout(address, "text")
			init, initErr := n.layout(address, "init")
			pointer, pointerErr := n.uint(address, "module", "mkobj.mod")
			for _, v := range []struct {
				key   string
				value uint64
				err   error
			}{{"Size", core, coreErr}, {"CoreTextSize", text, textErr}, {"InitSize", init, initErr}} {
				if v.err != nil {
					s.failures.add(v.err)
					r.Cells[v.key] = evidence.Missing("module_layout_unavailable", v.err)
				} else {
					r.Cells[v.key] = evidence.Number(v.value)
				}
			}
			valid := linuxModuleCandidateValid(core, text, init, pointer, address, wholeErr == nil && coreErr == nil && textErr == nil && initErr == nil && pointerErr == nil)
			if valid {
				r.Cells["Status"] = evidence.Text("valid")
			} else {
				s.rejected++
				r.Cells["Status"] = evidence.Text("invalid_module")
			}
			if s.failures.count > before {
				r.Cells["Error"] = evidence.Missing("scan_candidate_incomplete", fmt.Errorf("%d candidate errors", s.failures.count-before))
			}
			if err := s.out(r); err != nil {
				return err
			}
			if valid {
				info, err := s.info(address, "Scanner")
				if err != nil {
					return err
				}
				if info != nil {
					s.results["Scanner"] = append(s.results["Scanner"], *info)
				}
			}
		}
		if high-address <= step {
			break
		}
		address += step
	}
	return nil
}

func linuxGatherModuleSources(ctx context.Context, e plugin.Environment, p map[string]string, emit plugin.Emit) (*linuxModuleSources, error) {
	return linuxGatherModuleSourcesFor(ctx, e, p, emit, true)
}

func linuxGatherModuleLists(ctx context.Context, e plugin.Environment, p map[string]string, emit plugin.Emit) (*linuxModuleSources, error) {
	return linuxGatherModuleSourcesFor(ctx, e, p, emit, false)
}

func linuxGatherModuleSourcesFor(ctx context.Context, e plugin.Environment, p map[string]string, emit plugin.Emit, scan bool) (*linuxModuleSources, error) {
	max, _, err := limits(p)
	if err != nil {
		return nil, err
	}
	var span uint64
	if scan {
		span, err = strconv.ParseUint(p["max-scan-bytes"], 0, 64)
		if err != nil || span < 1 || span > 8<<30 {
			return nil, fmt.Errorf("max-scan-bytes must be 1..8589934592")
		}
	}
	s := &linuxModuleSources{comparisonOnly: !scan, ctx: ctx, e: e, emit: emit, maxNodes: max, maxScan: span, results: map[string][]linuxModuleInfo{"Lsmod": {}, "SysFs": {}, "Scanner": {}}}
	gatherers := []struct {
		name string
		run  func() error
	}{{"Lsmod", s.lsmod}, {"SysFs", s.sysfs}}
	if scan {
		gatherers = append(gatherers, struct {
			name string
			run  func() error
		}{"Scanner", s.scanner})
	}
	for _, g := range gatherers {
		if err := g.run(); err != nil {
			if ctx.Err() != nil {
				return s, ctx.Err()
			}
			if s.emitErr != nil {
				return s, s.emitErr
			}
			if err := s.issue(0, g.name, "module_source_incomplete", err); err != nil {
				return s, err
			}
		}
	}
	return s, nil
}

// Used by pointer-lookup consumers: first-seen base wins, in fixed gatherer
// order. Modxview itself deliberately aggregates by object offset instead.
func linuxFlattenModuleSources(results map[string][]linuxModuleInfo, mask uint64) []linuxModuleInfo {
	var out []linuxModuleInfo
	seen := map[uint64]bool{}
	for _, source := range []string{"Lsmod", "SysFs", "Scanner", "kernel"} {
		for _, info := range results[source] {
			if !seen[info.base&mask] {
				seen[info.base&mask] = true
				out = append(out, info)
			}
		}
	}
	return out
}

func linuxModuleCandidateValid(core, text, init, pointer, address uint64, readable bool) bool {
	return readable && text > 0 && text <= 20000000 && core > 0 && core <= 20000000 && (core >= 4096 || init >= 4096-core) && pointer != 0 && pointer == address
}

type linuxModuleAggregate struct {
	offset    uint64
	gatherers []string
}

func linuxAggregateModuleSources(results map[string][]linuxModuleInfo) []linuxModuleAggregate {
	modules := []linuxModuleAggregate{}
	byOffset := map[uint64]int{}
	for _, source := range []string{"Lsmod", "SysFs", "Scanner"} {
		for _, info := range results[source] {
			index, ok := byOffset[info.offset]
			if !ok {
				index = len(modules)
				byOffset[info.offset] = index
				modules = append(modules, linuxModuleAggregate{offset: info.offset})
			}
			modules[index].gatherers = append(modules[index].gatherers, source)
		}
	}
	return modules
}
