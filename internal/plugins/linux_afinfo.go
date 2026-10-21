package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var linuxAFInfoLegacyGlobals = []string{"tcp6_seq_afinfo", "tcp4_seq_afinfo", "udplite6_seq_afinfo", "udp6_seq_afinfo", "udplite4_seq_afinfo", "udp4_seq_afinfo"}
var linuxAFInfoModernGlobals = []string{"raw_seq_ops", "udp_seq_ops", "arp_seq_ops", "unix_seq_ops", "udp6_seq_ops", "raw6_seq_ops", "tcp_seq_ops", "tcp4_seq_ops", "tcp6_seq_ops", "packet_seq_ops"}

func linuxAFInfoPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.check_afinfo", Upstream: "linux.malware.check_afinfo.Check_afinfo", Platform: "linux", NeedsKernel: true, Description: "Check network operation handlers against exact kernel symbols, retaining every member decision", Parameters: []plugin.Parameter{{Name: "max-members", Kind: "uint", Default: "65536", Description: "Maximum considered operation members, 1..1000000"}}, Columns: []evidence.Column{{Name: "Symbol Name", Kind: "string"}, {Name: "Member", Kind: "string"}, {Name: "Handler Address", Kind: "address"}, {Name: "OperationAddress", Kind: "address"}, {Name: "OperationType", Kind: "string"}, {Name: "LookupMode", Kind: "string"}, {Name: "ExactSymbols", Kind: "structure"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Status", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}}}, linuxAFInfo}}
}

type linuxAFInfoCheck struct {
	ctx                                                                          context.Context
	e                                                                            plugin.Environment
	emit                                                                         plugin.Emit
	outputErr                                                                    error
	failures                                                                     pluginFailures
	max, visits, checked, flagged, zeros, ignored, missing, globals, diagnostics uint64
	mask                                                                         uint64
	absolute, relative                                                           map[uint64][]string
	layout                                                                       string
}

func (s *linuxAFInfoCheck) row(global, member, kind string) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: s.e.Kernel.Name()}}
	for _, c := range linuxAFInfoPlugins()[0].spec.Columns {
		r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
	}
	r.Cells["Symbol Name"], r.Cells["Member"], r.Cells["RecordType"] = evidence.Text(global), evidence.Text(member), evidence.Text(kind)
	return r
}
func (s *linuxAFInfoCheck) out(r evidence.Row) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.outputErr != nil {
		return s.outputErr
	}
	s.outputErr = s.emit(r)
	return s.outputErr
}
func (s *linuxAFInfoCheck) problem(r evidence.Row, reason string, cause error) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.failures.add(cause)
	s.diagnostics++
	r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Text(reason), evidence.Missing(reason, cause)
	return s.out(r)
}
func (s *linuxAFInfoCheck) reader(fields map[string]evidence.Value) *linuxModuleRead {
	return &linuxModuleRead{s.ctx, s.e, fields, &s.failures}
}

func (s *linuxAFInfoCheck) resolve(global string) (uint64, string, bool, error) {
	r := s.row(global, "", "symbol_observation")
	symbol, err := s.e.Symbols.Lookup(global)
	if err != nil {
		s.missing++
		r.Cells["Status"] = evidence.Text("optional_global_absent")
		return 0, "", false, s.out(r)
	}
	s.globals++
	at, err := s.e.Symbol(global)
	if err != nil {
		return 0, "", false, s.problem(r, "global_address_invalid", err)
	}
	r.Provenance.Offset = fmt.Sprintf("0x%x", at)
	fields := map[string]evidence.Value{"GlobalSymbol": {Kind: "structure", Data: map[string]evidence.Value{"Name": evidence.Text(global), "Address": evidence.Address(at), "SymbolDigest": evidence.Text(s.e.Symbols.Digest())}}}
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	if symbol.Type == nil {
		return 0, "", false, s.problem(r, "global_type_unavailable", fmt.Errorf("%s lacks typed symbol metadata", global))
	}
	ref := *symbol.Type
	if ref.Kind == "pointer" {
		at, err = s.reader(fields).scalar(at, ref)
		if err != nil {
			return 0, "", false, s.problem(r, "global_pointer_unreadable", err)
		}
		if ref.Underlying() == nil {
			return 0, "", false, s.problem(r, "global_target_type_unavailable", fmt.Errorf("%s lacks a target type", global))
		}
		ref = *ref.Underlying()
		if at == 0 {
			return 0, "", false, s.problem(r, "global_pointer_null", fmt.Errorf("%s pointer is null", global))
		}
	}
	if ref.Kind != "struct" && ref.Kind != "union" {
		return 0, "", false, s.problem(r, "global_type_unsupported", fmt.Errorf("%s must reference an operations structure", global))
	}
	r.Cells["OperationAddress"], r.Cells["OperationType"], r.Cells["Status"] = evidence.Address(at), evidence.Text(ref.Name), evidence.Text("available")
	return at, ref.Name, true, s.out(r)
}

func (s *linuxAFInfoCheck) container(global string, base uint64, typ, member string) (uint64, string, bool, error) {
	r := s.row(global, member, "container_observation")
	r.Provenance.Offset = fmt.Sprintf("0x%x", base)
	fields := map[string]evidence.Value{}
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	n := s.reader(fields)
	f, err := s.e.Objects.Field(typ, member)
	if err != nil {
		return 0, "", false, s.problem(r, "container_layout_unavailable", err)
	}
	// Capture the container field before attempting to follow a pointer.
	if _, err := n.capture(base, typ, member); err != nil {
		return 0, "", false, s.problem(r, "container_field_unreadable", err)
	}
	at, err := memory.Add(base, f.Offset)
	if err != nil {
		return 0, "", false, s.problem(r, "container_address_invalid", err)
	}
	ref := f.Type
	if ref.Kind == "pointer" {
		at, err = s.e.Objects.Uint(s.ctx, base, typ, member)
		if err != nil {
			return 0, "", false, s.problem(r, "container_pointer_unreadable", err)
		}
		if ref.Underlying() == nil {
			return 0, "", false, s.problem(r, "container_type_unavailable", fmt.Errorf("%s.%s lacks target metadata", typ, member))
		}
		ref = *ref.Underlying()
		if at == 0 {
			return 0, "", false, s.problem(r, "container_pointer_null", fmt.Errorf("%s.%s is null", typ, member))
		}
	}
	if ref.Kind != "struct" && ref.Kind != "union" {
		return 0, "", false, s.problem(r, "container_type_unsupported", fmt.Errorf("%s.%s is not an operation structure", typ, member))
	}
	r.Cells["OperationAddress"], r.Cells["OperationType"], r.Cells["Status"] = evidence.Address(at), evidence.Text(ref.Name), evidence.Text("available")
	return at, ref.Name, true, s.out(r)
}

var errAFInfoBound = errors.New("afinfo member inspection bound reached")

func (s *linuxAFInfoCheck) check(global string, at uint64, typ string, members []string, relative bool) error {
	for _, member := range members {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if s.visits >= s.max {
			return errAFInfoBound
		}
		s.visits++
		r := s.row(global, member, "member_observation")
		r.Cells["OperationAddress"], r.Cells["OperationType"] = evidence.Address(at), evidence.Text(typ)
		r.Provenance.Offset = fmt.Sprintf("0x%x", at)
		mode, index := "absolute_exact", s.absolute
		if relative {
			mode, index = "relative_exact", s.relative
			r.Cells["Member"] = evidence.Text("show")
		}
		r.Cells["LookupMode"] = evidence.Text(mode)
		if !relative && strings.HasPrefix(member, "__UNIQUE_ID_rh_kabi_hide") {
			s.ignored++
			r.Cells["Status"] = evidence.Text("ignored_rh_kabi_member")
			if err := s.out(r); err != nil {
				return err
			}
			continue
		}
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		addr, err := s.reader(fields).uint(at, typ, member)
		if err != nil {
			if err := s.problem(r, "handler_field_unreadable", err); err != nil {
				return err
			}
			continue
		}
		r.Cells["Handler Address"] = evidence.Address(addr)
		if addr == 0 && !relative {
			s.zeros++
			r.Cells["Status"] = evidence.Text("unimplemented_zero")
			if err := s.out(r); err != nil {
				return err
			}
			continue
		}
		s.checked++
		names := index[addr&s.mask]
		r.Cells["ExactSymbols"] = evidence.Value{Kind: "structure", Data: map[string]any{"Names": append([]string{}, names...), "SymbolDigest": s.e.Symbols.Digest(), "Mask": fmt.Sprintf("0x%x", s.mask)}}
		r.Cells["Status"] = evidence.Text("known_exact_symbol")
		if len(names) == 0 {
			s.flagged++
			r.Cells["RecordType"], r.Cells["Status"] = evidence.Text("handler"), evidence.Text("unknown_exact_symbol")
		}
		if err := s.out(r); err != nil {
			return err
		}
	}
	return nil
}

func linuxAFInfo(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("afinfo inspection requires kernel memory and symbols")
	}
	max, err := strconv.ParseUint(p["max-members"], 0, 32)
	if err != nil || max < 1 || max > 1000000 {
		return fmt.Errorf("max-members must be 1..1000000")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	tcp, err := e.Symbols.Type("tcp_seq_afinfo")
	if err != nil {
		return err
	}
	seq, err := e.Symbols.Type("seq_operations")
	if err != nil {
		return err
	}
	seqMembers := seq.MemberNames()
	if len(seqMembers) == 0 {
		return fmt.Errorf("seq_operations has no declared members")
	}
	s := &linuxAFInfoCheck{ctx: ctx, e: e, emit: out, max: max, mask: mask, absolute: map[uint64][]string{}, relative: map[uint64][]string{}, layout: "post_4_18"}
	for _, name := range e.Symbols.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		symbol, err := e.Symbols.Lookup(name)
		if err != nil {
			return err
		}
		at, err := e.Symbol(name)
		if err != nil {
			return err
		}
		s.absolute[at&mask] = append(s.absolute[at&mask], name)
		s.relative[symbol.Address&mask] = append(s.relative[symbol.Address&mask], name)
	}
	linuxAFSortSymbols(s.absolute)
	linuxAFSortSymbols(s.relative)
	_, legacy := tcp.Fields["seq_fops"]
	// Field lookup also supports declared anonymous embedded layouts.
	if _, err := e.Objects.Field("tcp_seq_afinfo", "seq_fops"); err == nil {
		legacy = true
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return err
	}
	globals := linuxAFInfoModernGlobals
	var opMembers []string
	if legacy {
		s.layout = "pre_4_18"
		globals = linuxAFInfoLegacyGlobals
		ops, err := e.Symbols.Type("file_operations")
		if err != nil {
			return err
		}
		opMembers = ops.MemberNames()
		if len(opMembers) == 0 {
			return fmt.Errorf("file_operations has no declared members")
		}
	}
	for _, global := range globals {
		at, typ, present, err := s.resolve(global)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if !legacy {
			err = s.check(global, at, typ, seqMembers, false)
		} else {
			n := s.reader(map[string]evidence.Value{})
			has, hasErr := n.has(typ, "seq_fops")
			if hasErr != nil {
				return hasErr
			}
			if has {
				base, kind, present, cause := s.container(global, at, typ, "seq_fops")
				if cause != nil {
					return cause
				}
				if present {
					err = s.check(global, base, kind, opMembers, false)
				}
			}
			if err == nil {
				has, hasErr = n.has(typ, "seq_ops")
				if hasErr != nil {
					return hasErr
				}
				if has {
					base, kind, present, cause := s.container(global, at, typ, "seq_ops")
					if cause != nil {
						return cause
					}
					if present {
						err = s.check(global, base, kind, seqMembers, false)
					}
				} else {
					has, hasErr = n.has(typ, "seq_show")
					if hasErr != nil {
						return hasErr
					}
					if has {
						err = s.check(global, at, typ, []string{"seq_show"}, true)
					} else {
						err = fmt.Errorf("%s lacks sequence operations members", typ)
					}
				}
			}
		}
		if s.outputErr != nil {
			return s.outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			r := s.row(global, "", "diagnostic")
			if cause := s.problem(r, "operation_inspection_incomplete", err); cause != nil {
				return cause
			}
			if errors.Is(err, errAFInfoBound) {
				break
			}
		}
	}
	r := s.row("", "", "summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"layout": s.layout, "globals_present": formatCount(s.globals), "globals_absent": formatCount(s.missing), "member_visits": formatCount(s.visits), "checked_nonzero_or_seq_show": formatCount(s.checked), "flagged_handlers": formatCount(s.flagged), "unimplemented_zero": formatCount(s.zeros), "ignored_rh_members": formatCount(s.ignored), "diagnostics": formatCount(s.diagnostics), "read_layout_errors": strconv.Itoa(s.failures.count), "member_order": "symbol_declaration_order", "scope": "exact symbol membership is not a verdict of maliciousness"})
	if err := s.out(r); err != nil {
		return err
	}
	return s.failures.err("Linux network operation checks")
}

// Keep symbol-name lists deterministic even for SymbolTable implementations
// whose Names snapshot is not sorted.
func linuxAFSortSymbols(index map[uint64][]string) {
	for _, names := range index {
		sort.Strings(names)
	}
}
