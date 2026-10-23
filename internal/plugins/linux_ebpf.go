package plugins

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/linuxcache"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxEBPFPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.ebpf", Upstream: "linux.ebpf.EBPF", Platform: "linux", NeedsKernel: true, Description: "Enumerate IDR-backed eBPF programs with raw index and metadata evidence", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "IDR node traversal bound, 1..1000000"}, {Name: "max-programs", Kind: "uint", Default: "1000000", Description: "IDR leaf/program bound, 1..1000000"}}, Columns: []evidence.Column{{Name: "Address", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "Tag", Kind: "string"}, {Name: "Type", Kind: "string"}, {Name: "ID", Kind: "uint64"}, {Name: "Index", Kind: "uint64"}, {Name: "Slot", Kind: "address"}, {Name: "Selected", Kind: "bool"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "Coverage", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "missing"}}}, linuxEBPF}}
}

type linuxIDRStats struct {
	layout         string
	nodes, entries uint64
}
type linuxIDREntry struct {
	index, id, address, slot uint64
	kind                     string
	selected                 bool
}

// Walk modern embedded roots through the shared tree implementation. Legacy
// IDR has a different eight-bit fanout and an exclusive cur bound. Keep all
// native leaves: Selected records the pinned legacy idr_max quirk (IDs 0..15).
func walkLinuxIDR(ctx context.Context, r *object.Reader, root, maxNodes, maxEntries uint64, emit func(linuxIDREntry) error) (stats linuxIDRStats, err error) {
	if maxNodes == 0 || maxNodes > 1000000 || maxEntries == 0 || maxEntries > 1000000 {
		return stats, fmt.Errorf("invalid IDR bounds")
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	rt, err := r.Field("idr", "idr_rt")
	if err == nil {
		if rt.Type.Kind != "struct" {
			return stats, fmt.Errorf("idr_rt is not embedded")
		}
		address, err := memory.Add(root, rt.Offset)
		if err != nil {
			return stats, err
		}
		base := uint64(0)
		if _, err := r.Field("idr", "idr_base"); err == nil {
			base, err = r.Uint(ctx, root, "idr", "idr_base")
			if err != nil {
				return stats, err
			}
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return stats, err
		}
		if base > 1<<31-1 {
			return stats, fmt.Errorf("invalid IDR base")
		}
		result, err := linuxcache.WalkRoot(ctx, r, address, rt.Type.Name, linuxcache.Limits{Nodes: maxNodes, Entries: maxEntries}, func(e linuxcache.Entry) error {
			id, err := memory.Add(base, e.Index)
			if err != nil || id > 1<<31-1 {
				return fmt.Errorf("IDR ID exceeds signed integer range")
			}
			if e.Kind == "page" && e.Span != 1 {
				return fmt.Errorf("nonunit IDR leaf span")
			}
			return emit(linuxIDREntry{e.Index, id, e.Value, e.Slot, e.Kind, true})
		})
		stats.layout, stats.nodes, stats.entries = result.Kind, result.Nodes, result.Entries
		return stats, err
	}
	if !errors.Is(err, object.ErrFieldAbsent) {
		return stats, err
	}
	stats.layout = "legacy"
	cur, err := r.Uint(ctx, root, "idr", "cur")
	if err != nil {
		return stats, err
	}
	if cur > 1<<31 {
		return stats, fmt.Errorf("invalid legacy IDR cursor")
	}
	topField, err := r.Field("idr", "top")
	if err != nil {
		return stats, err
	}
	if topField.Type.Kind != "pointer" {
		return stats, fmt.Errorf("legacy IDR top is not a pointer")
	}
	top, err := r.Uint(ctx, root, "idr", "top")
	if err != nil {
		return stats, err
	}
	if cur == 0 || top == 0 {
		return stats, nil
	}
	ary, err := r.Field("idr_layer", "ary")
	if err != nil {
		return stats, err
	}
	width := uint64(r.Symbols.PointerSize())
	if width != 4 && width != 8 || ary.Type.Kind != "array" || ary.Type.Count != 256 || ary.Type.Underlying() == nil || ary.Type.Underlying().Kind != "pointer" {
		return stats, fmt.Errorf("legacy IDR requires 256 declared pointer slots")
	}
	size, err := r.Size(*ary.Type.Underlying())
	if err != nil || size != width {
		return stats, fmt.Errorf("invalid IDR slot width")
	}
	height, err := r.Uint(ctx, top, "idr_layer", "layer")
	if err != nil {
		return stats, err
	}
	if height > 3 || cur > uint64(1)<<((height+1)*8) {
		return stats, fmt.Errorf("invalid legacy IDR height")
	}
	seen := map[uint64]bool{}
	var walk func(uint64, uint64, uint64) error
	walk = func(node, prefix, level uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if node == 0 || node%width != 0 || seen[node] {
			return fmt.Errorf("invalid/repeated IDR node %#x", node)
		}
		if stats.nodes >= maxNodes {
			return fmt.Errorf("IDR node limit exhausted")
		}
		stats.nodes++
		seen[node] = true
		actual, err := r.Uint(ctx, node, "idr_layer", "layer")
		if err != nil {
			return err
		}
		if actual != level {
			return fmt.Errorf("IDR layer mismatch")
		}
		slots, err := memory.Add(node, ary.Offset)
		if err != nil {
			return err
		}
		for i := uint64(0); i < 256; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			index := prefix + (i << (level * 8))
			if index >= cur {
				break
			}
			slot, err := memory.Add(slots, i*width)
			if err != nil {
				return err
			}
			value, err := r.Scalar(ctx, slot, *ary.Type.Underlying())
			if err != nil {
				return err
			}
			if value == 0 {
				continue
			}
			if level > 0 {
				if err = walk(value, index, level-1); err != nil {
					return err
				}
				continue
			}
			if value%width != 0 {
				return fmt.Errorf("unaligned IDR program pointer")
			}
			if stats.entries >= maxEntries {
				return fmt.Errorf("IDR entry limit exhausted")
			}
			stats.entries++
			if err = emit(linuxIDREntry{index, index, value, slot, "page", index < 16}); err != nil {
				return err
			}
		}
		return nil
	}
	err = walk(top, 0, height)
	return stats, err
}

// Every index read is persisted, including zero slots and failed/partial reads.
// An emitter failure is a real task failure, never an apparent memory hole.
type linuxIDRLayer struct {
	memory.MemoryLayer
	observe   func(uint64, []byte, int, error) error
	outputErr error
}

func (l *linuxIDRLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid IDR read count")
	}
	if err == nil && n != len(p) {
		err = io.ErrUnexpectedEOF
	}
	if l.outputErr != nil {
		return n, l.outputErr
	}
	if outputErr := l.observe(at, p[:n], len(p), err); outputErr != nil {
		l.outputErr = outputErr
		return n, errors.Join(err, outputErr)
	}
	return n, err
}

func linuxEBPFProgram(ctx context.Context, e plugin.Environment, address uint64) (map[string]evidence.Value, error) {
	fields := map[string]evidence.Value{}
	cells := map[string]evidence.Value{"Name": evidence.Missing("field_not_available", nil), "Tag": evidence.Missing("field_not_available", nil), "Type": evidence.Missing("field_not_available", nil)}
	var failures pluginFailures
	aux := uint64(0)
	if layout, err := e.Objects.Field("bpf_prog", "aux"); err == nil {
		if layout.Type.Kind != "pointer" {
			err = fmt.Errorf("bpf_prog.aux is not a pointer")
		} else {
			aux, _, err = linuxUnsignedField(ctx, e, address, "bpf_prog", "aux", fields, "Aux")
		}
		if err != nil {
			failures.add(err)
			cells["Name"] = evidence.Missing("aux_unreadable", err)
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		failures.add(err)
		cells["Name"] = evidence.Missing("aux_layout_invalid", err)
	}
	typ, base, path := "bpf_prog", address, "type"
	_, typeErr := e.Objects.Field(typ, path)
	if errors.Is(typeErr, object.ErrFieldAbsent) {
		if aux != 0 {
			typ, base, path = "bpf_prog_aux", aux, "prog_type"
			_, typeErr = e.Objects.Field(typ, path)
		}
	}
	if typeErr == nil {
		_, proof, err := linuxCaptureField(ctx, e, base, typ, path)
		fields["Type"] = proof
		if err == nil {
			value, names, enumErr := e.Objects.Enum(ctx, base, typ, path)
			fields["TypeValue"] = evidence.Missing("enum_unavailable", enumErr)
			if enumErr == nil {
				fields["TypeValue"] = evidence.Number(value)
			}
			err = enumErr
			if err == nil {
				if len(names) == 0 {
					err = fmt.Errorf("unknown BPF program type %d", value)
				} else {
					cells["Type"] = evidence.Text(names[0])
				}
			}
		}
		if err != nil {
			failures.add(err)
			cells["Type"] = evidence.Missing("type_unreadable_or_unknown", err)
		}
	} else if !errors.Is(typeErr, object.ErrFieldAbsent) {
		failures.add(typeErr)
		cells["Type"] = evidence.Missing("type_layout_invalid", typeErr)
	}
	for _, item := range []struct {
		typ, path, key string
		base           uint64
	}{{"bpf_prog", "tag", "Tag", address}, {"bpf_prog_aux", "name", "Name", aux}} {
		if item.base == 0 {
			continue
		}
		field, err := e.Objects.Field(item.typ, item.path)
		if errors.Is(err, object.ErrFieldAbsent) {
			continue
		}
		if err == nil {
			size, sizeErr := e.Objects.Size(field.Type)
			if sizeErr != nil {
				err = sizeErr
			} else if field.Type.Kind != "array" || size == 0 || size > 256 || size != field.Type.Count {
				err = fmt.Errorf("invalid BPF %s array extent", item.key)
			}
		}
		if err != nil {
			failures.add(err)
			cells[item.key] = evidence.Missing("field_layout_invalid", err)
			continue
		}
		raw, proof, err := linuxCaptureField(ctx, e, item.base, item.typ, item.path)
		fields[item.key] = proof
		if err != nil {
			failures.add(err)
			cells[item.key] = evidence.Missing("field_unreadable", err)
			continue
		}
		if item.key == "Tag" {
			cells[item.key] = evidence.Text(hex.EncodeToString(raw))
		} else {
			if n := bytes.IndexByte(raw, 0); n >= 0 {
				raw = raw[:n]
			}
			decoded, valid := replaceInvalidUTF8(raw)
			name, _, _ := strings.Cut(decoded, "\uFFFD")
			fields["NameDecoded"], fields["NameUTF8Valid"], fields["NameTruncated"] = evidence.Text(decoded), evidence.Bool(valid), evidence.Bool(name != decoded)
			if name != "" {
				cells[item.key] = evidence.Text(name)
			} else {
				cells[item.key] = evidence.Missing("empty_name", nil)
			}
		}
	}
	cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	return cells, failures.err("BPF program fields")
}

func linuxEBPF(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	bound := func(name string) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 32)
		if err != nil || n == 0 || n > 1000000 {
			return 0, fmt.Errorf("%s must be 1..1000000", name)
		}
		return n, nil
	}
	maxNodes, err := bound("max-nodes")
	if err != nil {
		return err
	}
	maxPrograms, err := bound("max-programs")
	if err != nil {
		return err
	}
	root, err := e.Symbol("prog_idr")
	if err != nil {
		return fmt.Errorf("eBPF prog_idr unavailable (unsupported kernel): %w", err)
	}
	baseRow := func(kind string, at uint64) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Address": evidence.Address(at), "Selected": evidence.Bool(false), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	}
	var reads, programs, selected, tagged uint64
	trace := &linuxIDRLayer{MemoryLayer: e.Kernel}
	trace.observe = func(at uint64, raw []byte, want int, err error) error {
		reads++
		row := baseRow("idr_read", at)
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(err == nil)}
		if err != nil {
			proof["Error"] = evidence.Missing("idr_read_failed", err)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return out(row)
	}
	reader := &object.Reader{Layer: trace, Symbols: e.Symbols}
	var failures pluginFailures
	var outputErr error
	emitRow := func(row evidence.Row) error { outputErr = out(row); return outputErr }
	stats, walkErr := walkLinuxIDR(ctx, reader, root, maxNodes, maxPrograms, func(entry linuxIDREntry) error {
		row := baseRow("ebpf_program", entry.address)
		row.Cells["ID"], row.Cells["Index"], row.Cells["Slot"] = evidence.Number(entry.id), evidence.Number(entry.index), evidence.Address(entry.slot)
		if entry.kind != "page" {
			tagged++
			row.Cells["RecordType"] = evidence.Text("idr_tagged_entry")
			row.Cells["EntryKind"] = evidence.Text(entry.kind)
			return emitRow(row)
		}
		programs++
		if entry.selected {
			selected++
		}
		row.Cells["Selected"] = evidence.Bool(entry.selected)
		cells, err := linuxEBPFProgram(ctx, e, entry.address)
		for k, v := range cells {
			row.Cells[k] = v
		}
		if err != nil {
			failures.add(err)
			row.Cells["Error"] = evidence.Missing("program_fields_incomplete", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return emitRow(row)
	})
	if outputErr != nil {
		return outputErr
	}
	if trace.outputErr != nil {
		return trace.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	runErr := errors.Join(walkErr, failures.err("eBPF enumeration"))
	summary := baseRow("idr_summary", root)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Layout": evidence.Text(stats.layout), "Nodes": evidence.Number(stats.nodes), "Entries": evidence.Number(stats.entries), "Reads": evidence.Number(reads), "Programs": evidence.Number(programs), "SelectedPrograms": evidence.Number(selected), "TaggedEntries": evidence.Number(tagged), "Completed": evidence.Bool(runErr == nil)}}
	if runErr != nil {
		summary.Cells["Error"] = evidence.Missing("enumeration_incomplete", runErr)
	}
	return errors.Join(runErr, out(summary))
}
