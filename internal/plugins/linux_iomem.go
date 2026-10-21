package plugins

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxIOMemPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.iomem", Upstream: "linux.iomem.IOMem", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate the kernel I/O memory resource tree with raw field captures and bounded traversal",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Resource visit bound, 1..1000000"}, {Name: "max-depth", Kind: "uint", Default: "256", Description: "Maximum resource depth, root is zero, 1..1024"}},
		Columns:     []evidence.Column{{Name: "Name", Kind: "string"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Offset", Kind: "address"}, {Name: "ParentOffset", Kind: "address"}, {Name: "Depth", Kind: "uint64"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "NameEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}},
	}, linuxIOMem}}
}

// Capture the entire contiguous prefix, including bytes after the first NUL.
// The pinned helper reads at most 128 bytes and decodes that prefix, stopping
// at either NUL or the first Unicode replacement character.
func linuxResourceName(ctx context.Context, e plugin.Environment, address uint64) (evidence.Value, evidence.Value, error) {
	raw := make([]byte, 128)
	got, err := e.Kernel.ReadAt(ctx, raw, address)
	if got < 0 || got > len(raw) {
		return evidence.Missing("resource_name_unreadable", fmt.Errorf("invalid name read count %d", got)), evidence.Missing("invalid_capture", nil), fmt.Errorf("invalid name read count %d", got)
	}
	if err == nil && got != len(raw) {
		err = io.ErrUnexpectedEOF
	}
	details := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw[:got]), "RequestedBytes": evidence.Number(128), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(err == nil)}
	if err != nil {
		details["Error"] = evidence.Missing("name_prefix_read_incomplete", err)
	}
	name := evidence.Text(spoofDecoded(raw[:got]))
	if got == 0 {
		name = evidence.Missing("resource_name_unreadable", err)
	}
	return name, evidence.Value{Kind: "structure", Data: details}, err
}

func linuxIOMem(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.iomem requires kernel memory and symbols")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	depthLimit, err := strconv.ParseUint(p["max-depth"], 0, 32)
	if err != nil || depthLimit < 1 || depthLimit > 1024 {
		return fmt.Errorf("max-depth must be 1..1024")
	}
	root, err := e.Symbol("iomem_resource")
	if err != nil {
		return err
	}
	// Validate the required layout before emitting anything; offsets come only
	// from symbols, including kernels with 64-bit resource extents on x86.
	for _, name := range []string{"name", "start", "end", "child", "sibling"} {
		f, err := e.Objects.Field("resource", name)
		if err != nil {
			return err
		}
		size, err := e.Objects.Size(f.Type)
		if err != nil || (size != 4 && size != 8) {
			return fmt.Errorf("resource.%s has unsupported extent %d: %v", name, size, err)
		}
	}
	type visit struct {
		address, parent, depth uint64
		hasParent              bool
	}
	stack := []visit{{address: root}}
	seen := map[uint64]bool{}
	var visits, resources, diagnostics uint64
	var failures pluginFailures
	base := func(v visit, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", v.address)}}
		for _, c := range linuxIOMemPlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["Offset"], r.Cells["Depth"], r.Cells["RecordType"] = evidence.Address(v.address), evidence.Number(v.depth), evidence.Text(kind)
		if v.hasParent {
			r.ParentID = fmt.Sprintf("resource:%x", v.parent)
			r.Cells["ParentOffset"] = evidence.Address(v.parent)
		}
		return r
	}
	diagnostic := func(v visit, reason string, cause error) error {
		diagnostics++
		failures.add(cause)
		r := base(v, "diagnostic")
		r.Cells["Error"] = evidence.Missing(reason, cause)
		return out(r)
	}
	for len(stack) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visits >= uint64(max) {
			if err := diagnostic(v, "resource_visit_bound", fmt.Errorf("resource visits exceed max-nodes %d", max)); err != nil {
				return err
			}
			break
		}
		visits++
		if v.depth > depthLimit {
			if err := diagnostic(v, "resource_depth_bound", fmt.Errorf("resource depth exceeds max-depth %d", depthLimit)); err != nil {
				return err
			}
			continue
		}
		if seen[v.address] {
			if err := diagnostic(v, "resource_repeated", fmt.Errorf("repeated resource %#x", v.address)); err != nil {
				return err
			}
			continue
		}
		seen[v.address] = true
		r := base(v, "resource")
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		incomplete := false
		issue := func(reason string, cause error) {
			incomplete = true
			failures.add(cause)
			fields[reason] = evidence.Missing(reason, cause)
		}
		read := func(name string) (uint64, error) {
			f, err := e.Objects.Field("resource", name)
			if err != nil {
				return 0, err
			}
			address, err := memory.Add(v.address, f.Offset)
			if err != nil {
				return 0, err
			}
			size, err := e.Objects.Size(f.Type)
			if err != nil {
				return 0, err
			}
			raw := make([]byte, int(size))
			got, err := e.Kernel.ReadAt(ctx, raw, address)
			if got < 0 || got > len(raw) {
				return 0, fmt.Errorf("invalid resource field read count %d", got)
			}
			capture := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw[:got]), "ReadComplete": evidence.Bool(err == nil && got == len(raw))}
			fields[name] = evidence.Value{Kind: "structure", Data: capture}
			if err == nil && got != len(raw) {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				capture["Error"] = evidence.Missing("field_unreadable", err)
				return 0, err
			}
			value, err := e.Objects.Uint(ctx, v.address, "resource", name)
			if err == nil {
				capture["Value"] = evidence.Address(value)
			}
			return value, err
		}
		name, cause := read("name")
		if cause != nil {
			r.Cells["Name"] = evidence.Missing("resource_name_unreadable", cause)
			issue("name_pointer_unreadable", cause)
		} else {
			value, details, cause := linuxResourceName(ctx, e, name)
			r.Cells["Name"], r.Cells["NameEvidence"] = value, details
			if cause != nil {
				issue("name_prefix_incomplete", cause)
			}
		}
		start, startErr := read("start")
		end, endErr := read("end")
		if startErr == nil {
			r.Cells["Start"] = evidence.Address(start)
		} else {
			r.Cells["Start"] = evidence.Missing("resource_extent_unreadable", startErr)
		}
		if endErr == nil {
			r.Cells["End"] = evidence.Address(end)
		} else {
			r.Cells["End"] = evidence.Missing("resource_extent_unreadable", endErr)
		}
		if startErr != nil || endErr != nil {
			if startErr != nil {
				issue("start_unreadable", startErr)
			}
			if endErr != nil {
				issue("end_unreadable", endErr)
			}
			diagnostics++
			r.Cells["RecordType"] = evidence.Text("diagnostic")
			r.Cells["Error"] = evidence.Missing("resource_extent_unreadable", fmt.Errorf("resource %#x extent unreadable", v.address))
			if err := out(r); err != nil {
				return err
			}
			continue
		}
		child, childErr := read("child")
		sibling, siblingErr := read("sibling")
		if childErr != nil {
			issue("child_unreadable", childErr)
		}
		if siblingErr != nil {
			issue("sibling_unreadable", siblingErr)
		}
		if incomplete {
			diagnostics++
			r.Cells["Error"] = evidence.Missing("resource_read_incomplete", fmt.Errorf("resource %#x has incomplete fields", v.address))
		}
		r.ID = fmt.Sprintf("resource:%x", v.address)
		if err := out(r); err != nil {
			return err
		}
		resources++
		// LIFO keeps child-before-sibling order without Go recursion or an
		// unbounded sibling frontier. A failed branch cannot hide a known sibling.
		if siblingErr == nil && sibling != 0 {
			stack = append(stack, visit{sibling, v.parent, v.depth, v.hasParent})
		}
		if childErr == nil && child != 0 {
			stack = append(stack, visit{child, v.address, v.depth + 1, true})
		}
	}
	r := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": poolCoverage(map[string]string{"visits": formatCount(visits), "resources": formatCount(resources), "diagnostics": formatCount(diagnostics)})}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	if err := out(r); err != nil {
		return err
	}
	return failures.err("Linux I/O memory resources")
}
