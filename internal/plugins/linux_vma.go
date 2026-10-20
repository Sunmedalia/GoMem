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
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxMapPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.maps", Upstream: "linux.proc.Maps", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate linked-list or Maple Tree VMAs with namespace-aware file paths",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "address", Kind: "string", Description: "Optional comma-separated virtual addresses; includes End when filtering, matching the pinned baseline"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-mm traversal limit"}, {Name: "include-past-eof", Kind: "bool", Default: "true", Description: "Retain file mappings whose page offset exceeds a positive inode size"}, {Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VMA traversal limit"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Protection", Kind: "string"}, {Name: "FlagsRaw", Kind: "uint64"}, {Name: "PgOff", Kind: "address"}, {Name: "Major", Kind: "uint64"}, {Name: "Minor", Kind: "uint64"}, {Name: "Inode", Kind: "uint64"}, {Name: "Path", Kind: "string"}, {Name: "PathRaw", Kind: "bytes"}, {Name: "PathScope", Kind: "string"}, {Name: "InodeSize", Kind: "int64"}, {Name: "FileOffsetPastEOF", Kind: "string"}, {Name: "Executable", Kind: "string"}, {Name: "Deleted", Kind: "string"}, {Name: "File", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}}}, linuxMaps}}
}

// Linked-list and Maple traversals yield addresses only. Every VMA is checked
// against the owning mm and address interval before it becomes evidence.
func linuxVMAAddresses(ctx context.Context, e plugin.Environment, mm uint64, max int) ([]uint64, error) {
	if _, err := e.Objects.Field("mm_struct", "mmap"); err == nil {
		current, err := e.Objects.Uint(ctx, mm, "mm_struct", "mmap")
		if err != nil {
			return nil, err
		}
		seen := map[uint64]bool{}
		var addresses []uint64
		var previous uint64
		for current != 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if seen[current] || len(seen) >= max {
				return nil, fmt.Errorf("VMA list cycle or node limit at %#x", current)
			}
			seen[current] = true
			if _, err := e.Objects.Field("vm_area_struct", "vm_prev"); err == nil {
				back, err := e.Objects.Uint(ctx, current, "vm_area_struct", "vm_prev")
				if err != nil {
					return nil, err
				}
				if back != previous {
					return nil, fmt.Errorf("VMA previous link mismatch at %#x", current)
				}
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return nil, err
			}
			addresses = append(addresses, current)
			next, err := e.Objects.Uint(ctx, current, "vm_area_struct", "vm_next")
			if err != nil {
				return nil, err
			}
			previous, current = current, next
		}
		return addresses, nil
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return nil, err
	}
	field, err := e.Objects.Field("mm_struct", "mm_mt")
	if err != nil {
		return nil, fmt.Errorf("no supported VMA list or Maple Tree: %w", err)
	}
	tree, err := memory.Add(mm, field.Offset)
	if err != nil {
		return nil, err
	}
	root, err := e.Objects.Uint(ctx, tree, "maple_tree", "ma_root")
	if err != nil {
		return nil, err
	}
	flags, err := e.Objects.Uint(ctx, tree, "maple_tree", "ma_flags")
	if err != nil {
		return nil, err
	}
	height := int(flags&0x7c) >> 2
	if root == 0 {
		if height != 0 {
			return nil, fmt.Errorf("empty Maple root with nonzero height")
		}
		return nil, nil
	}
	if height == 0 {
		if max < 1 || root < 4096 || root%uint64(e.Symbols.PointerSize()) != 0 {
			return nil, fmt.Errorf("invalid direct Maple root %#x", root)
		}
		return []uint64{root}, nil
	}
	type frame struct {
		entry, parent uint64
		depth         int
	}
	stack := []frame{{root, tree, 1}}
	seen, values := map[uint64]bool{}, map[uint64]bool{}
	var addresses []uint64
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := f.entry &^ uint64(255)
		kind := (f.entry >> 3) & 15
		if node < 4096 || seen[node] || len(seen) >= max || f.depth > height || kind > 3 {
			return nil, fmt.Errorf("invalid Maple node, cycle, type or depth at %#x", node)
		}
		seen[node] = true
		parent, err := e.Objects.Uint(ctx, node, "maple_node", "parent")
		if err != nil {
			return nil, err
		}
		if f.depth == 1 {
			if parent&1 == 0 || parent&^uint64(1) != tree {
				return nil, fmt.Errorf("Maple root parent mismatch")
			}
		} else if parent&^uint64(255) != f.parent {
			return nil, fmt.Errorf("Maple parent mismatch at %#x", node)
		}
		path := "mr64.slot"
		if kind == 0 {
			path = "slot"
		} else if kind == 3 {
			path = "ma64.slot"
		}
		slots, err := e.Objects.Field("maple_node", path)
		if err != nil {
			return nil, err
		}
		if slots.Type.Kind != "array" || slots.Type.Subtype == nil || slots.Type.Subtype.Kind != "pointer" || slots.Type.Count == 0 || slots.Type.Count > 256 {
			return nil, fmt.Errorf("invalid Maple slot array")
		}
		width, err := e.Objects.Size(*slots.Type.Subtype)
		if err != nil || width != uint64(e.Symbols.PointerSize()) {
			return nil, fmt.Errorf("invalid Maple slot width")
		}
		base, err := memory.Add(node, slots.Offset)
		if err != nil {
			return nil, err
		}
		leaf := kind == 0 || kind == 1
		if leaf && f.depth != height {
			return nil, fmt.Errorf("Maple leaf depth does not match tree height")
		}
		for n := uint64(0); n < slots.Type.Count; n++ {
			location, err := memory.Add(base, n*width)
			if err != nil {
				return nil, err
			}
			value, err := e.Objects.Scalar(ctx, location, symbols.TypeRef{Kind: "pointer"})
			if err != nil {
				return nil, err
			}
			if value < 4096 {
				continue
			} // NULL, reserved entries and leaf metadata.
			if leaf {
				if value%width != 0 || values[value] || len(values) >= max {
					return nil, fmt.Errorf("invalid, duplicate or excess Maple VMA slot %#x", value)
				}
				values[value] = true
				addresses = append(addresses, value)
			} else {
				stack = append(stack, frame{value, node, f.depth + 1})
			}
		}
	}
	return addresses, nil
}

func linuxMaps(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	limit, err := strconv.ParseUint(p["max-regions"], 0, 32)
	if err != nil || limit == 0 || limit > 1000000 {
		return fmt.Errorf("max-regions must be 1..1000000")
	}
	includePastEOF, err := strconv.ParseBool(p["include-past-eof"])
	if err != nil {
		return err
	}
	var filters []uint64
	if p["address"] != "" {
		for _, token := range strings.Split(p["address"], ",") {
			a, err := strconv.ParseUint(strings.TrimSpace(token), 0, 64)
			if err != nil {
				return fmt.Errorf("address: %w", err)
			}
			filters = append(filters, a)
		}
	}
	var count uint64
	return visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, created evidence.Value) error {
		mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
		if err != nil {
			return err
		}
		if mm == 0 {
			return nil
		}
		addresses, err := linuxVMAAddresses(ctx, e, mm, int(min(uint64(max), limit-count)))
		if err != nil {
			return fmt.Errorf("task %#x PID %d mappings: %w", task, pid, err)
		}
		count += uint64(len(addresses))
		type region struct{ object, start, end uint64 }
		regions := make([]region, 0, len(addresses))
		for _, address := range addresses {
			start, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_start")
			if err != nil {
				return err
			}
			end, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_end")
			if err != nil {
				return err
			}
			owner, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_mm")
			if err != nil {
				return err
			}
			if owner != mm || start >= end || start&4095 != 0 || end&4095 != 0 {
				return fmt.Errorf("invalid VMA owner or interval at %#x", address)
			}
			regions = append(regions, region{address, start, end})
		}
		sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
		for i := 1; i < len(regions); i++ {
			if regions[i].start < regions[i-1].end {
				return fmt.Errorf("overlapping VMAs")
			}
		}
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		for _, r := range regions {
			include := len(filters) == 0
			for _, a := range filters {
				include = include || (r.start <= a && a <= r.end)
			}
			if !include {
				continue
			}
			flags, err := e.Objects.Uint(ctx, r.object, "vm_area_struct", "vm_flags")
			if err != nil {
				return err
			}
			file, err := e.Objects.Uint(ctx, r.object, "vm_area_struct", "vm_file")
			if err != nil {
				return err
			}
			protection := []byte("---")
			for i, c := range []byte("rwx") {
				if flags&(1<<i) != 0 {
					protection[i] = c
				}
			}
			path, raw, deleted, inode, major, minor, inodeSize, pathScope := linuxVMAFile(ctx, e, task, mm, r.start, r.end, file)
			pageOffset := evidence.Address(0)
			if file != 0 {
				pages, err := e.Objects.Uint(ctx, r.object, "vm_area_struct", "vm_pgoff")
				if err != nil {
					pageOffset = evidence.Missing("unreadable_or_unavailable", err)
				} else if pages > ^uint64(0)>>12 {
					pageOffset = evidence.Missing("offset_overflow", fmt.Errorf("page offset overflow"))
				} else {
					pageOffset = evidence.Address(pages << 12)
				}
			}
			pastEOF := evidence.Text("false")
			if file != 0 {
				size, serr := inodeSize.Int()
				offset, oerr := pageOffset.Uint()
				if serr != nil || oerr != nil {
					pastEOF = evidence.Missing("unreadable_or_unavailable", fmt.Errorf("inode size/offset unavailable: %v %v", serr, oerr))
				} else if size > 0 && offset > uint64(size) {
					pastEOF = evidence.Text("true")
					if !includePastEOF {
						continue
					}
				}
			}

			row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "Offset": evidence.Address(r.object), "Start": evidence.Address(r.start), "End": evidence.Address(r.end), "Protection": evidence.Text(string(protection)), "FlagsRaw": evidence.Number(flags), "PgOff": pageOffset, "Major": major, "Minor": minor, "Inode": inode, "Path": path, "PathRaw": raw, "PathScope": pathScope, "InodeSize": inodeSize, "FileOffsetPastEOF": pastEOF, "Executable": evidence.Text(strconv.FormatBool(flags&4 != 0)), "Deleted": deleted, "File": evidence.Address(file), "ProcessOffset": evidence.Address(task), "ProcessIdentity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", r.object)}}
			if err := out(row); err != nil {
				return err
			}
		}
		return nil
	})
}
