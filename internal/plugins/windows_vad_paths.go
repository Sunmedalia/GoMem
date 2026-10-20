package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type windowsVADPath struct {
	start, end, address uint64
	file                evidence.Value
}

// windowsVADPaths builds one sorted file index per process, shared by every
// thread address lookup in that process. Unsupported layouts and incomplete
// trees are errors; a failed index must never become a clean "no mapping".
func windowsVADPaths(ctx context.Context, e plugin.Environment, process uint64, max int) ([]windowsVADPath, error) {
	root, err := e.Objects.Uint(ctx, process, "_EPROCESS", "VadRoot.Root")
	if err != nil {
		return nil, fmt.Errorf("modern RTL_AVL_TREE VAD root: %w", err)
	}
	if root == 0 {
		return nil, nil
	}
	member, err := e.Objects.Field("_MMVAD_SHORT", "VadNode")
	if err != nil {
		return nil, err
	}
	type frame struct {
		node, parent uint64
		depth        int
	}
	stack := []frame{{node: root}}
	seen := map[uint64]bool{}
	var regions []windowsVADPath
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.node == 0 {
			continue
		}
		if item.depth > 128 || len(seen) >= max || seen[item.node] {
			return nil, fmt.Errorf("VAD tree cycle, depth or node limit at %#x", item.node)
		}
		seen[item.node] = true
		if item.node < member.Offset {
			return nil, fmt.Errorf("VAD node offset underflow")
		}
		address := item.node - member.Offset
		left, err := e.Objects.Uint(ctx, item.node, "_RTL_BALANCED_NODE", "Left")
		if err != nil {
			return nil, err
		}
		right, err := e.Objects.Uint(ctx, item.node, "_RTL_BALANCED_NODE", "Right")
		if err != nil {
			return nil, err
		}
		parent, err := e.Objects.Uint(ctx, item.node, "_RTL_BALANCED_NODE", "ParentValue")
		if err != nil {
			return nil, err
		}
		if parent&^uint64(3) != item.parent {
			return nil, fmt.Errorf("VAD parent mismatch at %#x", item.node)
		}
		vpn := func(name string) (uint64, error) {
			low, err := e.Objects.Uint(ctx, address, "_MMVAD_SHORT", name)
			if err != nil {
				return 0, err
			}
			if _, err := e.Objects.Field("_MMVAD_SHORT", name+"High"); err == nil {
				high, err := e.Objects.Uint(ctx, address, "_MMVAD_SHORT", name+"High")
				if err != nil {
					return 0, err
				}
				if low > 0xffffffff || high > 0xff {
					return 0, fmt.Errorf("invalid VAD VPN width")
				}
				low |= high << 32
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return 0, err
			}
			return low, nil
		}
		first, err := vpn("StartingVpn")
		if err != nil {
			return nil, err
		}
		last, err := vpn("EndingVpn")
		if err != nil {
			return nil, err
		}
		if first > last || last >= uint64(1)<<52 {
			return nil, fmt.Errorf("invalid VAD address range")
		}
		start, end := first<<12, ((last+1)<<12)-1
		bias := uint64(12)
		if e.Symbols.PointerSize() == 4 {
			bias = 4
		}
		if address < bias {
			return nil, fmt.Errorf("VAD pool tag underflow")
		}
		tag, err := memory.Read(ctx, e.Kernel, address-bias, 4)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(string(tag), "Vad") {
			return nil, fmt.Errorf("unrecognized VAD pool tag %q at %#x", tag, address)
		}
		path := evidence.Missing("not_file_backed", nil)
		if string(tag) != "VadS" && string(tag) != "VadF" {
			path = windowsVADFile(ctx, e, address)
		}
		regions = append(regions, windowsVADPath{start: start, end: end, address: address, file: path})
		stack = append(stack, frame{node: right, parent: item.node, depth: item.depth + 1}, frame{node: left, parent: item.node, depth: item.depth + 1})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	for i := 1; i < len(regions); i++ {
		if regions[i].start <= regions[i-1].end {
			return nil, fmt.Errorf("overlapping VAD ranges")
		}
	}
	return regions, nil
}
func windowsVADFile(ctx context.Context, e plugin.Environment, address uint64) evidence.Value {
	subsection, err := e.Objects.Uint(ctx, address, "_MMVAD", "Subsection")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if subsection == 0 {
		return evidence.Missing("not_file_backed", nil)
	}
	control, err := e.Objects.Uint(ctx, subsection, "_SUBSECTION", "ControlArea")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if control == 0 {
		return evidence.Missing("not_file_backed", nil)
	}
	file, err := e.Objects.Uint(ctx, control, "_CONTROL_AREA", "FilePointer.Value")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	mask := uint64(15)
	if e.Symbols.PointerSize() == 4 {
		mask = 7
	}
	file &= ^mask
	if file == 0 {
		return evidence.Missing("not_file_backed", nil)
	}
	name, err := unicodeString(ctx, e, file, "_FILE_OBJECT", "FileName")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if name == "" {
		return evidence.Missing("not_file_backed", nil)
	}
	return evidence.Text(name)
}
func windowsPathAt(regions []windowsVADPath, address uint64) evidence.Value {
	if address == 0 {
		return evidence.Missing("not_set", nil)
	}
	n := sort.Search(len(regions), func(i int) bool { return regions[i].start > address }) - 1
	if n >= 0 && address <= regions[n].end {
		return regions[n].file
	}
	return evidence.Missing("not_mapped_in_vad", nil)
}
