package kallsyms

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

// BPFProgram retains the function pointer separately from its allocated region.
// Enumeration uses Function; legacy address lookup uses RegionStart.
type BPFProgram struct {
	Object, Aux, Function, RegionStart, RegionEnd, Pages, Alignment uint64
	Name                                                            string
	NameAvailable                                                   bool
}

func bpfPointer(ctx context.Context, r *object.Reader, at uint64, typ, field string) (uint64, error) {
	f, err := r.Field(typ, field)
	if err != nil {
		return 0, err
	}
	size, err := r.Size(f.Type)
	if err != nil {
		return 0, err
	}
	if f.Type.Kind != "pointer" || size != uint64(r.Symbols.PointerSize()) {
		return 0, fmt.Errorf("%s.%s is not a kernel-width pointer", typ, field)
	}
	return r.Uint(ctx, at, typ, field)
}
func bpfArray(ctx context.Context, r *object.Reader, at uint64, typ, field string) (string, uint64, error) {
	f, err := r.Field(typ, field)
	if err != nil {
		return "", 0, err
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil || f.Type.Count > 1<<20 {
		return "", 0, fmt.Errorf("invalid %s.%s name array", typ, field)
	}
	width, err := r.Size(*f.Type.Subtype)
	if err != nil {
		return "", 0, err
	}
	if width != 1 {
		return "", 0, fmt.Errorf("BPF name elements must be bytes")
	}
	if f.Type.Count == 0 {
		return "", 0, nil
	}
	start, err := memory.Add(at, f.Offset)
	if err != nil {
		return "", 0, err
	}
	raw, err := memory.Read(ctx, r.Layer, start, int(f.Type.Count))
	if err != nil {
		return "", 0, err
	}
	text := strings.ToValidUTF8(string(raw), "\ufffd")
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	if i := strings.IndexRune(text, '\ufffd'); i >= 0 {
		text = text[:i]
	}
	return text, f.Type.Count, nil
}

// ReadBPFProgram uses the fixed Intel page size (4096) and optional 64-byte
// BPF program-pack alignment. All metadata and image faults remain errors.
func ReadBPFProgram(ctx context.Context, r *object.Reader, prog uint64) (BPFProgram, error) {
	return readBPFProgram(ctx, r, prog, true)
}

// ReadBPFRegion reads allocation metadata without acquiring the optional name.
func ReadBPFRegion(ctx context.Context, r *object.Reader, prog uint64) (BPFProgram, error) {
	return readBPFProgram(ctx, r, prog, false)
}

func readBPFProgram(ctx context.Context, r *object.Reader, prog uint64, includeName bool) (BPFProgram, error) {
	info := BPFProgram{Object: prog, Alignment: 4096}
	if err := ctx.Err(); err != nil {
		return info, err
	}
	if r == nil || r.Symbols == nil || r.Layer == nil || prog == 0 {
		return info, fmt.Errorf("BPF program requires a reader and non-null object")
	}
	if w := r.Symbols.PointerSize(); w != 4 && w != 8 {
		return info, fmt.Errorf("unsupported BPF pointer width")
	}
	if _, err := r.Field("bpf_prog", "aux"); err == nil {
		info.Aux, err = bpfPointer(ctx, r, prog, "bpf_prog", "aux")
		if err != nil {
			return info, err
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return info, err
	}
	if includeName {
		if _, err := r.Field("bpf_prog_aux", "name"); err == nil {
			if info.Aux != 0 {
				var count uint64
				info.Name, count, err = bpfArray(ctx, r, info.Aux, "bpf_prog_aux", "name")
				if err != nil {
					return info, err
				}
				info.NameAvailable = count != 0
			}
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return info, err
		}
	}

	var err error
	info.Function, err = bpfPointer(ctx, r, prog, "bpf_prog", "bpf_func")
	if err != nil {
		return info, err
	}
	if _, err := r.Field("bpf_prog_aux", "use_bpf_prog_pack"); err == nil {
		if info.Aux == 0 {
			return info, fmt.Errorf("null BPF program-pack auxiliary object")
		}
		pack, err := r.Uint(ctx, info.Aux, "bpf_prog_aux", "use_bpf_prog_pack")
		if err != nil {
			return info, err
		}
		if pack != 0 {
			info.Alignment = 64
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return info, err
	}
	info.RegionStart = info.Function &^ (info.Alignment - 1)
	if _, err := r.Symbols.Type("bpf_binary_header"); err == nil {
		info.Pages, err = r.Uint(ctx, info.RegionStart, "bpf_binary_header", "pages")
		if err != nil {
			return info, err
		}
	} else {
		raw, err := memory.Read(ctx, r.Layer, info.RegionStart, 4)
		if err != nil {
			return info, err
		}
		valueType, err := r.Symbols.Type("unsigned int")
		if err != nil {
			// Some native symbol sets omit this base alias. Preserve the
			// enumeration fallback's four-byte word using pointer byte order.
			valueType, err = r.Symbols.Type("pointer")
			if err != nil {
				return info, err
			}
		} else if valueType.Size != 4 || valueType.Kind != "int" || valueType.Signed {
			return info, fmt.Errorf("invalid BPF unsigned int page-count metadata")
		}
		var order binary.ByteOrder = binary.LittleEndian
		switch valueType.Endian {
		case "", "little":
		case "big":
			order = binary.BigEndian
		default:
			return info, fmt.Errorf("unsupported BPF byte order")
		}
		info.Pages = uint64(order.Uint32(raw))
	}
	if info.Pages > ^uint64(0)/4096 {
		return info, fmt.Errorf("BPF region size overflow")
	}
	info.RegionEnd, err = memory.Add(info.RegionStart, info.Pages*4096)
	if err == nil {
		err = ctx.Err()
	}
	return info, err
}

// BPFConfig selects the resident index layout independently of the list used
// for enumeration. Layout is "modern" (bpf_ksym) or "legacy" (bpf_prog_aux).
type BPFConfig struct {
	Root, AddressMask uint64
	MaxNodes          int
	Layout            string
}

type BPFMatch struct {
	Symbol                                       Symbol
	NameAvailable                                bool
	Object, Program, Aux, RegionStart, RegionEnd uint64
	Search                                       object.LatchMatch
	Layout                                       string
	ProgramDetails                               *BPFProgram
}

// LookupBPF searches the resident latch tree, including the final region
// address to recognize return addresses. A nil result is a completed no-match;
// unreadable/invalid paths are errors. The caller wraps Reader.Layer to capture
// evidence and enforce an aggregate byte budget across repeated queries.
func LookupBPF(ctx context.Context, r *object.Reader, c BPFConfig, address uint64) (*BPFMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.Layer == nil || r.Symbols == nil || c.AddressMask == 0 || c.MaxNodes < 1 || c.MaxNodes > 1000000 || (c.Layout != "modern" && c.Layout != "legacy") {
		return nil, fmt.Errorf("invalid BPF lookup configuration")
	}
	if c.Root == 0 {
		return nil, nil
	}
	typ, member := "bpf_ksym", "tnode"
	if c.Layout == "legacy" {
		typ, member = "bpf_prog_aux", "ksym_tnode"
	}
	field, err := r.Field(typ, member)
	if err != nil {
		return nil, err
	}
	if field.Type.Kind != "struct" || field.Type.Name != "latch_tree_node" {
		return nil, fmt.Errorf("%s.%s is not embedded latch_tree_node", typ, member)
	}
	address &= c.AddressMask
	container := func(node uint64) (uint64, error) {
		if node < field.Offset {
			return 0, fmt.Errorf("BPF latch container underflow")
		}
		return node - field.Offset, nil
	}
	region := func(at uint64) (uint64, uint64, error) {
		if c.Layout == "modern" {
			start, err := r.Uint(ctx, at, typ, "start")
			if err != nil {
				return 0, 0, err
			}
			end, err := r.Uint(ctx, at, typ, "end")
			return start, end, err
		}
		prog, err := bpfPointer(ctx, r, at, typ, "prog")
		if err != nil {
			return 0, 0, err
		}
		info, err := ReadBPFRegion(ctx, r, prog)
		return info.RegionStart, info.RegionEnd, err
	}
	search, err := r.FindLatchTree(ctx, c.Root, address, c.MaxNodes, func(ctx context.Context, key, node uint64) (int, error) {
		at, err := container(node)
		if err != nil {
			return 0, err
		}
		start, end, err := region(at)
		if err != nil {
			return 0, err
		}
		start &= c.AddressMask
		end &= c.AddressMask
		if key < start {
			return -1, nil
		}
		if key > end {
			return 1, nil
		}
		return 0, nil
	})
	if err != nil {
		return nil, err
	}
	if !search.Found {
		return nil, nil
	}
	at, err := container(search.Node)
	if err != nil {
		return nil, err
	}
	result := &BPFMatch{Object: at, Search: search, Layout: c.Layout, NameAvailable: true}
	var name string
	var start, end uint64
	if c.Layout == "modern" {
		start, end, err = region(at)
		if err != nil {
			return nil, err
		}
		name, _, err = bpfArray(ctx, r, at, typ, "name")
		if err != nil {
			return nil, err
		}
	} else {
		prog, err := bpfPointer(ctx, r, at, typ, "prog")
		if err != nil {
			return nil, err
		}
		info, err := ReadBPFProgram(ctx, r, prog)
		if err != nil {
			return nil, err
		}
		start, end, name = info.RegionStart, info.RegionEnd, info.Name
		result.Program = prog
		result.ProgramDetails = &info
		result.Aux = info.Aux
		result.NameAvailable = info.NameAvailable
	}
	result.RegionStart, result.RegionEnd = start, end
	exported := false
	result.Symbol = Symbol{Name: name, Type: "t", Address: start & c.AddressMask, Exported: &exported, SizeStart: start, SizeEnd: end}
	if end > start {
		result.Symbol.Size = end - start
		result.Symbol.SizeAvailable = true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
