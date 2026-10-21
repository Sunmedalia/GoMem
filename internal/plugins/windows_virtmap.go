package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsVirtMapPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.virtmap", Upstream: "windows.virtmap.VirtMap", Platform: "windows", NeedsKernel: true,
		Description: "List kernel system virtual-address regions. The upstream End offset column is NumberOfBytes, not an end address",
		Columns: []evidence.Column{
			{Name: "Region", Kind: "string"},
			{Name: "Start", Kind: "address"},
			{Name: "Size", Kind: "uint64"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsVirtMap}}
}

type vaSpan struct {
	start uint64
	size  uint64
	at    uint64
}

type vaRegions struct {
	path     string
	spans    map[string][]vaSpan
	examined uint64
	count    uint64
}

func windowsVirtMap(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.virtmap requires a kernel layer and symbols")
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.virtmap needs a 4- or 8-byte pointer")
	}
	enum, err := e.Symbols.Enumeration("_MI_SYSTEM_VA_TYPE")
	if err != nil {
		return fmt.Errorf("_MI_SYSTEM_VA_TYPE: %w", err)
	}
	if enum.Size == 0 {
		return fmt.Errorf("_MI_SYSTEM_VA_TYPE has no size")
	}
	large, err := virtLargePage(e)
	if err != nil {
		return err
	}
	regions, err := virtCollect(ctx, e, pointer, large, enum)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(regions.spans))
	for name := range regions.spans {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := 0
	for _, name := range names {
		for _, span := range regions.spans[name] {
			rows++
			if err = out(virtEvidence(e, span.at, name, virtStart(span.start, pointer), evidence.Number(span.size))); err != nil {
				return err
			}
		}
	}
	coverage := map[string]string{
		"path":       regions.path,
		"examined":   formatCount(regions.examined),
		"count":      formatCount(regions.count),
		"rows":       formatCount(uint64(rows)),
		"names":      formatCount(uint64(len(names))),
		"large_page": formatCount(large),
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"Region": evidence.Missing("not_applicable", nil), "Start": evidence.Missing("not_applicable", nil),
		"Size": evidence.Missing("not_applicable", nil), "RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(coverage),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func virtLargePage(e plugin.Environment) (uint64, error) {
	pte, err := e.Symbols.Type("_MMPTE")
	if err != nil {
		return 0, fmt.Errorf("_MMPTE: %w", err)
	}
	if pte.Size == 0 {
		return 0, fmt.Errorf("_MMPTE size is zero")
	}
	const page = uint64(4096)
	return (page * page) / pte.Size, nil
}

func virtCollect(ctx context.Context, e plugin.Environment, pointer int, large uint64, enum symbols.Enumeration) (vaRegions, error) {
	if _, err := e.Symbols.Lookup("MiVisibleState"); err == nil {
		return virtVisible(ctx, e, pointer, large, enum)
	}
	if _, err := e.Symbols.Lookup("MiSystemVaType"); err == nil {
		return virtLegacy(ctx, e, pointer, large, enum)
	}
	return vaRegions{}, fmt.Errorf("windows.virtmap: MiVisibleState required structures not found")
}

func virtVisible(ctx context.Context, e plugin.Environment, pointer int, large uint64, enum symbols.Enumeration) (vaRegions, error) {
	symbol, err := e.Symbol("MiVisibleState")
	if err != nil {
		return vaRegions{}, err
	}
	raw, err := readLE(ctx, e.Kernel, symbol, pointer)
	if err != nil {
		if ctx.Err() != nil {
			return vaRegions{}, ctx.Err()
		}
		return vaRegions{}, fmt.Errorf("MiVisibleState at %#x: %w", symbol, err)
	}
	state := canonicalPointer(raw, pointer)
	regions, err := e.Objects.Field("_MI_VISIBLE_STATE", "SystemVaRegions")
	if err == nil {
		return virtAssignments(ctx, e, state, regions, enum)
	}
	if !errors.Is(err, object.ErrFieldAbsent) {
		return vaRegions{}, err
	}
	types, err := e.Objects.Field("_MI_VISIBLE_STATE", "SystemVaType")
	if err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			return vaRegions{}, fmt.Errorf("windows.virtmap: SystemVaRegions required structures not found")
		}
		return vaRegions{}, err
	}
	start, err := virtRangeStart(ctx, e, pointer)
	if err != nil {
		return vaRegions{}, err
	}
	base, err := memory.Add(state, types.Offset)
	if err != nil {
		return vaRegions{}, err
	}
	names, err := virtTypeNames(ctx, e, base, types.Type, enum)
	if err != nil {
		return vaRegions{}, err
	}
	spans, err := coalesceSystemVa(start, large, names)
	if err != nil {
		return vaRegions{}, err
	}
	return vaRegions{path: "visible_system_va_type", spans: stampSpans(spans, base), examined: uint64(len(names)), count: types.Type.Count}, nil
}

func virtLegacy(ctx context.Context, e plugin.Environment, pointer int, large uint64, enum symbols.Enumeration) (vaRegions, error) {
	symbol, err := e.Symbol("MiSystemVaType")
	if err != nil {
		return vaRegions{}, err
	}
	start, err := virtRangeStart(ctx, e, pointer)
	if err != nil {
		return vaRegions{}, err
	}
	count, err := legacyVaCount(start, large)
	if err != nil {
		return vaRegions{}, err
	}
	char, err := e.Symbols.Type("char")
	if err != nil {
		return vaRegions{}, fmt.Errorf("char: %w", err)
	}
	if char.Size != 1 {
		return vaRegions{}, fmt.Errorf("char size %d is not 1", char.Size)
	}
	ref := symbols.TypeRef{Kind: "base", Name: "char"}
	names, err := virtTypeNames(ctx, e, symbol, symbols.TypeRef{Kind: "array", Count: uint64(count), Subtype: &ref}, enum)
	if err != nil {
		return vaRegions{}, err
	}
	spans, err := coalesceSystemVa(start, large, names)
	if err != nil {
		return vaRegions{}, err
	}
	return vaRegions{path: "mi_system_va_type", spans: stampSpans(spans, symbol), examined: uint64(len(names)), count: uint64(count)}, nil
}

func virtAssignments(ctx context.Context, e plugin.Environment, state uint64, field symbols.Field, enum symbols.Enumeration) (vaRegions, error) {
	if field.Type.Kind != "array" || field.Type.Subtype == nil {
		return vaRegions{}, fmt.Errorf("SystemVaRegions is not an array")
	}
	sub := field.Type.Subtype
	if sub.Kind != "struct" && sub.Kind != "union" {
		return vaRegions{}, fmt.Errorf("SystemVaRegions element is %s", sub.Kind)
	}
	elem, err := e.Objects.Size(*sub)
	if err != nil {
		return vaRegions{}, err
	}
	if elem == 0 {
		return vaRegions{}, fmt.Errorf("SystemVaRegions element size is zero")
	}
	baseField, err := e.Objects.Field(sub.Name, "BaseAddress")
	if err != nil {
		return vaRegions{}, fmt.Errorf("SystemVaRegions.BaseAddress: %w", err)
	}
	sizeField, err := e.Objects.Field(sub.Name, "NumberOfBytes")
	if err != nil {
		return vaRegions{}, fmt.Errorf("SystemVaRegions.NumberOfBytes: %w", err)
	}
	if baseField.Type.Kind != "pointer" {
		return vaRegions{}, fmt.Errorf("SystemVaRegions.BaseAddress is %s, not a pointer", baseField.Type.Kind)
	}
	baseWidth, err := e.Objects.Size(baseField.Type)
	if err != nil {
		return vaRegions{}, err
	}
	sizeWidth, err := e.Objects.Size(sizeField.Type)
	if err != nil {
		return vaRegions{}, err
	}
	if baseWidth != 4 && baseWidth != 8 || sizeWidth < 1 || sizeWidth > 8 || sizeField.Type.Kind == "pointer" {
		return vaRegions{}, fmt.Errorf("SystemVaRegions field widths %d and %d are unsupported", baseWidth, sizeWidth)
	}
	base, err := memory.Add(state, field.Offset)
	if err != nil {
		return vaRegions{}, err
	}
	spans := map[string][]vaSpan{}
	for i := uint64(0); i < field.Type.Count; i++ {
		if err = ctx.Err(); err != nil {
			return vaRegions{}, err
		}
		name, err := systemVaName(enum, i, false, 8)
		if err != nil {
			return vaRegions{}, fmt.Errorf("SystemVaRegions index %d: %w", i, err)
		}
		if elem != 0 && i > ^uint64(0)/elem {
			return vaRegions{}, fmt.Errorf("SystemVaRegions index %d overflows", i)
		}
		at, err := memory.Add(base, i*elem)
		if err != nil {
			return vaRegions{}, err
		}
		baseAt, err := memory.Add(at, baseField.Offset)
		if err != nil {
			return vaRegions{}, err
		}
		sizeAt, err := memory.Add(at, sizeField.Offset)
		if err != nil {
			return vaRegions{}, err
		}
		raw, err := readLE(ctx, e.Kernel, baseAt, int(baseWidth))
		if err != nil {
			if ctx.Err() != nil {
				return vaRegions{}, ctx.Err()
			}
			return vaRegions{}, fmt.Errorf("SystemVaRegions BaseAddress at %#x: %w", at, err)
		}
		size, err := readLE(ctx, e.Kernel, sizeAt, int(sizeWidth))
		if err != nil {
			if ctx.Err() != nil {
				return vaRegions{}, ctx.Err()
			}
			return vaRegions{}, fmt.Errorf("SystemVaRegions NumberOfBytes at %#x: %w", at, err)
		}
		spans[name] = append(spans[name], vaSpan{start: pointerIdentity(raw, int(baseWidth)), size: size, at: at})
	}
	return vaRegions{path: "system_va_regions", spans: spans, examined: field.Type.Count, count: field.Type.Count}, nil
}

func virtRangeStart(ctx context.Context, e plugin.Environment, pointer int) (uint64, error) {
	symbol, err := e.Symbol("MmSystemRangeStart")
	if err != nil {
		return 0, fmt.Errorf("MmSystemRangeStart: %w", err)
	}
	raw, err := readLE(ctx, e.Kernel, symbol, pointer)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("MmSystemRangeStart at %#x: %w", symbol, err)
	}
	return pointerIdentity(raw, pointer), nil
}

func virtTypeNames(ctx context.Context, e plugin.Environment, base uint64, ref symbols.TypeRef, enum symbols.Enumeration) ([]string, error) {
	if ref.Kind != "array" || ref.Subtype == nil {
		return nil, fmt.Errorf("system VA type is not an array")
	}
	signed, width, err := scalarSigned(e.Symbols, *ref.Subtype)
	if err != nil {
		return nil, err
	}
	if width < 1 || width > 8 {
		return nil, fmt.Errorf("system VA type element is %d bytes", width)
	}
	if ref.Count > uint64(memory.MaxRead)/uint64(width) {
		return nil, fmt.Errorf("system VA type array of %d exceeds the read limit", ref.Count)
	}
	total := int(ref.Count) * width
	if total == 0 {
		return nil, nil
	}
	buf, err := memory.Read(ctx, e.Kernel, base, total)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("system VA type array at %#x: %w", base, err)
	}
	names := make([]string, ref.Count)
	for i := 0; i < int(ref.Count); i++ {
		var value uint64
		for bit := 0; bit < width; bit++ {
			value |= uint64(buf[i*width+bit]) << (8 * bit)
		}
		name, err := systemVaName(enum, value, signed, width)
		if err != nil {
			return nil, fmt.Errorf("system VA type index %d: %w", i, err)
		}
		names[i] = name
	}
	return names, nil
}

func scalarSigned(table symbols.SymbolTable, ref symbols.TypeRef) (bool, int, error) {
	if ref.Kind == "pointer" {
		return false, table.PointerSize(), nil
	}
	name := ref.Name
	if name == "" && ref.Subtype != nil {
		return scalarSigned(table, *ref.Subtype)
	}
	t, err := table.Type(name)
	if err != nil {
		return false, 0, err
	}
	return t.Signed, int(t.Size), nil
}

func systemVaName(enum symbols.Enumeration, value uint64, signed bool, width int) (string, error) {
	lookup := value
	if signed && width > 0 && width < 8 {
		sign := uint64(1) << (uint(width)*8 - 1)
		if value&sign != 0 {
			lookup |= ^uint64(0) << (uint(width) * 8)
		}
	}
	names := enum.Names(lookup)
	if len(names) == 0 {
		return "", fmt.Errorf("enumeration value %d is outside _MI_SYSTEM_VA_TYPE", value)
	}
	return names[0], nil
}

func legacyVaCount(start, large uint64) (int, error) {
	if large == 0 {
		return 0, fmt.Errorf("large page size is zero")
	}
	const limit = uint64(0x1_0000_0000)
	if start >= limit {
		return 0, nil
	}
	n := (limit - start) / large
	if n > uint64(memory.MaxRead) {
		return 0, fmt.Errorf("MiSystemVaType count %d exceeds the read limit", n)
	}
	return int(n), nil
}

// coalesceSystemVa repeats the pinned _enumerate_system_va_type state machine.
// A run's accumulated size is attached to the next different name, and the
// final run's extra pages are dropped.
func coalesceSystemVa(start, page uint64, names []string) (map[string][]vaSpan, error) {
	if page == 0 {
		return nil, fmt.Errorf("large page size is zero")
	}
	result := map[string][]vaSpan{}
	prev := ""
	seen := false
	cur := page
	for _, name := range names {
		if !seen || name != prev {
			result[name] = append(result[name], vaSpan{start: start, size: cur})
			next, err := memory.Add(start, cur)
			if err != nil {
				return nil, err
			}
			start, cur = next, page
		} else {
			next, err := memory.Add(cur, page)
			if err != nil {
				return nil, err
			}
			cur = next
		}
		prev, seen = name, true
	}
	return result, nil
}

func stampSpans(spans map[string][]vaSpan, at uint64) map[string][]vaSpan {
	for name, list := range spans {
		for i := range list {
			list[i].at = at
		}
		spans[name] = list
	}
	return spans
}

func virtStart(value uint64, width int) evidence.Value {
	if width == 8 && value > 0x0000ffffffffffff || width == 4 && value > 0xffffffff {
		return evidence.Address(value)
	}
	return evidence.Address(canonicalPointer(value, width))
}

func virtEvidence(e plugin.Environment, at uint64, region string, start, size evidence.Value) evidence.Row {
	offset := ""
	if at != 0 {
		offset = fmt.Sprintf("0x%x", at)
	}
	return evidence.Row{Cells: map[string]evidence.Value{
		"Region": evidence.Text(region), "Start": start, "Size": size,
		"RecordType": evidence.Text("region"), "Coverage": evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: offset}}
}
