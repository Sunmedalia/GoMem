package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const (
	poolPaged    = 1
	poolNonPaged = 2
	poolFree     = 4
)

type poolConstraint struct {
	tag        []byte
	typeName   string
	objectType string
	pageType   int
	minSize    uint64
	maxSize    uint64
	hasMin     bool
	hasMax     bool
	minIndex   uint64
	maxIndex   uint64
	skipType   bool
	additional []string
	// External executive types use their own table for body sizes and validity;
	// pool and executive headers continue to use the matching kernel table.
	objectTable symbols.SymbolTable
	valid       func(context.Context, *object.Reader, uint64) (bool, error)
}

type poolLayout struct {
	headerSize  uint64
	tagOffset   uint64
	alignment   uint64
	vista       bool
	topDown     bool
	windows10   bool
	body        uint64
	infoMask    uint64
	pointerAt   uint64
	pointerSize uint64
	optional    []uint64
	padding     int
}

type poolHit struct {
	object     uint64
	header     uint64
	tag        []byte
	objectType string
	typ        string
	layer      string
	scan       *object.Reader
	native     memory.MemoryLayer
}

// poolFatalError stops the scan. A failed symlink creation-time read is not
// caught by the pinned plugin, so it must fail the task instead of dropping one row.
type poolFatalError struct{ error }

func (e poolFatalError) Unwrap() error { return e.error }

func builtinPoolConstraints(tags ...string) ([]poolConstraint, error) {
	all := []poolConstraint{
		{tag: []byte("AtmT"), typeName: "_RTL_ATOM_TABLE", minSize: 200, hasMin: true, pageType: poolPaged | poolNonPaged | poolFree},
		{tag: []byte("Pro\xe3"), typeName: "_EPROCESS", objectType: "Process", minSize: 600, hasMin: true, skipType: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Proc"), typeName: "_EPROCESS", objectType: "Process", minSize: 600, hasMin: true, skipType: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Thr\xe5"), typeName: "_ETHREAD", objectType: "Thread", minSize: 600, hasMin: true, skipType: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Thre"), typeName: "_ETHREAD", objectType: "Thread", minSize: 600, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Fil\xe5"), typeName: "_FILE_OBJECT", objectType: "File", minSize: 150, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("File"), typeName: "_FILE_OBJECT", objectType: "File", minSize: 150, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Mut\xe1"), typeName: "_KMUTANT", objectType: "Mutant", minSize: 64, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Muta"), typeName: "_KMUTANT", objectType: "Mutant", minSize: 64, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Dri\xf6"), typeName: "_DRIVER_OBJECT", objectType: "Driver", minSize: 248, hasMin: true, pageType: poolNonPaged | poolFree, additional: []string{"_DRIVER_EXTENSION"}},
		{tag: []byte("Driv"), typeName: "_DRIVER_OBJECT", objectType: "Driver", minSize: 248, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("MmLd"), typeName: "_LDR_DATA_TABLE_ENTRY", minSize: 76, hasMin: true, pageType: poolNonPaged | poolFree},
		{tag: []byte("Sym\xe2"), typeName: "_OBJECT_SYMBOLIC_LINK", objectType: "SymbolicLink", minSize: 72, hasMin: true, pageType: poolPaged | poolFree},
		{tag: []byte("Symb"), typeName: "_OBJECT_SYMBOLIC_LINK", objectType: "SymbolicLink", minSize: 72, hasMin: true, pageType: poolPaged | poolFree},
		{tag: []byte("CM10"), typeName: "_CMHIVE", minSize: 800, hasMin: true, skipType: true, pageType: poolPaged | poolFree},
	}
	if len(tags) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, tag := range tags {
		want[tag] = true
	}
	var out []poolConstraint
	for _, constraint := range all {
		if want[string(constraint.tag)] {
			out = append(out, constraint)
			delete(want, string(constraint.tag))
		}
	}
	if len(want) != 0 {
		return nil, fmt.Errorf("unknown pool tag")
	}
	return out, nil
}

func scanPoolObjects(ctx context.Context, e plugin.Environment, constraints []poolConstraint, hitLabel string, rowFor func(string, uint64) evidence.Row, out plugin.Emit, emit func(context.Context, poolHit) (evidence.Row, bool, error)) error {
	return scanPoolObjectsExtra(ctx, e, constraints, hitLabel, rowFor, out, emit, nil)
}

func scanPoolObjectsExtra(ctx context.Context, e plugin.Environment, constraints []poolConstraint, hitLabel string, rowFor func(string, uint64) evidence.Row, out plugin.Emit, emit func(context.Context, poolHit) (evidence.Row, bool, error), extra map[string]string) error {
	if e.Objects == nil || e.Symbols == nil || e.Kernel == nil || e.Physical == nil {
		return fmt.Errorf("pool scan needs kernel symbols, a kernel layer and physical memory")
	}
	layout, err := poolScanLayout(e, constraints)
	if err != nil {
		return err
	}
	scanLayer := e.Kernel
	if !layout.windows10 {
		scanLayer = e.Physical
	}
	scanReader := e.Objects
	if !layout.windows10 {
		scanReader = &object.Reader{Layer: scanLayer, Symbols: e.Symbols}
	}
	ranges, err := layerRanges(ctx, scanLayer)
	if err != nil {
		return err
	}
	typeMap, err := windowsObjectTypes(ctx, e)
	if err != nil {
		return err
	}
	cookie, hasCookie, err := windowsHeaderCookie(ctx, e)
	if err != nil {
		return err
	}
	lookup := map[string]poolConstraint{}
	var needles [][]byte
	var needleWidth int
	for _, constraint := range constraints {
		key := string(constraint.tag)
		if _, ok := lookup[key]; ok {
			return fmt.Errorf("duplicate pool tag %q", key)
		}
		lookup[key] = constraint
		needles = append(needles, constraint.tag)
		if len(constraint.tag) > needleWidth {
			needleWidth = len(constraint.tag)
		}
	}
	var hits, skippedInvalid, skippedType, skippedName uint64
	var indexFailures pluginFailures
	scanned, failures, err := scanNeedles(ctx, scanLayer, ranges, needles, needleWidth, func(address uint64, tag []byte) error {
		if address < layout.tagOffset {
			return nil
		}
		header := address - layout.tagOffset
		block, err := scanReader.Uint(ctx, header, "_POOL_HEADER", "BlockSize")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			skippedInvalid++
			return nil
		}
		poolType, err := scanReader.Uint(ctx, header, "_POOL_HEADER", "PoolType")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			skippedInvalid++
			return nil
		}
		constraint := lookup[string(tag)]
		blockBytes := layout.alignment * block
		if constraint.hasMin && blockBytes < constraint.minSize || constraint.hasMax && blockBytes > constraint.maxSize {
			return nil
		}
		if !poolPageOK(poolType, constraint.pageType, layout.vista) {
			return nil
		}
		indexOK, indexErr := poolIndexOK(ctx, scanReader, header, constraint)
		if indexErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			skippedInvalid++
			indexFailures.add(indexErr)
			return nil
		}
		if !indexOK {
			return nil
		}
		objects, err := carvePoolObjects(ctx, layout, constraint, header, blockBytes, scanReader, e.Kernel)
		if err != nil {
			return err
		}
		for _, objectAddress := range objects {
			if constraint.objectType != "" && !constraint.skipType {
				name, err := poolObjectType(ctx, scanReader, e.Kernel, objectAddress, layout.body, typeMap, cookie, hasCookie)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					skippedType++
					continue
				}
				if name != constraint.objectType {
					skippedType++
					continue
				}
			}
			row, keep, err := emit(ctx, poolHit{object: objectAddress, header: header, tag: constraint.tag, objectType: constraint.objectType, typ: constraint.typeName, layer: scanLayer.Name(), scan: scanReader, native: e.Kernel})
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				var fatal poolFatalError
				if errors.As(err, &fatal) {
					return err
				}
				skippedName++
				continue
			}
			if !keep {
				continue
			}
			hits++
			if err := out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := rowFor(scanLayer.Name(), 0)
	summary.Cells["RecordType"] = evidence.Text("summary")
	coverage := map[string]string{
		"ranges":           formatCount(uint64(len(ranges))),
		"scanned_bytes":    formatCount(scanned),
		hitLabel:           formatCount(hits),
		"skipped_invalid":  formatCount(skippedInvalid),
		"skipped_type":     formatCount(skippedType),
		"skipped_name":     formatCount(skippedName),
		"read_failures":    formatCount(uint64(failures.count + indexFailures.count)),
		"type_map_entries": formatCount(uint64(len(typeMap))),
		"windows10":        yesNo(layout.windows10),
		"top_down":         yesNo(layout.topDown),
		"vista_pool":       yesNo(layout.vista),
		"layer":            scanLayer.Name(),
	}
	for key, value := range extra {
		coverage[key] = value
	}
	summary.Cells["Coverage"] = poolCoverage(coverage)
	cause := errors.Join(failures.err("Windows pool scan"), indexFailures.err("Windows pool index reads"))
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("pool_scan_incomplete", cause)
		diagnostic := rowFor(scanLayer.Name(), 0)
		diagnostic.Cells["RecordType"] = evidence.Text("diagnostic")
		diagnostic.Cells["Error"] = evidence.Missing("pool_scan_incomplete", cause)
		if err := out(diagnostic); err != nil {
			return err
		}
	}
	if err := out(summary); err != nil {
		return err
	}
	return cause
}

func yesNo(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// The pinned scanner tests each endpoint for truthiness. An index constraint
// (0, 0), used by shutdown callbacks, therefore does not restrict PoolIndex.
// Do not replace this with an equality check against zero.
func poolIndexOK(ctx context.Context, reader *object.Reader, header uint64, c poolConstraint) (bool, error) {
	if c.minIndex == 0 && c.maxIndex == 0 {
		return true, nil
	}
	index, err := reader.Uint(ctx, header, "_POOL_HEADER", "PoolIndex")
	if err != nil {
		return false, err
	}
	return (c.minIndex == 0 || index >= c.minIndex) && (c.maxIndex == 0 || index <= c.maxIndex), nil
}

func poolScanLayout(e plugin.Environment, constraints []poolConstraint) (poolLayout, error) {
	header, err := e.Symbols.Type("_POOL_HEADER")
	if err != nil {
		return poolLayout{}, fmt.Errorf("pool header type: %w", err)
	}
	tag, err := e.Objects.Field("_POOL_HEADER", "PoolTag")
	if err != nil {
		return poolLayout{}, err
	}
	tagSize, err := e.Objects.Size(tag.Type)
	if err != nil {
		return poolLayout{}, err
	}
	if _, err := e.Objects.Field("_POOL_HEADER", "BlockSize"); err != nil {
		return poolLayout{}, err
	}
	if _, err := e.Objects.Field("_POOL_HEADER", "PoolType"); err != nil {
		return poolLayout{}, err
	}
	if header.Size == 0 || header.Size > 4096 || tag.Offset > header.Size || tagSize != 4 || tag.Offset > header.Size-tagSize {
		return poolLayout{}, fmt.Errorf("incomplete pool header layout")
	}
	alignment, err := poolAlignment(e.Symbols.PointerSize())
	if err != nil {
		return poolLayout{}, err
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return poolLayout{}, err
	}
	layout := poolLayout{
		headerSize: header.Size, tagOffset: tag.Offset, alignment: alignment, body: body.Offset,
		vista: windowsVistaOrLater(e.Symbols), topDown: windows8OrLater(e.Symbols), windows10: windows10OrLater(e.Symbols),
		padding: -1,
	}
	executive := false
	for _, constraint := range constraints {
		executive = executive || constraint.objectType != ""
	}
	// Nonexecutive allocations start directly after the pool header. The
	// original scanner does not inspect executive optional-header metadata.
	if layout.topDown && executive {
		info, err := e.Objects.Field("_OBJECT_HEADER", "InfoMask")
		if err != nil {
			return poolLayout{}, err
		}
		pointer, err := e.Objects.Field("_OBJECT_HEADER", "PointerCount")
		if err != nil {
			return poolLayout{}, err
		}
		size, err := e.Objects.Size(pointer.Type)
		if err != nil || size == 0 || size > 8 {
			return poolLayout{}, fmt.Errorf("invalid object header pointer count")
		}
		layout.infoMask = info.Offset
		layout.pointerAt = pointer.Offset
		layout.pointerSize = size
		layout.optional, layout.padding = optionalHeaderSizes(e.Symbols)
	}
	for _, constraint := range constraints {
		if constraint.objectTable != nil && constraint.objectTable.PointerSize() != e.Symbols.PointerSize() {
			return poolLayout{}, fmt.Errorf("pool object/kernel pointer widths differ")
		}
		if constraint.minIndex != 0 || constraint.maxIndex != 0 {
			field, err := e.Objects.Field("_POOL_HEADER", "PoolIndex")
			if err != nil {
				return poolLayout{}, err
			}
			if _, err := e.Objects.ScalarType(field.Type); err != nil {
				return poolLayout{}, fmt.Errorf("pool index schema: %w", err)
			}
		}
		if constraint.objectType != "" && constraint.valid == nil && constraint.typeName != "_FILE_OBJECT" && constraint.typeName != "_EPROCESS" && constraint.typeName != "_ETHREAD" && constraint.typeName != "_KMUTANT" && constraint.typeName != "_DRIVER_OBJECT" && constraint.typeName != "_OBJECT_SYMBOLIC_LINK" {
			return poolLayout{}, fmt.Errorf("pool validity for %s is not implemented", constraint.typeName)
		}
	}
	return layout, nil
}

func optionalHeaderSizes(table symbols.SymbolTable) ([]uint64, int) {
	names := []string{
		"_OBJECT_HEADER_CREATOR_INFO", "_OBJECT_HEADER_NAME_INFO", "_OBJECT_HEADER_HANDLE_INFO",
		"_OBJECT_HEADER_QUOTA_INFO", "_OBJECT_HEADER_PROCESS_INFO", "_OBJECT_HEADER_AUDIT_INFO",
		"_OBJECT_HEADER_EXTENDED_INFO", "_OBJECT_HEADER_HANDLE_REVOCATION_INFO", "_OBJECT_HEADER_PADDING_INFO",
	}
	var sizes []uint64
	padding := -1
	for _, name := range names {
		typ, err := table.Type(name)
		if err != nil {
			continue
		}
		if name == "_OBJECT_HEADER_PADDING_INFO" {
			padding = len(sizes)
		}
		sizes = append(sizes, typ.Size)
	}
	return sizes, padding
}

func poolAlignment(pointer int) (uint64, error) {
	switch pointer {
	case 8:
		return 16, nil
	case 4:
		return 8, nil
	default:
		return 0, fmt.Errorf("pool scan needs a 4- or 8-byte pointer")
	}
}

func windows10OrLater(table symbols.SymbolTable) bool {
	if major, _, ok := windowsPEVersion(table); ok {
		return major >= 10
	}
	_, err := table.Lookup("ObHeaderCookie")
	return err == nil
}

func windows8OrLater(table symbols.SymbolTable) bool {
	if major, minor, ok := windowsPEVersion(table); ok {
		return major > 6 || major == 6 && minor >= 2
	}
	typ, err := table.Type("_HANDLE_TABLE")
	if err != nil {
		return false
	}
	_, present := typ.Fields["HandleCount"]
	return !present
}

func poolPageOK(poolType uint64, want int, vista bool) bool {
	if want == 0 {
		return true
	}
	free := poolType == 0
	var paged, nonpaged bool
	if vista {
		paged = poolType%2 == 1
		nonpaged = poolType%2 == 0 && poolType > 0
	} else {
		paged = poolType%2 == 0 && poolType > 0
		nonpaged = poolType%2 == 1
	}
	return want&poolFree != 0 && free || want&poolNonPaged != 0 && nonpaged || want&poolPaged != 0 && paged
}

func layerRanges(ctx context.Context, layer memory.MemoryLayer) ([]memory.Range, error) {
	if ranges := layer.Ranges(); len(ranges) > 0 {
		return ranges, nil
	}
	virtual, ok := layer.(*memory.Virtual)
	if !ok || virtual.Translator == nil {
		return nil, fmt.Errorf("%s has no enumerable ranges", layer.Name())
	}
	intel, ok := virtual.Translator.(*memory.Intel)
	if !ok {
		return nil, fmt.Errorf("%s is not an Intel address space", layer.Name())
	}
	return intel.MappedRanges(ctx)
}

func windowsObjectTypes(ctx context.Context, e plugin.Environment) (map[int]string, error) {
	address, err := e.Symbol("ObTypeIndexTable")
	if err != nil {
		address, err = e.Symbol("ObpObjectTypes")
		if err != nil {
			return nil, fmt.Errorf("object type table: %w", err)
		}
	}
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported object type pointer")
	}
	if _, err := memory.Read(ctx, e.Kernel, address, width); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return map[int]string{}, nil
	}
	out := map[int]string{}
	for index := 0; index < 100; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		slot, err := memory.Add(address, uint64(index*width))
		if err != nil {
			return nil, err
		}
		ptr, err := readLE(ctx, e.Kernel, slot, width)
		if err != nil {
			continue
		}
		if index > 0 && ptr == 0 {
			break
		}
		if ptr == 0 {
			continue
		}
		name, err := readPoolUnicode(ctx, e.Objects, e.Kernel, ptr, "_OBJECT_TYPE", "Name", 128)
		if err != nil || name == "" {
			continue
		}
		out[index] = name
	}
	return out, nil
}

func windowsHeaderCookie(ctx context.Context, e plugin.Environment) (uint64, bool, error) {
	address, err := e.Symbol("ObHeaderCookie")
	if err != nil {
		return 0, false, nil
	}
	value, err := readLE(ctx, e.Kernel, address, 4)
	if err != nil {
		return 0, false, fmt.Errorf("ObHeaderCookie: %w", err)
	}
	return value, true, nil
}

func carvePoolObjects(ctx context.Context, layout poolLayout, constraint poolConstraint, header, blockBytes uint64, scan *object.Reader, native memory.MemoryLayer) ([]uint64, error) {
	if constraint.objectType == "" {
		address, err := memory.Add(header, layout.headerSize)
		if err != nil {
			return nil, nil
		}
		return []uint64{address}, nil
	}
	if layout.topDown {
		return carveTopDown(ctx, layout, constraint, header, blockBytes, scan, native)
	}
	return carveBottomUp(ctx, layout, constraint, header, blockBytes, scan, native)
}

func carveTopDown(ctx context.Context, layout poolLayout, constraint poolConstraint, header, blockBytes uint64, scan *object.Reader, native memory.MemoryLayer) ([]uint64, error) {
	var optionalBytes uint64
	for _, size := range layout.optional {
		optionalBytes += size
	}
	limit := blockBytes
	if optionalBytes < limit {
		limit = optionalBytes
	}
	start, err := memory.Add(header, layout.headerSize)
	if err != nil {
		return nil, nil
	}
	windowLen, err := memory.Add(limit, layout.infoMask)
	if err != nil || windowLen > uint64(memory.MaxRead) {
		return nil, fmt.Errorf("pool optional-header window is invalid")
	}
	window, err := readPadded(ctx, scan.Layer, start, int(windowLen))
	if err != nil {
		return nil, err
	}
	var objects []uint64
	for addr := uint64(0); addr < limit; addr += layout.alignment {
		off := addr + layout.pointerAt
		if off+layout.pointerSize > uint64(len(window)) {
			continue
		}
		count := signedLE(window[off : off+layout.pointerSize])
		if count < 0 || count >= 0x1000000 {
			continue
		}
		maskAt := addr + layout.infoMask
		if maskAt >= uint64(len(window)) {
			continue
		}
		var optional uint64
		paddingPresent := false
		for index, size := range layout.optional {
			if window[maskAt]&(1<<uint(index)) == 0 {
				continue
			}
			optional += size
			if index == layout.padding {
				paddingPresent = true
			}
		}
		var padding int64
		if paddingPresent {
			if addr < optional || addr-optional+4 > uint64(len(window)) {
				continue
			}
			padding = int64(binary.LittleEndian.Uint32(window[addr-optional:addr-optional+4])) - int64(layout.optional[layout.padding])
		}
		if int64(addr)-int64(optional) >= padding && padding > int64(addr) {
			continue
		}
		body, err := memory.Add(start, addr)
		if err != nil {
			continue
		}
		body, err = memory.Add(body, layout.body)
		if err != nil {
			continue
		}
		valid, err := poolObjectValid(ctx, constraint, body, scan, native)
		if err != nil {
			return nil, err
		}
		if valid {
			objects = append(objects, body)
		}
	}
	return objects, nil
}

func carveBottomUp(ctx context.Context, layout poolLayout, constraint poolConstraint, header, blockBytes uint64, scan *object.Reader, native memory.MemoryLayer) ([]uint64, error) {
	table := scan.Symbols
	if constraint.objectTable != nil {
		table = constraint.objectTable
	}
	typ, err := table.Type(constraint.typeName)
	if err != nil {
		return nil, err
	}
	size := typ.Size
	for _, name := range constraint.additional {
		extra, err := table.Type(name)
		if err != nil {
			return nil, err
		}
		size += extra.Size
	}
	rounded := alignUp(size, layout.alignment)
	var object uint64
	switch {
	case blockBytes >= rounded:
		object = header + blockBytes - rounded
	case header >= rounded-blockBytes:
		object = header - (rounded - blockBytes)
	default:
		return nil, nil
	}
	valid, err := poolObjectValid(ctx, constraint, object, scan, native)
	if err != nil || !valid {
		return nil, err
	}
	return []uint64{object}, nil
}

func poolObjectValid(ctx context.Context, constraint poolConstraint, object uint64, scan *object.Reader, native memory.MemoryLayer) (bool, error) {
	if constraint.valid != nil {
		return constraint.valid(ctx, scan, object)
	}
	switch constraint.typeName {
	case "_FILE_OBJECT":
		return fileObjectValid(ctx, scan, native, object)
	case "_EPROCESS":
		return processObjectValid(ctx, scan, object)
	case "_ETHREAD":
		return threadObjectValid(ctx, scan, object)
	case "_KMUTANT":
		return mutantObjectValid(ctx, object)
	case "_DRIVER_OBJECT":
		return driverObjectValid(ctx)
	case "_OBJECT_SYMBOLIC_LINK":
		return symlinkObjectValid(ctx)
	default:
		if constraint.objectType == "" {
			return true, nil
		}
		return false, fmt.Errorf("pool validity for %s is not implemented", constraint.typeName)
	}
}

func fileObjectValid(ctx context.Context, scan *object.Reader, native memory.MemoryLayer, object uint64) (bool, error) {
	length, err := scan.Uint(ctx, object, "_FILE_OBJECT", "FileName.Length")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if length == 0 {
		return false, nil
	}
	buffer, err := scan.Uint(ctx, object, "_FILE_OBJECT", "FileName.Buffer")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if _, err := memory.Read(ctx, native, buffer, 1); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	return true, nil
}

func poolObjectType(ctx context.Context, scan *object.Reader, native memory.MemoryLayer, objectAddress, body uint64, typeMap map[int]string, cookie uint64, hasCookie bool) (string, error) {
	if objectAddress < body {
		return "", fmt.Errorf("object header precedes the address space")
	}
	header := objectAddress - body
	if _, err := scan.Field("_OBJECT_HEADER", "Type"); err == nil {
		ptr, err := scan.Uint(ctx, header, "_OBJECT_HEADER", "Type")
		if err != nil {
			return "", err
		}
		if ptr == 0 {
			return "", nil
		}
		return readPoolUnicode(ctx, &object.Reader{Layer: native, Symbols: scan.Symbols}, native, ptr, "_OBJECT_TYPE", "Name", 128)
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return "", err
	}
	index, err := scan.Uint(ctx, header, "_OBJECT_HEADER", "TypeIndex")
	if err != nil {
		return "", err
	}
	if hasCookie {
		index = ((header >> 8) ^ cookie ^ index) & 0xFF
	}
	return typeMap[int(index)], nil
}

func readPoolUnicode(ctx context.Context, reader *object.Reader, native memory.MemoryLayer, base uint64, typ, field string, maxBytes int) (string, error) {
	member, err := reader.Field(typ, field)
	if err != nil {
		return "", err
	}
	address, err := memory.Add(base, member.Offset)
	if err != nil {
		return "", err
	}
	length, err := reader.Uint(ctx, address, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	if maxBytes > 0 && (length == 0 || length > uint64(maxBytes)) || length > 65535 {
		return "", nil
	}
	if length == 0 {
		return "", nil
	}
	buffer, err := reader.Uint(ctx, address, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, native, buffer, int(length))
	if err != nil {
		return "", err
	}
	text := poolUTF16(raw)
	if maxBytes > 0 {
		count := 0
		for range []rune(text) {
			count++
			if count > maxBytes {
				return "", nil
			}
		}
		if text == "" {
			return "", nil
		}
	}
	return text, nil
}

func poolUTF16(raw []byte) string {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	var decoded []rune
	for i := 0; i < len(units); i++ {
		unit := rune(units[i])
		if utf16.IsSurrogate(unit) {
			if i+1 < len(units) {
				pair := utf16.DecodeRune(unit, rune(units[i+1]))
				if pair != '\uFFFD' {
					decoded = append(decoded, pair)
					i++
					continue
				}
			}
			decoded = append(decoded, '\uFFFD')
			continue
		}
		decoded = append(decoded, unit)
	}
	if len(raw)%2 == 1 {
		decoded = append(decoded, '\uFFFD')
	}
	for i, r := range decoded {
		if r == 0 {
			decoded = decoded[:i]
			break
		}
	}
	return string(decoded)
}

func signedLE(b []byte) int64 {
	var value uint64
	for i, c := range b {
		value |= uint64(c) << (8 * i)
	}
	bits := len(b) * 8
	if bits > 0 && bits < 64 && value&(uint64(1)<<uint(bits-1)) != 0 {
		value |= ^uint64(0) << uint(bits)
	}
	return int64(value)
}

func alignUp(n, align uint64) uint64 {
	if align == 0 || n%align == 0 {
		return n
	}
	return n + (align - n%align)
}

func readPadded(ctx context.Context, layer memory.MemoryLayer, address uint64, n int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n < 0 || n > memory.MaxRead {
		return nil, fmt.Errorf("invalid padded read")
	}
	buf := make([]byte, n)
	for off := 0; off < n; {
		got, err := layer.ReadAt(ctx, buf[off:], address+uint64(off))
		if err == nil {
			if got != n-off {
				return nil, fmt.Errorf("short padded read")
			}
			return buf, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if got > 0 {
			off += got
			continue
		}
		buf[off] = 0
		off++
	}
	return buf, nil
}

func scanNeedles(ctx context.Context, layer memory.MemoryLayer, ranges []memory.Range, needles [][]byte, width int, visit func(uint64, []byte) error) (uint64, pluginFailures, error) {
	var scanned uint64
	var failures pluginFailures
	if width < 1 {
		return 0, failures, fmt.Errorf("pool tag is empty")
	}
	buf := make([]byte, 1<<20)
	for _, r := range ranges {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 {
			return scanned, failures, fmt.Errorf("invalid pool scan range")
		}
		var tail []byte
		pos := r.Start
		for pos < end {
			if err := ctx.Err(); err != nil {
				return scanned, failures, err
			}
			n := int(min(uint64(len(buf)), end-pos))
			got, readErr := layer.ReadAt(ctx, buf[:n], pos)
			if ctx.Err() != nil {
				return scanned, failures, ctx.Err()
			}
			if got > 0 {
				if err := searchWindow(pos, tail, buf[:got], needles, visit); err != nil {
					return scanned, failures, err
				}
				scanned += uint64(got)
				pos += uint64(got)
				if readErr == nil {
					tail = keepTail(tail, buf[:got], width-1)
					continue
				}
				tail = nil
			}
			if readErr == nil {
				continue
			}
			if !errors.Is(readErr, memory.ErrUnmapped) {
				failures.add(readErr)
			}
			next := (pos &^ 4095) + 4096
			if next <= pos {
				return scanned, failures, fmt.Errorf("pool scan address overflow")
			}
			if next > end {
				next = end
			}
			pos = next
		}
	}
	return scanned, failures, nil
}

func searchWindow(pos uint64, tail, data []byte, needles [][]byte, visit func(uint64, []byte) error) error {
	window := make([]byte, 0, len(tail)+len(data))
	window = append(window, tail...)
	window = append(window, data...)
	if len(tail) > len(window) {
		return fmt.Errorf("pool scan window underflow")
	}
	base := pos - uint64(len(tail))
	for _, needle := range needles {
		if len(needle) == 0 || len(needle) > len(window) {
			continue
		}
		for from := 0; from+len(needle) <= len(window); {
			rel := bytes.Index(window[from:], needle)
			if rel < 0 {
				break
			}
			rel += from
			if rel+len(needle) > len(tail) {
				if err := visit(base+uint64(rel), needle); err != nil {
					return err
				}
			}
			from = rel + 1
		}
	}
	return nil
}

func keepTail(tail, data []byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	window := append(append([]byte{}, tail...), data...)
	if len(window) <= n {
		out := make([]byte, len(window))
		copy(out, window)
		return out
	}
	out := make([]byte, n)
	copy(out, window[len(window)-n:])
	return out
}
