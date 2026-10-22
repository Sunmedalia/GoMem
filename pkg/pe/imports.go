package pe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

var ErrImportStringLimit = errors.New("PE import string limit exhausted")

// Import retains the actual IAT slot and captured pointer separately from the
// pinned IAT command's twice-based Address. Value is meaningful only when
// ValueAvailable is true. A nil Name denotes an unresolved ordinal import.
type Import struct {
	Library          []byte
	Name             []byte
	ByOrdinal        bool
	Ordinal          uint16
	Hint             uint16
	DescriptorRVA    uint64
	LookupRVA        uint64
	Slot             uint64
	Address          uint64
	Value            uint64
	ValueAvailable   bool
	Bound            bool
	NameTruncated    bool
	LibraryTruncated bool
}

type ImportLimits struct {
	MaxDescriptors uint64
	MaxImports     uint64
	MaxThunks      uint64
	MaxBytes       uint64
	MaxString      uint64
	Observe        func(ExportRead) error
	Emit           func(Import) error
}

func DefaultImportLimits() ImportLimits {
	return ImportLimits{MaxDescriptors: 4096, MaxImports: 100000, MaxThunks: 2000000, MaxBytes: 64 << 20, MaxString: 512}
}

type ImportTable struct {
	Base          uint64
	ImageSize     uint64
	DirectoryRVA  uint32
	DirectorySize uint32
	Descriptors   uint64
	Thunks        uint64
	Imports       uint64
	ReadBytes     uint64
	Complete      bool
	Entries       []Import
}

type importReader struct {
	memory.MemoryLayer
	limits ImportLimits
	used   uint64
	stop   error
}

func (r *importReader) ReadAt(ctx context.Context, dst []byte, at uint64) (int, error) {
	if r.stop != nil {
		return 0, r.stop
	}
	if err := ctx.Err(); err != nil {
		r.stop = err
		return 0, err
	}
	if uint64(len(dst)) > r.limits.MaxBytes-r.used {
		r.stop = fmt.Errorf("PE import byte limit exhausted")
		return 0, r.stop
	}
	n, err := r.MemoryLayer.ReadAt(ctx, dst, at)
	if n < 0 || n > len(dst) {
		n = 0
		err = fmt.Errorf("invalid PE import read count")
	}
	if n != len(dst) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	r.used += uint64(n)
	if r.limits.Observe != nil {
		if cause := r.limits.Observe(ExportRead{at, len(dst), append([]byte(nil), dst[:n]...), err}); cause != nil {
			r.stop = cause
			return n, cause
		}
	}
	if cause := ctx.Err(); cause != nil {
		r.stop = cause
		return n, cause
	}
	return n, err
}

// ReadImports inspects mapped Intel PE imports without reconstruction padding or
// whole-image allocation. It keeps original descriptor/thunk order, duplicates,
// ordinal naming and the pinned IAT address convention. Damaged descriptors do
// not hide later descriptors. All source failures remain in the returned error.
// Emit, when set, streams completed descriptor results instead of storing them.
func ReadImports(ctx context.Context, layer memory.MemoryLayer, base uint64, limits ImportLimits) (table *ImportTable, err error) {
	table = &ImportTable{Base: base}
	if layer == nil || limits.MaxDescriptors == 0 || limits.MaxDescriptors > 65536 || limits.MaxImports == 0 || limits.MaxImports > 1000000 || limits.MaxThunks == 0 || limits.MaxThunks > 4000000 || limits.MaxBytes == 0 || limits.MaxBytes > 1<<30 || limits.MaxString == 0 || limits.MaxString > 512 {
		return table, fmt.Errorf("invalid PE import source or limits")
	}
	r := &importReader{MemoryLayer: layer, limits: limits}
	defer func() { table.ReadBytes = r.used }()
	image, cause := Plan(ctx, r, base)
	if cause != nil {
		return table, cause
	}
	table.ImageSize = image.Size
	read := func(rva, n uint64) ([]byte, error) {
		if rva > image.Size || n > image.Size-rva || n > memory.MaxRead {
			return nil, fmt.Errorf("PE import RVA/length outside mapped image: %#x/%d", rva, n)
		}
		return memory.Read(ctx, r, base+rva, int(n))
	}
	dos, cause := read(60, 4)
	if cause != nil {
		return table, cause
	}
	nt := uint64(binary.LittleEndian.Uint32(dos))
	directory := uint64(96)
	width := uint64(4)
	if image.Machine == 0x8664 {
		directory = 112
		width = 8
	}
	count, cause := read(nt+24+directory-4, 4)
	if cause != nil {
		return table, cause
	}
	if binary.LittleEndian.Uint32(count) < 2 {
		table.Complete = true
		return table, nil
	}
	header, cause := read(nt+20, 2)
	if cause != nil {
		return table, cause
	}
	if uint64(binary.LittleEndian.Uint16(header)) < directory+16 {
		return table, fmt.Errorf("PE import directory exceeds optional header")
	}
	dir, cause := read(nt+24+directory+8, 8)
	if cause != nil {
		return table, cause
	}
	table.DirectoryRVA = binary.LittleEndian.Uint32(dir)
	table.DirectorySize = binary.LittleEndian.Uint32(dir[4:])
	if table.DirectoryRVA == 0 {
		table.Complete = true
		return table, nil
	}
	var failures []error
	record := func(cause error) {
		if cause != nil {
			failures = append(failures, cause)
		}
	}
	defer func() { err = errors.Join(err, errors.Join(failures...)); table.Complete = err == nil }()
	str := func(at uint64) ([]byte, error) {
		var result []byte
		for i := uint64(0); i < limits.MaxString; i++ {
			if at > ^uint64(0)-i {
				return result, fmt.Errorf("PE import string RVA overflow")
			}
			v, cause := read(at+i, 1)
			if cause != nil {
				return result, cause
			}
			if v[0] == 0 {
				return result, nil
			}
			result = append(result, v[0])
		}
		return result, ErrImportStringLimit
	}
	ordinalFlag := uint64(1) << (width*8 - 1)
	readThunk := func(start, maxLen uint64) ([]uint64, []uint64, error) {
		var values, acquired []uint64
		if start == 0 {
			return values, acquired, nil
		}
		seen := map[uint64]bool{}
		repeated := 0
		minima := [2]uint64{^uint64(0), ^uint64(0)}
		var maxima [2]uint64
		for at := start; ; at += width {
			if at-start >= maxLen {
				return values, acquired, fmt.Errorf("PE import thunk range limit exhausted")
			}
			if table.Thunks >= limits.MaxThunks {
				r.stop = fmt.Errorf("PE import thunk count limit exhausted")
				return nil, acquired, r.stop
			}
			if repeated >= 15 || (minima[0] != ^uint64(0) && maxima[0]-minima[0] > 128<<20) || (minima[1] != ^uint64(0) && maxima[1]-minima[1] > 128<<20) {
				return nil, acquired, fmt.Errorf("implausible PE import thunk repetition/address spread")
			}
			table.Thunks++
			data, cause := read(at, width)
			if cause != nil {
				return nil, acquired, cause
			}
			value := uint64(binary.LittleEndian.Uint32(data))
			if width == 8 {
				value = binary.LittleEndian.Uint64(data)
			}
			acquired = append(acquired, value)
			if value == 0 {
				return values, acquired, nil
			}
			if value >= start && value <= at {
				return values, acquired, fmt.Errorf("PE import thunk overlaps its own table")
			}
			if value&ordinalFlag != 0 {
				if value&0x7fffffff > 0xffff {
					return nil, acquired, fmt.Errorf("invalid PE import ordinal encoding")
				}
			} else {
				if seen[value] {
					repeated++
				}
				seen[value] = true
				index := 0
				if value >= 1<<32 {
					index = 1
				}
				minima[index] = min(minima[index], value)
				maxima[index] = max(maxima[index], value)
			}
			values = append(values, value)
		}
	}
	for at := uint64(table.DirectoryRVA); ; at += 20 {
		if cause := ctx.Err(); cause != nil {
			return table, cause
		}
		if r.stop != nil {
			return table, r.stop
		}
		if table.Descriptors >= limits.MaxDescriptors {
			return table, fmt.Errorf("PE import descriptor limit exhausted")
		}
		desc, cause := read(at, 20)
		if cause != nil {
			return table, cause
		}
		if bytes.Equal(desc, make([]byte, 20)) {
			return table, nil
		}
		table.Descriptors++
		iltRVA := uint64(binary.LittleEndian.Uint32(desc))
		stamp := binary.LittleEndian.Uint32(desc[4:])
		nameRVA := uint64(binary.LittleEndian.Uint32(desc[12:]))
		iatRVA := uint64(binary.LittleEndian.Uint32(desc[16:]))
		maxLen := image.Size - at
		if at+20 > iltRVA || at+20 > iatRVA {
			maxLen = 0
			if at+20 > iltRVA {
				maxLen = at + 20 - iltRVA
			}
			if at+20 > iatRVA {
				maxLen = max(maxLen, at+20-iatRVA)
			}
		}
		ilt, _, iltErr := readThunk(iltRVA, maxLen)
		record(iltErr)
		if r.stop != nil {
			return table, r.stop
		}
		iat, iatCaptured, iatErr := readThunk(iatRVA, maxLen)
		record(iatErr)
		if r.stop != nil {
			return table, r.stop
		}
		selected, selectedRVA := ilt, iltRVA
		if len(selected) == 0 {
			selected, selectedRVA = iat, iatRVA
		}
		if len(selected) == 0 {
			continue
		}
		var imports []Import
		valid := true
		for i, value := range selected {
			entry := Import{DescriptorRVA: at, LookupRVA: selectedRVA + uint64(i)*width, Bound: stamp != 0}
			if value&ordinalFlag != 0 {
				entry.ByOrdinal = true
				entry.Ordinal = uint16(value)
				if entry.Ordinal == 0 {
					continue
				}
			} else {
				hint, cause := read(value&(ordinalFlag-1), 2)
				if cause != nil {
					record(cause)
					valid = false
					break
				}
				entry.Hint = binary.LittleEndian.Uint16(hint)
				name, cause := str(value + 2)
				record(cause)
				if r.stop != nil {
					return table, r.stop
				}
				if cause != nil && !errors.Is(cause, ErrImportStringLimit) {
					valid = false
					break
				}
				entry.NameTruncated = errors.Is(cause, ErrImportStringLimit)
				if !validImportName(name, false) || len(name) == 0 {
					continue
				}
				entry.Name = name
			}
			slot, cause := memory.Add(base, iatRVA+uint64(i)*width)
			if cause != nil {
				record(cause)
				valid = false
				break
			}
			entry.Slot = slot
			entry.Address, cause = memory.Add(base, slot)
			if cause != nil {
				record(cause)
				valid = false
				break
			}
			if i < len(iatCaptured) {
				entry.Value = iatCaptured[i]
				entry.ValueAvailable = true
			}
			imports = append(imports, entry)
		}
		if !valid || len(imports) == 0 {
			continue
		}
		library, cause := str(nameRVA)
		record(cause)
		if r.stop != nil {
			return table, r.stop
		}
		if cause != nil && !errors.Is(cause, ErrImportStringLimit) {
			continue
		}
		libraryTruncated := errors.Is(cause, ErrImportStringLimit)
		if !validImportName(library, true) {
			library = []byte("*invalid*")
		}
		if len(library) == 0 {
			continue
		}
		for _, entry := range imports {
			if cause := ctx.Err(); cause != nil {
				return table, cause
			}
			if table.Imports >= limits.MaxImports {
				return table, fmt.Errorf("PE import result limit exhausted")
			}
			entry.Library = append([]byte(nil), library...)
			entry.LibraryTruncated = libraryTruncated
			if entry.ByOrdinal {
				if name, ok := importOrdinalName(string(library), entry.Ordinal); ok {
					entry.Name = []byte(name)
				}
			}
			if limits.Emit != nil {
				if cause := limits.Emit(entry); cause != nil {
					return table, cause
				}
			} else {
				table.Entries = append(table.Entries, entry)
			}
			table.Imports++
		}
	}
}

func validImportName(raw []byte, library bool) bool {
	extra := "._?@$()<>"
	if library {
		extra = "!#$%&'()-@^_`{}~+,.;=[]:\\/"
	}
	for _, b := range raw {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9') && !strings.ContainsRune(extra, rune(b)) {
			return false
		}
	}
	return true
}

func importOrdinalName(library string, ordinal uint16) (string, bool) {
	table, known := importOrdinals[strings.ToLower(library)]
	if !known {
		return "", false
	}
	if name, ok := table[ordinal]; ok {
		return name, true
	}
	return fmt.Sprintf("ord%d", ordinal), true
}
