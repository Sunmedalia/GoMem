package pe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Export is one export-table entry. Forwarder is metadata, not a resolved target.
// Ordinal-only entries have Named=false; names retain their original bytes.
type Export struct {
	Ordinal   uint64 `json:"ordinal"`
	RVA       uint32 `json:"rva"`
	Address   uint64 `json:"address"`
	Named     bool   `json:"named"`
	Name      []byte `json:"name"`
	Forwarder []byte `json:"forwarder"`
}

// ExportRead describes one actual acquisition. Raw is owned by the observer.
// A short read is always an error, even when the layer returns no error.
type ExportRead struct {
	Address   uint64
	Requested int
	Raw       []byte
	Err       error
}

type ExportLimits struct {
	MaxEntries uint64
	MaxBytes   uint64
	MaxString  uint64
	Observe    func(ExportRead) error
}

func DefaultExportLimits() ExportLimits {
	return ExportLimits{MaxEntries: 65536, MaxBytes: 16 << 20, MaxString: 4096}
}

type ExportTable struct {
	Base          uint64
	ImageSize     uint64
	DirectoryRVA  uint32
	DirectorySize uint32
	DLLName       []byte
	Entries       []Export
	ReadBytes     uint64
	Complete      bool
}

type exportReader struct {
	memory.MemoryLayer
	limits ExportLimits
	used   uint64
	stop   error
}

func (r *exportReader) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if r.stop != nil {
		return 0, r.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > r.limits.MaxBytes-r.used {
		return 0, fmt.Errorf("PE export acquisition byte limit exhausted")
	}
	n, err := r.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n, err = 0, fmt.Errorf("invalid PE export read count")
	}
	if err == nil && n != len(p) {
		err = io.ErrUnexpectedEOF
	}
	r.used += uint64(n)
	if r.limits.Observe != nil {
		if cause := r.limits.Observe(ExportRead{at, len(p), append([]byte(nil), p[:n]...), err}); cause != nil {
			r.stop = cause
			return n, cause
		}
	}
	if cause := ctx.Err(); cause != nil {
		return n, cause
	}
	return n, err
}

// ReadExports parses an Intel PE mapped image without padding or whole-image
// allocation. The returned table retains completed entries on failure; Complete
// distinguishes an empty export directory from an incomplete acquisition.
// Named entries follow name-table order, then unnamed entries follow EAT order.
func ReadExports(ctx context.Context, layer memory.MemoryLayer, base uint64, limits ExportLimits) (table *ExportTable, err error) {
	table = &ExportTable{Base: base}
	if layer == nil || limits.MaxEntries == 0 || limits.MaxEntries > 1000000 || limits.MaxBytes == 0 || limits.MaxBytes > 1<<30 || limits.MaxString == 0 || limits.MaxString > 65536 {
		return table, fmt.Errorf("invalid PE export source or limits")
	}
	r := &exportReader{MemoryLayer: layer, limits: limits}
	defer func() { table.ReadBytes = r.used }()
	image, err := Plan(ctx, r, base)
	if err != nil {
		return table, err
	}
	table.ImageSize = image.Size
	read := func(rva uint64, length uint64) ([]byte, error) {
		if rva > image.Size || length > image.Size-rva || length > memory.MaxRead {
			return nil, fmt.Errorf("PE export RVA/length outside mapped image: %#x/%d", rva, length)
		}
		return memory.Read(ctx, r, base+rva, int(length))
	}
	dos, err := read(60, 4)
	if err != nil {
		return table, err
	}
	nt := uint64(binary.LittleEndian.Uint32(dos))
	// Plan has validated machine, optional-header size and image extent.
	directoryOffset := uint64(96)
	if image.Machine == 0x8664 {
		directoryOffset = 112
	}
	count, err := read(nt+24+directoryOffset-4, 4)
	if err != nil {
		return table, err
	}
	if binary.LittleEndian.Uint32(count) == 0 {
		table.Complete = true
		return table, nil
	}
	optional, err := read(nt+20, 2)
	if err != nil {
		return table, err
	}
	if uint64(binary.LittleEndian.Uint16(optional)) < directoryOffset+8 {
		return table, fmt.Errorf("PE export directory is outside optional header")
	}
	dir, err := read(nt+24+directoryOffset, 8)
	if err != nil {
		return table, err
	}
	table.DirectoryRVA, table.DirectorySize = binary.LittleEndian.Uint32(dir), binary.LittleEndian.Uint32(dir[4:])
	dirRVA, dirSize := uint64(table.DirectoryRVA), uint64(table.DirectorySize)
	if dirRVA == 0 && dirSize == 0 {
		table.Complete = true
		return table, nil
	}
	if dirRVA == 0 || dirSize < 40 || dirRVA > image.Size || dirSize > image.Size-dirRVA {
		return table, fmt.Errorf("invalid PE export directory bounds")
	}
	header, err := read(dirRVA, 40)
	if err != nil {
		return table, err
	}
	get := func(off int) uint64 { return uint64(binary.LittleEndian.Uint32(header[off:])) }
	ordinalBase, functions, names := get(16), get(20), get(24)
	if functions > limits.MaxEntries || names > limits.MaxEntries {
		return table, fmt.Errorf("PE export table exceeds entry limit")
	}
	stringAt := func(rva, end uint64) ([]byte, error) {
		if rva == 0 || rva >= end || end > image.Size {
			return nil, fmt.Errorf("PE export string RVA outside bounds")
		}
		var value []byte
		for pos := rva; pos < end && uint64(len(value)) < limits.MaxString; {
			// Do not read beyond a NUL into a potentially unavailable page.
			raw, cause := read(pos, 1)
			if cause != nil {
				return nil, cause
			}
			if raw[0] == 0 {
				return value, nil
			}
			value = append(value, raw[0])
			pos++
		}
		return nil, fmt.Errorf("unterminated or oversized PE export string")
	}
	if get(12) != 0 {
		table.DLLName, err = stringAt(get(12), image.Size)
		if err != nil {
			return table, err
		}
	}
	array := func(rva, count, width uint64) ([]byte, error) {
		if count == 0 {
			return nil, nil
		}
		if rva == 0 {
			return nil, fmt.Errorf("null PE export array")
		}
		return read(rva, count*width)
	}
	eat, err := array(get(28), functions, 4)
	if err != nil {
		return table, err
	}
	nametab, err := array(get(32), names, 4)
	if err != nil {
		return table, err
	}
	ordinals, err := array(get(36), names, 2)
	if err != nil {
		return table, err
	}
	seen := make([]bool, int(functions))
	appendEntry := func(index uint64, named bool, nameRVA uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rva := uint64(binary.LittleEndian.Uint32(eat[index*4:]))
		if rva == 0 {
			return nil
		}
		if rva >= image.Size {
			return fmt.Errorf("PE export target RVA outside mapped image: %#x", rva)
		}
		if uint64(len(table.Entries)) >= limits.MaxEntries {
			return fmt.Errorf("PE export output entry limit exhausted")
		}
		e := Export{Ordinal: ordinalBase + index, RVA: uint32(rva), Address: base + rva, Named: named}
		if named {
			e.Name, err = stringAt(nameRVA, image.Size)
			if err != nil {
				return err
			}
		}
		if rva >= dirRVA && rva < dirRVA+dirSize {
			e.Forwarder, err = stringAt(rva, dirRVA+dirSize)
			if err != nil {
				return err
			}
		}
		table.Entries = append(table.Entries, e)
		return nil
	}
	for i := uint64(0); i < names; i++ {
		index := uint64(binary.LittleEndian.Uint16(ordinals[i*2:]))
		if index >= functions {
			return table, fmt.Errorf("PE export name ordinal exceeds address table")
		}
		if err = appendEntry(index, true, uint64(binary.LittleEndian.Uint32(nametab[i*4:]))); err != nil {
			return table, err
		}
		seen[index] = true
	}
	for index := uint64(0); index < functions; index++ {
		if !seen[index] {
			if err = appendEntry(index, false, 0); err != nil {
				return table, err
			}
		}
	}
	table.Complete = true
	return table, nil
}

// NameAt implements the pinned ExportSymbolFinder's exact-address, first-entry
// lookup. It deliberately does not guess nearest symbols or follow forwarders.
func (t *ExportTable) NameAt(address uint64) ([]byte, bool) {
	for _, e := range t.Entries {
		if e.Address == address {
			return append([]byte(nil), e.Name...), e.Named
		}
	}
	return nil, false
}

func (t *ExportTable) AddressForName(name []byte) (uint64, bool) {
	for _, e := range t.Entries {
		if e.Named && bytes.Equal(e.Name, name) {
			return e.Address, true
		}
	}
	return 0, false
}
