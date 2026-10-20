package symbols

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
)

// Select a universal Mach-O slice before debug/macho parses its symbol table.
// This avoids ingesting all unselected architectures and supports FAT64 offsets.
func selectMacho(r io.ReaderAt, fileSize uint64, arch string) (io.ReaderAt, string, error) {
	var header [8]byte
	if _, err := r.ReadAt(header[:], 0); err != nil {
		return nil, "", err
	}
	magic := binary.BigEndian.Uint32(header[:])
	var order binary.ByteOrder = binary.BigEndian
	fat64 := false
	switch magic {
	case 0xcafebabe:
	case 0xbebafeca:
		order = binary.LittleEndian
	case 0xcafebabf:
		fat64 = true
	case 0xbfbafeca:
		order = binary.LittleEndian
		fat64 = true
	default:
		return r, "", nil
	}
	count := uint64(order.Uint32(header[4:]))
	stride := uint64(20)
	if fat64 {
		stride = 32
	}
	if count == 0 || count > 64 || fileSize < 8 || count > (fileSize-8)/stride {
		return nil, "", fmt.Errorf("invalid or excessive fat Mach-O slice count")
	}
	var chosen io.ReaderAt
	var expected string
	type segment struct{ offset, size uint64 }
	var segments []segment
	for i := uint64(0); i < count; i++ {
		record := make([]byte, int(stride))
		if _, err := r.ReadAt(record, int64(8+i*stride)); err != nil {
			return nil, "", err
		}
		cpu := macho.Cpu(order.Uint32(record))
		offset, size := uint64(order.Uint32(record[8:])), uint64(order.Uint32(record[12:]))
		alignment := order.Uint32(record[16:])
		if fat64 {
			offset, size = order.Uint64(record[8:]), order.Uint64(record[16:])
			alignment = order.Uint32(record[24:])
		}
		if size == 0 || offset < 8+count*stride || offset > fileSize || size > fileSize-offset || alignment >= 63 || offset&((uint64(1)<<alignment)-1) != 0 {
			return nil, "", fmt.Errorf("invalid fat Mach-O slice bounds")
		}
		for _, other := range segments {
			if offset < other.offset+other.size && other.offset < offset+size {
				return nil, "", fmt.Errorf("overlapping fat Mach-O slices")
			}
		}
		segments = append(segments, segment{offset, size})
		name := machoArch(cpu)
		if arch != "" && name != arch {
			continue
		}
		if arch == "" && count != 1 {
			continue
		}
		if chosen != nil {
			return nil, "", fmt.Errorf("ambiguous fat Mach-O architecture")
		}
		chosen = io.NewSectionReader(r, int64(offset), int64(size))
		expected = name
	}
	if chosen == nil {
		return nil, "", fmt.Errorf("fat Mach-O requires a matching --binary-arch")
	}
	return chosen, expected, nil
}
