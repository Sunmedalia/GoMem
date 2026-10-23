package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

// boundELF checks allocation-driving tables before debug/elf constructs them.
// Extended section counts are read from section zero before allocation.
func boundELF(ctx context.Context, source MemorySource) error {
	ident := make([]byte, 16)
	if _, err := source.ReadAt(ctx, ident, 0); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch ident[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return fmt.Errorf("invalid ELF byte order")
	}
	size, sectionSize, programSize := 64, 64, 56
	if ident[4] == 1 {
		size, sectionSize, programSize = 52, 40, 32
	} else if ident[4] != 2 {
		return fmt.Errorf("invalid ELF class")
	}
	header := make([]byte, size)
	if _, err := source.ReadAt(ctx, header, 0); err != nil {
		return err
	}
	var shoff, phoff uint64
	var shentsize, phentsize, shnum, phnum, stridx uint64
	if size == 64 {
		phoff, shoff = order.Uint64(header[32:]), order.Uint64(header[40:])
		phentsize, phnum, shentsize, shnum, stridx = uint64(order.Uint16(header[54:])), uint64(order.Uint16(header[56:])), uint64(order.Uint16(header[58:])), uint64(order.Uint16(header[60:])), uint64(order.Uint16(header[62:]))
	} else {
		phoff, shoff = uint64(order.Uint32(header[28:])), uint64(order.Uint32(header[32:]))
		phentsize, phnum, shentsize, shnum, stridx = uint64(order.Uint16(header[42:])), uint64(order.Uint16(header[44:])), uint64(order.Uint16(header[46:])), uint64(order.Uint16(header[48:])), uint64(order.Uint16(header[50:]))
	}
	// debug/elf does not resolve PN_XNUM into the actual program count.
	if phnum == 0xffff {
		return fmt.Errorf("%w: ELF extended program count PN_XNUM", ErrUnsupported)
	}
	check := func(offset, count, stride uint64) error {
		if count == 0 {
			return nil
		}
		if stride == 0 || count > 65536 {
			return fmt.Errorf("ELF header table count exceeds 65536")
		}
		end, err := Add(offset, count*stride)
		if err != nil || end > source.Size() {
			return fmt.Errorf("truncated ELF header table")
		}
		return nil
	}
	if shoff != 0 {
		if shentsize != uint64(sectionSize) {
			return fmt.Errorf("invalid ELF section header size")
		}
		if err := check(shoff, 1, shentsize); err != nil {
			return err
		}
		zero := make([]byte, sectionSize)
		if _, err := source.ReadAt(ctx, zero, shoff); err != nil {
			return err
		}
		if size == 64 {
			if shnum == 0 {
				shnum = order.Uint64(zero[32:])
			}
			if stridx == 0xffff {
				stridx = uint64(order.Uint32(zero[40:]))
			}
		} else {
			if shnum == 0 {
				shnum = uint64(order.Uint32(zero[20:]))
			}
			if stridx == 0xffff {
				stridx = uint64(order.Uint32(zero[24:]))
			}
		}
		if err := check(shoff, shnum, shentsize); err != nil {
			return err
		}
		if stridx != 0 {
			if stridx >= shnum {
				return fmt.Errorf("invalid ELF section string index")
			}
			strHeader := make([]byte, sectionSize)
			if _, err := source.ReadAt(ctx, strHeader, shoff+stridx*shentsize); err != nil {
				return err
			}
			var flags uint64
			if size == 64 {
				flags = order.Uint64(strHeader[8:])
			} else {
				flags = uint64(order.Uint32(strHeader[8:]))
			}
			if flags&0x800 != 0 {
				return fmt.Errorf("compressed ELF section names are unsupported")
			}
			var offset, length uint64
			if size == 64 {
				offset, length = order.Uint64(strHeader[24:]), order.Uint64(strHeader[32:])
			} else {
				offset, length = uint64(order.Uint32(strHeader[16:])), uint64(order.Uint32(strHeader[20:]))
			}
			end, err := Add(offset, length)
			if err != nil || length > MaxRead || end > source.Size() {
				return fmt.Errorf("ELF section names exceed source or metadata budget")
			}
			names := make([]byte, int(length))
			if n, err := source.ReadAt(ctx, names, offset); err != nil {
				return err
			} else if n != len(names) {
				return fmt.Errorf("short ELF names read")
			}
			block := make([]byte, 64<<10)
			var namesTotal uint64
			for row := uint64(0); row < shnum; {
				count := min(uint64(len(block))/shentsize, shnum-row)
				data := block[:int(count*shentsize)]
				if n, err := source.ReadAt(ctx, data, shoff+row*shentsize); err != nil {
					return err
				} else if n != len(data) {
					return fmt.Errorf("short ELF section table")
				}
				for i := uint64(0); i < count; i++ {
					start := uint64(order.Uint32(data[i*shentsize:]))
					if start >= uint64(len(names)) {
						return fmt.Errorf("invalid ELF section name offset")
					}
					size := min(uint64(len(names))-start, uint64(4097))
					nameLength := bytes.IndexByte(names[start:start+size], 0)
					if nameLength < 0 || nameLength > 4096 {
						return fmt.Errorf("ELF section name exceeds 4096-byte budget")
					}
					namesTotal += uint64(nameLength)
					if namesTotal > MaxRead {
						return fmt.Errorf("ELF cumulative section names exceed metadata budget")
					}
				}
				row += count
			}
		}
	} else if shnum != 0 || stridx != 0 {
		return fmt.Errorf("ELF missing section table")
	}
	if phnum != 0 {
		if phentsize != uint64(programSize) {
			return fmt.Errorf("invalid ELF program header size")
		}
		if err := check(phoff, phnum, phentsize); err != nil {
			return err
		}
	}
	return nil
}
