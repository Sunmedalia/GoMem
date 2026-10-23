package memory

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

type VMwareHeader struct {
	Version        uint8  `json:"version"`
	Groups         uint32 `json:"groups"`
	Tags           uint64 `json:"tags"`
	Regions        uint64 `json:"regions"`
	MemorySource   string `json:"memory_source"`
	MetadataSource string `json:"metadata_source"`
}
type VMwareLayer struct {
	*Mapped
	header VMwareHeader
}

func (v *VMwareLayer) VMwareHeader() VMwareHeader { return v.header }

func vmwareImage(ctx context.Context, source *VMwareSource) (MemoryLayer, error) {
	metadata := source.metadata
	var cache []byte
	var cacheStart uint64
	read := func(offset uint64, size int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 0 || size > MaxRead {
			return nil, fmt.Errorf("VMware metadata read exceeds budget")
		}
		end, err := Add(offset, uint64(size))
		if err != nil || end > metadata.Size() {
			return nil, fmt.Errorf("truncated VMware metadata")
		}
		result := make([]byte, size)
		for copied := 0; copied < size; {
			at := offset + uint64(copied)
			if cache == nil || at < cacheStart || at-cacheStart >= uint64(len(cache)) {
				cacheStart = at &^ uint64((64<<10)-1)
				length := min(uint64(64<<10), metadata.Size()-cacheStart)
				cache = make([]byte, int(length))
				n, err := metadata.ReadAt(ctx, cache, cacheStart)
				if err != nil {
					return nil, err
				}
				if n != len(cache) {
					return nil, fmt.Errorf("short VMware metadata read")
				}
			}
			copied += copy(result[copied:], cache[at-cacheStart:])
		}
		return result, nil
	}
	headerBytes, err := read(0, 12)
	if err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint32(headerBytes)
	switch magic {
	case 0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3:
	default:
		return nil, fmt.Errorf("invalid VMware metadata magic")
	}
	header := VMwareHeader{Version: headerBytes[0] & 15, Groups: binary.LittleEndian.Uint32(headerBytes[8:]), MemorySource: sourceDisplay(source.memory), MetadataSource: sourceDisplay(metadata)}
	if header.Groups == 0 || header.Groups > 65536 {
		return nil, fmt.Errorf("VMware group count exceeds 1..65536")
	}
	groupEnd, err := Add(12, uint64(header.Groups)*80)
	if err != nil || groupEnd > metadata.Size() {
		return nil, fmt.Errorf("truncated VMware group table")
	}
	var tagsOffset uint64
	found := false
	groups, err := read(12, int(header.Groups)*80)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < header.Groups; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		group := groups[uint64(i)*80 : uint64(i+1)*80]
		name := strings.TrimRight(string(group[:64]), "\x00")
		if name == "memory" {
			if found {
				return nil, fmt.Errorf("duplicate VMware memory group")
			}
			tagsOffset = binary.LittleEndian.Uint64(group[64:])
			found = true
		}
	}
	if !found || tagsOffset < groupEnd || tagsOffset >= metadata.Size() {
		return nil, fmt.Errorf("VMware memory group missing or invalid")
	}
	type regionField struct {
		name  string
		index uint32
	}
	values := make(map[regionField]uint64)
	position := tagsOffset
	var walked uint64
	terminated := false
	for header.Tags < 1<<20 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pair, err := read(position, 2)
		if err != nil {
			return nil, err
		}
		flags, nameLength := pair[0], int(pair[1])
		if flags == 0 && nameLength == 0 {
			terminated = true
			break
		}
		if nameLength == 0 {
			return nil, fmt.Errorf("VMware tag has empty name")
		}
		indices := int(flags >> 6)
		label, err := read(position+2, nameLength+indices*4)
		if err != nil {
			return nil, err
		}
		nameBytes := label[:nameLength]
		if strings.IndexByte(string(nameBytes), 0) >= 0 {
			return nil, fmt.Errorf("VMware tag contains embedded NUL")
		}
		name := string(nameBytes)
		dataOffset := position + 2 + uint64(len(label))
		length := uint64(flags & 63)
		extended := length == 62 || length == 63
		if length == 62 || length == 63 {
			width := 4
			if header.Version != 0 {
				width = 8
			}
			descriptor, err := read(dataOffset, 2*width+2)
			if err != nil {
				return nil, err
			}
			if width == 4 {
				length = uint64(binary.LittleEndian.Uint32(descriptor))
			} else {
				length = binary.LittleEndian.Uint64(descriptor)
			}
			dataOffset += uint64(len(descriptor))
		}
		next, err := Add(dataOffset, length)
		if err != nil || next > metadata.Size() || next <= position {
			return nil, fmt.Errorf("invalid VMware tag extent")
		}
		if next-position > 1<<30-walked {
			return nil, fmt.Errorf("VMware tag walk exceeds 1GiB budget")
		}
		walked += next - position
		relevant := name == "regionsCount" || name == "regionPPN" || name == "regionPageNum" || name == "regionSize"
		if relevant {
			expectedIndices := 1
			if name == "regionsCount" {
				expectedIndices = 0
			}
			if extended || indices != expectedIndices || length != 4 && length != 8 {
				return nil, fmt.Errorf("invalid VMware region tag layout")
			}
			index := uint32(0)
			if indices == 1 {
				index = binary.LittleEndian.Uint32(label[nameLength:])
			}
			if index >= 65536 {
				return nil, fmt.Errorf("VMware region index exceeds 65535")
			}
			key := regionField{name, index}
			if _, exists := values[key]; exists {
				return nil, fmt.Errorf("duplicate VMware region tag")
			}
			data, err := read(dataOffset, int(length))
			if err != nil {
				return nil, err
			}
			value := uint64(binary.LittleEndian.Uint32(data))
			if length == 8 {
				value = binary.LittleEndian.Uint64(data)
			}
			values[key] = value
		}
		header.Tags++
		position = next
	}
	if !terminated {
		return nil, fmt.Errorf("VMware tag count exceeds 1048576")
	}
	count, ok := values[regionField{"regionsCount", 0}]
	if !ok || count == 0 || count > 65536 {
		return nil, fmt.Errorf("VMware region count exceeds 1..65536")
	}
	header.Regions = count
	if len(values) != 1+int(count)*3 {
		return nil, fmt.Errorf("VMware region tags incomplete or contain undeclared regions")
	}
	runs := make([]Range, 0, int(count))
	for i := uint32(0); uint64(i) < count; i++ {
		numbers := [3]uint64{}
		for j, name := range []string{"regionPPN", "regionPageNum", "regionSize"} {
			value, ok := values[regionField{name, i}]
			if !ok {
				return nil, fmt.Errorf("VMware region %d missing %s", i, name)
			}
			if value > math.MaxUint64/4096 {
				return nil, fmt.Errorf("VMware region page arithmetic overflow")
			}
			numbers[j] = value * 4096
		}
		runs = append(runs, Range{Start: numbers[0], FileOffset: numbers[1], Length: numbers[2]})
	}
	if err := source.Validate(ctx); err != nil {
		return nil, err
	}
	mapped, err := NewMapped(source, "physical:vmware", runs)
	if err != nil {
		return nil, fmt.Errorf("VMware mapping: %w", err)
	}
	return &VMwareLayer{Mapped: mapped, header: header}, nil
}
