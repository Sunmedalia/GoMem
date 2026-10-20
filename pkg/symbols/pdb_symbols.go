package symbols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type pdbSection struct{ rva, size uint32 }
type omapEntry struct{ from, to uint32 }

func (b *codeView) symbols(msf *msfFile, dbi []byte) error {
	debugOffset := uint64(64)
	for _, offset := range []int{24, 28, 32, 36, 40, 52} {
		size := binary.LittleEndian.Uint32(dbi[offset:])
		if size > 0x7fffffff {
			return fmt.Errorf("negative DBI substream size")
		}
		debugOffset += uint64(size)
	}
	debugSize := uint64(binary.LittleEndian.Uint32(dbi[48:]))
	if debugSize%2 != 0 || debugOffset+debugSize != uint64(len(dbi)) {
		return fmt.Errorf("invalid DBI debug substream layout")
	}
	debug := dbi[debugOffset:]
	streamNumber := func(n int) uint16 {
		if n*2+2 > len(debug) {
			return 0xffff
		}
		return binary.LittleEndian.Uint16(debug[n*2:])
	}
	sectionID := streamNumber(5)
	var omap []omapEntry
	if original := streamNumber(10); original != 0xffff {
		sectionID = original
		if mapping := streamNumber(4); mapping != 0xffff {
			data, err := msf.stream(mapping)
			if err != nil {
				return err
			}
			if len(data)%8 != 0 || len(data)/8 > b.max {
				return fmt.Errorf("invalid OMAP stream length")
			}
			for offset := 0; offset < len(data); offset += 8 {
				e := omapEntry{binary.LittleEndian.Uint32(data[offset:]), binary.LittleEndian.Uint32(data[offset+4:])}
				if len(omap) > 0 && e.from <= omap[len(omap)-1].from {
					return fmt.Errorf("unordered OMAP stream")
				}
				omap = append(omap, e)
			}
		}
	}
	if sectionID == 0xffff {
		return fmt.Errorf("PDB has no PE section headers for symbol relocation")
	}
	sectionBytes, err := msf.stream(sectionID)
	if err != nil {
		return err
	}
	if len(sectionBytes) == 0 || len(sectionBytes)%40 != 0 || len(sectionBytes)/40 > 65535 {
		return fmt.Errorf("invalid PDB PE section stream")
	}
	sections := make([]pdbSection, 0, len(sectionBytes)/40)
	for off := 0; off < len(sectionBytes); off += 40 {
		sections = append(sections, pdbSection{binary.LittleEndian.Uint32(sectionBytes[off+12:]), max(binary.LittleEndian.Uint32(sectionBytes[off+8:]), binary.LittleEndian.Uint32(sectionBytes[off+16:]))})
	}
	mapStart := uint64(64) + uint64(binary.LittleEndian.Uint32(dbi[24:])) + uint64(binary.LittleEndian.Uint32(dbi[28:]))
	mapSize := uint64(binary.LittleEndian.Uint32(dbi[32:]))
	absSegments := map[uint16]bool{}
	if mapSize > 0 {
		segmentMap := dbi[mapStart : mapStart+mapSize]
		if len(segmentMap) < 4 || uint64(binary.LittleEndian.Uint16(segmentMap))*20+4 != mapSize {
			return fmt.Errorf("invalid DBI section map")
		}
		for off := 4; off < len(segmentMap); off += 20 {
			if binary.LittleEndian.Uint16(segmentMap[off:])&0x200 != 0 {
				absSegments[uint16((off-4)/20+1)] = true
			}
		}
	}
	b.absolute = map[string]string{}
	b.removed = map[string]string{}
	consume := func(data []byte) error {
		for off := 0; off < len(data); {
			if err := b.ctx.Err(); err != nil {
				return err
			}
			b.entries++
			if b.entries > b.max {
				return fmt.Errorf("PDB cumulative record limit")
			}
			if off+4 > len(data) {
				return fmt.Errorf("truncated PDB symbol record")
			}
			length := int(binary.LittleEndian.Uint16(data[off:]))
			if length < 2 || length+2 > len(data)-off {
				return fmt.Errorf("invalid PDB symbol record length")
			}
			leaf := binary.LittleEndian.Uint16(data[off+2:])
			c := cvCursor{data: data[off+4 : off+2+length]}
			off += length + 2
			var name string
			var segment uint16
			var offset, typ uint32
			var function bool
			switch leaf {
			case 0x110e, 0x1009: // public
				flags := c.u32()
				offset = c.u32()
				segment = c.u16()
				name = c.name(leaf == 0x1009)
				function = flags&2 != 0
			case 0x110c, 0x110d, 0x1007, 0x1008: // local/global data
				typ = c.u32()
				offset = c.u32()
				segment = c.u16()
				name = c.name(leaf < 0x1100)
			case 0x110f, 0x1110, 0x1146, 0x1147: // local/global procedures, including ID variants
				c.take(24)
				c.u32()
				offset = c.u32()
				segment = c.u16()
				c.u8()
				name = c.name(false)
				function = true
			case 0x1108, 0x1003: // UDT / typedef alias
				target := c.u32()
				name := c.name(leaf == 0x1003)
				if c.err != nil {
					return c.err
				}
				ref, err := b.ref(target, 0)
				if err != nil {
					return err
				}
				if err = b.alias(name, ref); err != nil {
					return err
				}
				continue
			default:
				continue // scope, line and local register records carry no global RVA
			}
			if c.err != nil {
				return c.err
			}
			if name == "" {
				return fmt.Errorf("empty PDB symbol name")
			}
			if absSegments[segment] {
				b.absolute[name] = fmt.Sprintf("0x%x", offset)
				continue
			}
			rva, err := pdbRVA(sections, omap, segment, offset)
			if errors.Is(err, errOMAPRemoved) {
				b.removed[name] = fmt.Sprintf("0x%x", rva)
				continue
			}
			if err != nil {
				return fmt.Errorf("PDB symbol %s: %w", name, err)
			}
			key := stripPDBName(name)
			s := Symbol{Address: rva}
			if key != name {
				s.LinkageName = name
			}
			if typ != 0 {
				ref, err := b.ref(typ, 0)
				if err != nil {
					return err
				}
				s.Type = &ref
			}
			if function {
				ref := TypeRef{Kind: "function"}
				s.Type = &ref
			}
			if old, ok := b.table.Symbols[key]; ok {
				if old.Address != rva {
					// Decoration and module-local C names can collide. Preserve
					// both address-qualified entries; disclose that the canonical
					// alias follows the last record, as the baseline does.
					b.table.Symbols[fmt.Sprintf("%s@0x%x", key, old.Address)] = old
					b.table.Symbols[fmt.Sprintf("%s@0x%x", key, rva)] = s
					b.collisions++
				} else if s.Type == nil {
					s.Type = old.Type
				}
			}
			b.table.Symbols[key] = s
		}
		return nil
	}
	global, err := msf.stream(binary.LittleEndian.Uint16(dbi[20:]))
	if err != nil {
		return err
	}
	if err = consume(global); err != nil {
		return err
	}
	// Module symbol streams provide typed functions and private data absent from
	// the public stream. Only their symbol substream is decoded, never line data.
	moduleSize := int(binary.LittleEndian.Uint32(dbi[24:]))
	modules := dbi[64 : 64+moduleSize]
	for off := 0; off < len(modules); {
		if len(modules)-off < 64 {
			return fmt.Errorf("truncated DBI module descriptor")
		}
		h := modules[off : off+64]
		id := binary.LittleEndian.Uint16(h[34:])
		symbolBytes := binary.LittleEndian.Uint32(h[36:])
		c := cvCursor{data: modules[off+64:]}
		c.name(false)
		c.name(false)
		if c.err != nil {
			return c.err
		}
		off = (off + 64 + c.pos + 3) &^ 3
		if off > len(modules) {
			return fmt.Errorf("truncated DBI module alignment")
		}
		if id == 0xffff || symbolBytes == 0 {
			continue
		}
		stream, err := msf.stream(id)
		if err != nil {
			return err
		}
		if symbolBytes < 4 || uint64(symbolBytes) > uint64(len(stream)) || binary.LittleEndian.Uint32(stream) != 4 {
			return fmt.Errorf("invalid module symbol substream")
		}
		if err = consume(stream[4:symbolBytes]); err != nil {
			return err
		}
	}
	return nil
}

func stripPDBName(name string) string {
	original := name
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "\x7f") {
		name = name[1:]
	}
	parts := strings.Split(name, "@")
	if len(parts) == 2 {
		if _, err := strconv.ParseUint(parts[1], 10, 64); err == nil && !strings.HasPrefix(parts[0], "?") {
			name = parts[0]
		} else {
			name = original
		}
	}
	return name
}

var errOMAPRemoved = errors.New("symbol eliminated by OMAP")

func pdbRVA(sections []pdbSection, omap []omapEntry, segment uint16, offset uint32) (uint64, error) {
	if segment == 0 || int(segment) > len(sections) {
		return 0, fmt.Errorf("PDB symbol segment %d is invalid", segment)
	}
	section := sections[segment-1]
	if offset > section.size {
		return 0, fmt.Errorf("PDB symbol exceeds PE section")
	}
	rva := uint64(section.rva) + uint64(offset)
	if rva > 0xffffffff {
		return 0, fmt.Errorf("PDB symbol RVA overflow")
	}
	if len(omap) > 0 {
		n := sort.Search(len(omap), func(i int) bool { return uint64(omap[i].from) > rva }) - 1
		if n < 0 {
			return 0, fmt.Errorf("PDB symbol precedes the OMAP mapping")
		}
		if omap[n].to == 0 {
			return rva, errOMAPRemoved
		}
		rva = uint64(omap[n].to) + (rva - uint64(omap[n].from))
		if rva > 0xffffffff {
			return 0, fmt.Errorf("OMAP destination overflows RVA")
		}
	}
	return rva, nil
}
