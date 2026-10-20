package memory

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// CrashHeader contains acquisition hints, not verified address-space identity.
// Consumers must verify any selected page table and kernel against memory.
type CrashHeader struct {
	Bits               int
	Machine            uint32
	Architecture       string
	DirectoryTableBase uint64
	LoadedModuleList   uint64
	ActiveProcessHead  uint64
	DebuggerData       uint64
	Signature          string
	MajorVersion       uint32
	MinorVersion       uint32
	PfnDataBase        uint64
	NumberProcessors   uint32
	DumpType           uint32
	SystemTime         uint64
	SystemUpTime       uint64
	Comment            string
	HasBitmap          bool
	BitmapHeaderSize   uint64
	BitmapPages        uint64
	BitmapSize         uint64
}

func (h CrashHeader) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"bits": h.Bits, "machine": fmt.Sprintf("0x%x", h.Machine), "architecture": h.Architecture,
		"directory_table_base": fmt.Sprintf("0x%x", h.DirectoryTableBase), "loaded_module_list": fmt.Sprintf("0x%x", h.LoadedModuleList),
		"active_process_head": fmt.Sprintf("0x%x", h.ActiveProcessHead), "debugger_data": fmt.Sprintf("0x%x", h.DebuggerData)})
}

type crashMapped struct {
	*Mapped
	header CrashHeader
}

func (m *crashMapped) CrashHeader() CrashHeader { return m.header }

// Windows complete and bitmap dumps use physical page runs. Other dump types
// have different addressing semantics and are rejected before a layer is built.
func crash(ctx context.Context, s MemorySource) (MemoryLayer, string, error) {
	first := make([]byte, 8)
	if _, e := s.ReadAt(ctx, first, 0); e != nil {
		return nil, "crash", e
	}
	size, descriptor, stride, dumpAt := 4096, 100, 8, 3976
	switch string(first) {
	case "PAGEDUMP":
	case "PAGEDU64":
		size, descriptor, stride, dumpAt = 8192, 136, 16, 3992
	default:
		return nil, "crash", fmt.Errorf("invalid Windows dump signature")
	}
	h := make([]byte, size)
	if _, e := s.ReadAt(ctx, h, 0); e != nil {
		return nil, "crash", e
	}
	header := CrashHeader{Bits: 32, Machine: binary.LittleEndian.Uint32(h[32:]), DirectoryTableBase: uint64(binary.LittleEndian.Uint32(h[16:])), LoadedModuleList: uint64(binary.LittleEndian.Uint32(h[24:])), ActiveProcessHead: uint64(binary.LittleEndian.Uint32(h[28:])), DebuggerData: uint64(binary.LittleEndian.Uint32(h[96:]))}
	if stride == 16 {
		header = CrashHeader{Bits: 64, Machine: binary.LittleEndian.Uint32(h[48:]), DirectoryTableBase: binary.LittleEndian.Uint64(h[16:]), LoadedModuleList: binary.LittleEndian.Uint64(h[32:]), ActiveProcessHead: binary.LittleEndian.Uint64(h[40:]), DebuggerData: binary.LittleEndian.Uint64(h[128:])}
	}
	if header.Bits == 64 && header.Machine == 0x8664 {
		header.Architecture = "x64"
	}
	if header.Bits == 32 && header.Machine == 0x14c {
		header.Architecture = "x86"
		if h[92] != 0 {
			header.Architecture = "pae"
		}
	}
	kind := binary.LittleEndian.Uint32(h[dumpAt:])
	header.DumpType = kind
	header.Signature = crashText(h[:4])
	header.MajorVersion = binary.LittleEndian.Uint32(h[8:])
	header.MinorVersion = binary.LittleEndian.Uint32(h[12:])
	if stride == 16 {
		header.PfnDataBase = binary.LittleEndian.Uint64(h[24:])
		header.NumberProcessors = binary.LittleEndian.Uint32(h[52:])
		header.SystemTime = binary.LittleEndian.Uint64(h[4008:])
		header.SystemUpTime = binary.LittleEndian.Uint64(h[4144:])
		header.Comment = crashText(h[4016:4144])
	} else {
		header.PfnDataBase = uint64(binary.LittleEndian.Uint32(h[20:]))
		header.NumberProcessors = binary.LittleEndian.Uint32(h[36:])
		header.SystemTime = binary.LittleEndian.Uint64(h[4032:])
		header.SystemUpTime = binary.LittleEndian.Uint64(h[4024:])
		header.Comment = crashText(h[2080:2208])
	}
	var runs []Range
	switch kind {
	case 1:
		count := int(binary.LittleEndian.Uint32(h[descriptor:]))
		start := descriptor + 8
		if stride == 16 {
			start = descriptor + 16
		}
		if count == 0 || count > (size-start)/stride {
			return nil, "crash", fmt.Errorf("invalid Windows physical run count")
		}
		off := uint64(size)
		for j := 0; j < count; j++ {
			b := h[start+j*stride:]
			base, n := uint64(binary.LittleEndian.Uint32(b)), uint64(binary.LittleEndian.Uint32(b[4:]))
			if stride == 16 {
				base, n = binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:])
			}
			if base > ^uint64(0)/4096 || n > ^uint64(0)/4096 {
				return nil, "crash", fmt.Errorf("Windows physical run overflow")
			}
			runs = append(runs, Range{Start: base * 4096, Length: n * 4096, FileOffset: off})
			var e error
			off, e = Add(off, n*4096)
			if e != nil {
				return nil, "crash", e
			}
		}
	case 5:
		summary := make([]byte, 56)
		if _, e := s.ReadAt(ctx, summary, uint64(size)); e != nil {
			return nil, "crash", e
		}
		if string(summary[:8]) != "SDMPDUMP" && string(summary[:8]) != "FDMPDUMP" {
			return nil, "crash", fmt.Errorf("invalid Windows bitmap summary signature")
		}
		off := binary.LittleEndian.Uint64(summary[32:])
		pages := binary.LittleEndian.Uint64(summary[40:])
		bits := binary.LittleEndian.Uint64(summary[48:])
		header.HasBitmap = true
		header.BitmapHeaderSize = off
		header.BitmapPages = pages
		header.BitmapSize = bits
		bitmapBytes := (bits + 7) / 8
		if bits == 0 || bits > 1<<30 || off < uint64(size)+56+bitmapBytes || off > s.Size() {
			return nil, "crash", fmt.Errorf("invalid Windows bitmap bounds")
		}
		buffer := make([]byte, 4096)
		var mapped uint64
		var current *Range
		for pos := uint64(0); pos < bitmapBytes; {
			n := int(min(uint64(len(buffer)), bitmapBytes-pos))
			if _, e := s.ReadAt(ctx, buffer[:n], uint64(size)+56+pos); e != nil {
				return nil, "crash", e
			}
			for j, v := range buffer[:n] {
				for b := uint(0); b < 8; b++ {
					page := (pos+uint64(j))*8 + uint64(b)
					if page >= bits {
						break
					}
					if v&(1<<b) == 0 {
						current = nil
						continue
					}
					if current == nil {
						if len(runs) >= 1000000 {
							return nil, "crash", fmt.Errorf("too many bitmap segments")
						}
						runs = append(runs, Range{Start: page * 4096, Length: 0, FileOffset: off})
						current = &runs[len(runs)-1]
					}
					current.Length += 4096
					var e error
					off, e = Add(off, 4096)
					if e != nil || off > s.Size() {
						return nil, "crash", fmt.Errorf("truncated Windows bitmap data")
					}
					mapped++
				}
			}
			pos += uint64(n)
		}
		if mapped != pages {
			return nil, "crash", fmt.Errorf("Windows bitmap page count mismatch")
		}
	default:
		return nil, "crash", fmt.Errorf("%w: Windows dump type %#x", ErrUnsupported, kind)
	}
	m, e := NewMapped(s, "physical:crash", runs)
	if e != nil {
		return nil, "crash", e
	}
	return &crashMapped{Mapped: m, header: header}, "crash", nil
}

func crashText(raw []byte) string {
	// Match utility.bytes_to_decoded_string: UTF-8 with errors replaced, then
	// cut at the first NUL or U+FFFD. The terminator itself is not kept, so an
	// invalid sequence ends the field instead of remaining as a replacement.
	out := make([]byte, 0, len(raw))
	for len(raw) > 0 {
		if raw[0] == 0 {
			break
		}
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError {
			break
		}
		out = append(out, raw[:size]...)
		raw = raw[size:]
	}
	return string(out)
}
