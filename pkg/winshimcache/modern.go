package winshimcache

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// LoadedModule is the subset of PsLoadedModuleList needed by Shimcache.
type LoadedModule struct {
	Offset, Base, Size uint64
	Name               string
}

// DiscoveryEvidence records one candidate storage address and the result of
// the original pointer/handle validity path.
type DiscoveryEvidence struct {
	ModuleOffset, Storage, Target uint64
	Stage                         string
	Valid, HeadValid              bool
	Head                          uint64
	Error                         error
}

// ModernResult preserves accepted handles and aggregate scan coverage. Evidence
// contains null, rejected and failed candidates as well as accepted handles;
// null slots are aggregated to keep real .data sections from producing a row
// for every zero pointer.
type ModernResult struct {
	Heads          []uint64
	HandleTargets  []uint64
	StorageOffsets []uint64
	Evidence       []DiscoveryEvidence
	Scanned        uint64
	NullPointers   uint64
	NonCanonical   uint64
	Unmapped       uint64
	ReadFailures   uint64
}

// ModernScanner finds the two SHIM_CACHE_HANDLE pointers in a loaded module's
// .data section. It reads the section incrementally and only attempts a
// HandleReader validation at pointer-aligned slots whose storage bytes are
// available.
type ModernScanner struct {
	Layer memory.MemoryLayer
	// Probe performs side-effect-free candidate mapping checks. Scan falls back
	// to Layer when Probe is nil for standalone and synthetic callers.
	Probe       memory.MemoryLayer
	Reader      *HandleReader
	Module      LoadedModule
	Data, Page  ModuleSection
	MaxPointers uint64
	// MaxEvidence bounds non-null candidate evidence while leaving scan and
	// read counters complete. Zero selects the default of 4096.
	MaxEvidence uint64
}

func (s ModernScanner) Scan(ctx context.Context) (ModernResult, error) {
	if err := ctx.Err(); err != nil {
		return ModernResult{}, err
	}
	if s.Layer == nil || s.Reader == nil || s.Data.VirtualSize == 0 || s.Page.VirtualSize == 0 {
		return ModernResult{}, fmt.Errorf("modern Shimcache discovery requires layer, handle reader, data and PAGE sections")
	}
	probe := s.Probe
	if probe == nil {
		probe = s.Layer
	}
	width := s.Reader.width
	if width != 4 && width != 8 {
		return ModernResult{}, fmt.Errorf("invalid modern Shimcache pointer width")
	}
	if s.MaxPointers == 0 || s.MaxPointers > 1<<20 {
		return ModernResult{}, fmt.Errorf("max pointers must be 1..1048576")
	}
	maxEvidence := s.MaxEvidence
	if maxEvidence == 0 {
		maxEvidence = 4096
	}
	if maxEvidence > 1<<20 {
		return ModernResult{}, fmt.Errorf("max evidence must be 1..1048576")
	}
	if err := validateLoadedModule(s.Module); err != nil {
		return ModernResult{}, err
	}
	if err := validateModuleSection(s.Module, s.Data); err != nil {
		return ModernResult{}, err
	}
	if err := validateModuleSection(s.Module, s.Page); err != nil {
		return ModernResult{}, err
	}
	pageStart, pageEnd, err := sectionInclusiveRange(s.Page)
	if err != nil {
		return ModernResult{}, err
	}
	dataEnd, err := sectionExclusiveEnd(s.Data)
	if err != nil {
		return ModernResult{}, err
	}
	var result ModernResult
	appendEvidence := func(ev DiscoveryEvidence) error {
		if len(result.Evidence) >= int(maxEvidence) {
			return fmt.Errorf("Shimcache discovery evidence budget exceeded %d", maxEvidence)
		}
		result.Evidence = append(result.Evidence, ev)
		return nil
	}
	const chunkSize = 1 << 20
	buffer := make([]byte, chunkSize)
	for relative := uint64(0); relative < s.Data.VirtualSize; {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		address, err := memory.Add(s.Data.Address, relative)
		if err != nil {
			return result, err
		}
		requested := min(uint64(len(buffer)), dataEnd-address)
		requested -= requested % uint64(width)
		if requested == 0 {
			break
		}
		raw := buffer[:requested]
		n, readErr := s.Layer.ReadAt(ctx, raw, address)
		if n < 0 || uint64(n) > requested {
			return result, fmt.Errorf("invalid Shimcache .data read length %d", n)
		}
		consumed := uint64(n) - uint64(n)%uint64(width)
		for i := 0; i+width <= n; i += width {
			if result.Scanned >= s.MaxPointers {
				return result, fmt.Errorf("Shimcache .data pointer budget exceeded %d", s.MaxPointers)
			}
			result.Scanned++
			storage := address + uint64(i)
			rawTarget := littlePointer(raw[i:i+width], width)
			target := canonicalizePointer(rawTarget&s.Reader.mask, width)
			ev := DiscoveryEvidence{ModuleOffset: s.Module.Offset, Storage: storage, Target: target, Stage: "pointer"}
			// A null pointer cannot be a valid SHIM_CACHE_HANDLE. The original
			// pointer property short-circuits here.
			if target == 0 {
				result.NullPointers++
				continue
			}
			if width == 8 && s.Reader.mask == 0x0000ffffffffffff &&
				(rawTarget>>48 == 0 && rawTarget>>47 != 0 || rawTarget>>48 != 0 && rawTarget>>48 != 0xffff) {
				result.NonCanonical++
				continue
			}
			mapped, mappedErr := candidateMapped(ctx, probe, target)
			if mappedErr != nil {
				return result, mappedErr
			}
			if !mapped {
				result.Unmapped++
				continue
			}
			valid, validErr := s.Reader.Valid(ctx, target, pageStart, pageEnd)
			if validErr != nil {
				ev.Stage, ev.Error = "handle_invalid", validErr
				result.ReadFailures++
				if err := appendEvidence(ev); err != nil {
					return result, err
				}
				if ctx.Err() != nil {
					return result, ctx.Err()
				}
				continue
			}
			if !valid {
				ev.Stage = "handle_invalid"
				if err := appendEvidence(ev); err != nil {
					return result, err
				}
				continue
			}
			ev.Valid, ev.Stage = true, "handle_valid"
			head, headValid, headErr := s.Reader.Head(ctx, target)
			ev.Head, ev.HeadValid = head, headValid
			if headErr != nil {
				ev.Stage, ev.Error = "head_unreadable", headErr
				result.ReadFailures++
				if err := appendEvidence(ev); err != nil {
					return result, err
				}
				if ctx.Err() != nil {
					return result, ctx.Err()
				}
				continue
			}
			if !headValid {
				ev.Stage = "head_invalid"
				if err := appendEvidence(ev); err != nil {
					return result, err
				}
				continue
			}
			ev.Stage = "accepted"
			if err := appendEvidence(ev); err != nil {
				return result, err
			}
			if readErr != nil {
				result.ReadFailures++
			}
			result.HandleTargets = append(result.HandleTargets, target)
			result.StorageOffsets = append(result.StorageOffsets, storage)
			result.Heads = append(result.Heads, head)
			if len(result.Heads) == 2 {
				return result, readErr
			}
		}
		if readErr != nil {
			result.ReadFailures++
			// A hole makes the current chunk incomplete. Resume at the next
			// page after preserving all complete pointer slots actually read.
			next := address + consumed
			next = (next + 0xfff) &^ 0xfff
			if next <= address {
				return result, readErr
			}
			relative = next - s.Data.Address
			if relative >= s.Data.VirtualSize {
				return result, readErr
			}
			if relative%uint64(width) != 0 {
				relative += uint64(width) - relative%uint64(width)
			}
			continue
		}
		if uint64(n) != requested {
			result.ReadFailures++
			return result, fmt.Errorf("short Shimcache .data read at %#x", address)
		}
		relative += requested
	}
	return result, nil
}

func littlePointer(raw []byte, width int) uint64 {
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(raw))
	}
	return binary.LittleEndian.Uint64(raw)
}

// canonicalizePointer reconstructs the canonical native address represented
// by a masked pointer. The pinned layer strips the top sixteen x64 bits, while
// native Go page-table reads need the sign-extended high-half form.
func canonicalizePointer(value uint64, width int) uint64 {
	if width == 4 {
		return value & 0xffffffff
	}
	value &= 0x0000ffffffffffff
	if value&(uint64(1)<<47) != 0 {
		return value | 0xffff000000000000
	}
	return value
}

func candidateMapped(ctx context.Context, layer memory.MemoryLayer, address uint64) (bool, error) {
	if virtual, ok := layer.(*memory.Virtual); ok {
		if translator, ok := virtual.Translator.(*memory.Intel); ok {
			translation, err := translator.Translate(ctx, address)
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if err != nil || translation.Available == 0 {
				return false, nil
			}
			if _, err := memory.Read(ctx, virtual.Physical, translation.Physical, 1); err != nil {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				return false, nil
			}
			return true, nil
		}
	}
	raw, err := memory.Read(ctx, layer, address, 1)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return false, nil
	}
	return len(raw) == 1, nil
}

func sectionInclusiveRange(section ModuleSection) (uint64, uint64, error) {
	if section.VirtualSize == 0 {
		return 0, 0, fmt.Errorf("empty Shimcache module section")
	}
	end, err := memory.Add(section.Address, section.VirtualSize-1)
	if err != nil {
		return 0, 0, err
	}
	return section.Address, end, nil
}

func sectionExclusiveEnd(section ModuleSection) (uint64, error) {
	if section.VirtualSize == 0 {
		return 0, fmt.Errorf("empty Shimcache module section")
	}
	return memory.Add(section.Address, section.VirtualSize)
}

func validateLoadedModule(module LoadedModule) error {
	if module.Offset == 0 || module.Base == 0 || module.Size == 0 || module.Size > 1<<32 {
		return fmt.Errorf("invalid Shimcache loaded module extent")
	}
	return nil
}

func validateModuleSection(module LoadedModule, section ModuleSection) error {
	if section.ModuleOffset != module.Offset || section.ModuleBase != module.Base {
		return fmt.Errorf("Shimcache section %s belongs to a different module", section.Name)
	}
	if section.Address < module.Base {
		return fmt.Errorf("Shimcache section %s starts before its module", section.Name)
	}
	moduleEnd, err := memory.Add(module.Base, module.Size)
	if err != nil {
		return err
	}
	sectionEnd, err := sectionExclusiveEnd(section)
	if err != nil {
		return err
	}
	if sectionEnd > moduleEnd {
		return fmt.Errorf("Shimcache section %s extends beyond module image", section.Name)
	}
	return nil
}

// ReadModuleSection locates a case-insensitive section name in a mapped PE. The scan
// bounds and names come from headers, not from module size or symbol guesses.
func ReadModuleSection(ctx context.Context, layer memory.MemoryLayer, module LoadedModule, name string) (ModuleSection, error) {
	if layer == nil || module.Base == 0 || len(name) == 0 || len(name) > 8 {
		return ModuleSection{}, fmt.Errorf("invalid mapped PE section request")
	}
	dos, err := memory.Read(ctx, layer, module.Base, 64)
	if err != nil {
		return ModuleSection{}, fmt.Errorf("module %s DOS header: %w", module.Name, err)
	}
	if !bytes.Equal(dos[:2], []byte("MZ")) {
		return ModuleSection{}, fmt.Errorf("module %s has no MZ header", module.Name)
	}
	peOffset := uint64(binary.LittleEndian.Uint32(dos[0x3c:]))
	nt, err := memory.Add(module.Base, peOffset)
	if err != nil {
		return ModuleSection{}, err
	}
	header, err := memory.Read(ctx, layer, nt, 160)
	if err != nil {
		return ModuleSection{}, fmt.Errorf("module %s PE header: %w", module.Name, err)
	}
	if !bytes.Equal(header[:4], []byte("PE\x00\x00")) {
		return ModuleSection{}, fmt.Errorf("module %s has no PE signature", module.Name)
	}
	optionalMagic := binary.LittleEndian.Uint16(header[24+0:])
	if optionalMagic != 0x10b && optionalMagic != 0x20b {
		return ModuleSection{}, fmt.Errorf("module %s has unsupported PE optional header", module.Name)
	}
	sizeOfImage := uint64(binary.LittleEndian.Uint32(header[24+56:]))
	if sizeOfImage == 0 || module.Size != 0 && sizeOfImage > module.Size {
		return ModuleSection{}, fmt.Errorf("module %s has invalid PE image size %#x (module %#x)", module.Name, sizeOfImage, module.Size)
	}
	count := int(binary.LittleEndian.Uint16(header[6:]))
	optional := int(binary.LittleEndian.Uint16(header[20:]))
	if count < 1 || count > 96 || optional < 64 || optional > 4096 || optional%8 != 0 {
		return ModuleSection{}, fmt.Errorf("module %s has invalid PE section count or optional header", module.Name)
	}
	tableAt, err := memory.Add(nt, uint64(24+optional))
	if err != nil {
		return ModuleSection{}, err
	}
	table, err := memory.Read(ctx, layer, tableAt, count*40)
	if err != nil {
		return ModuleSection{}, fmt.Errorf("module %s section table: %w", module.Name, err)
	}
	for i := 0; i < count; i++ {
		entry := table[i*40 : (i+1)*40]
		rawName := entry[:8]
		if j := bytes.IndexByte(rawName, 0); j >= 0 {
			rawName = rawName[:j]
		}
		if !strings.EqualFold(string(rawName), name) {
			continue
		}
		virtualSize := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		rva := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		rawSize := uint64(binary.LittleEndian.Uint32(entry[16:20]))
		address, err := memory.Add(module.Base, rva)
		if err != nil {
			return ModuleSection{}, err
		}
		if virtualSize == 0 {
			return ModuleSection{}, fmt.Errorf("module %s section %s is empty", module.Name, name)
		}
		section := ModuleSection{ModuleOffset: module.Offset, ModuleBase: module.Base, Address: address, VirtualSize: virtualSize, Name: name}
		if err := validateModuleSection(module, section); err != nil {
			return ModuleSection{}, err
		}
		if rva >= sizeOfImage || virtualSize > sizeOfImage-rva || rawSize > 1<<32 {
			return ModuleSection{}, fmt.Errorf("module %s section %s has invalid image bounds", module.Name, name)
		}
		return section, nil
	}
	return ModuleSection{}, fmt.Errorf("module %s has no %s section", module.Name, name)
}
