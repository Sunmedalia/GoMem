package memory

import (
	"context"
	"encoding/binary"
	"fmt"
)

// ARM64 translates little-endian stage-1 tables with 4 KiB granules,
// 48-bit virtual addresses and up to 48-bit physical addresses (no LPA2).
// Kernel and user roots are supplied separately by the caller.
type ARM64 struct{ cache *Intel }

func NewARM64(p MemoryLayer, root uint64, capacity int) (*ARM64, error) {
	if root&4095 != 0 || root>>48 != 0 {
		return nil, fmt.Errorf("invalid ARM64 page-table root %#x", root)
	}
	c, err := NewIntel(p, root, "x64", capacity)
	if err != nil {
		return nil, err
	}
	return &ARM64{cache: c}, nil
}
func (a *ARM64) Root() uint64 { return a.cache.Root() }
func (a *ARM64) Translate(ctx context.Context, address uint64) (Translation, error) {
	upper := address >> 48
	if upper != 0 && upper != 0xffff {
		return Translation{}, fmt.Errorf("noncanonical ARM64 address %#x", address)
	}
	table := a.Root()
	writable, executable := true, true
	kernel := upper == 0xffff
	for level, shift := range []uint{39, 30, 21, 12} {
		at := table + ((address>>shift)&511)*8
		entry, err := a.cache.entry(ctx, at, 8)
		if err != nil {
			// A sparse acquisition may omit an unrelated byte at the end of
			// the table page. Require the descriptor itself to be resident.
			b, readErr := Read(ctx, a.cache.physical, at, 8)
			if readErr != nil {
				return Translation{}, readErr
			}
			entry = binary.LittleEndian.Uint64(b)
		}
		if entry&1 == 0 {
			return Translation{}, fmt.Errorf("%w: invalid ARM64 descriptor %#x at %#x", ErrUnmapped, entry, at)
		}
		if entry&(uint64(3)<<48) != 0 {
			return Translation{}, fmt.Errorf("unsupported ARM64 extended physical address descriptor at %#x", at)
		}
		last := shift == 12
		block := entry&2 == 0
		if (level == 0 && block) || (last && block) {
			return Translation{}, fmt.Errorf("reserved ARM64 descriptor at %#x", at)
		}
		if last || block {
			size := uint64(1) << shift
			frame := entry & 0x0000fffffffff000
			if frame&(size-1) != 0 {
				return Translation{}, fmt.Errorf("misaligned ARM64 block at %#x", at)
			}
			writable = writable && entry&(1<<7) == 0
			xn := uint(54)
			if kernel {
				xn = 53
			}
			executable = executable && entry&(uint64(1)<<xn) == 0
			offset := address & (size - 1)
			return Translation{Physical: frame + offset, Available: size - offset, PageSize: size, EntryAddress: at, Entry: entry, EntryWidth: 8, Writable: writable, Executable: executable, PermissionsKnown: true}, nil
		}
		writable = writable && entry&(uint64(1)<<62) == 0
		xn := uint(60)
		if kernel {
			xn = 59
		}
		executable = executable && entry&(uint64(1)<<xn) == 0
		table = entry & 0x0000fffffffff000
	}
	return Translation{}, fmt.Errorf("incomplete ARM64 page walk")
}

type RootedTranslator interface {
	Translator
	Root() uint64
}

// NewTranslatorForOS selects the hardware walker without applying Intel
// software-entry rules to ARM64 descriptors.
func NewTranslatorForOS(p MemoryLayer, root uint64, arch, os string, capacity int) (RootedTranslator, error) {
	if arch == "arm64" {
		if os != "linux" {
			return nil, fmt.Errorf("ARM64 translation currently requires Linux")
		}
		return NewARM64(p, root, capacity)
	}
	return NewIntelForOS(p, root, arch, os, capacity)
}
