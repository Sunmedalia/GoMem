package memory

import (
	"context"
	"errors"
	"fmt"
)

// SwappedPageError identifies a Windows software entry, never a RAM address.
// Offset is the base in the numbered pagefile; Virtual retains the request.
type SwappedPageError struct {
	Virtual, EntryAddress, Entry, Offset, PageSize uint64
	EntryWidth                                     uint8
	Number                                         uint8
}

func (e *SwappedPageError) Error() string {
	return fmt.Sprintf("%v: virtual %#x is in pagefile %d at %#x (entry %#x at %#x)", ErrUnmapped, e.Virtual, e.Number, e.Offset, e.Entry, e.EntryAddress)
}
func (e *SwappedPageError) Unwrap() error { return ErrUnmapped }

func (i *Intel) swapEntry(virtual, at, entry uint64, shift uint, width int) (*SwappedPageError, error) {
	bitOffset := uint(32)
	if i.mode == "x86" {
		bitOffset = 12
	}
	if !i.windows || entry&(1|1024|2048) != 0 || entry&128 == 0 || entry>>bitOffset == 0 {
		return nil, nil
	}
	if entry>>bitOffset > ^uint64(0)>>shift {
		return nil, fmt.Errorf("%w: pagefile offset overflows", ErrUnmapped)
	}
	return &SwappedPageError{Virtual: virtual, EntryAddress: at, Entry: entry, EntryWidth: uint8(width), Number: uint8((entry >> 1) & 15), Offset: (entry >> bitOffset) << shift, PageSize: uint64(1) << shift}, nil
}

// BackingTranslation explicitly separates RAM addresses from external offsets.
// Physical is meaningful only when Pagefile is nil. Layer and Offset identify
// the bytes to read in either case; no synthetic RAM address is invented.
// For a pagefile, PageSize denotes the software block span, not a hardware leaf.
type BackingTranslation struct {
	Translation
	Layer    MemoryLayer
	Offset   uint64
	Pagefile *uint8
}

type BackingTranslator interface {
	Resolve(context.Context, uint64) (BackingTranslation, error)
}

type pagefilePhysical struct {
	MemoryLayer
	files map[uint8]MemoryLayer
}

// WithPagefiles attaches immutable numbered backing layers to physical memory.
// Reads and physical ranges continue to refer only to the original RAM image.
func WithPagefiles(physical MemoryLayer, files map[uint8]MemoryLayer) (MemoryLayer, error) {
	if physical == nil {
		return nil, fmt.Errorf("pagefiles require physical memory")
	}
	copyFiles := make(map[uint8]MemoryLayer, len(files))
	if attached, ok := physical.(*pagefilePhysical); ok {
		if len(files) == 0 {
			return physical, nil
		}
		for number, layer := range attached.files {
			copyFiles[number] = layer
		}
		physical = attached.MemoryLayer
	}
	for number, layer := range files {
		if number > 15 || layer == nil {
			return nil, fmt.Errorf("pagefile number must be 0..15 with a backing layer")
		}
		if _, exists := copyFiles[number]; exists {
			return nil, fmt.Errorf("pagefile %d is already attached", number)
		}
		copyFiles[number] = layer
	}
	if len(copyFiles) == 0 {
		return physical, nil
	}
	return &pagefilePhysical{MemoryLayer: physical, files: copyFiles}, nil
}

func (i *Intel) Resolve(ctx context.Context, address uint64) (BackingTranslation, error) {
	t, err := i.Translate(ctx, address)
	if err == nil {
		return BackingTranslation{Translation: t, Layer: i.physical, Offset: t.Physical}, nil
	}
	var swapped *SwappedPageError
	if !errors.As(err, &swapped) {
		return BackingTranslation{}, err
	}
	layer := i.pagefiles[swapped.Number]
	if layer == nil {
		return BackingTranslation{}, err
	}
	displacement := address & (swapped.PageSize - 1)
	offset, err := Add(swapped.Offset, displacement)
	if err != nil {
		return BackingTranslation{}, err
	}
	number := swapped.Number
	return BackingTranslation{Translation: Translation{PageSize: swapped.PageSize, EntryAddress: swapped.EntryAddress, Entry: swapped.Entry, EntryWidth: swapped.EntryWidth, Available: swapped.PageSize - displacement}, Layer: layer, Offset: offset, Pagefile: &number}, nil
}

// Resolve exposes byte provenance for the currently selected virtual space.
func (v *Virtual) Resolve(ctx context.Context, address uint64) (BackingTranslation, error) {
	if resolver, ok := v.Translator.(BackingTranslator); ok {
		return resolver.Resolve(ctx, address)
	}
	t, err := v.Translator.Translate(ctx, address)
	if err != nil {
		return BackingTranslation{}, err
	}
	return BackingTranslation{Translation: t, Layer: v.Physical, Offset: t.Physical}, nil
}
