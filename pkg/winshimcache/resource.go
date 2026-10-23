package winshimcache

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ResourceReader uses the image's kernel types, not Shimcache's external type
// placeholders. All offsets and the semaphore extent come from those symbols.
type ResourceReader struct {
	reader        object.Reader
	semaphoreSize uint64
}

func NewResourceReader(layer memory.MemoryLayer, kernel *symbols.ISF) (*ResourceReader, error) {
	if layer == nil || kernel == nil {
		return nil, fmt.Errorf("Shimcache resource requires layer and kernel symbols")
	}
	if width := kernel.PointerSize(); width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported resource pointer width %d", width)
	}
	if p := kernel.Bases["pointer"]; p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("invalid resource pointer representation")
	}
	r := &ResourceReader{reader: object.Reader{Layer: layer, Symbols: kernel}}
	for _, name := range []string{"_ERESOURCE", "_LIST_ENTRY", "_KSEMAPHORE"} {
		t, err := kernel.Type(name)
		if err != nil || t.Kind != "struct" || t.Size == 0 || t.Size > 1<<20 {
			return nil, fmt.Errorf("invalid resource type %s", name)
		}
		if name == "_KSEMAPHORE" {
			r.semaphoreSize = t.Size
		}
	}
	for _, spec := range [][2]string{{"_ERESOURCE", "SystemResourcesList"}, {"_ERESOURCE", "SharedWaiters"}, {"_ERESOURCE", "NumberOfSharedWaiters"}, {"_LIST_ENTRY", "Flink"}, {"_LIST_ENTRY", "Blink"}} {
		f, err := r.reader.Field(spec[0], spec[1])
		if err != nil {
			return nil, err
		}
		switch spec[1] {
		case "SystemResourcesList":
			if f.Type.Kind != "struct" || f.Type.Name != "_LIST_ENTRY" {
				return nil, fmt.Errorf("invalid resource list type")
			}
		case "NumberOfSharedWaiters":
			if f.Type.Kind != "base" {
				return nil, fmt.Errorf("invalid resource waiter count")
			}
			base, ok := kernel.Bases[f.Type.Name]
			if !ok || base.Kind != "int" || base.Endian != "little" || base.Size < 1 || base.Size > 8 {
				return nil, fmt.Errorf("invalid resource waiter scalar")
			}
		default:
			if f.Type.Kind != "pointer" || f.Type.Subtype == nil || f.Type.Base != "" && f.Type.Base != "pointer" {
				return nil, fmt.Errorf("invalid resource pointer %s", spec[1])
			}
			sub := f.Type.Subtype
			if spec[1] == "SharedWaiters" {
				// Modern kernels use void*: the original only inspects the
				// pointer value and storage, never dereferences its target.
				if !(sub.Kind == "struct" && sub.Name == "_KSEMAPHORE" || sub.Kind == "base" && sub.Name == "void") {
					return nil, fmt.Errorf("invalid resource waiter pointer")
				}
			} else if sub.Kind != "struct" || sub.Name != "_LIST_ENTRY" {
				return nil, fmt.Errorf("invalid resource list pointer %s", spec[1])
			}
		}
	}
	return r, nil
}

// Valid mirrors the pinned ERESOURCE.is_valid predicate. Nonzero SharedWaiters
// checks a semaphore-sized span at the pointer's STORAGE address. Both list
// backlinks compare with the resource base, even for a nonzero embedded offset.
// Mapping checks use bounded reads so unavailable bytes remain explicit errors.
func (r *ResourceReader) Valid(ctx context.Context, at uint64) (bool, error) {
	return r.validMasked(ctx, at, ^uint64(0))
}

// Handle pointers use the native layer's mask, as do all pointers constructed
// while validating their resource. The standalone reader keeps full-width
// native addresses; its callers need not normalize canonical virtual addresses.
func (r *ResourceReader) validMasked(ctx context.Context, at, mask uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if r == nil || r.reader.Layer == nil || r.reader.Symbols == nil {
		return false, fmt.Errorf("missing resource reader")
	}
	if _, err := memory.Read(ctx, r.reader.Layer, at, 1); err != nil {
		return false, err
	}
	waiters, err := r.reader.Uint(ctx, at, "_ERESOURCE", "SharedWaiters")
	waiters &= mask
	if err != nil {
		return false, err
	}
	if waiters != 0 {
		field, err := r.reader.Field("_ERESOURCE", "SharedWaiters")
		if err != nil {
			return false, err
		}
		storage, err := memory.Add(at, field.Offset)
		if err != nil {
			return false, err
		}
		if _, err := memory.Read(ctx, r.reader.Layer, storage, int(r.semaphoreSize)); err != nil {
			return false, err
		}
	}
	flink, err := r.reader.Uint(ctx, at, "_ERESOURCE", "SystemResourcesList.Flink")
	flink &= mask
	if err != nil {
		return false, err
	}
	blink, err := r.reader.Uint(ctx, at, "_ERESOURCE", "SystemResourcesList.Blink")
	blink &= mask
	if err != nil {
		return false, err
	}
	if flink == blink {
		return false, nil
	}
	back, err := r.reader.Uint(ctx, flink, "_LIST_ENTRY", "Blink")
	if err != nil || back&mask != at {
		return false, err
	}
	forward, err := r.reader.Uint(ctx, blink, "_LIST_ENTRY", "Flink")
	if err != nil || forward&mask != at {
		return false, err
	}
	count, err := r.reader.Uint(ctx, at, "_ERESOURCE", "NumberOfSharedWaiters")
	return err == nil && count == 0, err
}
