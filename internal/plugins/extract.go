package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func extractionOptions(p map[string]string) (bool, uint64, error) {
	dump := false
	maxsize := uint64(1 << 30)
	var err error
	if p["dump"] != "" {
		dump, err = strconv.ParseBool(p["dump"])
		if err != nil {
			return false, 0, err
		}
	}
	if p["maxsize"] != "" {
		maxsize, err = strconv.ParseUint(p["maxsize"], 0, 64)
		if err != nil {
			return false, 0, err
		}
	}
	return dump, maxsize, nil
}

func processMemory(ctx context.Context, e plugin.Environment, process, mm uint64, identity string) (memory.MemoryLayer, error) {
	var root uint64
	if e.OS == "windows" {
		field, err := e.Objects.Field("_EPROCESS", "Pcb.DirectoryTableBase")
		if err != nil {
			return nil, err
		}
		location, err := memory.Add(process, field.Offset)
		if err != nil {
			return nil, err
		}
		ref := field.Type
		if ref.Kind == "array" {
			if ref.Subtype == nil || ref.Count == 0 {
				return nil, fmt.Errorf("invalid process CR3 array")
			}
			ref = *ref.Subtype
		}
		root, err = e.Objects.Scalar(ctx, location, ref)
		if err != nil {
			return nil, err
		}
		if root == 0 {
			return nil, fmt.Errorf("process page-table root is not set")
		}
	} else {
		pgd, err := e.Objects.Uint(ctx, mm, "mm_struct", "pgd")
		if err != nil {
			return nil, err
		}
		if pgd == 0 {
			return nil, fmt.Errorf("process pgd is not set")
		}
		kernel, ok := e.Kernel.(*memory.Virtual)
		if !ok {
			return nil, fmt.Errorf("kernel translator is unavailable for process pgd")
		}
		translated, err := kernel.Translator.Translate(ctx, pgd)
		if err != nil {
			return nil, err
		}
		root = translated.Physical
	}
	translator, err := memory.NewTranslatorForOS(e.Physical, root, e.Architecture, e.OS, 1024)
	if err != nil {
		return nil, err
	}
	if translator.Root() == 0 {
		return nil, fmt.Errorf("process page-table root normalizes to zero")
	}
	return &memory.Virtual{Physical: e.Physical, Translator: translator, ID: "process:" + identity}, nil
}

func extractRegion(ctx context.Context, e plugin.Environment, layer memory.MemoryLayer, name string, start, size uint64) (evidence.Value, error) {
	return extractRanges(ctx, e, layer, name, start, []extractionRange{{start, size}})
}

type extractionRange struct{ start, size uint64 }

func extractRanges(ctx context.Context, e plugin.Environment, layer memory.MemoryLayer, name string, base uint64, ranges []extractionRange) (evidence.Value, error) {
	var size uint64
	for _, r := range ranges {
		if r.size == 0 || r.size-1 > ^uint64(0)-r.start || r.size > ^uint64(0)-size {
			err := fmt.Errorf("invalid extraction range")
			return evidence.Missing("extraction_unavailable", err), err
		}
		size += r.size
	}
	if e.Artifacts == nil || size == 0 {
		err := fmt.Errorf("extraction sink or region range unavailable")
		return evidence.Missing("extraction_unavailable", err), err
	}
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: name, Size: size, Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", base)})
	if err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	for _, r := range ranges {
		if err = writeRegion(ctx, layer, w, r.start, r.size); err != nil {
			break
		}
	}
	a, finishErr := w.Finish(ctx, err)
	return evidence.Value{Kind: "artifact", Data: a}, errors.Join(err, finishErr)
}

// Resolve each source page independently; padding logs retain actual virtual
// addresses even when noncontiguous spans are concatenated into one artifact.
func writeRegion(ctx context.Context, layer memory.MemoryLayer, w evidence.ArtifactWriter, start, size uint64) (err error) {
	buffer := make([]byte, 4096)
	for offset := uint64(0); offset < size; {
		if err = ctx.Err(); err != nil {
			break
		}
		address := start + offset
		n := min(uint64(len(buffer))-(address&4095), size-offset)
		got, readErr := layer.ReadAt(ctx, buffer[:n], address)
		if got < 0 || uint64(got) > n {
			err = fmt.Errorf("source returned invalid read length")
			break
		}
		if got > 0 {
			var written int
			if written, err = w.Write(buffer[:got]); err == nil && written != got {
				err = io.ErrShortWrite
			}
			if err != nil {
				break
			}
		}
		if err = ctx.Err(); err != nil {
			break
		}
		if uint64(got) < n {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			if err = w.PadZero(ctx, n-uint64(got), address+uint64(got), layer.Name(), readErr); err != nil {
				break
			}
		} else if readErr != nil {
			err = readErr
			break
		}
		offset += n
	}
	return err
}
