package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// scanModulePDB retains the first RSDS for each candidate in candidate order.
// A bounded carry handles records spanning reads without rescanning the image.
// ReadAt goes through the resolver's evidence observer and shared byte budget.
func scanModulePDB(ctx context.Context, module pesymbols.Module) ([]symbols.PDBIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if module.Layer == nil || len(module.PDBNames) > 16 || module.Size == 0 || module.Size > pe.MaxImageSize || module.Size-1 > ^uint64(0)-module.Base {
		return nil, fmt.Errorf("invalid module PDB scan bounds")
	}
	names := make([][]byte, len(module.PDBNames))
	found := make([]*symbols.PDBIdentity, len(names))
	maxRecord := 25
	for i, name := range module.PDBNames {
		if name == "" || len(name) > 256 || !utf8.ValidString(name) {
			return nil, fmt.Errorf("invalid module PDB candidate")
		}
		for _, r := range name {
			if r > 255 || r == 0 || r == '/' || r == '\\' {
				return nil, fmt.Errorf("module PDB candidate is not a Latin-1 basename")
			}
			names[i] = append(names[i], byte(r))
		}
		maxRecord = max(maxRecord, 25+len(names[i]))
	}
	if len(names) == 0 {
		return nil, nil
	}
	var carry []byte
	var failures []error
	totalFailures := 0
	for offset := uint64(0); offset < module.Size; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(uint64(4096)-(module.Base+offset)%4096, module.Size-offset)
		chunk, err := memory.Read(ctx, module.Layer, module.Base+offset, int(n))
		if err != nil {
			cause := fmt.Errorf("scan module RSDS at %#x: %w", module.Base+offset, err)
			if !errors.Is(err, memory.ErrUnmapped) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, cause
			}
			// A missing page cannot bridge two otherwise readable fragments.
			// Retain bounded causes and let the observer retain every raw fault.
			totalFailures++
			if len(failures) < 64 {
				failures = append(failures, cause)
			}
			carry = nil
			offset += n
			continue
		}
		data := append(carry, chunk...)
		for at := 0; at+25 <= len(data); {
			next := bytes.Index(data[at:], []byte("RSDS"))
			if next < 0 {
				break
			}
			at += next
			for i, name := range names {
				end := at + 24 + len(name)
				if found[i] != nil || end >= len(data) || data[end] != 0 || !bytes.Equal(data[at+24:end], name) {
					continue
				}
				if !utf8.Valid(name) {
					return nil, fmt.Errorf("matched Latin-1 PDB name is not UTF-8")
				}
				g := data[at+4 : at+20]
				id := symbols.PDBIdentity{Database: string(name), GUID: fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:]), Age: uint64(binary.LittleEndian.Uint32(data[at+20:]))}
				found[i] = &id
			}
			at++
		}
		keep := min(len(data), maxRecord-1)
		carry = append([]byte(nil), data[len(data)-keep:]...)
		offset += n
	}
	var result []symbols.PDBIdentity
	for _, identity := range found {
		if identity != nil {
			result = append(result, *identity)
		}
	}
	if totalFailures > len(failures) {
		failures = append(failures, fmt.Errorf("%d additional module scan read failures retained in evidence", totalFailures-len(failures)))
	}
	return result, errors.Join(append(failures, ctx.Err())...)
}
