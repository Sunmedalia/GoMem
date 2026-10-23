package explore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
)

const findMaxHits = 10000

// find is an interactive view, not a plugin task or sealed evidence row.
// Explicit sections prevent a mistyped command from walking all address space.
func (s *Session) find(ctx context.Context, args []string, w io.Writer) error {
	if len(args) != 4 {
		return fmt.Errorf("find ADDRESS LENGTH \"LITERAL\"")
	}
	address, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return err
	}
	length, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return err
	}
	needle := []byte(args[3])
	if length == 0 || length > 1<<30 {
		return fmt.Errorf("find length must be 1..1073741824 bytes")
	}
	if len(needle) == 0 || len(needle) > 65536 {
		return fmt.Errorf("find literal must be 1..65536 UTF-8 bytes")
	}
	if _, err := memory.Add(address, length); err != nil {
		return err
	}
	v, ok := s.Layer.(*memory.Virtual)
	if !ok {
		return fmt.Errorf("find requires a selected Intel virtual space; use kernel or process")
	}
	tr, ok := v.Translator.(*memory.Intel)
	if !ok {
		return fmt.Errorf("find currently requires an Intel backing-map translator")
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	hits := 0
	var outputErr error
	options := memoryscan.BackingScanOptions{Mappings: memory.BackingMapOptions{MaxTables: 65536, MaxEntries: 4000000, Sections: []memory.Range{{Start: address, Length: length}}}, ChunkSize: 1 << 20, Overlap: uint64(len(needle) - 1), MaxChunks: 2048}
	stats, scanErr := memoryscan.VisitBackingChunks(ctx, tr, options, func(chunk memoryscan.BackingChunk) error {
		if err := s.Engine.ValidateSource(ctx); err != nil {
			return err
		}
		buffer, err := memoryscan.AcquireBacking(ctx, chunk)
		if err != nil {
			return err
		}
		if err := s.Engine.ValidateSource(ctx); err != nil {
			return err
		}
		for cursor := 0; cursor < len(buffer.Data); {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := bytes.Index(buffer.Data[cursor:], needle)
			if n < 0 {
				break
			}
			at := uint64(cursor + n)
			if buffer.Accepts(at, uint64(len(needle))) {
				if hits >= findMaxHits {
					return fmt.Errorf("find hit limit %d exhausted; narrow the requested interval", findMaxHits)
				}
				sources, err := buffer.Sources(at, uint64(len(needle)))
				if err != nil {
					return err
				}
				data := buffer.Data[at : at+uint64(len(needle))]
				sum := sha256.Sum256(data)
				row := struct {
					Kind        string                  `json:"kind"`
					ImageSHA256 string                  `json:"image_sha256"`
					Layer       string                  `json:"layer"`
					Address     string                  `json:"address"`
					Bytes       []byte                  `json:"bytes"`
					SHA256      string                  `json:"sha256"`
					Sources     []memory.BackingMapping `json:"sources"`
				}{"interactive_literal_hit", s.Engine.Hash, s.Layer.Name(), fmt.Sprintf("0x%016x", chunk.Start+at), data, hex.EncodeToString(sum[:]), sources}
				if err := encoder.Encode(row); err != nil {
					outputErr = err
					return err
				}
				hits++
			}
			cursor += n + 1
		}
		return s.Engine.ValidateSource(ctx)
	})
	if outputErr != nil {
		return outputErr
	}
	validationErr := s.Engine.ValidateSource(ctx)
	err = errors.Join(scanErr, validationErr)
	// Do not describe partial hits as a clean completed search. Summary is also
	// emitted on failure when the output remains writable; errors still return.
	summary := struct {
		Kind        string                      `json:"kind"`
		ImageSHA256 string                      `json:"image_sha256"`
		Layer       string                      `json:"layer"`
		Address     string                      `json:"address"`
		Length      uint64                      `json:"length"`
		Hits        int                         `json:"hits"`
		Complete    bool                        `json:"complete"`
		Stats       memoryscan.BackingScanStats `json:"stats"`
		Error       string                      `json:"error,omitempty"`
	}{Kind: "interactive_literal_summary", ImageSHA256: s.Engine.Hash, Layer: s.Layer.Name(), Address: fmt.Sprintf("0x%016x", address), Length: length, Hits: hits, Complete: err == nil, Stats: stats}
	if err != nil {
		summary.Error = err.Error()
	}
	return errors.Join(err, encoder.Encode(summary))
}
