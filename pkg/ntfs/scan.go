package ntfs

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Scan uses the locked YARA scanner's 16 MiB chunks and 4 KiB forward overlap.
// Matches in the overlap intentionally repeat in the following chunk. Adjacent
// physical spans join; holes never supply synthetic signature bytes. The fixed
// signatures require no runtime YARA dependency.
func Scan(ctx context.Context, layer memory.MemoryLayer, emit func(uint64) error) error {
	if layer == nil || emit == nil {
		return fmt.Errorf("MFT scan needs a layer and emitter")
	}
	ranges := append([]memory.Range(nil), layer.Ranges()...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	var spans []memory.Range
	for _, r := range ranges {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 {
			return fmt.Errorf("invalid MFT scan range")
		}
		if len(spans) > 0 {
			p := &spans[len(spans)-1]
			last := p.Start + p.Length
			if r.Start < last {
				return fmt.Errorf("overlapping MFT scan ranges")
			}
			if r.Start == last {
				p.Length = end - p.Start
				continue
			}
		}
		spans = append(spans, memory.Range{Start: r.Start, Length: r.Length})
	}
	if len(spans) == 0 {
		return fmt.Errorf("MFT scan needs enumerated physical ranges")
	}
	const chunk = 16 << 20
	const overlap = 4096
	for _, span := range spans {
		end := span.Start + span.Length
		for at := span.Start; at < end; {
			if err := ctx.Err(); err != nil {
				return err
			}
			main := min(uint64(chunk), end-at)
			extra := min(uint64(overlap), end-at-main)
			data, err := memory.Read(ctx, layer, at, int(main))
			if err != nil {
				return err
			}
			if extra > 0 {
				tail, err := memory.Read(ctx, layer, at+main, int(extra))
				if err != nil {
					return err
				}
				data = append(data, tail...)
			}
			for from := 0; from+4 <= len(data); {
				if err := ctx.Err(); err != nil {
					return err
				}
				// Only candidates starting with F or B can match. Byte matching includes
				// overlapping occurrences, just as the fixed single YARA expression does.
				i := bytes.IndexAny(data[from:], "FB")
				if i < 0 {
					break
				}
				from += i
				size := 0
				if bytes.HasPrefix(data[from:], []byte("BAAD")) {
					size = 4
				} else if from+5 <= len(data) && bytes.Equal(data[from:from+4], []byte("FILE")) && (data[from+4] == '0' || data[from+4] == '*') {
					size = 5
				}
				if size > 0 {
					if err := emit(at + uint64(from)); err != nil {
						return err
					}
				}
				from++
			}
			advance := main + extra
			if advance > chunk {
				advance -= overlap
			}
			at += advance
		}
	}
	return ctx.Err()
}
