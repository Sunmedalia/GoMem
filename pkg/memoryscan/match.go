package memoryscan

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

var ErrIncomplete = errors.New("scan buffer has incomplete acquisition coverage")

// Hit preserves both baseline reported coordinates and actual source bytes.
// Empty matches have no source bytes and cannot establish source correspondence.
type Hit struct {
	Offset                 uint64
	Length                 uint64
	Sources                []Source
	CoordinatesMatchSource bool
}

// Find runs the native byte scanner over successfully acquired parts. Even if
// partial results are emitted, incomplete acquisition is returned as an error.
// A finite match bound applies independently of the regex VM execution limits.
func Find(ctx context.Context, re *byteregex.Regexp, b Buffer, maxStart int, limits byteregex.Limits, maxHits uint64, out func(Hit) error) error {
	if ctx == nil || re == nil || out == nil || maxHits == 0 || maxHits > 1000000 {
		return fmt.Errorf("scan matching requires context, regex, emitter and match bound 1..1000000")
	}
	var count uint64
	err := re.FindIter(ctx, b.Data, maxStart, limits, func(m byteregex.Match) error {
		if count >= maxHits {
			return fmt.Errorf("scan match bound exhausted")
		}
		at, err := memory.Add(b.Base, uint64(m.Start))
		if err != nil {
			return err
		}
		sources, err := b.Sources(m.Start, m.End)
		if err != nil {
			return err
		}
		same := len(sources) > 0
		for _, s := range sources {
			reported, err := memory.Add(at, s.Offset)
			if err != nil {
				return err
			}
			if reported != s.Virtual {
				same = false
			}
		}
		count++
		return out(Hit{Offset: at, Length: uint64(m.End - m.Start), Sources: sources, CoordinatesMatchSource: same})
	})
	if !b.Complete {
		return errors.Join(err, ErrIncomplete)
	}
	return err
}
