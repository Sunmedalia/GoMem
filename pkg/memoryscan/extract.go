package memoryscan

import (
	"context"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
)

// Extraction is a display selection within separately acquired context bytes.
// Start/End locate the selected original bytes; a failed re-search selects the
// entire context. This does not assert that padding or context reads succeeded.
type Extraction struct {
	Start, End int
	Matched    bool
	Text       string
}

// Extract reapplies a separately compiled (normally non-DOTALL) regex to result
// context. Generic scanning searches; VMA scanning anchors at context start.
// The caller retains the raw context and its read/padding provenance separately.
func Extract(ctx context.Context, re *byteregex.Regexp, data []byte, anchored bool, limits byteregex.Limits) (Extraction, error) {
	match, err := re.Search(ctx, data, 0, anchored, limits)
	if err != nil {
		return Extraction{}, err
	}
	result := Extraction{End: len(data)}
	if match != nil {
		result.Start = match.Start
		result.End = match.End
		result.Matched = true
	}
	result.Text = DisplayUTF8(data[result.Start:result.End])
	return result, nil
}
