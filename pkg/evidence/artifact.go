package evidence

import (
	"context"
	"io"
)

// Artifact describes a case-owned extracted file. Sizes are decimal strings;
// addresses in the provenance and padding log are lossless hexadecimal strings.
type Artifact struct {
	ID           string     `json:"id"`
	TaskID       string     `json:"task_id"`
	Name         string     `json:"name"`
	Path         string     `json:"path"`
	GapsPath     string     `json:"gaps_path"`
	State        string     `json:"state"`
	ExpectedSize string     `json:"expected_size"`
	Size         string     `json:"size,omitempty"`
	SHA256       string     `json:"sha256,omitempty"`
	GapsSHA256   string     `json:"gaps_sha256,omitempty"`
	GapsSize     string     `json:"gaps_size,omitempty"`
	MissingBytes string     `json:"missing_bytes"`
	GapCount     string     `json:"gap_count"`
	Error        string     `json:"error,omitempty"`
	Provenance   Provenance `json:"provenance"`
}

type ArtifactGap struct {
	Offset  string `json:"offset"`
	Length  string `json:"length"`
	Address string `json:"address"`
	Layer   string `json:"layer"`
	Error   string `json:"error"`
}

type ArtifactRequest struct {
	Name          string
	Size          uint64
	Layer, Offset string
}

type ArtifactWriter interface {
	io.Writer
	// PadZero records exactly which written bytes are padding for an unreadable
	// source range. The source read error is evidence, not a write failure.
	PadZero(context.Context, uint64, uint64, string, error) error
	Finish(context.Context, error) (Artifact, error)
}

type ArtifactSink interface {
	Create(context.Context, ArtifactRequest) (ArtifactWriter, error)
}
