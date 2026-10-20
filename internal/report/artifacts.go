package report

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type artifactRecord struct {
	Artifact evidence.Artifact `json:"artifact"`
	Included bool              `json:"included"`
	Error    string            `json:"error,omitempty"`
}

func eachArtifact(ctx context.Context, s *store.Store, tasks []evidence.Task, emit func(evidence.Artifact) error) error {
	for _, task := range tasks {
		for offset := 0; ; offset += 500 {
			page, err := s.ArtifactPage(ctx, task.ID, offset, 500)
			if err != nil {
				return err
			}
			for _, a := range page {
				if err = emit(a); err != nil {
					return err
				}
			}
			if len(page) < 500 {
				break
			}
		}
	}
	return nil
}

func copyArtifact(ctx context.Context, s *store.Store, z *zip.Writer, a evidence.Artifact, gaps bool) error {
	f, err := s.OpenArtifactMember(ctx, a, gaps)
	if err != nil {
		return err
	}
	defer f.Close()
	name, sum := a.Path, a.SHA256
	if gaps {
		name, sum = a.GapsPath, a.GapsSHA256
	}
	part, err := z.Create(name)
	if err != nil {
		return err
	}
	hash := sha256.New()
	writer := io.MultiWriter(part, hash)
	buf := make([]byte, 1<<20)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			if _, err = writer.Write(buf[:n]); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != sum {
		return fmt.Errorf("artifact changed while exporting: %s", a.ID)
	}
	return nil
}

func bundleArtifacts(ctx context.Context, s *store.Store, z *zip.Writer, m *Manifest) error {
	// ZIP requires each member to be finished before starting another. Stream
	// file members first, then stream the small metadata records in a second pass.
	if err := eachArtifact(ctx, s, m.Tasks, func(a evidence.Artifact) error {
		if a.State == "writing" || a.State == "interrupted" {
			return nil
		}
		if err := copyArtifact(ctx, s, z, a, false); err != nil {
			return err
		}
		return copyArtifact(ctx, s, z, a, true)
	}); err != nil {
		return err
	}
	part, err := z.Create("artifacts.jsonl")
	if err != nil {
		return err
	}
	hash := sha256.New()
	encoder := json.NewEncoder(io.MultiWriter(part, hash))
	var count int64
	if err = eachArtifact(ctx, s, m.Tasks, func(a evidence.Artifact) error {
		included := a.State != "writing" && a.State != "interrupted"
		record := artifactRecord{Artifact: a, Included: included}
		if !included {
			record.Error = "unfinalized bytes omitted; original partial files remain in the case"
		}
		count++
		return encoder.Encode(record)
	}); err != nil {
		return err
	}
	m.ArtifactIndex = &Entry{Path: "artifacts.jsonl", SHA256: hex.EncodeToString(hash.Sum(nil)), Rows: count}
	return nil
}

func artifactsJSONL(ctx context.Context, s *store.Store, w io.Writer, tasks []evidence.Task) error {
	encoder := json.NewEncoder(w)
	return eachArtifact(ctx, s, tasks, func(a evidence.Artifact) error {
		return encoder.Encode(map[string]any{"record_type": "artifact", "task_id": a.TaskID, "artifact": a})
	})
}

func artifactsHTML(ctx context.Context, s *store.Store, w io.Writer, tasks []evidence.Task) error {
	return eachArtifact(ctx, s, tasks, func(a evidence.Artifact) error {
		b, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			return err
		}
		return artifactTemplate.Execute(w, string(b))
	})
}
