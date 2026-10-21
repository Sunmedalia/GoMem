package library

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type LocalMatch struct {
	Table      symbols.IndexEntry `json:"table"`
	Identities []Identity         `json:"identities"`
}
type LocalDiagnostic struct {
	Location string `json:"location"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}
type LocalResult struct {
	Matches     []LocalMatch      `json:"matches"`
	Diagnostics []LocalDiagnostic `json:"diagnostics"`
}

// MatchLocal compares every observed identity against actual local tables,
// including ZIP members. Per-file failures remain visible and do not hide a
// valid table elsewhere in the library. Cancellation still aborts the scan.
func (l Library) MatchLocal(ctx context.Context, p Probe) (LocalResult, error) {
	result := LocalResult{Matches: []LocalMatch{}, Diagnostics: []LocalDiagnostic{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := os.Lstat(l.Directory(Symbols)); os.IsNotExist(err) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	files, err := l.List(Symbols)
	if err != nil {
		return result, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		path := l.Path(Symbols, file.Name)
		if IsSourceRecord(file.Name) {
			result.Diagnostics = append(result.Diagnostics, LocalDiagnostic{path, "source-only", "Source/provenance record, not a symbol table; import the corresponding full ISF or debug file"})
			continue
		}
		index, err := symbols.BuildIndex(ctx, []string{path})
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			result.Diagnostics = append(result.Diagnostics, LocalDiagnostic{path, "error", err.Error()})
			continue
		}
		for _, entry := range index.Entries {
			match := LocalMatch{Table: entry, Identities: []Identity{}}
			for _, id := range p.Identities {
				if id.OS != entry.OS {
					continue
				}
				if id.OS == "linux" && id.Banner == entry.Banner || id.OS == "windows" && id.PDB != nil && entry.PDB != nil && id.PDB.Equal(*entry.PDB) {
					match.Identities = append(match.Identities, id)
				}
			}
			if len(match.Identities) > 0 {
				result.Matches = append(result.Matches, match)
			}
		}
	}
	return result, nil
}

// Unique returns a location only when all matches describe the same content.
// Multiple copies of one table do not make selection ambiguous.
func (r LocalResult) Unique() (string, error) {
	var location, digest string
	for _, match := range r.Matches {
		if digest != "" && digest != match.Table.SHA256 {
			return "", fmt.Errorf("multiple different local symbol tables match; select a table explicitly")
		}
		location, digest = match.Table.Location, match.Table.SHA256
	}
	return location, nil
}

func IsSourceRecord(path string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".source.json")
}
