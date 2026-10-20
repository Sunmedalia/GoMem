package symbols

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxIndexSize = 16 << 20
const MaxIndexEntries = 10000

type PDBIdentity struct {
	Database string `json:"database"`
	GUID     string `json:"GUID"`
	Age      uint64 `json:"age"`
}

func (p PDBIdentity) Equal(other PDBIdentity) bool {
	return strings.EqualFold(p.Database, other.Database) &&
		strings.EqualFold(strings.ReplaceAll(p.GUID, "-", ""), strings.ReplaceAll(other.GUID, "-", "")) && p.Age == other.Age
}
func (p PDBIdentity) validate() error {
	guid, err := hex.DecodeString(strings.ReplaceAll(p.GUID, "-", ""))
	if err != nil || len(guid) != 16 || p.Database == "" || strings.ContainsAny(p.Database, "\x00/\\") {
		return fmt.Errorf("invalid PDB name or GUID")
	}
	return nil
}
func (t *ISF) PDBIdentity() (PDBIdentity, error) {
	var meta struct {
		PDB PDBIdentity `json:"pdb"`
	}
	if err := json.Unmarshal(t.Meta["windows"], &meta); err != nil {
		return meta.PDB, err
	}
	return meta.PDB, meta.PDB.validate()
}

type IndexEntry struct {
	Location      string       `json:"location"`
	SHA256        string       `json:"sha256"`
	OS            string       `json:"os"`
	PointerSize   int          `json:"pointer_size"`
	Architecture  string       `json:"architecture,omitempty"`
	Banner        string       `json:"banner,omitempty"`
	BannerAddress string       `json:"banner_address,omitempty"`
	PDB           *PDBIdentity `json:"pdb,omitempty"`
}
type Index struct {
	Schema  string       `json:"schema"`
	Entries []IndexEntry `json:"entries"`
}

func entry(ctx context.Context, path string) (IndexEntry, error) {
	t, err := LoadContext(ctx, path)
	if err != nil {
		return IndexEntry{}, err
	}
	return describeEntry(t, path)
}
func describeEntry(t *ISF, path string) (IndexEntry, error) {
	e := IndexEntry{Location: path, SHA256: t.Digest(), PointerSize: t.PointerSize(), Architecture: t.Architecture()}
	if _, ok := t.Meta["windows"]; ok {
		e.OS = "windows"
		p, err := t.PDBIdentity()
		if err != nil {
			return e, err
		}
		e.PDB = &p
	} else {
		name := "linux_banner"
		e.OS = "linux"
		if _, ok := t.Meta["mac"]; ok {
			e.OS, name = "mac", "version"
		} else if _, ok := t.Meta["linux"]; !ok {
			return e, fmt.Errorf("symbol index requires linux, mac or windows identity metadata")
		}
		banner, err := t.Banner()
		if err != nil {
			return e, err
		}
		symbol, err := t.Lookup(name)
		if err != nil {
			return e, err
		}
		e.Banner, e.BannerAddress = string(banner), fmt.Sprintf("0x%x", symbol.Address)
	}
	return e, nil
}

// BuildIndex indexes explicit tables or all ISF members of ZIP packages. Source
// paths are absolute; archive members are never extracted to filesystem paths.
// Any invalid input aborts the build rather than silently reducing coverage.
func BuildIndex(ctx context.Context, paths []string) (*Index, error) {
	index := &Index{Schema: "gomem.symbol-index/v1"}
	locations := map[string]bool{}
	add := func(path string) error {
		if !locations[path] && len(locations) >= MaxIndexEntries {
			return fmt.Errorf("symbol index exceeds %d entries", MaxIndexEntries)
		}
		locations[path] = true
		return nil
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, member, hasMember := strings.Cut(path, "#")
		abs, err := filepath.Abs(name)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(filepath.Ext(name), ".zip") && !hasMember {
			z, err := zip.OpenReader(abs)
			if err != nil {
				return nil, err
			}
			count := 0
			for _, f := range z.File {
				if !f.FileInfo().IsDir() && isSymbolName(f.Name) {
					if err = add(abs + "#" + f.Name); err != nil {
						break
					}
					count++
				}
			}
			closeErr := z.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
			if count == 0 {
				return nil, fmt.Errorf("no ISF members in %s", abs)
			}
		} else {
			if hasMember {
				abs += "#" + member
			}
			if err = add(abs); err != nil {
				return nil, err
			}
		}
	}
	ordered := make([]string, 0, len(locations))
	for path := range locations {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		e, err := entry(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("index %s: %w", path, err)
		}
		index.Entries = append(index.Entries, e)
	}
	if err := index.validate(); err != nil {
		return nil, err
	}
	return index, nil
}
func (i *Index) validate() error {
	if i.Schema != "gomem.symbol-index/v1" || len(i.Entries) == 0 || len(i.Entries) > MaxIndexEntries {
		return fmt.Errorf("invalid symbol index schema or entry count")
	}
	seen := map[string]bool{}
	for _, e := range i.Entries {
		hash, err := hex.DecodeString(e.SHA256)
		filename, member, hasMember := strings.Cut(e.Location, "#")
		if err != nil || len(hash) != 32 || filename == "" || hasMember && member == "" || strings.ContainsRune(e.Location, 0) || seen[e.Location] || e.PointerSize != 4 && e.PointerSize != 8 {
			return fmt.Errorf("invalid symbol index entry %q", e.Location)
		}
		seen[e.Location] = true
		switch e.OS {
		case "windows":
			if e.PDB == nil || e.PDB.validate() != nil || e.Banner != "" || e.BannerAddress != "" {
				return fmt.Errorf("invalid indexed Windows identity")
			}
		case "linux", "mac":
			if _, err := strconv.ParseUint(e.BannerAddress, 0, 64); err != nil || len(e.Banner) == 0 || len(e.Banner) > 4096 || !utf8.ValidString(e.Banner) || strings.ContainsRune(e.Banner, 0) || e.PDB != nil {
				return fmt.Errorf("invalid indexed kernel banner")
			}
		default:
			return fmt.Errorf("invalid indexed OS %q", e.OS)
		}
	}
	return nil
}
func (i *Index) Encode() ([]byte, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(i, "", "  ")
	if err == nil && len(b) >= MaxIndexSize {
		err = fmt.Errorf("symbol index exceeds size limit")
	}
	return append(b, '\n'), err
}
func LoadIndex(ctx context.Context, path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, MaxIndexSize+1))
	if err != nil || len(b) > MaxIndexSize {
		if err == nil {
			err = fmt.Errorf("symbol index exceeds size limit")
		}
		return nil, err
	}
	return ParseIndex(b, filepath.Dir(path))
}

// ParseIndex validates bounded JSON and resolves locations against directory.
// It never reads a table or contacts a symbol server.
func ParseIndex(b []byte, directory string) (*Index, error) {
	if len(b) > MaxIndexSize {
		return nil, fmt.Errorf("symbol index exceeds size limit")
	}
	var index Index
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&index); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing symbol index data")
	}
	if err := index.validate(); err != nil {
		return nil, err
	}
	// Relative locations are resolved against the index, never the caller's cwd.
	base, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	for n := range index.Entries {
		e := &index.Entries[n]
		filename, member, hasMember := strings.Cut(e.Location, "#")
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(base, filename)
		} else {
			filename = filepath.Clean(filename)
		}
		e.Location = filename
		if hasMember {
			// Archive members use ZIP separators on every host. Never pass
			// their names through filepath.Join or filepath.Clean.
			e.Location += "#" + member
		}
	}
	if err := index.validate(); err != nil {
		return nil, err
	}
	return &index, nil
}

// LoadEntry checks both the full table content digest and the indexed identity.
// A stale or edited source cannot be silently reused through an old index.
func LoadEntry(ctx context.Context, e IndexEntry) (*ISF, error) {
	t, err := LoadContext(ctx, e.Location)
	if err != nil {
		return nil, err
	}
	actual, err := describeEntry(t, e.Location)
	if err != nil {
		return nil, err
	}
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(e)
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("symbol index is stale or its identity changed: %s", e.Location)
	}
	return t, nil
}
