// Package library manages local acquisitions and identity-matched symbols.
package library

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Identity struct {
	OS       string               `json:"os"`
	Physical uint64               `json:"physical"`
	Banner   string               `json:"banner,omitempty"`
	PDB      *symbols.PDBIdentity `json:"pdb,omitempty"`
}

type Probe struct {
	Format     string     `json:"format"`
	OS         string     `json:"os"`
	Status     string     `json:"status"`
	Identities []Identity `json:"identities"`
}

func ProbeFile(ctx context.Context, path string) (Probe, error) {
	src, err := memory.OpenImageSource(ctx, path, memory.ImageSourceOptions{Offline: true})
	if err != nil {
		return Probe{}, err
	}
	defer src.Close()
	layer, format, err := memory.Detect(ctx, src)
	if err != nil {
		return Probe{}, err
	}
	p, err := ProbeLayer(ctx, layer)
	p.Format = format
	return p, err
}

// ProbeLayer reports resident identity candidates, not proof of the active
// kernel. Multiple banners/RSDS records can survive in a physical acquisition.
func ProbeLayer(ctx context.Context, layer memory.MemoryLayer) (Probe, error) {
	p := Probe{OS: "unknown", Status: "unavailable", Identities: []Identity{}}
	seen := map[string]bool{}
	hits := 0
	countHit := func() error {
		hits++
		if hits > 8192 {
			return fmt.Errorf("kernel marker candidate limit exceeded")
		}
		return nil
	}
	add := func(id Identity, key string) error {
		if seen[key] {
			return nil
		}
		if len(seen) >= 256 {
			return fmt.Errorf("kernel identity candidate limit exceeded")
		}
		seen[key] = true
		p.Identities = append(p.Identities, id)
		return nil
	}
	err := memory.Scan(ctx, layer, []byte("Linux version "), func(at uint64) error {
		if err := countHit(); err != nil {
			return err
		}
		banner, err := residentString(ctx, layer, at, 4096)
		if err != nil {
			return err
		}
		if !utf8.ValidString(banner) || strings.ContainsAny(banner, "\r\t") || len(strings.Fields(banner)) < 3 {
			return nil
		}
		return add(Identity{OS: "linux", Physical: at, Banner: banner}, banner)
	})
	if err != nil {
		return p, err
	}
	err = memory.Scan(ctx, layer, []byte("RSDS"), func(at uint64) error {
		if err := countHit(); err != nil {
			return err
		}
		b, err := memory.Read(ctx, layer, at, 24)
		if err != nil {
			return err
		}
		name, err := residentString(ctx, layer, at+24, 512)
		if err != nil {
			return err
		}
		if slash := strings.LastIndexAny(name, "/\\"); slash >= 0 {
			name = name[slash+1:]
		}
		switch strings.ToLower(name) {
		case "ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb":
		default:
			return nil
		}
		g := b[4:20]
		id := &symbols.PDBIdentity{Database: name, GUID: fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:]), Age: uint64(binary.LittleEndian.Uint32(b[20:]))}
		return add(Identity{OS: "windows", Physical: at, PDB: id}, fmt.Sprint(*id))
	})
	if err != nil {
		return p, err
	}
	if len(p.Identities) > 0 {
		p.OS, p.Status = p.Identities[0].OS, "candidate"
		for _, id := range p.Identities {
			if id.OS != p.OS {
				p.OS = "unknown"
			}
		}
		if len(p.Identities) > 1 {
			p.Status = "ambiguous"
		}
	}
	if _, ok := layer.(interface{ CrashHeader() memory.CrashHeader }); ok {
		p.OS = "windows"
		if len(p.Identities) == 0 {
			p.Status = "header-only"
		}
	}
	return p, nil
}

func residentString(ctx context.Context, layer memory.MemoryLayer, at uint64, limit int) (string, error) {
	var b []byte
	for i := 0; i < limit; i++ {
		a, err := memory.Add(at, uint64(i))
		if err != nil {
			return "", err
		}
		v, err := memory.Read(ctx, layer, a, 1)
		if err != nil {
			return "", err
		}
		if v[0] == 0 {
			return string(b), nil
		}
		b = append(b, v[0])
	}
	return "", nil // unterminated marker is not an identity
}

func (id Identity) Matches(t *symbols.ISF) bool {
	if id.OS == "windows" && id.PDB != nil {
		return t.MatchPDB(id.PDB.Database, id.PDB.GUID, id.PDB.Age) == nil
	}
	if id.OS == "linux" {
		b, err := t.Banner()
		_, linux := t.Meta["linux"]
		return linux && err == nil && string(b) == id.Banner
	}
	return false
}
