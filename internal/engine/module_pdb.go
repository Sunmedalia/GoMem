package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// modulePDBProvider captures configuration once; concurrent tasks never mutate
// engine discovery state while acquiring additional module tables.
func (e *Engine) modulePDBProvider() pesymbols.Provider {
	config, build, kernel := e.Config, e.Build, e.Env.Symbols
	return func(ctx context.Context, module pesymbols.Module) (pesymbols.PDB, error) {
		var result pesymbols.PDB
		if module.Layer == nil || module.Size == 0 || module.Size > pe.MaxImageSize || module.Size-1 > ^uint64(0)-module.Base {
			return result, fmt.Errorf("invalid module extent for PDB acquisition")
		}
		module.Layer = modulePDBExtent{MemoryLayer: module.Layer, base: module.Base, size: module.Size}
		var images []kernelPE
		var discoveryErr error
		if module.PDBNames != nil {
			identities, err := scanModulePDB(ctx, module)
			if err != nil && len(identities) == 0 {
				return result, err
			}
			discoveryErr = err
			for _, identity := range identities {
				images = append(images, kernelPE{Identity: identity})
			}
		} else {
			image, err := readKernelPE(ctx, module.Layer, module.Base)
			if err != nil {
				if errors.Is(err, errNoMappedPDB) {
					return result, fmt.Errorf("%w: %v", pesymbols.ErrUnavailable, err)
				}
				return result, err
			}
			if image.Size > module.Size {
				return result, fmt.Errorf("PDB PE image exceeds collected module extent")
			}
			images = append(images, image)
		}
		for _, image := range images {
			resolved, err := resolveModulePDB(ctx, config, build, kernel, image)
			result = resolved
			if err == nil || !errors.Is(err, pesymbols.ErrUnavailable) {
				return resolved, errors.Join(err, discoveryErr)
			}
		}
		if discoveryErr != nil {
			return result, discoveryErr
		}
		return result, pesymbols.ErrUnavailable
	}
}

func resolveModulePDB(ctx context.Context, config Config, build string, kernel symbols.SymbolTable, image kernelPE) (result pesymbols.PDB, err error) {
	result.Identity = image.Identity
	verify := func(table *symbols.ISF) (pesymbols.PDB, error) {
		if err := table.MatchPDB(image.Identity.Database, image.Identity.GUID, image.Identity.Age); err != nil {
			return result, err
		}
		// Candidate scanning does not require a PE header. In that mode the
		// exact resident GUID/Age/name identifies the PDB; Machine is unset.
		if arch := table.Architecture(); image.Machine != 0 && (arch == "x86_64" && image.Machine != 0x8664 || arch == "i386" && image.Machine != 0x14c || arch == "arm64" && image.Machine != 0xaa64) {
			return result, fmt.Errorf("module PDB machine and PE machine disagree")
		}
		result.Table = table
		return result, nil
	}
	if table, ok := kernel.(*symbols.ISF); ok && table.MatchPDB(image.Identity.Database, image.Identity.GUID, image.Identity.Age) == nil {
		return verify(table)
	}
	indexPath := config.SymbolIndex
	if indexPath == "" && config.CaseDir != "" {
		candidate := filepath.Join(config.CaseDir, "symbols", "index.json")
		if _, err := os.Stat(candidate); err == nil {
			indexPath = candidate
		} else if !os.IsNotExist(err) {
			return result, err
		}
	}
	if indexPath != "" {
		index, err := symbols.LoadIndex(ctx, indexPath)
		if err != nil {
			return result, err
		}
		var match *symbols.IndexEntry
		for _, entry := range index.Entries {
			if entry.OS == "windows" && entry.PDB != nil && entry.PDB.Equal(image.Identity) {
				if match != nil && match.SHA256 != entry.SHA256 {
					return result, fmt.Errorf("ambiguous indexed module PDB identity")
				}
				copy := entry
				match = &copy
			}
		}
		if match != nil {
			table, err := symbols.LoadEntry(ctx, *match)
			if err != nil {
				return result, err
			}
			return verify(table)
		}
	}
	cache := config.SymbolCache
	if cache == "" {
		if config.CaseDir != "" {
			cache = filepath.Join(config.CaseDir, "symbols", "windows")
		} else {
			root, err := os.UserCacheDir()
			if err != nil {
				return result, err
			}
			cache = filepath.Join(root, "gomem", "symbols", "windows")
		}
	}
	table, resolution, err := symbols.ResolvePDB(ctx, image.Identity, symbols.PDBCacheOptions{Directory: cache, BuildSHA256: build, Server: config.SymbolServer, Offline: config.Offline})
	if errors.Is(err, symbols.ErrOfflineSymbols) {
		return result, fmt.Errorf("%w: %v", pesymbols.ErrUnavailable, err)
	}
	if err != nil {
		return result, err
	}
	result.SourceSHA256 = resolution.SourceSHA256
	return verify(table)
}

type modulePDBExtent struct {
	memory.MemoryLayer
	base, size uint64
}

func (l modulePDBExtent) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at < l.base || at-l.base > l.size || uint64(len(p)) > l.size-(at-l.base) {
		return 0, fmt.Errorf("module PDB acquisition exceeds collected extent")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
