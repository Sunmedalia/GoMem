package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

var ErrNoMatchingSymbols = errors.New("local symbol selection failed")

func (e *Engine) selectSymbols(ctx context.Context, path string) (*symbols.ISF, symbols.IndexEntry, error) {
	var none symbols.IndexEntry
	if e.Env.Kernel == nil {
		return nil, none, fmt.Errorf("local symbol selection requires --dtb; DTB discovery is pending")
	}
	index, err := symbols.LoadIndex(ctx, path)
	if err != nil {
		return nil, none, fmt.Errorf("symbol index: %w", err)
	}
	matches := map[string]symbols.IndexEntry{}
	var diagnostics []string
	var pdb symbols.PDBIdentity
	var pdbErr error
	pdbRead := false
	for _, candidate := range index.Entries {
		if err = ctx.Err(); err != nil {
			return nil, none, err
		}
		if e.Config.OS != "" && e.Config.OS != candidate.OS || (e.Config.Arch == "x64") != (candidate.PointerSize == 8) {
			continue
		}
		arch := candidate.Architecture
		if arch != "" && arch != "EM_X86_64" && arch != "EM_386" && arch != "x86_64" && arch != "i386" {
			continue
		}
		matched := false
		var probeErr error
		switch candidate.OS {
		case "windows":
			if !pdbRead {
				pdbRead = true
				if e.Config.KernelBase == 0 {
					pdbErr = fmt.Errorf("Windows indexed symbols require --kernel-base")
				} else {
					pdb, pdbErr = readKernelPDB(ctx, e.Env.Kernel, e.Config.KernelBase)
				}
			}
			probeErr = pdbErr
			matched = probeErr == nil && candidate.PDB.Equal(pdb)
		case "linux":
			address, _ := strconv.ParseUint(candidate.BannerAddress, 0, 64)
			address, probeErr = memory.Add(address, e.Config.KernelSlide)
			if probeErr == nil {
				var data []byte
				data, probeErr = memory.Read(ctx, e.Env.Kernel, address, len(candidate.Banner)+1)
				matched = probeErr == nil && bytes.Equal(data, append([]byte(candidate.Banner), 0))
			}
		default:
			probeErr = fmt.Errorf("%s kernel identity verification is unavailable", candidate.OS)
		}
		if probeErr != nil && len(diagnostics) < 5 {
			diagnostics = append(diagnostics, probeErr.Error())
		}
		if matched {
			matches[candidate.SHA256] = candidate
		}
	}
	if len(matches) == 0 {
		detail := "no exact resident kernel identity matched"
		if len(diagnostics) > 0 {
			detail += "; read/verification failures: " + strings.Join(diagnostics, "; ")
		}
		return nil, none, fmt.Errorf("%w: %s", ErrNoMatchingSymbols, detail)
	}
	if len(matches) != 1 {
		return nil, none, fmt.Errorf("local symbol selection is ambiguous: %d different tables match; provide --symbols explicitly", len(matches))
	}
	for _, selected := range matches {
		table, err := symbols.LoadEntry(ctx, selected)
		if err != nil {
			return nil, none, fmt.Errorf("indexed symbols: %w", err)
		}
		return table, selected, nil
	}
	panic("unreachable symbol selection")
}
