package plugins

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type analysisVADRange struct {
	windowsVADPath
	protection string
}

type vadProtectionCache struct {
	env    plugin.Environment
	base   uint64
	loaded bool
	values map[uint64]string
}

func (p *vadProtectionCache) read(ctx context.Context, region windowsVADPath) (string, error) {
	typ := "_MMVAD"
	if region.tag == "VadS" || region.tag == "VadF" {
		typ = "_MMVAD_SHORT"
	}
	path, _, err := windowsVADField(p.env, typ, []string{"u.VadFlags.Protection", "Core.u.VadFlags.Protection"})
	if err != nil {
		return "", err
	}
	index, err := p.env.Objects.Uint(ctx, region.address, typ, path)
	if err != nil {
		return "", err
	}
	if !p.loaded {
		p.base, err = p.env.Symbol("MmProtectToValue")
		if err != nil {
			return "", err
		}
		p.values = map[uint64]string{}
		p.loaded = true
	}
	// The pinned MMVAD.get_protection treats an out-of-array index as zero and
	// ignores bits not named by winnt_protections. Read only the selected entry.
	if index >= 32 {
		return "", nil
	}
	if value, found := p.values[index]; found {
		return value, nil
	}
	address, err := memory.Add(p.base, index*4)
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, p.env.Kernel, address, 4)
	if err != nil {
		return "", err
	}
	value, err := windowsProtectionNames(uint64(binary.LittleEndian.Uint32(raw)) & 0x400007ff)
	if err != nil {
		return "", err
	}
	p.values[index] = value
	return value, nil
}
func analysisVADRanges(ctx context.Context, e plugin.Environment, process uint64, max int, protect *vadProtectionCache) ([]analysisVADRange, error) {
	regions, err := windowsVADRegions(ctx, e, process, max)
	if err != nil {
		return nil, err
	}
	result := make([]analysisVADRange, 0, len(regions))
	for _, region := range regions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		protection, err := protect.read(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("VAD %#x protection: %w", region.address, err)
		}
		result = append(result, analysisVADRange{region, protection})
	}
	return result, nil
}

// The suspicious-thread baseline uses address < end, despite end being the
// final accessible byte. Preserve that boundary and the first preorder match.
func analysisThreadRange(ranges []analysisVADRange, address uint64) (analysisVADRange, bool) {
	for _, region := range ranges {
		if region.start <= address && address < region.end {
			return region, true
		}
	}
	return analysisVADRange{}, false
}
