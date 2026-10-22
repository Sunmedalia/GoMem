package plugins

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/winconsole"
)

// Keep the two pinned plugins' acquisition scopes distinct: Consoles searches
// only the first conhost executable VAD; CmdScan searches all VADs below 1 GiB.
type conhostScanScope uint8

const (
	conhostHistoryVADs conhostScanScope = iota
	conhostExecutableVAD
)

type conhostAcquisition struct {
	Layer memory.MemoryLayer
	Scan  memory.MemoryLayer // nil when no selected bytes are acquired
}

func conhostScanSections(vads []windowsVADPath, scope conhostScanScope) (uint64, []memory.Range, error) {
	if scope != conhostHistoryVADs && scope != conhostExecutableVAD {
		return 0, nil, fmt.Errorf("invalid conhost scan scope %d", scope)
	}
	var base uint64
	executable := -1
	for i, v := range vads {
		if v.file.Kind == "string" && strings.HasSuffix(strings.ToLower(v.file.String()), "conhost.exe") {
			base, executable = v.start, i
			break
		}
	}
	if executable < 0 || base == 0 {
		return 0, nil, nil
	}
	selected := vads
	if scope == conhostExecutableVAD {
		selected = vads[executable : executable+1]
	}
	sections := []memory.Range{}
	for _, v := range selected {
		if v.end < v.start {
			return base, nil, fmt.Errorf("reversed VAD range")
		}
		length := v.end - v.start + 1
		if length == 0 {
			return base, nil, fmt.Errorf("VAD length overflow")
		}
		if scope == conhostExecutableVAD || length < 0x40000000 {
			sections = append(sections, memory.Range{Start: v.start, Length: length})
		}
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Start < sections[j].Start })
	return base, sections, nil
}

func (s *cmdScan) acquireConhost(ctx context.Context, process uint64, identity string, scope conhostScanScope) (*conhostAcquisition, error) {
	if s.regions >= s.maxRegions {
		return nil, fmt.Errorf("max-regions exhausted")
	}
	vads, err := windowsVADRegions(ctx, s.env, process, int(min(s.maxNodes, s.maxRegions-s.regions)))
	if err != nil {
		return nil, err
	}
	s.regions += uint64(len(vads))
	base, sections, err := conhostScanSections(vads, scope)
	if err != nil {
		return nil, err
	}
	if base == 0 {
		return nil, s.diagnostic("conhost_image_unavailable", process, fmt.Errorf("no conhost.exe VAD filename"))
	}
	space, err := processMemory(ctx, s.env, process, 0, identity)
	if err != nil {
		return nil, err
	}
	original := space.(*memory.Virtual)
	space = s.traced(space, 4096)
	if s.catalog == nil {
		version, err := winconsole.VersionFromMemory(ctx, s.env.Objects, s.env.KernelBase)
		if err != nil {
			return nil, err
		}
		if version.NeedsRevision() {
			direct, directErr := readProductVersion(ctx, space, base)
			if directErr == nil {
				version.Revision = direct.build
			} else {
				if err := s.diagnostic("conhost_version_unavailable", base, directErr); err != nil {
					return nil, err
				}
				fallback, found, fallbackErr := findExtensiveVersion(ctx, s.env.Physical, "CONHOST.EXE")
				if fallbackErr != nil {
					return nil, errors.Join(directErr, fallbackErr)
				}
				if found {
					version.Revision = fallback.build
				}
			}
		}
		s.selected, err = winconsole.Select(version)
		if err != nil {
			return nil, err
		}
		cache := ""
		if s.env.SymbolCache != "" {
			cache = filepath.Join(s.env.SymbolCache, "console-symbols")
		}
		s.catalog, err = winconsole.Load(ctx, cache, s.selected.Name, s.env.Offline)
		if err != nil {
			return nil, err
		}
		if err := s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("layout_selection"), "LayoutSelection": {Kind: "structure", Data: s.selected}}}); err != nil {
			return nil, err
		}
	}
	if len(sections) == 0 {
		return &conhostAcquisition{Layer: space}, nil
	}
	if s.mapTables >= s.maxTables || s.mapEntries >= s.maxEntries {
		return nil, fmt.Errorf("page map bound exhausted")
	}
	ranges := []memory.Range{}
	stats, err := original.Translator.(*memory.Intel).VisitPageMappings(ctx, memory.PageMapOptions{Sections: sections, MaxTables: s.maxTables - s.mapTables, MaxEntries: s.maxEntries - s.mapEntries, OnReadError: func(_ uint64, err error) error { return s.diagnostic("page_map_unavailable", process, err) }, OnUnavailableMapping: func(m memory.PageMapping) error {
		return s.diagnostic("mapping_unavailable", m.Virtual, fmt.Errorf("unavailable mapped physical page"))
	}}, func(m memory.PageMapping) error {
		ranges = append(ranges, memory.Range{Start: m.Virtual, Length: m.Length})
		if uint64(len(ranges)) > s.maxRegions {
			return fmt.Errorf("mapped run bound exhausted")
		}
		return nil
	})
	s.mapTables += stats.Tables
	s.mapEntries += stats.Entries
	if err != nil {
		return nil, err
	}
	var requested, mapped uint64
	for _, section := range sections {
		requested += section.Length
	}
	for _, mappedRange := range ranges {
		mapped += mappedRange.Length
	}
	if err := s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("process_scan_coverage"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"RequestedVADBytes": evidence.Number(requested), "MappedVADBytes": evidence.Number(mapped), "Complete": evidence.Bool(mapped == requested)}}}}); err != nil {
		return nil, err
	}
	if mapped != requested {
		if err := s.diagnostic("vad_acquisition_incomplete", process, fmt.Errorf("mapped %d of %d selected VAD bytes", mapped, requested)); err != nil {
			return nil, err
		}
	}
	if len(ranges) == 0 {
		return &conhostAcquisition{Layer: space}, nil
	}
	// Sort and merge only contiguous acquired mappings; absent pages never join.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	merged := []memory.Range{}
	for _, v := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			end, err := memory.Add(last.Start, last.Length)
			if err != nil {
				return nil, err
			}
			if v.Start < end {
				return nil, fmt.Errorf("overlapping selected mappings")
			}
			if v.Start == end {
				last.Length += v.Length
				continue
			}
		}
		merged = append(merged, v)
	}
	scan := poolScannerLayer{MemoryLayer: space, a: s.a, ranges: merged, rawLimit: 4096}
	return &conhostAcquisition{Layer: space, Scan: scan}, nil
}
