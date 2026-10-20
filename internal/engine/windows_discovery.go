package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type WindowsDiscovery struct {
	Method            string              `json:"method"`
	Architecture      string              `json:"architecture"`
	DTB               string              `json:"dtb"`
	KernelBase        string              `json:"kernel_base"`
	DebuggerData      string              `json:"debugger_data,omitempty"`
	LoadedModuleList  string              `json:"loaded_module_list"`
	ActiveProcessHead string              `json:"active_process_head,omitempty"`
	ModuleEntry       string              `json:"module_entry,omitempty"`
	BaseField         string              `json:"base_field,omitempty"`
	Identity          symbols.PDBIdentity `json:"pdb"`
	Verified          bool                `json:"verified"`
	InitialDTB        string              `json:"initial_dtb,omitempty"`
	SystemProcess     string              `json:"system_process,omitempty"`
	SystemRootError   string              `json:"system_root_error,omitempty"`
}
type windowsCandidate struct {
	base       uint64
	image      kernelPE
	method     string
	link, slot uint64
}

func (e *Engine) resolveWindowsIdentity(ctx context.Context, identity symbols.PDBIdentity) (*symbols.ISF, *symbols.PDBResolution, error) {
	cache := e.Config.SymbolCache
	if cache == "" {
		if e.Config.CaseDir != "" {
			cache = filepath.Join(e.Config.CaseDir, "symbols", "windows")
		} else {
			userCache, err := os.UserCacheDir()
			if err != nil {
				return nil, nil, err
			}
			cache = filepath.Join(userCache, "gomem", "symbols", "windows")
		}
	}
	table, resolution, err := symbols.ResolvePDB(ctx, identity, symbols.PDBCacheOptions{Directory: cache, BuildSHA256: e.Build, Server: e.Config.SymbolServer, Offline: e.Config.Offline})
	if err != nil {
		return nil, nil, err
	}
	e.Config.SymbolCache = cache
	return table, &resolution, nil
}

func (e *Engine) tableForWindowsCandidate(ctx context.Context, id symbols.PDBIdentity) (*symbols.ISF, string, *symbols.PDBResolution, error) {
	if e.Env.Symbols != nil {
		table, ok := e.Env.Symbols.(*symbols.ISF)
		if !ok {
			return nil, "", nil, fmt.Errorf("Windows discovery requires an ISF-compatible table")
		}
		if err := table.MatchPDB(id.Database, id.GUID, id.Age); err != nil {
			return nil, "", nil, err
		}
		return table, e.Config.Symbols, nil, nil
	}
	indexPath := e.Config.SymbolIndex
	if indexPath == "" && e.Config.CaseDir != "" {
		path := filepath.Join(e.Config.CaseDir, "symbols", "index.json")
		if _, err := os.Stat(path); err == nil {
			indexPath = path
		} else if !os.IsNotExist(err) {
			return nil, "", nil, err
		}
	}
	if indexPath != "" {
		index, err := symbols.LoadIndex(ctx, indexPath)
		if err != nil {
			return nil, "", nil, err
		}
		var matched *symbols.IndexEntry
		for _, entry := range index.Entries {
			if entry.OS == "windows" && entry.PDB.Equal(id) {
				if matched != nil && matched.SHA256 != entry.SHA256 {
					return nil, "", nil, fmt.Errorf("ambiguous indexed Windows symbols for discovered PDB identity")
				}
				copy := entry
				matched = &copy
			}
		}
		if matched != nil {
			table, err := symbols.LoadEntry(ctx, *matched)
			return table, matched.Location, nil, err
		}
		if e.Config.SymbolIndex != "" {
			return nil, "", nil, fmt.Errorf("explicit symbol index has no table matching discovered kernel identity")
		}
	}
	table, resolution, err := e.resolveWindowsIdentity(ctx, id)
	if err != nil {
		return nil, "", nil, err
	}
	return table, resolution.TablePath, resolution, nil
}

func windowsKernelName(name string) bool {
	switch strings.ToLower(name) {
	case "ntoskrnl.pdb", "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb":
		return true
	}
	return false
}
func (e *Engine) windowsPointer(v uint64) (uint64, error) {
	if e.Config.Arch == "x86" || e.Config.Arch == "pae" {
		if v>>32 != 0 && v>>32 != 0xffffffff {
			return 0, fmt.Errorf("invalid 32-bit kernel pointer %#x", v)
		}
		return v & 0xffffffff, nil
	}
	if v>>47 != 0 && v>>47 != 0x1ffff {
		return 0, fmt.Errorf("noncanonical kernel pointer %#x", v)
	}
	return v, nil
}
func (e *Engine) candidatePE(ctx context.Context, base uint64) (kernelPE, error) {
	var empty kernelPE
	if base == 0 || base&0xfff != 0 {
		return empty, fmt.Errorf("kernel candidate is not page aligned")
	}
	if _, err := e.windowsPointer(base); err != nil {
		return empty, err
	}
	image, err := readKernelPE(ctx, e.Env.Kernel, base)
	if err != nil {
		return empty, err
	}
	if (e.Config.Arch == "x64" && image.Machine != 0x8664) || (e.Config.Arch != "x64" && image.Machine != 0x14c) {
		return empty, fmt.Errorf("candidate PE machine does not match address translation")
	}
	if table, ok := e.Env.Symbols.(*symbols.ISF); ok {
		if err := table.MatchPDB(image.Identity.Database, image.Identity.GUID, image.Identity.Age); err != nil {
			return empty, err
		}
	} else if !windowsKernelName(image.Identity.Database) {
		return empty, fmt.Errorf("PE candidate is not a known Windows kernel PDB")
	}
	return image, nil
}

func (e *Engine) kdbgCandidate(ctx context.Context, h memory.CrashHeader) (windowsCandidate, error) {
	var candidate windowsCandidate
	if h.DebuggerData == 0 {
		return candidate, fmt.Errorf("crash header has no debugger-data pointer")
	}
	data, err := memory.Read(ctx, e.Env.Kernel, h.DebuggerData, 88)
	if err != nil {
		return candidate, fmt.Errorf("read debugger data: %w", err)
	}
	if string(data[16:20]) != "KDBG" {
		return candidate, fmt.Errorf("debugger data is encoded or lacks a decoded KDBG header")
	}
	size := binary.LittleEndian.Uint32(data[20:])
	if size < 88 || size > 1<<20 {
		return candidate, fmt.Errorf("invalid KDBG structure size")
	}
	base, err := e.windowsPointer(binary.LittleEndian.Uint64(data[24:]))
	if err != nil {
		return candidate, err
	}
	moduleHead, err := e.windowsPointer(binary.LittleEndian.Uint64(data[72:]))
	if err != nil {
		return candidate, err
	}
	processHead, err := e.windowsPointer(binary.LittleEndian.Uint64(data[80:]))
	if err != nil {
		return candidate, err
	}
	if moduleHead != h.LoadedModuleList || h.ActiveProcessHead != 0 && processHead != h.ActiveProcessHead {
		return candidate, fmt.Errorf("KDBG list anchors disagree with the crash header")
	}
	image, err := e.candidatePE(ctx, base)
	if err != nil {
		return candidate, err
	}
	return windowsCandidate{base: base, image: image, method: "crash-header-kdbg-pe"}, nil
}

// moduleCandidates does not assume a vendor-specific LDR layout before symbols
// are available. It probes bounded pointer slots in the validated module list;
// a slot becomes evidence only if the matched symbols later identify it as the
// actual DllBase field and their global list anchors match the crash header.
func (e *Engine) moduleCandidates(ctx context.Context, h memory.CrashHeader) ([]windowsCandidate, error) {
	width := 8
	if e.Config.Arch != "x64" {
		width = 4
	}
	readPointer := func(address uint64) (uint64, error) {
		data, err := memory.Read(ctx, e.Env.Kernel, address, width)
		if err != nil {
			return 0, err
		}
		if width == 4 {
			return uint64(binary.LittleEndian.Uint32(data)), nil
		}
		return binary.LittleEndian.Uint64(data), nil
	}
	links := func(address uint64) (uint64, uint64, error) {
		if address == 0 || address%uint64(width) != 0 {
			return 0, 0, fmt.Errorf("invalid module list link %#x", address)
		}
		data, err := memory.Read(ctx, e.Env.Kernel, address, width*2)
		if err != nil {
			return 0, 0, err
		}
		if width == 4 {
			return uint64(binary.LittleEndian.Uint32(data)), uint64(binary.LittleEndian.Uint32(data[4:])), nil
		}
		return binary.LittleEndian.Uint64(data), binary.LittleEndian.Uint64(data[8:]), nil
	}
	head := h.LoadedModuleList
	current, tail, err := links(head)
	if err != nil {
		return nil, err
	}
	if current == head {
		return nil, fmt.Errorf("crash module list is empty")
	}
	previous := head
	seen := map[uint64]bool{}
	probed := map[uint64]kernelPE{}
	var candidates []windowsCandidate
	for current != head {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(seen) >= 4096 || seen[current] {
			return nil, fmt.Errorf("module discovery list cycle or 4096-node limit")
		}
		seen[current] = true
		next, back, err := links(current)
		if err != nil {
			return nil, err
		}
		if back != previous {
			return nil, fmt.Errorf("module discovery backlink mismatch at %#x", current)
		}
		for offset := uint64(0); offset < 256; offset += uint64(width) {
			slot, err := memory.Add(current, offset)
			if err != nil {
				return nil, err
			}
			base, err := readPointer(slot)
			if err != nil {
				continue
			}
			if base == 0 || base&0xfff != 0 {
				continue
			}
			image, known := probed[base]
			if !known {
				image, err = e.candidatePE(ctx, base)
				probed[base] = image
				if err != nil {
					continue
				}
			}
			if image.Identity.Database == "" {
				continue
			}
			candidates = append(candidates, windowsCandidate{base: base, image: image, method: "crash-header-module-list-pe", link: current, slot: slot})
			if len(candidates) > 128 {
				return nil, fmt.Errorf("too many module kernel candidates; supply --kernel-base")
			}
		}
		previous, current = current, next
	}
	if previous != tail {
		return nil, fmt.Errorf("module discovery tail mismatch")
	}
	return candidates, nil
}

func (e *Engine) validateWindowsCandidate(ctx context.Context, h memory.CrashHeader, c windowsCandidate, table *symbols.ISF) error {
	if err := table.MatchPDB(c.image.Identity.Database, c.image.Identity.GUID, c.image.Identity.Age); err != nil {
		return err
	}
	if (e.Config.Arch == "x64") != (table.PointerSize() == 8) {
		return fmt.Errorf("discovered symbol pointer size disagrees with dump architecture")
	}
	if arch := table.Architecture(); arch != "" && ((e.Config.Arch == "x64" && arch != "x86_64") || (e.Config.Arch != "x64" && arch != "i386")) {
		return fmt.Errorf("PDB machine disagrees with discovered dump architecture")
	}
	for _, anchor := range []struct {
		name    string
		address uint64
	}{{"PsLoadedModuleList", h.LoadedModuleList}, {"PsActiveProcessHead", h.ActiveProcessHead}} {
		if anchor.address == 0 {
			continue
		}
		s, err := table.Lookup(anchor.name)
		if err != nil {
			return err
		}
		address, err := memory.Add(c.base, s.Address)
		if err != nil {
			return err
		}
		if address != anchor.address {
			return fmt.Errorf("symbol %s does not match crash-header anchor", anchor.name)
		}
		if _, err = memory.Read(ctx, e.Env.Kernel, address, table.PointerSize()*2); err != nil {
			return fmt.Errorf("verify %s: %w", anchor.name, err)
		}
	}
	if c.link != 0 {
		r := object.Reader{Layer: e.Env.Kernel, Symbols: table}
		typ := "_KLDR_DATA_TABLE_ENTRY"
		link, err := r.Field(typ, "InLoadOrderLinks")
		if err != nil {
			typ = "_LDR_DATA_TABLE_ENTRY"
			link, err = r.Field(typ, "InLoadOrderLinks")
		}
		if err != nil {
			return err
		}
		if c.link < link.Offset {
			return fmt.Errorf("LDR object offset underflows")
		}
		field, err := r.Field(typ, "DllBase")
		if err != nil {
			return err
		}
		address, err := memory.Add(c.link-link.Offset, field.Offset)
		if err != nil {
			return err
		}
		if address != c.slot {
			return fmt.Errorf("probed kernel pointer is not the symbol-declared DllBase field")
		}
	}
	return nil
}

func (e *Engine) discoverWindows(ctx context.Context, h memory.CrashHeader) error {
	if h.LoadedModuleList == 0 {
		return fmt.Errorf("crash header has no loaded-module anchor; provide --kernel-base")
	}
	var candidates []windowsCandidate
	kdbg, kdbgErr := e.kdbgCandidate(ctx, h)
	if kdbgErr == nil {
		candidates = []windowsCandidate{kdbg}
	} else {
		var err error
		candidates, err = e.moduleCandidates(ctx, h)
		if err != nil {
			return fmt.Errorf("KDBG path: %v; module-list path: %w", kdbgErr, err)
		}
	}
	type match struct {
		candidate  windowsCandidate
		table      *symbols.ISF
		location   string
		resolution *symbols.PDBResolution
	}
	matches := map[uint64]match{}
	var failures []string
	tables := map[string]*symbols.ISF{}
	locations := map[string]string{}
	resolutions := map[string]*symbols.PDBResolution{}
	lookupErrors := map[string]bool{}
	lookupSeen := map[string]bool{}
	process := func(candidates []windowsCandidate) error {
		for _, c := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			key := strings.ToLower(c.image.Identity.Database) + "/" + c.image.Identity.GUID + "/" + strconv.FormatUint(c.image.Identity.Age, 10)
			if lookupErrors[key] {
				continue
			}
			table := tables[key]
			if table == nil {
				if !lookupSeen[key] && len(lookupSeen) >= 8 {
					return fmt.Errorf("Windows discovery exceeds eight distinct kernel PDB identities; supply --symbols/--kernel-base")
				}
				lookupSeen[key] = true
				var err error
				table, locations[key], resolutions[key], err = e.tableForWindowsCandidate(ctx, c.image.Identity)
				if err != nil {
					lookupErrors[key] = true
					if len(failures) < 5 {
						failures = append(failures, err.Error())
					}
					continue
				}
				tables[key] = table
			}
			if err := e.validateWindowsCandidate(ctx, h, c, table); err != nil {
				if len(failures) < 5 {
					failures = append(failures, err.Error())
				}
				continue
			}
			matches[c.base] = match{c, table, locations[key], resolutions[key]}
		}
		return nil
	}
	if err := process(candidates); err != nil {
		return err
	}
	if len(matches) == 0 && kdbgErr == nil {
		fallback, err := e.moduleCandidates(ctx, h)
		if err != nil {
			return fmt.Errorf("KDBG candidate failed identity/anchor verification; module fallback: %w", err)
		}
		if err = process(fallback); err != nil {
			return err
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("no kernel candidate passed PE/PDB and symbol-anchor verification (%s); provide exact --dtb/--kernel-base/--symbols", strings.Join(failures, "; "))
	}
	if len(matches) > 1 {
		return fmt.Errorf("multiple Windows kernel bases passed discovery; provide --kernel-base")
	}
	for _, m := range matches {
		e.Env.KernelBase, e.Config.KernelBase = m.candidate.base, m.candidate.base
		e.Env.Symbols, e.Env.OS, e.Config.Symbols = m.table, "windows", m.location
		e.SymbolResolution = m.resolution
		e.WindowsDiscovery = &WindowsDiscovery{Method: m.candidate.method, Architecture: e.Config.Arch, DTB: e.Config.DTB, KernelBase: fmt.Sprintf("0x%x", m.candidate.base), LoadedModuleList: fmt.Sprintf("0x%x", h.LoadedModuleList), ActiveProcessHead: fmt.Sprintf("0x%x", h.ActiveProcessHead), Identity: m.candidate.image.Identity, Verified: true}
		if m.candidate.link != 0 {
			e.WindowsDiscovery.ModuleEntry = fmt.Sprintf("0x%x", m.candidate.link)
			e.WindowsDiscovery.BaseField = fmt.Sprintf("0x%x", m.candidate.slot)
		} else {
			e.WindowsDiscovery.DebuggerData = fmt.Sprintf("0x%x", h.DebuggerData)
		}
	}
	return nil
}
