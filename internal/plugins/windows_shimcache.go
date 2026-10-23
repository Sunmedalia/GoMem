package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/winshimcache"
)

func windowsShimcachePlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Order", Kind: "uint64"},
		{Name: "Last Modified", Kind: "string"},
		{Name: "Last Update", Kind: "string"},
		{Name: "Exec Flag", Kind: "string"},
		{Name: "File Size", Kind: "uint64"},
		{Name: "File Path", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Layout", Kind: "string"},
		{Name: "EntryOffset", Kind: "address"},
		{Name: "Head", Kind: "address"},
		{Name: "Module", Kind: "string"},
		{Name: "ModuleBase", Kind: "address"},
		{Name: "DataSection", Kind: "address"},
		{Name: "PageSection", Kind: "address"},
		{Name: "HandleTarget", Kind: "address"},
		{Name: "StorageOffset", Kind: "address"},
		{Name: "FieldEvidence", Kind: "structure"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Offset", Kind: "address"},
		{Name: "Requested", Kind: "uint64"},
		{Name: "Captured", Kind: "uint64"},
		{Name: "Raw", Kind: "bytes"},
		{Name: "ReadComplete", Kind: "bool"},
		{Name: "Error", Kind: "missing"},
	}
	return []builtin{{spec: plugin.Spec{
		Name:        "windows.shimcachemem",
		Upstream:    "windows.shimcachemem.ShimcacheMem",
		Platform:    "windows",
		NeedsKernel: true,
		Description: "Enumerate Shimcache entries natively; this preview implements the Windows 8+ discovery route",
		Parameters: []plugin.Parameter{
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Loaded module and entry traversal bound, 1..1000000"},
			{Name: "max-pointers", Kind: "uint", Default: "1048576", Description: "Module .data pointer-slot scan bound, 1..1048576"},
			{Name: "max-entries", Kind: "uint", Default: "1000000", Description: "Decoded Shimcache entry bound, 1..1000000"},
			{Name: "max-evidence", Kind: "uint", Default: "4096", Description: "Non-null handle-candidate evidence bound, 1..1048576"},
		},
		Columns: columns,
	}, run: windowsShimcache}}
}

// shimcacheReadLayer retains every actual native read. A single layer is used
// by PE discovery, predicates, linked traversal and field projection so the
// emitted evidence can be independently replayed against the original image.
type shimcacheReadLayer struct {
	layer    memory.MemoryLayer
	out      plugin.Emit
	failures *pluginFailures
	reads    uint64
	bytes    uint64
	errors   uint64
}

func (l *shimcacheReadLayer) Name() string           { return l.layer.Name() }
func (l *shimcacheReadLayer) Ranges() []memory.Range { return l.layer.Ranges() }

func (l *shimcacheReadLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := l.layer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		err = errors.Join(err, fmt.Errorf("invalid Shimcache read count %d for %d bytes at %#x", n, len(p), at))
		n = 0
	}
	l.reads++
	l.bytes += uint64(n)
	if err != nil {
		l.errors++
	}
	errorCell := evidence.Missing("no_error", nil)
	if err != nil {
		errorCell = evidence.Missing("read_error", err)
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"RecordType":   evidence.Text("memory_read"),
		"Offset":       evidence.Address(at),
		"Requested":    evidence.Number(uint64(len(p))),
		"Captured":     evidence.Number(uint64(n)),
		"Raw":          evidence.Bytes(p[:n]),
		"ReadComplete": evidence.Bool(err == nil && n == len(p)),
		"Error":        errorCell,
		"Coverage": {Kind: "structure", Data: map[string]any{
			"layer": l.layer.Name(), "purpose": "shimcache_native_read",
		}},
	}, Provenance: evidence.Provenance{Layer: l.layer.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	if emitErr := l.out(row); emitErr != nil {
		return n, emitErr
	}
	if err != nil {
		l.failures.add(fmt.Errorf("read %#x (%d bytes): %w", at, len(p), err))
	}
	return n, err
}

type shimcacheDiscoveryCoverage struct {
	ModulesExamined uint64
	ModulesMatched  uint64
	Scanned         uint64
	NullPointers    uint64
	NonCanonical    uint64
	Unmapped        uint64
	Candidates      uint64
	Heads           uint64
	HeadValues      []uint64
	Targets         []uint64
	Storages        []uint64
}

func windowsShimcache(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("windows.shimcachemem requires kernel translation and symbols")
	}
	nodes, err := shimcacheUint(p, "max-nodes", 1, 1000000)
	if err != nil {
		return err
	}
	maxPointers, err := shimcacheUint(p, "max-pointers", 1, 1048576)
	if err != nil {
		return err
	}
	maxEntries, err := shimcacheUint(p, "max-entries", 1, 1000000)
	if err != nil {
		return err
	}
	maxEvidence, err := shimcacheUint(p, "max-evidence", 1, 1048576)
	if err != nil {
		return err
	}
	isf, ok := e.Symbols.(*symbols.ISF)
	if !ok {
		return fmt.Errorf("windows.shimcachemem requires native ISF symbols")
	}
	selection, err := winshimcache.SelectLayout(isf)
	if err != nil {
		return err
	}
	layout, err := winshimcache.LayoutData(selection.Layout)
	if err != nil {
		return err
	}
	kernel := e.Kernel
	var failures pluginFailures
	layer := &shimcacheReadLayer{layer: kernel, out: out, failures: &failures}
	env := e
	env.Kernel = layer
	env.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
	coverage := map[string]any{
		"route":                 familyName(selection.Family),
		"layout":                selection.Layout,
		"layout_sha256":         rawDigest(layout),
		"symbols_sha256":        e.Symbols.Digest(),
		"versioned":             selection.Versioned,
		"fallback_checks":       selection.FallbackChecks,
		"modules_examined":      uint64(0),
		"modules_matched":       uint64(0),
		"pointers_scanned":      uint64(0),
		"null_pointers":         uint64(0),
		"noncanonical_rejected": uint64(0),
		"unmapped_rejected":     uint64(0),
		"discovery_candidates":  uint64(0),
		"heads_found":           uint64(0),
		"entries_emitted":       uint64(0),
		"entries_rejected":      uint64(0),
		"reads":                 uint64(0),
		"captured_bytes":        uint64(0),
		"read_failures":         uint64(0),
		"completed":             false,
		"unsupported_route":     false,
	}
	status := "complete"
	defer func() {
		coverage["reads"] = layer.reads
		coverage["captured_bytes"] = layer.bytes
		coverage["read_failures"] = layer.errors
		if failures.count != 0 || err != nil {
			status = "failed"
		}
		coverage["status"] = status
		coverage["completed"] = err == nil && failures.count == 0
		coverage["error_count"] = failures.count
		if failures.first != nil {
			coverage["first_error"] = failures.first.Error()
		}
		row := evidence.Row{ID: "shimcache-summary", Cells: map[string]evidence.Value{
			"RecordType": evidence.Text("summary"),
			"Coverage":   {Kind: "structure", Data: coverage},
		}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: "0x0"}}
		summaryErr := out(row)
		err = errors.Join(err, failures.err("Shimcache analysis"), summaryErr)
	}()
	if selection.Family != winshimcache.Family8OrLater {
		coverage["unsupported_route"] = true
		status = "unsupported"
		return fmt.Errorf("Shimcache route %s is not implemented in this development preview", familyName(selection.Family))
	}
	module, data, page, discovery, err := shimcacheFindModernModule(ctx, env, kernel, isf, selection, layout, maxPointers, maxEvidence, int(nodes))
	coverage["modules_examined"] = discovery.ModulesExamined
	coverage["modules_matched"] = discovery.ModulesMatched
	coverage["pointers_scanned"] = discovery.Scanned
	coverage["null_pointers"] = discovery.NullPointers
	coverage["noncanonical_rejected"] = discovery.NonCanonical
	coverage["unmapped_rejected"] = discovery.Unmapped
	coverage["discovery_candidates"] = discovery.Candidates
	coverage["heads_found"] = discovery.Heads
	if err != nil {
		return err
	}
	linked, err := winshimcache.NewLinkedEntryReader(layer, layout, isf, e.PointerMask)
	if err != nil {
		return err
	}
	fields, err := winshimcache.NewEntryFieldsReader(layer, layout, isf, e.PointerMask)
	if err != nil {
		return err
	}
	temporal, err := winshimcache.NewTemporalReader(layer, layout, isf, e.PointerMask)
	if err != nil {
		return err
	}
	head, err := winshimcache.ChooseModernHead(selection, discovery.HeadValues)
	if err != nil {
		return err
	}
	handleTarget, storage, err := discoveryTarget(discovery, head)
	if err != nil {
		return err
	}
	listOffset, err := shimcacheListOffset(layout)
	if err != nil {
		return err
	}
	coverage["selected_head"] = evidence.Address(head)
	coverage["selected_handle"] = evidence.Address(handleTarget)
	coverage["selected_storage"] = evidence.Address(storage)
	coverage["module"] = module.Name
	coverage["module_offset"] = evidence.Address(module.Offset)
	coverage["module_base"] = evidence.Address(module.Base)
	coverage["module_size"] = evidence.Number(module.Size)
	coverage["data_section"] = sectionEvidence(data)
	coverage["page_section"] = sectionEvidence(page)
	coverage["layout_sha256"] = linked.LayoutSHA256
	coverage["kernel_sha256"] = fields.KernelSHA256
	coverage["temporal_layout_sha256"] = temporal.LayoutSHA256
	coverage["list_offset"] = evidence.Number(listOffset)

	// WalkList validates both directions and rejects cycles. The pinned entry
	// predicate remains an additional required check, not a replacement for a
	// complete list traversal.
	order := uint64(0)
	walkErr := env.Objects.WalkList(ctx, head, listOffset, int(nodes), func(at uint64) error {
		if order >= maxEntries {
			return fmt.Errorf("Shimcache entry budget exceeded %d", maxEntries)
		}
		valid, validErr := linked.Valid(ctx, at)
		if validErr != nil || !valid {
			coverage["entries_rejected"] = coverage["entries_rejected"].(uint64) + 1
			if validErr == nil {
				validErr = fmt.Errorf("entry %#x failed pinned linked-entry predicate", at)
			}
			return validErr
		}
		modified, modifiedErr := temporal.LastModified(ctx, at)
		updated, updatedErr := temporal.LastUpdate(ctx, at)
		exec, execErr := temporal.ExecFlag(ctx, at)
		size, sizeErr := fields.FileSize(ctx, at)
		path, pathErr := fields.FilePath(ctx, at)
		fieldErr := errors.Join(modifiedErr, updatedErr, execErr, sizeErr, pathErr)
		fieldEvidence := map[string]any{
			"layout":        selection.Layout,
			"list_entry":    evidence.Address(at + listOffset),
			"last_modified": temporalEvidence(modified),
			"last_update":   temporalEvidence(updated),
			"exec_flag":     temporalEvidence(exec),
			"file_size": map[string]any{
				"value": size, "method": "SHIM_CACHE_ENTRY.FileSize",
			},
			"file_path": map[string]any{
				"value": path.Value, "address": evidence.Address(path.Address),
				"requested": evidence.Number(path.Requested), "captured": evidence.Number(uint64(len(path.Raw))),
				"raw_sha256": rawDigest(path.Raw), "complete": evidence.Bool(path.Complete),
			},
			"linked_entry_valid": evidence.Bool(valid),
		}
		row := evidence.Row{ID: fmt.Sprintf("shimcache-entry-%d", order), Cells: map[string]evidence.Value{
			"Order": evidence.Number(order), "Last Modified": modified.Value, "Last Update": updated.Value,
			"Exec Flag": exec.Value, "File Size": size, "File Path": path.Value,
			"RecordType": evidence.Text("entry"), "Layout": evidence.Text(selection.Layout),
			"EntryOffset": evidence.Address(at), "Head": evidence.Address(head),
			"Module": evidence.Text(module.Name), "ModuleBase": evidence.Address(module.Base),
			"DataSection": evidence.Address(data.Address), "PageSection": evidence.Address(page.Address),
			"HandleTarget": evidence.Address(handleTarget), "StorageOffset": evidence.Address(storage),
			"FieldEvidence": {Kind: "structure", Data: fieldEvidence},
			"Coverage": {Kind: "structure", Data: map[string]any{
				"entry_index": order, "layout": selection.Layout, "route": familyName(selection.Family),
			}},
			"Error": evidence.Missing("no_error", nil),
		}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", at)}}
		if fieldErr != nil {
			row.Cells["Error"] = evidence.Missing("field_read_error", fieldErr)
			failures.add(fieldErr)
		}
		if err := out(row); err != nil {
			return err
		}
		order++
		coverage["entries_emitted"] = order
		return nil
	})
	return walkErr
}

func shimcacheFindModernModule(ctx context.Context, e plugin.Environment, probe memory.MemoryLayer, isf *symbols.ISF, selection winshimcache.Selection, layout []byte, maxPointers, maxEvidence uint64, maxModules int) (winshimcache.LoadedModule, winshimcache.ModuleSection, winshimcache.ModuleSection, shimcacheDiscoveryCoverage, error) {
	var coverage shimcacheDiscoveryCoverage
	modules, err := shimcacheLoadedModules(ctx, e, maxModules)
	if err != nil {
		return winshimcache.LoadedModule{}, winshimcache.ModuleSection{}, winshimcache.ModuleSection{}, coverage, err
	}
	wanted := winshimcache.ModernModuleNames(selection)
	for _, module := range modules {
		coverage.ModulesExamined++
		if !containsExact(wanted, module.Name) {
			continue
		}
		coverage.ModulesMatched++
		handle, err := winshimcache.NewHandleReader(e.Kernel, layout, isf, e.PointerMask)
		if err != nil {
			return winshimcache.LoadedModule{}, winshimcache.ModuleSection{}, winshimcache.ModuleSection{}, coverage, err
		}
		data, err := winshimcache.ReadModuleSection(ctx, e.Kernel, module, ".data")
		if err != nil {
			return winshimcache.LoadedModule{}, winshimcache.ModuleSection{}, winshimcache.ModuleSection{}, coverage, err
		}
		page, err := winshimcache.ReadModuleSection(ctx, e.Kernel, module, "PAGE")
		if err != nil {
			return winshimcache.LoadedModule{}, winshimcache.ModuleSection{}, winshimcache.ModuleSection{}, coverage, err
		}
		result, scanErr := (winshimcache.ModernScanner{
			Layer: e.Kernel, Probe: probe, Reader: handle, Module: module, Data: data, Page: page,
			MaxPointers: maxPointers, MaxEvidence: maxEvidence,
		}).Scan(ctx)
		coverage.Scanned += result.Scanned
		coverage.NullPointers += result.NullPointers
		coverage.NonCanonical += result.NonCanonical
		coverage.Unmapped += result.Unmapped
		coverage.Candidates += uint64(len(result.Evidence))
		coverage.Heads += uint64(len(result.Heads))
		coverage.HeadValues = append([]uint64(nil), result.Heads...)
		coverage.Targets = append([]uint64(nil), result.HandleTargets...)
		coverage.Storages = append([]uint64(nil), result.StorageOffsets...)
		if scanErr != nil {
			return module, data, page, coverage, scanErr
		}
		return module, data, page, coverage, nil
	}
	return winshimcache.LoadedModule{}, winshimcache.ModuleSection{}, winshimcache.ModuleSection{}, coverage, fmt.Errorf("Shimcache modules %v were not found", wanted)
}

func shimcacheLoadedModules(ctx context.Context, e plugin.Environment, max int) ([]winshimcache.LoadedModule, error) {
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return nil, err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	link, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if errors.Is(err, object.ErrFieldAbsent) {
		typ = "_LDR_DATA_TABLE_ENTRY"
		link, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return nil, err
	}
	var modules []winshimcache.LoadedModule
	err = e.Objects.WalkList(ctx, head, link.Offset, max, func(at uint64) error {
		name, nameErr := unicodeString(ctx, e, at, typ, "BaseDllName")
		base, baseErr := e.Objects.Uint(ctx, at, typ, "DllBase")
		size, sizeErr := e.Objects.Uint(ctx, at, typ, "SizeOfImage")
		if nameErr != nil || baseErr != nil || sizeErr != nil {
			return errors.Join(nameErr, baseErr, sizeErr)
		}
		modules = append(modules, winshimcache.LoadedModule{Offset: at, Base: base, Size: size, Name: name})
		return nil
	})
	return modules, err
}

func shimcacheListOffset(layout []byte) (uint64, error) {
	var doc struct {
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err := json.Unmarshal(layout, &doc); err != nil {
		return 0, err
	}
	entry, ok := doc.Types["SHIM_CACHE_ENTRY"]
	if !ok {
		return 0, fmt.Errorf("layout has no SHIM_CACHE_ENTRY")
	}
	f, ok := entry.Fields["ListEntry"]
	if !ok {
		return 0, fmt.Errorf("layout has no SHIM_CACHE_ENTRY.ListEntry")
	}
	return f.Offset, nil
}

func shimcacheUint(p map[string]string, name string, lo, hi uint64) (uint64, error) {
	n, err := strconv.ParseUint(p[name], 0, 64)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be %d..%d", name, lo, hi)
	}
	return n, nil
}

func familyName(f winshimcache.Family) string {
	switch f {
	case winshimcache.Family8OrLater:
		return "windows-8-or-later"
	case winshimcache.Family2003To7:
		return "windows-2003-to-7"
	case winshimcache.FamilyXP:
		return "windows-xp"
	default:
		return "unsupported"
	}
}

func sectionEvidence(s winshimcache.ModuleSection) map[string]any {
	return map[string]any{
		"name": s.Name, "address": evidence.Address(s.Address),
		"virtual_size":  evidence.Number(s.VirtualSize),
		"module_offset": evidence.Address(s.ModuleOffset),
		"module_base":   evidence.Address(s.ModuleBase),
	}
}

func temporalEvidence(v winshimcache.TemporalField) map[string]any {
	return map[string]any{
		"value": v.Value, "address": evidence.Address(v.Address),
		"requested": evidence.Number(v.Requested), "captured": evidence.Number(uint64(len(v.Raw))),
		"raw_sha256": rawDigest(v.Raw), "complete": evidence.Bool(v.Complete),
	}
}

func discoveryTarget(c shimcacheDiscoveryCoverage, head uint64) (uint64, uint64, error) {
	for i := range c.HeadValues {
		if c.HeadValues[i] == head && i < len(c.Targets) && i < len(c.Storages) {
			return c.Targets[i], c.Storages[i], nil
		}
	}
	return 0, 0, fmt.Errorf("selected head %#x has no discovery provenance", head)
}

func containsExact(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func rawDigest(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
