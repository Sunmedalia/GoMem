package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsPsXViewPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.psxview", Upstream: "windows.malware.psxview.PsXView", Platform: "windows", NeedsKernel: true,
		Description: "Compare active, pool-scanned, thread-owner and csrss process-handle views",
		Parameters:  []plugin.Parameter{{Name: "physical-offsets", Kind: "bool", Default: "false", Description: "Translate object offsets through the kernel layer, retaining failed translations"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active process traversal bound; not an upstream parameter"}, {Name: "max-processes", Kind: "uint", Default: "1000000", Description: "Maximum distinct offsets per source; not an upstream parameter"}},
		Columns:     []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "PID", Kind: "uint64"}, {Name: "pslist", Kind: "bool"}, {Name: "psscan", Kind: "bool"}, {Name: "thrdscan", Kind: "bool"}, {Name: "csrss", Kind: "bool"}, {Name: "ExitTime", Kind: "string"}, {Name: "ExitTimeRaw", Kind: "uint64"}, {Name: "Identity", Kind: "string"}, {Name: "ObjectOffset", Kind: "address"}, {Name: "ObjectLayer", Kind: "string"}, {Name: "OffsetSpace", Kind: "string"}, {Name: "Sources", Kind: "structure"}, {Name: "TranslationError", Kind: "string"}, {Name: "Created", Kind: "string"}, {Name: "CreatedRaw", Kind: "uint64"}, {Name: "Source", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "string"}},
	}, windowsPsXView}}
}

var psxviewSources = [...]string{"pslist", "psscan", "thrdscan", "csrss"}

type psxviewProcess struct {
	address uint64
	reader  *object.Reader
	space   string
	err     error
}
type psxviewIndex struct {
	env        plugin.Environment
	physical   bool
	limit      uint64
	sources    [4]map[uint64]psxviewProcess
	rejected   [4]uint64
	duplicates [4]uint64
}

// The pinned filter accepts only ASCII letters, a period and a space. Digits,
// hyphens, underscores and non-ASCII letters are deliberately rejected.
func psxviewNameValid(name string) bool {
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == ' ' {
			continue
		}
		return false
	}
	return true
}

func (x *psxviewIndex) add(ctx context.Context, source int, reader *object.Reader, address uint64) (bool, error) {
	valid, err := processObjectValid(ctx, reader, address)
	if err != nil {
		return false, err
	}
	if !valid {
		x.rejected[source]++
		return false, nil
	}
	name, err := processImageName(ctx, reader, address, false)
	if err != nil {
		return false, err
	}
	if !psxviewNameValid(name) {
		x.rejected[source]++
		return false, nil
	}
	key, space, translationErr := psxviewOffset(ctx, x.env, address, reader.Layer.Name(), x.physical)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if x.sources[source] == nil {
		x.sources[source] = map[uint64]psxviewProcess{}
	}
	if _, exists := x.sources[source][key]; exists {
		x.duplicates[source]++
	} else if uint64(len(x.sources[source])) >= x.limit {
		return false, fmt.Errorf("psxview source %s exceeds max-processes", psxviewSources[source])
	}
	x.sources[source][key] = psxviewProcess{address, reader, space, translationErr}
	return true, nil
}

func psxviewOffset(ctx context.Context, e plugin.Environment, address uint64, layerName string, physical bool) (uint64, string, error) {
	space := "kernel_virtual"
	if layerName == e.Physical.Name() && layerName != e.Kernel.Name() {
		space = "physical_pool"
	}
	if !physical {
		return address, space, nil
	}
	layer, ok := e.Kernel.(*memory.Virtual)
	if !ok || layer.Translator == nil {
		return address, space, fmt.Errorf("kernel translator is unavailable")
	}
	mapping, err := layer.Translator.Translate(ctx, address)
	if err != nil {
		// The pinned physical-offsets helper leaves the original value on a
		// page fault. Keep the actual coordinate space and error alongside it.
		return address, space, err
	}
	return mapping.Physical, "physical", nil
}

func psxviewRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsPsXViewPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}

func (x *psxviewIndex) emit(ctx context.Context, out plugin.Emit) error {
	keys := map[uint64]bool{}
	for _, source := range x.sources {
		for key := range source {
			keys[key] = true
		}
	}
	ordered := make([]uint64, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, key := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		var selected psxviewProcess
		origins := map[string]any{}
		for i, source := range x.sources {
			if process, ok := source[key]; ok {
				if selected.reader == nil {
					selected = process
				}
				origin := map[string]any{"offset": evidence.Address(process.address).String(), "layer": process.reader.Layer.Name(), "display_space": process.space}
				if process.err != nil {
					origin["translation_error"] = process.err.Error()
				}
				origins[psxviewSources[i]] = origin
			}
		}
		row, err := psxviewProcessRow(ctx, x.env, key, selected)
		if err != nil {
			return err
		}
		for i, source := range x.sources {
			_, exists := source[key]
			row.Cells[psxviewSources[i]] = evidence.Bool(exists)
		}
		row.Cells["Sources"] = evidence.Value{Kind: "structure", Data: origins}
		if err = out(row); err != nil {
			return err
		}
	}
	return nil
}

func psxviewProcessRow(ctx context.Context, e plugin.Environment, key uint64, process psxviewProcess) (evidence.Row, error) {
	reader := process.reader
	pid, err := reader.Uint(ctx, process.address, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return evidence.Row{}, err
	}
	name, err := processImageName(ctx, reader, process.address, false)
	if err != nil {
		return evidence.Row{}, err
	}
	raw, err := windowsRawTime(ctx, plugin.Environment{Objects: reader}, process.address, "_EPROCESS", "ExitTime")
	if err != nil {
		return evidence.Row{}, err
	}
	signed, err := quadSigned(reader, "_EPROCESS", "ExitTime")
	if err != nil {
		return evidence.Row{}, err
	}
	ticks, interpretable := interpretedTicks(raw, signed)
	exited := ""
	if when, datetime := volatilityFiletime(ticks); interpretable && datetime {
		exited = when.Format("2006-01-02 15:04:05+00:00")
	}
	scanEnv := e
	scanEnv.Objects = reader
	created, createdRaw := windowsTime(ctx, scanEnv, process.address, "_EPROCESS", "CreateTime")
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	row := psxviewRow(reader.Layer.Name(), process.address)
	row.Cells["Offset"] = evidence.Address(key)
	row.Cells["Name"] = evidence.Text(name)
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["ExitTime"] = evidence.Text(exited)
	row.Cells["ExitTimeRaw"] = evidence.Number(raw)
	row.Cells["Created"], row.Cells["CreatedRaw"] = created, createdRaw
	row.Cells["ObjectOffset"] = evidence.Address(process.address)
	row.Cells["ObjectLayer"] = evidence.Text(reader.Layer.Name())
	row.Cells["OffsetSpace"] = evidence.Text(process.space)
	row.Cells["Identity"] = evidence.Text(evidence.ProcessID(e.ImageHash, reader.Layer.Name(), process.address, pid, stamp))
	row.Cells["RecordType"] = evidence.Text("process")
	if process.err != nil {
		row.Cells["TranslationError"] = evidence.Missing("physical_translation_failed", process.err)
	}
	return row, nil
}

func windowsPsXView(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Physical == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.psxview requires kernel symbols and physical memory")
	}
	for _, check := range []struct{ typ, path string }{{"_EPROCESS", "ImageFileName"}, {"_EPROCESS", "UniqueProcessId"}, {"_EPROCESS", "CreateTime"}, {"_EPROCESS", "ExitTime"}, {"_EPROCESS", "Pcb.DirectoryTableBase"}, {"_EPROCESS", "ThreadListHead.Flink"}, {"_EPROCESS", "ThreadListHead.Blink"}, {"_ETHREAD", "Cid.UniqueProcess"}, {"_ETHREAD", "Cid.UniqueThread"}, {"_ETHREAD", "CreateTime"}} {
		if _, err := e.Objects.Field(check.typ, check.path); err != nil {
			return err
		}
	}
	if _, err := e.Objects.Field("_ETHREAD", "ThreadsProcess"); err != nil {
		if !errors.Is(err, object.ErrFieldAbsent) {
			return err
		}
		if _, err := e.Objects.Field("_ETHREAD", "Tcb.Process"); err != nil {
			return err
		}
	}
	physical, err := strconv.ParseBool(p["physical-offsets"])
	if err != nil {
		return err
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	limit, err := strconv.ParseUint(p["max-processes"], 0, 32)
	if err != nil || limit < 1 || limit > 1000000 {
		return fmt.Errorf("max-processes must be 1..1000000")
	}
	index := psxviewIndex{env: e, physical: physical, limit: limit}
	head, err := e.Symbol("PsActiveProcessHead")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	var active []uint64
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(address uint64) error {
		active = append(active, address)
		_, err := index.add(ctx, 0, e.Objects, address)
		return err
	})
	if err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Pro\xe3", "Proc", "Thr\xe5", "Thre")
	if err != nil {
		return err
	}
	poolStats := evidence.Missing("not_available", nil)
	err = scanPoolObjects(ctx, e, constraints, "indexed_candidates", psxviewRow, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "summary":
			poolStats = row.Cells["Coverage"]
		case "diagnostic":
			row.Cells["Source"] = evidence.Text("pool_scan")
			return out(row)
		}
		return nil
	}, func(ctx context.Context, hit poolHit) (evidence.Row, bool, error) {
		source, address, reader := 1, hit.object, hit.scan
		if hit.typ == "_ETHREAD" {
			source = 2
			address, err = threadOwnerAddress(ctx, hit.scan, hit.object)
			if err != nil {
				return evidence.Row{}, false, poolFatalError{err}
			}
			reader = e.Objects
		}
		keep, err := index.add(ctx, source, reader, address)
		if err != nil {
			return evidence.Row{}, false, poolFatalError{err}
		}
		return psxviewRow(hit.layer, address), keep, nil
	})
	if err != nil {
		return err
	}
	walker, err := newHandleWalkerMode(ctx, e, false)
	if err != nil {
		return err
	}
	walker.visit = func(ctx context.Context, item handleItem) error {
		typeName, ok, err := walker.objectType(ctx, item.header)
		if err != nil || !ok || typeName != "Process" {
			return err
		}
		_, err = index.add(ctx, 3, e.Objects, item.body)
		return err
	}
	var csrss uint64
	for _, address := range active {
		name, err := processImageName(ctx, e.Objects, address, false)
		if err != nil {
			return err
		}
		if name != "csrss.exe" {
			continue
		}
		csrss++
		if err = walker.emitProcess(ctx, address, 0, name, nil); err != nil {
			return err
		}
	}
	if err = index.emit(ctx, out); err != nil {
		return err
	}
	coverage := map[string]string{"active_candidates": formatCount(uint64(len(active))), "csrss_processes": formatCount(csrss), "csrss_handles": formatCount(uint64(walker.handles)), "csrss_unreadable_object_tables": formatCount(uint64(walker.skippedObjects)), "csrss_unreadable_handle_tables": formatCount(uint64(walker.skippedTables)), "csrss_handle_cycles": formatCount(uint64(walker.cycles))}
	for i, source := range psxviewSources {
		coverage[source] = formatCount(uint64(len(index.sources[i])))
		coverage[source+"_rejected"] = formatCount(index.rejected[i])
		coverage[source+"_duplicates"] = formatCount(index.duplicates[i])
	}
	row := psxviewRow(e.Kernel.Name(), 0)
	row.Provenance.Offset = ""
	row.Cells["RecordType"] = evidence.Text("summary")
	row.Cells["Coverage"] = poolCoverage(coverage)
	row.Cells["Sources"] = evidence.Value{Kind: "structure", Data: map[string]any{"pool": poolStats}}
	return out(row)
}
