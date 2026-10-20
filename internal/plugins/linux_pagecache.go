package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/linuxcache"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxPageCachePlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "PageVAddr PagePAddr MappingAddr InodeOffset TreeValue Slot"},
		{"uint64", "Index TreeIndex Span FlagsRaw Size CachedPages TreeNodes TreeEntries"},
		{"bool", "DumpSafe Captured"}, {"string", "Flags RecordType TreeKind"},
		{"structure", "MemoryModel InodeLookup"}, {"artifact", "FileOutput"}, {"string", "Error"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.inodepages", Upstream: "linux.pagecache.InodePages", Platform: "linux", NeedsKernel: true,
		Description: "Locate regular files or explicit inodes and recover their radix/XArray cache with auditable sparse artifacts",
		Parameters: []plugin.Parameter{
			{Name: "inode", Kind: "uint", Default: "0", Description: "Explicit regular inode address; mutually exclusive with find"},
			{Name: "find", Kind: "string", Description: "First exact regular-file path in captured mounted superblock trees; mutually exclusive with inode"},
			{Name: "max-mounts", Kind: "uint", Default: "1000000", Description: "Path lookup mount bound, 1..1000000"},
			{Name: "max-dentries", Kind: "uint", Default: "1000000", Description: "Path lookup dentry visit bound, 1..1000000"},
			{Name: "max-depth", Kind: "uint", Default: "256", Description: "Path lookup directory depth, 1..1024"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Recover cached file bytes into the case, recording uncached and unreadable ranges"},
			{Name: "maxsize", Kind: "uint", Default: "1073741824", Description: "Maximum recovered file length, 0..4294967295"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Maximum tree nodes, 1..1000000"},
			{Name: "max-pages", Kind: "uint", Default: "1000000", Description: "Maximum nonzero tree entries, 1..1000000"},
		}, Columns: columns}, linuxInodePages}}
}

type linuxPageModel struct {
	base, size, maxPFN uint64
	kind, source       string
	bounded            bool
}

func linuxPageMemoryModel(ctx context.Context, e plugin.Environment) (linuxPageModel, error) {
	var m linuxPageModel
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return m, fmt.Errorf("unsupported page memory architecture %s", e.Architecture)
	}
	t, err := e.Symbols.Type("page")
	if err != nil {
		return m, err
	}
	m.size = t.Size
	if m.size == 0 || m.size > 4096 {
		return m, fmt.Errorf("invalid struct page size")
	}
	readSymbol := func(name string) (uint64, error) {
		a, err := e.Symbol(name)
		if err != nil {
			return 0, err
		}
		return e.Objects.Scalar(ctx, a, symbols.TypeRef{Kind: "pointer"})
	}
	if _, err := e.Symbols.Lookup("mem_section"); err == nil {
		if e.Architecture != "x64" {
			return m, fmt.Errorf("32-bit sparse memory model requires an independently supported section decoder")
		}
		m.kind = "sparsemem_vmemmap"
		m.source = "Intel four-level fixed VMEMMAP_START"
		m.base = 0xffffea0000000000
		if _, err = e.Symbols.Lookup("vmemmap_base"); err == nil {
			m.base, err = readSymbol("vmemmap_base")
			if err != nil {
				return m, err
			}
			m.source = "vmemmap_base symbol value"
		}
	} else if _, err := e.Symbols.Lookup("mem_map"); err == nil {
		m.kind, m.source = "flatmem", "mem_map symbol value"
		m.base, err = readSymbol("mem_map")
		if err != nil {
			return m, err
		}
	} else {
		return m, fmt.Errorf("unsupported Linux page memory model (no vmemmap or flatmem evidence)")
	}
	if m.base == 0 || m.base%uint64(e.Symbols.PointerSize()) != 0 || e.Architecture == "x64" && m.base>>48 != 0xffff {
		return m, fmt.Errorf("invalid page-array base %#x", m.base)
	}
	if _, err := e.Symbols.Lookup("max_pfn"); err == nil {
		m.maxPFN, err = readSymbol("max_pfn")
		if err != nil {
			return m, err
		}
		if m.maxPFN == 0 {
			return m, fmt.Errorf("invalid max_pfn")
		}
		m.bounded = true
	}
	return m, nil
}
func (m linuxPageModel) physical(page uint64) (uint64, error) {
	if page < m.base || (page-m.base)%m.size != 0 {
		return 0, fmt.Errorf("struct page is outside/aligned incorrectly in page array")
	}
	pfn := (page - m.base) / m.size
	if pfn > ^uint64(0)/4096 || m.bounded && pfn >= m.maxPFN {
		return 0, fmt.Errorf("page PFN exceeds memory model")
	}
	return pfn * 4096, nil
}
func (m linuxPageModel) value() evidence.Value {
	d := map[string]any{"model": m.kind, "source": m.source, "base": fmt.Sprintf("0x%x", m.base), "struct_page_size": strconv.FormatUint(m.size, 10), "page_size": "4096", "max_pfn_available": m.bounded}
	if m.bounded {
		d["max_pfn"] = strconv.FormatUint(m.maxPFN, 10)
	}
	return evidence.Value{Kind: "structure", Data: d}
}
func linuxPageFlags(e plugin.Environment, flags uint64) (string, error) {
	enum, err := e.Symbols.Enumeration("pageflags")
	if err != nil {
		return "", err
	}
	var names []string
	for name, index := range enum.Constants {
		if !strings.HasPrefix(name, "PG_") {
			continue
		}
		bit, err := strconv.ParseUint(string(index), 10, 64)
		if err != nil || bit >= 64 {
			continue
		}
		if flags&(uint64(1)<<bit) != 0 {
			names = append(names, strings.TrimPrefix(name, "PG_"))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ","), nil
}

type linuxCachedPage struct{ index, physical uint64 }

func linuxInodePages(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	inode, err := strconv.ParseUint(p["inode"], 0, 64)
	if err != nil || (inode == 0) == (p["find"] == "") {
		return fmt.Errorf("exactly one of a nonzero inode address or find path is required")
	}

	dump, maxSize, err := extractionOptions(p)
	if err != nil || maxSize > 4294967295 {
		return fmt.Errorf("invalid dump/maxsize parameters")
	}
	maxNodes, er1 := strconv.ParseUint(p["max-nodes"], 0, 64)
	maxPages, er2 := strconv.ParseUint(p["max-pages"], 0, 64)
	if er1 != nil || er2 != nil || maxNodes == 0 || maxPages == 0 || maxNodes > 1000000 || maxPages > 1000000 {
		return fmt.Errorf("tree bounds must be 1..1000000")
	}
	lookup := evidence.Missing("not_requested", nil)
	if p["find"] != "" {
		inode, lookup, err = linuxResolveCachedFile(ctx, e, p)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			cells := map[string]evidence.Value{}
			for _, column := range linuxPageCachePlugins()[0].spec.Columns {
				cells[column.Name] = evidence.Missing("not_reached", nil)
			}
			cells["RecordType"], cells["InodeLookup"], cells["Error"] = evidence.Text("lookup_diagnostic"), lookup, evidence.Missing("inode_lookup_incomplete", err)
			row := evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
			if emitErr := out(row); emitErr != nil {
				return emitErr
			}
			return err
		}
	}
	ino, err := e.Objects.Uint(ctx, inode, "inode", "i_ino")
	if err != nil {
		return err
	}
	if ino == 0 {
		return fmt.Errorf("invalid inode number")
	}
	count, err := e.Objects.Int(ctx, inode, "inode", "i_count.counter")
	if err != nil {
		return err
	}
	if count < 0 {
		return fmt.Errorf("negative inode reference count")
	}
	mode, err := e.Objects.Uint(ctx, inode, "inode", "i_mode")
	if err != nil {
		return err
	}
	if mode&0170000 != 0100000 {
		return fmt.Errorf("inode is not a regular file")
	}
	sizeSigned, err := e.Objects.Int(ctx, inode, "inode", "i_size")
	if err != nil {
		return err
	}
	if sizeSigned < 0 {
		return fmt.Errorf("negative inode size")
	}
	size := uint64(sizeSigned)
	if dump && size > maxSize {
		return fmt.Errorf("inode length %d exceeds maxsize %d", size, maxSize)
	}
	mapping, err := e.Objects.Uint(ctx, inode, "inode", "i_mapping")
	if err != nil {
		return err
	}
	if mapping == 0 {
		return fmt.Errorf("inode has no address_space")
	}
	nrPages, err := e.Objects.Uint(ctx, mapping, "address_space", "nrpages")
	if err != nil {
		return err
	}
	model, err := linuxPageMemoryModel(ctx, e)
	if err != nil {
		return err
	}
	columns := linuxPageCachePlugins()[0].spec.Columns
	baseRow := func(kind string) evidence.Row {
		cells := map[string]evidence.Value{}
		for _, col := range columns {
			cells[col.Name] = evidence.Missing("not_applicable", nil)
		}
		cells["RecordType"], cells["InodeOffset"], cells["Size"], cells["CachedPages"], cells["MappingAddr"], cells["MemoryModel"] = evidence.Text(kind), evidence.Address(inode), evidence.Number(size), evidence.Number(nrPages), evidence.Address(mapping), model.value()
		cells["InodeLookup"] = lookup
		return evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", inode)}}
	}
	pages := []linuxCachedPage{}
	var failures pluginFailures
	var outputErr error
	stats, treeErr := linuxcache.Walk(ctx, e.Objects, mapping, linuxcache.Limits{Nodes: maxNodes, Entries: maxPages}, func(entry linuxcache.Entry) error {
		row := baseRow(entry.Kind)
		c := row.Cells
		c["TreeIndex"], c["Span"], c["TreeValue"], c["Slot"] = evidence.Number(entry.Index), evidence.Number(entry.Span), evidence.Address(entry.Value), evidence.Address(entry.Slot)
		if entry.Kind == "page" {
			row.Provenance.Offset = fmt.Sprintf("0x%x", entry.Value)
			c["PageVAddr"] = evidence.Address(entry.Value)
			var pageErr error
			mappingRead, me := e.Objects.Uint(ctx, entry.Value, "page", "mapping")
			index, ie := e.Objects.Uint(ctx, entry.Value, "page", "index")
			physical, pe := model.physical(entry.Value)
			flags, fe := e.Objects.Uint(ctx, entry.Value, "page", "flags")
			if me == nil {
				c["MappingAddr"] = evidence.Address(mappingRead)
			} else {
				c["MappingAddr"] = evidence.Missing("page_mapping_unreadable", me)
			}
			if ie == nil {
				c["Index"] = evidence.Number(index)
			} else {
				c["Index"] = evidence.Missing("page_index_unreadable", ie)
			}
			if pe == nil {
				c["PagePAddr"] = evidence.Address(physical)
			} else {
				c["PagePAddr"] = evidence.Missing("page_physical_unavailable", pe)
			}
			if fe == nil {
				c["FlagsRaw"] = evidence.Number(flags)
				var names string
				names, fe = linuxPageFlags(e, flags)
				if fe == nil {
					c["Flags"] = evidence.Text(names)
				}
			}
			if fe != nil {
				if c["FlagsRaw"].Kind == "missing" {
					c["FlagsRaw"] = evidence.Missing("page_flags_unreadable", fe)
				}
				c["Flags"] = evidence.Missing("page_flags_unavailable", fe)
			}
			pageErr = errors.Join(me, ie, pe, fe)
			if me == nil && mappingRead != mapping {
				pageErr = errors.Join(pageErr, fmt.Errorf("page mapping %#x differs from inode mapping %#x", mappingRead, mapping))
			}
			if ie == nil && index != entry.Index {
				pageErr = errors.Join(pageErr, fmt.Errorf("page index %d differs from tree index %d", index, entry.Index))
			}
			if entry.Span != 1 {
				pageErr = errors.Join(pageErr, fmt.Errorf("multi-index folio extraction is not supported (span %d)", entry.Span))
			}
			safe := pageErr == nil && index <= ^uint64(0)/4096 && index*4096 < size
			c["DumpSafe"] = evidence.Value{Kind: "bool", Data: safe}
			if pe == nil {
				_, readErr := memory.Read(ctx, e.Physical, physical, 4096)
				c["Captured"] = evidence.Value{Kind: "bool", Data: readErr == nil}
				if readErr != nil {
					pageErr = errors.Join(pageErr, fmt.Errorf("page payload: %w", readErr))
				}
			}
			// A missing payload is a physical read gap, not an uncached logical page.
			if safe {
				pages = append(pages, linuxCachedPage{index, physical})
			}
			if pageErr != nil {
				failures.add(pageErr)
				c["Error"] = evidence.Missing("page_incomplete", pageErr)
			}
		}
		if entry.Kind == "sibling" || entry.Kind == "internal_value" {
			err := fmt.Errorf("unsupported XArray %s entry at index %d; folio/retry coverage is unresolved", entry.Kind, entry.Index)
			failures.add(err)
			c["Error"] = evidence.Missing("cache_entry_unsupported", err)
		}

		outputErr = out(row)
		return outputErr
	})
	if outputErr != nil {
		return outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	failures.add(treeErr)
	summary := baseRow("summary")
	summary.Cells["TreeKind"], summary.Cells["TreeNodes"], summary.Cells["TreeEntries"] = evidence.Text(stats.Kind), evidence.Number(stats.Nodes), evidence.Number(stats.Entries)
	if dump {
		value, er := recoverLinuxCachedFile(ctx, e, inode, size, pages, failures.err("cache coverage"))
		summary.Cells["FileOutput"] = value
		failures.add(er)
	}
	if err := failures.err("Linux inode page cache"); err != nil {
		summary.Cells["Error"] = evidence.Missing("cache_incomplete", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := out(summary); err != nil {
		return err
	}
	return failures.err("Linux inode page cache")
}

func recoverLinuxCachedFile(ctx context.Context, e plugin.Environment, inode, size uint64, pages []linuxCachedPage, treeErr error) (evidence.Value, error) {
	if e.Artifacts == nil {
		err := fmt.Errorf("case artifact sink required for dump")
		return evidence.Missing("extraction_unavailable", err), err
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].index < pages[j].index })
	for _, page := range pages {
		if page.index > ^uint64(0)/4096 || page.index*4096 >= size || page.physical > ^uint64(0)-4095 {
			err := fmt.Errorf("invalid cached file page interval")
			return evidence.Missing("extraction_unavailable", err), err
		}
	}
	for i := 1; i < len(pages); i++ {
		if pages[i].index == pages[i-1].index {
			err := fmt.Errorf("duplicate file cache index")
			return evidence.Missing("extraction_unavailable", err), err
		}
	}
	layer := fmt.Sprintf("file-cache:inode:0x%x", inode)
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: fmt.Sprintf("inode_0x%x.dmp", inode), Size: size, Layer: layer, Offset: "0x0"})
	if err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	missing := errors.New("uncached_page: logical file bytes have no validated cache page")
	if treeErr != nil {
		missing = fmt.Errorf("coverage_unknown_due_to_cache_error: %w", treeErr)
	}
	var position uint64
	for _, page := range pages {
		offset := page.index * 4096
		if offset > position {
			err = w.PadZero(ctx, offset-position, position, layer, missing)
			if err != nil {
				break
			}
		}
		err = writeRegion(ctx, e.Physical, w, page.physical, min(uint64(4096), size-offset))
		if err != nil {
			break
		}
		position = offset + min(uint64(4096), size-offset)
	}
	if err == nil && position < size {
		err = w.PadZero(ctx, size-position, position, layer, missing)
	}
	artifact, finishErr := w.Finish(ctx, err)
	return evidence.Value{Kind: "artifact", Data: artifact}, errors.Join(err, finishErr)
}
