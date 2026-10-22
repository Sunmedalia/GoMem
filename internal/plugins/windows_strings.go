package plugins

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsStringsPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.strings", Upstream: "windows.strings.Strings", Platform: "windows", NeedsKernel: true,
		Description: "Associate external strings offsets with baseline and actual physical address-space mappings",
		InputFiles:  []plugin.FileInput{{Name: "strings_file", MaxBytes: 64 << 20}},
		Parameters: []plugin.Parameter{
			{Name: "strings_file", Kind: "string", Description: "Required local strings output file or file URI; immutable snapshot limited to 64 MiB"},
			{Name: "pid", Kind: "string", Description: "Optional comma-separated active process PID filter; kernel mapping remains included"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active process list traversal bound, 1..1000000"},
			{Name: "max-lines", Kind: "uint", Default: "1000000", Description: "Input line bound, 1..1000000"},
			{Name: "max-line-bytes", Kind: "uint", Default: "1048576", Description: "Maximum complete input line bytes, 1..16777216"},
			{Name: "max-map-tables", Kind: "uint", Default: "262144", Description: "Task page-table read count, 1..16777216"},
			{Name: "max-map-entries", Kind: "uint", Default: "268435456", Description: "Task inspected page-table entries, 1..4294967296"},
			{Name: "max-mappings", Kind: "uint", Default: "1000000", Description: "Task merged mapping runs, 1..10000000"},
			{Name: "max-associations", Kind: "uint", Default: "1000000", Description: "Task query-page and address-space associations, 1..10000000"},
			{Name: "max-read-bytes", Kind: "uint", Default: "536870912", Description: "Task captured kernel metadata and page-table bytes, 1..4294967296"},
		}, Columns: []evidence.Column{
			{Name: "String", Kind: "string"}, {Name: "PhysicalAddress", Kind: "address"}, {Name: "Result", Kind: "string"}, {Name: "MappingComplete", Kind: "bool"}, {Name: "StringVerified", Kind: "bool"},
			{Name: "PhysicalAssociations", Kind: "structure"}, {Name: "BaselineAssociations", Kind: "structure"},
			{Name: "RecordType", Kind: "string"}, {Name: "InputPage", Kind: "address"}, {Name: "InputLine", Kind: "uint64"}, {Name: "InputOffset", Kind: "address"}, {Name: "RawLine", Kind: "bytes"},
			{Name: "InputSHA256", Kind: "string"}, {Name: "Mapping", Kind: "structure"}, {Name: "Offset", Kind: "address"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Resolution", Kind: "structure"},
		}}, windowsStrings}}
}

// Python byte-regex word classes are ASCII, including underscore. The pinned
// greedy decimal group backtracks if a remaining word-plus-byte cannot fit.
func parseWindowsStringLine(line []byte) (uint64, []byte, error) {
	word := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
	}
	start := 0
	for start < len(line) && !word(line[start]) {
		start++
	}
	end := start
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	for digits := end; digits > start; digits-- {
		text := digits
		for text < len(line) && !word(line[text]) {
			text++
		}
		if len(line)-text < 2 {
			continue
		}
		offset, err := strconv.ParseUint(string(line[start:digits]), 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("decimal source offset is outside uint64: %w", err)
		}
		return offset, line[text:], nil
	}
	return 0, nil, fmt.Errorf("unrecognized strings line")
}

func stringsLatin1(data []byte) string {
	var out strings.Builder
	for _, b := range data {
		out.WriteRune(rune(b))
	}
	return out.String()
}

type windowsStringsLine struct {
	line, at, offset uint64
	raw, text        []byte
}
type windowsStringsAssociation struct {
	name, identity string
	process, pid   uint64
	mapping        memory.PageMapping
	baseline       bool
	physical       bool
}

func windowsStringsOwner(assoc windowsStringsAssociation, field string) evidence.Value {
	if assoc.name == "kernel" {
		return evidence.Missing("kernel_address_space", nil)
	}
	switch field {
	case "Identity":
		return evidence.Text(assoc.identity)
	case "ProcessOffset":
		return evidence.Address(assoc.process)
	default:
		return evidence.Number(assoc.pid)
	}
}

type windowsStringsPage struct {
	baseline     map[string]struct{}
	associations []windowsStringsAssociation
}
type windowsStringsRead struct {
	memory.MemoryLayer
	a     *windowsSymbolAnalysis
	scope string
}

func (l windowsStringsRead) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if l.a.stop != nil {
		return 0, l.a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > l.a.maxBytes-l.a.coverage.Bytes {
		l.a.stop = fmt.Errorf("Windows strings acquisition byte limit exhausted")
		return 0, l.a.stop
	}
	n, err := (windowsSymbolLayer{MemoryLayer: l.MemoryLayer, analysis: l.a}).ReadAt(ctx, p, at)
	if cause := l.a.capture(l.Name(), l.scope, pe.ExportRead{Address: at, Requested: len(p), Raw: append([]byte(nil), p[:n]...), Err: err}); cause != nil {
		return n, cause
	}
	return n, err
}
func windowsStringsVirtual(at uint64, arch string) uint64 {
	if arch == "x64" {
		at &= 0x0000ffffffffffff
		if at&(1<<47) != 0 {
			at |= 0xffff000000000000
		}
	}
	return at
}

func windowsStrings(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	bounds := map[string]uint64{}
	for key, limit := range map[string]uint64{"max-lines": 1000000, "max-line-bytes": memory.MaxRead, "max-map-tables": 1 << 24, "max-map-entries": 1 << 32, "max-mappings": 10000000, "max-associations": 10000000, "max-read-bytes": 1 << 32} {
		value, cause := strconv.ParseUint(p[key], 0, 64)
		if cause != nil || value == 0 || value > limit {
			return fmt.Errorf("%s must be 1..%d", key, limit)
		}
		bounds[key] = value
	}
	if e.Kernel == nil || e.Physical == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("Windows strings needs kernel, physical memory and symbols")
	}
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return fmt.Errorf("Windows strings needs Intel translation")
	}
	input, ok := e.Inputs["strings_file"]
	if !ok || input.Reader == nil || input.Size < 0 || input.Size > 64<<20 || len(input.SHA256) != 64 {
		return fmt.Errorf("strings_file requires an engine-prepared immutable snapshot")
	}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: out, maxNodes: max, maxBytes: bounds["max-read-bytes"]}
	a.env.Kernel = windowsStringsRead{e.Kernel, a, "metadata"}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	var totalLines, invalidLines, processes, mappings, associations uint64
	stats := memory.PageMapStats{}
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: map[string]any{"acquisition": a.coverage, "lines": totalLines, "invalid_lines": invalidLines, "processes": processes, "mappings": mappings, "associations": associations, "page_tables": stats.Tables, "page_entries": stats.Entries, "unavailable_mappings": stats.Unavailable}}}}))
	}()
	inputLayer := "input:sha256:" + input.SHA256
	if err = a.emit(evidence.Row{ID: "strings-input", Cells: map[string]evidence.Value{"RecordType": evidence.Text("input"), "InputSHA256": evidence.Text(input.SHA256), "Captured": evidence.Number(uint64(input.Size))}, Provenance: evidence.Provenance{Layer: inputLayer, Offset: "0x0"}}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(input.Reader, 0, input.Size), int(bounds["max-line-bytes"])+1)
	var lines []windowsStringsLine
	pages := map[uint64]*windowsStringsPage{}
	var position uint64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		raw, cause := reader.ReadSlice('\n')
		if len(raw) == 0 && cause == io.EOF {
			break
		}
		if cause != nil && cause != io.EOF && cause != bufio.ErrBufferFull {
			return cause
		}
		totalLines++
		if totalLines > bounds["max-lines"] {
			return fmt.Errorf("max-lines exhausted")
		}
		owned := append([]byte(nil), raw...)
		offset, text, parseErr := parseWindowsStringLine(owned)
		if uint64(len(raw)) > bounds["max-line-bytes"] || cause == bufio.ErrBufferFull {
			parseErr = fmt.Errorf("max-line-bytes exhausted")
		}
		if parseErr != nil {
			invalidLines++
			a.failure(parseErr)
			if err = a.emit(evidence.Row{ParentID: "strings-input", Cells: map[string]evidence.Value{"RecordType": evidence.Text("input_error"), "InputLine": evidence.Number(totalLines), "InputOffset": evidence.Address(position), "RawLine": evidence.Bytes(owned), "Error": evidence.Missing("input_line_unrecognized", parseErr)}, Provenance: evidence.Provenance{Layer: inputLayer, Offset: fmt.Sprintf("0x%x", position)}}); err != nil {
				return err
			}
			if cause == bufio.ErrBufferFull || uint64(len(raw)) > bounds["max-line-bytes"] {
				return parseErr
			}
		} else {
			lines = append(lines, windowsStringsLine{totalLines, position, offset, owned, text})
			if pages[offset>>12] == nil {
				pages[offset>>12] = &windowsStringsPage{baseline: map[string]struct{}{}}
			}
		}
		position += uint64(len(raw))
		if cause == io.EOF {
			break
		}
	}
	keys := make([]uint64, 0, len(pages))
	for key := range pages {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	pageToken := func(page uint64) string { return fmt.Sprintf("strings-page:%x", page) }
	for _, page := range keys {
		if err = a.emit(evidence.Row{ID: pageToken(page), ParentID: "strings-input", Cells: map[string]evidence.Value{"RecordType": evidence.Text("query_page"), "InputPage": evidence.Address(page << 12)}}); err != nil {
			return err
		}
	}
	add := func(page uint64, assoc windowsStringsAssociation, translator *memory.Intel) error {
		if associations >= bounds["max-associations"] {
			return fmt.Errorf("max-associations exhausted")
		}
		proof := evidence.Missing("baseline_coordinate_only", nil)
		if assoc.physical {
			address := windowsStringsVirtual(assoc.mapping.Virtual+((page<<12)-assoc.mapping.Physical), e.Architecture)
			translated, cause := translator.Translate(ctx, address)
			if a.stop != nil || ctx.Err() != nil {
				return errors.Join(a.stop, ctx.Err())
			}
			if cause == nil && translated.Physical != page<<12 {
				cause = fmt.Errorf("pinned mapping physical %#x differs from native translation %#x", page<<12, translated.Physical)
			}
			if cause != nil {
				a.failure(cause)
				assoc.physical = false
				proof = evidence.Missing("native_translation_unverified", cause)
			} else {
				proof = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Virtual": evidence.Address(address), "Physical": evidence.Address(translated.Physical), "PhysicalEntry": evidence.Address(translated.EntryAddress), "Entry": evidence.Address(translated.Entry), "EntryWidth": evidence.Number(uint64(translated.EntryWidth)), "PageSize": evidence.Number(translated.PageSize)}}
			}
		}
		associations++
		pages[page].associations = append(pages[page].associations, assoc)
		baselineAddress := assoc.mapping.Physical
		if assoc.name == "kernel" {
			baselineAddress = assoc.mapping.Virtual
			if e.Architecture == "x64" {
				baselineAddress &= 0x0000ffffffffffff
			}
		}
		if assoc.baseline {
			pages[page].baseline[fmt.Sprintf("%s:0x%x", assoc.name, baselineAddress)] = struct{}{}
		}
		return a.emit(evidence.Row{ParentID: pageToken(page), Cells: map[string]evidence.Value{"RecordType": evidence.Text("association"), "InputPage": evidence.Address(page << 12), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"Name": evidence.Text(assoc.name), "Identity": windowsStringsOwner(assoc, "Identity"), "ProcessOffset": windowsStringsOwner(assoc, "ProcessOffset"), "PID": windowsStringsOwner(assoc, "PID"), "Virtual": evidence.Address(assoc.mapping.Virtual), "Physical": evidence.Address(assoc.mapping.Physical), "Length": evidence.Number(assoc.mapping.Length), "Baseline": evidence.Bool(assoc.baseline), "PhysicalMatch": evidence.Bool(assoc.physical), "BaselineAddress": evidence.Address(baselineAddress), "Translation": proof, "Root": evidence.Address(translator.Root())}}}})
	}
	walk := func(layer memory.MemoryLayer, name, identity string, process, pid uint64) error {
		space, ok := layer.(*memory.Virtual)
		if !ok {
			return fmt.Errorf("native virtual address space unavailable")
		}
		rooted, ok := space.Translator.(memory.RootedTranslator)
		if !ok {
			return fmt.Errorf("native page root unavailable")
		}
		if stats.Tables >= bounds["max-map-tables"] || stats.Entries >= bounds["max-map-entries"] {
			return fmt.Errorf("task page map budget exhausted")
		}
		intel, cause := memory.NewIntelForOS(windowsStringsRead{e.Physical, a, "page_table"}, rooted.Root(), e.Architecture, "windows", 1)
		if cause != nil {
			return cause
		}
		options := memory.PageMapOptions{MaxTables: bounds["max-map-tables"] - stats.Tables, MaxEntries: bounds["max-map-entries"] - stats.Entries,
			OnReadError: func(_ uint64, _ error) error { return a.stop },
			OnUnavailableMapping: func(m memory.PageMapping) error {
				failure := fmt.Errorf("%s mapping physical %#x length %#x is outside captured ranges", name, m.Physical, m.Length)
				a.failure(failure)
				if a.coverage.Errors <= 64 {
					return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("mapping_unavailable"), "Offset": evidence.Address(m.Physical), "Error": evidence.Missing("physical_range_unavailable", failure), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"Virtual": evidence.Address(m.Virtual), "Physical": evidence.Address(m.Physical), "Length": evidence.Number(m.Length)}}}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", m.Physical)}})
				}
				return nil
			}}
		observed, cause := intel.VisitPageMappings(ctx, options, func(m memory.PageMapping) error {
			if mappings >= bounds["max-mappings"] {
				return fmt.Errorf("max-mappings exhausted")
			}
			mappings++
			virtualPage := m.Virtual >> 12
			if e.Architecture == "x64" {
				virtualPage = (m.Virtual & 0x0000ffffffffffff) >> 12
			}
			first, last := m.Physical>>12, (m.Physical+m.Length-1)>>12
			index := sort.Search(len(keys), func(i int) bool { return keys[i] >= first })
			baselineAdded := false
			for index < len(keys) && keys[index] <= last {
				page := keys[index]
				baseline := name == "kernel" || page == virtualPage
				if err := add(page, windowsStringsAssociation{name, identity, process, pid, m, baseline, true}, intel); err != nil {
					return err
				}
				if page == virtualPage {
					baselineAdded = true
				}
				index++
			}
			if name != "kernel" && pages[virtualPage] != nil && !baselineAdded {
				return add(virtualPage, windowsStringsAssociation{name, identity, process, pid, m, true, false}, intel)
			}
			return nil
		})
		stats.Tables += observed.Tables
		stats.Entries += observed.Entries
		stats.Mappings += observed.Mappings
		stats.Unavailable += observed.Unavailable
		return cause
	}
	if len(keys) > 0 {
		if err = walk(e.Kernel, "kernel", "", 0, 0); err != nil {
			return err
		}
		err = visitWindowsProcesses(ctx, a.env, max, pids, func(process, pid uint64, _ string, created evidence.Value) error {
			processes++
			identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
			space, cause := processMemory(ctx, a.env, process, 0, identity)
			if cause != nil {
				a.failure(cause)
				return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("process_unavailable"), "Offset": evidence.Address(process), "Error": evidence.Missing("process_space_unavailable", cause)}})
			}
			return walk(space, fmt.Sprintf("Process %d", pid), identity, process, pid)
		})
		if err != nil {
			return err
		}
	}
	for _, line := range lines {
		page := pages[line.offset>>12]
		baseline := make([]string, 0, len(page.baseline))
		for value := range page.baseline {
			baseline = append(baseline, value)
		}
		sort.Strings(baseline)
		result := "FREE MEMORY"
		if len(baseline) > 0 {
			result = strings.Join(baseline, ", ")
		}
		physical := []map[string]evidence.Value{}
		for _, assoc := range page.associations {
			m := assoc.mapping
			if !assoc.physical || line.offset < m.Physical || line.offset-m.Physical >= m.Length {
				continue
			}
			address := windowsStringsVirtual(m.Virtual+(line.offset-m.Physical), e.Architecture)
			physical = append(physical, map[string]evidence.Value{"Name": evidence.Text(assoc.name), "Identity": windowsStringsOwner(assoc, "Identity"), "ProcessOffset": windowsStringsOwner(assoc, "ProcessOffset"), "PID": windowsStringsOwner(assoc, "PID"), "VirtualAddress": evidence.Address(address), "PhysicalAddress": evidence.Address(line.offset), "RunVirtual": evidence.Address(m.Virtual), "RunPhysical": evidence.Address(m.Physical), "RunLength": evidence.Number(m.Length)})
		}
		if err = a.emit(evidence.Row{ParentID: pageToken(line.offset >> 12), Cells: map[string]evidence.Value{"RecordType": evidence.Text("string"), "String": evidence.Text(stringsLatin1(line.text)), "PhysicalAddress": evidence.Address(line.offset), "Result": evidence.Text(result), "BaselineAssociations": {Kind: "structure", Data: baseline}, "PhysicalAssociations": {Kind: "structure", Data: physical}, "InputLine": evidence.Number(line.line), "InputOffset": evidence.Address(line.at), "RawLine": evidence.Bytes(line.raw), "InputSHA256": evidence.Text(input.SHA256), "MappingComplete": evidence.Bool(a.coverage.Errors == 0), "StringVerified": evidence.Bool(false)}, Provenance: evidence.Provenance{Layer: inputLayer, Offset: fmt.Sprintf("0x%x", line.at)}}); err != nil {
			return err
		}
	}
	return nil
}
