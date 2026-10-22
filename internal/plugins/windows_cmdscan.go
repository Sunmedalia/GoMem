package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
	"github.com/Sunmedalia/GoMem/pkg/winconsole"
)

func windowsCmdScanPlugins() []builtin {
	s := windowsPoolScannerPlugins()[0].spec
	s.Name, s.Upstream, s.Description = "windows.cmdscan", "windows.cmdscan.CmdScan", "Recover conhost command histories from bounded process VAD scans with original read evidence"
	s.ExternalSymbols = true
	s.Parameters = append(append([]plugin.Parameter{}, s.Parameters...),
		plugin.Parameter{Name: "no-registry", Kind: "bool", Default: "false", Description: "Skip Console HistoryBufferSize registry discovery"},
		plugin.Parameter{Name: "max-history", Kind: "string", Default: "50", Description: "Comma-separated history sizes in 0..65535"},
		plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-process VAD node bound, 1..1000000"},
		plugin.Parameter{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VAD bound, 1..1000000"},
		plugin.Parameter{Name: "max-candidates", Kind: "uint", Default: "1000000", Description: "Total history signature matches, 1..1000000"},
		plugin.Parameter{Name: "max-slots", Kind: "uint", Default: "1000000", Description: "Per-history command slot bound, 1..1000000"},
		plugin.Parameter{Name: "max-map-tables", Kind: "uint", Default: "262144", Description: "Total page-map table reads, 1..16777216"},
		plugin.Parameter{Name: "max-map-entries", Kind: "uint", Default: "268435456", Description: "Total page-map entries, 1..4294967296"})
	for _, c := range []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ConsoleInfo", Kind: "address"}, {Name: "Property", Kind: "string"}, {Name: "Address", Kind: "address"}, {Name: "Data", Kind: "string"}, {Name: "TypedData", Kind: "structure"}, {Name: "Depth", Kind: "uint64"}, {Name: "LayoutName", Kind: "string"}, {Name: "LayoutSHA256", Kind: "string"}, {Name: "LayoutSelection", Kind: "structure"}, {Name: "HiveOffset", Kind: "address"}, {Name: "RegistryCellIndex", Kind: "uint64"}} {
		s.Columns = append(s.Columns, c)
	}
	return []builtin{{s, windowsCmdScan}}
}

type cmdScan struct {
	a                                             *poolScannerAnalysis
	env                                           plugin.Environment
	owner                                         map[string]evidence.Value
	catalog                                       *winconsole.CatalogData
	selected                                      winconsole.Selection
	console                                       *consoleScanOptions
	maxNodes, maxRegions, maxCandidates, maxSlots uint64
	regions, candidates, histories                uint64
	mapTables, mapEntries, maxTables, maxEntries  uint64
}

func (s *cmdScan) emit(row evidence.Row) error {
	if row.Cells == nil {
		row.Cells = map[string]evidence.Value{}
	}
	for k, v := range s.owner {
		row.Cells[k] = v
	}
	if s.catalog != nil {
		row.Cells["LayoutName"] = evidence.Text(s.catalog.Name)
		row.Cells["LayoutSHA256"] = evidence.Text(s.catalog.SHA256)
	}
	return s.a.emit(row)
}
func (s *cmdScan) name() string {
	if s.console != nil {
		return "consoles"
	}
	return "cmdscan"
}
func (s *cmdScan) diagnostic(kind string, at uint64, err error) error {
	s.a.failures.add(err)
	return s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at), "Error": evidence.Missing(s.name()+"_incomplete", err)}})
}
func (s *cmdScan) traced(layer memory.MemoryLayer, raw int) memory.MemoryLayer {
	return poolScannerLayer{MemoryLayer: layer, a: s.a, ranges: layer.Ranges(), rawLimit: raw}
}
func (s *cmdScan) environment(e plugin.Environment) (plugin.Environment, error) {
	v, ok := e.Kernel.(*memory.Virtual)
	if !ok {
		return e, fmt.Errorf("%s requires native Intel kernel translation", s.name())
	}
	original, ok := v.Translator.(*memory.Intel)
	if !ok {
		return e, fmt.Errorf("%s requires Intel translation", s.name())
	}
	physical := s.traced(e.Physical, 4096)
	paging, err := memory.NewIntelForOS(physical, original.Root(), e.Architecture, e.OS, 1024)
	if err != nil {
		return e, err
	}
	e.Physical = physical
	e.Kernel = s.traced(&memory.Virtual{Physical: physical, Translator: paging, ID: v.Name()}, 4096)
	e.Objects = &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}
	return e, nil
}
func parseCmdHistory(text string) ([]uint64, error) {
	set := map[uint64]bool{}
	for _, part := range strings.Split(text, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("max-history must contain decimal integers in 0..65535: %w", err)
		}
		set[n] = true
	}
	out := make([]uint64, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
func windowsCmdScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	return windowsConhostRun(ctx, e, p, out, nil)
}
func windowsConhostRun(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit, console *consoleScanOptions) error {
	a := &poolScannerAnalysis{ctx: ctx}
	s := &cmdScan{a: a, console: console}
	a.out = out
	// Read captures pass through the same owner/layout enrichment as properties.
	originalOut := out
	a.out = func(row evidence.Row) error {
		for k, v := range s.owner {
			row.Cells[k] = v
		}
		if s.catalog != nil {
			row.Cells["LayoutName"] = evidence.Text(s.catalog.Name)
			row.Cells["LayoutSHA256"] = evidence.Text(s.catalog.SHA256)
		}
		return originalOut(row)
	}
	for key, target := range map[string]*uint64{"max-read-bytes": &a.maxBytes, "max-reads": &a.maxReads, "max-rows": &a.maxRows, "max-nodes": &s.maxNodes, "max-regions": &s.maxRegions, "max-candidates": &s.maxCandidates, "max-slots": &s.maxSlots, "max-map-tables": &s.maxTables, "max-map-entries": &s.maxEntries} {
		limit := uint64(1000000)
		switch key {
		case "max-read-bytes":
			limit = 1 << 40
		case "max-reads", "max-map-tables":
			limit = 1 << 24
		case "max-rows":
			limit = 10000000
		case "max-map-entries":
			limit = 1 << 32
		}
		n, err := strconv.ParseUint(p[key], 0, 64)
		if err != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", key, limit)
		}
		*target = n
	}
	histories, err := parseCmdHistory(p["max-history"])
	if err != nil {
		return err
	}
	noRegistry, err := strconv.ParseBool(p["no-registry"])
	if err != nil {
		return err
	}
	if e.Physical == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("%s requires physical memory and kernel symbols", s.name())
	}
	s.env, err = s.environment(e)
	if err != nil {
		return err
	}
	if !noRegistry {
		histories, err = s.registry(ctx, histories)
		if err != nil {
			if stop := s.diagnostic("registry_unavailable", 0, err); stop != nil {
				return stop
			}
		}
	}
	if !noRegistry && s.console != nil {
		s.console.buffers, err = s.registrySetting(ctx, s.console.buffers, "NumberOfHistoryBuffers", "registry_buffer_count")
		if err != nil {
			if stop := s.diagnostic("registry_unavailable", 0, err); stop != nil {
				return stop
			}
		}
	}

	err = visitWindowsProcesses(ctx, s.env, int(s.maxNodes), nil, func(process, pid uint64, name string, created evidence.Value) error {
		// CmdScan.run's original process filter is case sensitive.
		if (s.console == nil && name != "conhost.exe") || (s.console != nil && !strings.EqualFold(name, "conhost.exe")) {
			return nil
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		s.owner = map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity)}
		defer func() { s.owner = nil }()
		run := s.process
		if s.console != nil {
			run = s.consoleProcess
		}
		if err := run(ctx, process, identity, histories); err != nil {
			if a.stop != nil || ctx.Err() != nil {
				return err
			}
			return s.diagnostic("process_unavailable", process, err)
		}
		return nil
	})
	cause := errors.Join(err, a.stop, a.failures.err(s.name()+" reads and coverage"))
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	coverage := map[string]evidence.Value{"Regions": evidence.Number(s.regions), "Candidates": evidence.Number(s.candidates), "Reads": evidence.Number(a.reads), "RequestedBytes": evidence.Number(a.requested), "Completed": evidence.Bool(cause == nil)}
	countName := "Histories"
	if s.console != nil {
		countName = "Consoles"
	}
	coverage[countName] = evidence.Number(s.histories)
	row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("task_summary"), "Coverage": {Kind: "structure", Data: coverage}}}
	if cause != nil {
		row.Cells["Error"] = evidence.Missing(s.name()+"_incomplete", cause)
	}
	return errors.Join(cause, s.emit(row))
}
func (s *cmdScan) registry(ctx context.Context, values []uint64) ([]uint64, error) {
	return s.registrySetting(ctx, values, "HistoryBufferSize", "registry_history_size")
}
func (s *cmdScan) registrySetting(ctx context.Context, values []uint64, setting, record string) ([]uint64, error) {
	layout, err := windowsHiveLayout(s.env)
	if err != nil {
		return values, err
	}
	proc, _, err := windowsRegistryLayer(ctx, s.env)
	if err != nil {
		return values, err
	}
	hives, err := listPrintKeyHives(ctx, s.env)
	if err != nil {
		return values, err
	}
	set := map[uint64]bool{}
	for _, v := range values {
		set[v] = true
	}
	var failures pluginFailures
	for _, item := range hives {
		if err := ctx.Err(); err != nil {
			return values, err
		}
		h, err := registry.Open(ctx, s.env.Kernel, proc, item.Address, item.Name, layout)
		if err != nil {
			failures.add(err)
			continue
		}
		root, err := h.RootKey(ctx)
		if err != nil {
			failures.add(err)
			continue
		}
		children, err := h.Subkeys(ctx, root)
		failures.add(err)
		for _, key := range children {
			if !strings.EqualFold(key.Name, "Console") {
				continue
			}
			entries, err := h.Values(ctx, key)
			failures.add(err)
			for _, v := range entries {
				if v.Name != setting {
					continue
				}
				if v.DataErr != nil {
					failures.add(v.DataErr)
					continue
				}
				var n uint64
				switch {
				case v.Type == 4 && len(v.Data) == 4:
					n = uint64(binary.LittleEndian.Uint32(v.Data))
				case v.Type == 5 && len(v.Data) == 4:
					n = uint64(binary.BigEndian.Uint32(v.Data))
				case v.Type == 11 && len(v.Data) == 8:
					n = binary.LittleEndian.Uint64(v.Data)
				default:
					failures.add(fmt.Errorf("unsupported Console %s registry type/length %d/%d", setting, v.Type, len(v.Data)))
					continue
				}
				if n > 65535 {
					failures.add(fmt.Errorf("registry history size %d exceeds signature width", n))
					continue
				}
				set[n] = true
				if err := s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(record), "Offset": evidence.Address(v.Address), "Data": evidence.Text(strconv.FormatUint(n, 10)), "Raw": evidence.Bytes(v.Data), "HiveOffset": evidence.Address(item.Address), "RegistryCellIndex": evidence.Number(uint64(v.Index))}, Provenance: evidence.Provenance{Layer: s.env.Kernel.Name(), Offset: fmt.Sprintf("0x%x", item.Address)}}); err != nil {
					return values, err
				}
			}
		}
	}
	result := make([]uint64, 0, len(set))
	for n := range set {
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, failures.err("Console registry settings")
}
func (s *cmdScan) process(ctx context.Context, process uint64, identity string, histories []uint64) error {
	acquired, err := s.acquireConhost(ctx, process, identity, conhostHistoryVADs)
	if err != nil || acquired == nil {
		return err
	}
	space := acquired.Layer
	if acquired.Scan == nil {
		return s.noHistory(space.Name(), 0)
	}

	r := winconsole.Reader{Objects: &object.Reader{Layer: space, Symbols: s.catalog.Layout}}
	field, err := r.Objects.Field("_COMMAND_HISTORY", "CommandCountMax")
	if err != nil {
		return err
	}
	scan := acquired.Scan
	found := false
	var last uint64
	for _, maximum := range histories {
		needle := []byte{byte(maximum), byte(maximum >> 8)}
		err = memory.Scan(ctx, scan, needle, func(match uint64) error {
			if s.candidates >= s.maxCandidates {
				return fmt.Errorf("max-candidates exhausted")
			}
			s.candidates++
			if match < field.Offset {
				return s.diagnostic("candidate_underflow", match, fmt.Errorf("history signature before structure start"))
			}
			last = match - field.Offset
			valid, err := r.ValidHistory(ctx, last, int64(maximum))
			if err != nil {
				return s.diagnostic("candidate_unreadable", last, err)
			}
			if !valid {
				return nil
			}
			found = true
			s.histories++
			if err := s.history(ctx, r, last, maximum); err != nil {
				if s.a.stop != nil || ctx.Err() != nil {
					return err
				}
				return s.diagnostic("history_incomplete", last, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if !found {
		return s.noHistory(space.Name(), last)
	}
	return nil
}

func (s *cmdScan) noHistory(layer string, last uint64) error {
	console := evidence.Missing("not_applicable", nil)
	if last != 0 {
		console = evidence.Address(last)
	}
	return s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("history_not_found"), "ConsoleInfo": console, "Property": evidence.Text("_COMMAND_HISTORY"), "Address": evidence.Missing("not_applicable", nil), "Data": evidence.Text("History Not Found"), "Depth": evidence.Number(0)}, Provenance: evidence.Provenance{Layer: layer}})
}
func (s *cmdScan) history(ctx context.Context, r winconsole.Reader, at, maximum uint64) error {
	root := fmt.Sprintf("cmdscan:%s:%x:%d", s.owner["ProcessIdentity"].String(), at, maximum)
	bucketID := root + ":CommandBucket"
	property := func(name string, depth uint64, address evidence.Value, text string, typed evidence.Value, raw []byte) error {
		id, parent := root+":"+name, root
		if depth == 0 {
			id, parent = root, ""
		}
		if depth == 2 {
			parent = bucketID
		}
		if name == "CommandBucket" {
			id = bucketID
		}
		row := evidence.Row{ID: id, ParentID: parent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("history_property"), "ConsoleInfo": evidence.Address(at), "Property": evidence.Text("_COMMAND_HISTORY" + name), "Address": address, "Data": evidence.Text(text), "TypedData": {Kind: "structure", Data: typed}, "Depth": evidence.Number(depth)}, Provenance: evidence.Provenance{Layer: r.Objects.Layer.Name(), Offset: fmt.Sprintf("0x%x", at)}}
		if depth > 0 {
			row.Cells["Property"] = evidence.Text("_COMMAND_HISTORY." + name)
		}
		if raw != nil {
			row.Cells["Raw"] = evidence.Bytes(raw)
		}
		return s.emit(row)
	}
	if err := property("", 0, evidence.Address(at), "None", evidence.Missing("not_applicable", nil), nil); err != nil {
		return err
	}
	address := func(path string) (uint64, error) {
		f, err := r.Objects.Field("_COMMAND_HISTORY", path)
		if err != nil {
			return 0, err
		}
		return memory.Add(at, f.Offset)
	}
	app, err := address("Application")
	if err != nil {
		return err
	}
	text, raw, err := r.Application(ctx, at)
	if err != nil {
		return err
	}
	typed, display := evidence.Missing("baseline_none", nil), "None"
	if text != nil {
		typed, display = evidence.Text(*text), *text
	}
	if err := property("Application", 1, evidence.Address(app), display, typed, raw); err != nil {
		return err
	}
	ptr, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "ConsoleProcessHandle")
	if err != nil {
		return err
	}
	handleField, err := r.Objects.Field("_CONSOLE_PROCESS_HANDLE", "ProcessHandle")
	if err != nil {
		return err
	}
	handleAt, err := memory.Add(ptr, handleField.Offset)
	if err != nil {
		return err
	}
	handle, err := r.ProcessHandle(ctx, at)
	if err != nil {
		return err
	}
	if err := property("ProcessHandle", 1, evidence.Address(handleAt), fmt.Sprintf("0x%x", handle), evidence.Number(handle), nil); err != nil {
		return err
	}
	count, err := r.CommandCount(ctx, at)
	if err != nil {
		return err
	}
	if err := property("CommandCount", 1, evidence.Missing("not_applicable", nil), strconv.FormatInt(count, 10), evidence.Integer(count), nil); err != nil {
		return err
	}
	last, err := r.Objects.Int(ctx, at, "_COMMAND_HISTORY", "LastDisplayed")
	if err != nil {
		return err
	}
	lastAt, err := address("LastDisplayed")
	if err != nil {
		return err
	}
	if err := property("LastDisplayed", 1, evidence.Address(lastAt), strconv.FormatInt(last, 10), evidence.Integer(last), nil); err != nil {
		return err
	}
	max, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "CommandCountMax")
	if err != nil {
		return err
	}
	maxAt, err := address("CommandCountMax")
	if err != nil {
		return err
	}
	if err := property("CommandCountMax", 1, evidence.Address(maxAt), strconv.FormatUint(max, 10), evidence.Number(max), nil); err != nil {
		return err
	}
	bucket, err := address("CommandBucket")
	if err != nil {
		return err
	}
	if err := property("CommandBucket", 1, evidence.Address(bucket), "", evidence.Text(""), nil); err != nil {
		return err
	}
	// Fetch only fields the default bucket walker needs, after emitting the
	// preceding properties so faults preserve the original partial history tree.
	begin, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "CommandBucket.Begin")
	if err != nil {
		return err
	}
	capacity, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "CommandBucket.EndCapacity")
	if err != nil {
		return err
	}
	return r.WalkBucket(ctx, winconsole.History{Begin: begin, Capacity: capacity, Maximum: max}, nil, s.maxSlots, func(index uint64, c winconsole.Command) error {
		text, raw, err := r.Text(ctx, c.Address)
		if err != nil {
			return s.diagnostic("command_unreadable", c.Address, err)
		}
		typed, display := evidence.Missing("baseline_none", nil), "None"
		if text != nil {
			typed, display = evidence.Text(*text), *text
		}
		return property(fmt.Sprintf("CommandBucket_Command_%d", index), 2, evidence.Address(c.Address), display, typed, raw)
	})
}
