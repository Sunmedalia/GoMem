package plugins

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

func windowsWindowStationsPlugins() []builtin {
	s := windowsPoolScannerPlugins()[0].spec
	s.Name = "windows.windowstations"
	s.Upstream = "windows.windowstations.WindowStations"
	s.Description = "Scan GUI window stations, rebind to their session and retain executive names with acquisition evidence"
	s.ExternalSymbols = true
	s.Columns = append(append([]evidence.Column{}, s.Columns...), evidence.Column{Name: "SessionId", Kind: "uint64"}, evidence.Column{Name: "NameRaw", Kind: "bytes"}, evidence.Column{Name: "NameHeader", Kind: "address"}, evidence.Column{Name: "NameInfo", Kind: "address"}, evidence.Column{Name: "NameBuffer", Kind: "address"}, evidence.Column{Name: "GUISymbols", Kind: "structure"})
	s.Parameters = append(append([]plugin.Parameter{}, s.Parameters...), plugin.Parameter{Name: "max-processes", Kind: "uint", Default: "131072", Description: "Session discovery process bound, 1..1000000"}, plugin.Parameter{Name: "max-sessions", Kind: "uint", Default: "4096", Description: "Session address-space bound, 1..1000000"}, plugin.Parameter{Name: "max-stations", Kind: "uint", Default: "15", Description: "Additional station traversal bound per root, 0..1000000"})
	return []builtin{{s, windowsWindowStations}}
}

type guiScanOptions struct {
	maxProcesses, maxSessions, maxStations     uint64
	maxDesktops, maxThreads                    uint64
	maxWindows, maxWindowSteps, maxWindowDepth uint64
	mode                                       string
}

func windowsWindowStations(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	return windowsGUIRun(ctx, e, p, out, "")
}
func windowsGUIRun(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit, mode string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.Symbols == nil || e.Symbols.PointerSize() != 8 || e.Architecture != "x64" {
		return fmt.Errorf("Windows GUI scans support only native Windows x64")
	}
	a := &poolScannerAnalysis{ctx: ctx, out: out}
	opts := guiScanOptions{mode: mode}
	for _, b := range []struct {
		name   string
		target *uint64
		limit  uint64
		zero   bool
	}{
		{"max-read-bytes", &a.maxBytes, 1 << 40, false}, {"max-reads", &a.maxReads, 1 << 24, false}, {"max-rows", &a.maxRows, 10000000, false},
		{"max-processes", &opts.maxProcesses, 1000000, false}, {"max-sessions", &opts.maxSessions, 1000000, false}, {"max-stations", &opts.maxStations, 1000000, true},
	} {
		n, err := strconv.ParseUint(p[b.name], 0, 64)
		if err != nil || n > b.limit || !b.zero && n == 0 {
			return fmt.Errorf("invalid %s bound", b.name)
		}
		*b.target = n
	}
	if mode != "" {
		for _, bound := range []struct {
			name   string
			target *uint64
			zero   bool
		}{{"max-desktops", &opts.maxDesktops, true}} {
			n, err := strconv.ParseUint(p[bound.name], 0, 64)
			if err != nil || n > 1000000 || !bound.zero && n == 0 {
				return fmt.Errorf("invalid %s bound", bound.name)
			}
			*bound.target = n
		}
	}
	if mode == "desktops" || mode == "deskscan" {
		n, err := strconv.ParseUint(p["max-threads"], 0, 64)
		if err != nil || n == 0 || n > 1000000 {
			return fmt.Errorf("invalid max-threads bound")
		}
		opts.maxThreads = n
	}
	if mode == "windows" {
		for _, b := range []struct {
			name   string
			target *uint64
			limit  uint64
		}{{"max-windows", &opts.maxWindows, 1000000}, {"max-window-steps", &opts.maxWindowSteps, 10000000}, {"max-window-depth", &opts.maxWindowDepth, 256}} {
			n, err := strconv.ParseUint(p[b.name], 0, 64)
			if err != nil || n == 0 || n > b.limit {
				return fmt.Errorf("invalid %s bound", b.name)
			}
			*b.target = n
		}
	}
	selection, err := wingui.Select(e.Symbols)
	if err != nil {
		return err
	}
	cache := e.SymbolCache
	if cache != "" {
		cache = filepath.Join(cache, "gui")
	}
	catalog, err := wingui.Load(ctx, cache, selection.Name, e.Offline)
	if err != nil {
		return err
	}
	if mode == "windows" {
		catalog.Layout, err = wingui.ParseWindowLayout(catalog.Data)
		if err != nil {
			return err
		}
	}
	symbolRow := poolScannerRow("", 0)
	symbolRow.Cells["RecordType"] = evidence.Text("gui_symbols")
	symbolRow.Cells["GUISymbols"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Layout": evidence.Text(catalog.Name), "SHA256": evidence.Text(catalog.SHA256), "Selection": evidence.Text(selection.Method), "URL": evidence.Text(catalog.URL), "FromCache": evidence.Bool(catalog.FromCache), "Baseline": evidence.Text("881e970121c16f0932fb9d16fbd5fb258cbcbf75")}}
	if err = a.emit(symbolRow); err != nil {
		return err
	}
	env, err := poolScannerEnvironment(ctx, e, a)
	if err != nil {
		return err
	}
	return runWindowStations(ctx, env, catalog.Layout, opts, a)
}

// The environment's kernel is already traced. Session translation has its own
// physical recorder so page tables and session reads retain their exact layers.
func runWindowStations(ctx context.Context, e plugin.Environment, layout *wingui.Layout, opts guiScanOptions, a *poolScannerAnalysis) error {
	spaces := map[uint64]wingui.SessionSpace{}
	physical := e.Physical
	if traced, ok := physical.(poolScannerLayer); ok {
		traced.rawLimit = 4096
		physical = traced
	}
	discovery := wingui.SessionReader{Kernel: &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}, Physical: physical, KernelBase: e.KernelBase}
	discoveryErr := discovery.Visit(ctx, wingui.SessionOptions{MaxProcesses: opts.maxProcesses, MaxSessions: opts.maxSessions}, func(space wingui.SessionSpace) error {
		space.Layer = poolScannerLayer{MemoryLayer: space.Layer, a: a, rawLimit: 65535}
		spaces[space.SessionID] = space
		row := poolScannerRow(space.Layer.Name(), space.Process)
		row.Cells["RecordType"] = evidence.Text("gui_session")
		row.Cells["SessionId"] = evidence.Number(space.SessionID)
		row.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"PID": evidence.Number(space.PID), "Process": evidence.Address(space.Process), "SessionPointer": evidence.Address(space.SessionPointer), "RawCR3": evidence.Address(space.RawCR3), "CR3": evidence.Address(space.CR3), "Method": evidence.Text(space.Method)}}
		return a.emit(row)
	})
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(discoveryErr, a.stop, ctx.Err())
	}
	tag := "Wind"
	if opts.mode == "deskscan" {
		tag = "Desk"
	}
	constraints, err := guiPoolConstraints(layout, tag)
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	var stations, candidates, unbound, desktopRows uint64
	var semantic pluginFailures
	scanErr := scanPoolObjects(ctx, e, constraints, "gui_candidates", poolScannerRow, a.emit, func(ctx context.Context, hit poolHit) (evidence.Row, bool, error) {
		if a.stop != nil {
			return evidence.Row{}, false, poolFatalError{a.stop}
		}
		candidates++
		scanReader := wingui.Reader{Layer: hit.scan.Layer, Layout: layout, KernelSymbols: e.Symbols, KernelBase: e.KernelBase}
		var sid *uint64
		var err error
		if opts.mode == "deskscan" {
			sid, err = scanReader.DesktopSession(ctx, hit.object)
		} else {
			sid, err = scanReader.StationSession(ctx, hit.object)
		}
		if err != nil {
			semantic.add(err)
			return evidence.Row{}, false, nil
		}
		space, ok := spaces[*sid]
		if !ok {
			unbound++
			row := poolScannerRow(hit.layer, hit.object)
			row.Cells["RecordType"] = evidence.Text("gui_candidate")
			row.Cells["SessionId"] = evidence.Number(*sid)
			row.Cells["Error"] = evidence.Missing("session_layer_unavailable", nil)
			if err = a.emit(row); err != nil {
				return evidence.Row{}, false, poolFatalError{err}
			}
			return evidence.Row{}, false, nil
		}
		reader := wingui.Reader{Layer: space.Layer, Layout: layout, KernelSymbols: e.Symbols, KernelBase: e.KernelBase}
		if opts.mode == "deskscan" {
			rows, err := scanGUIDesktopOwners(ctx, reader, hit.object, opts, a)
			desktopRows += rows
			if a.stop != nil || ctx.Err() != nil {
				return evidence.Row{}, false, poolFatalError{errors.Join(err, a.stop, ctx.Err())}
			}
			semantic.add(err)
			return evidence.Row{}, false, nil
		}
		err = reader.TraverseStations(ctx, hit.object, opts.maxStations, func(at uint64) error {
			if seen[at] {
				return nil
			}
			seen[at] = true
			info, cause := reader.StationInfo(ctx, at)
			if cause != nil {
				semantic.add(cause)
			}
			if a.stop != nil {
				return a.stop
			}
			row := poolScannerRow(space.Layer.Name(), at)
			row.Cells["RecordType"] = evidence.Text("windowstation")
			row.Cells["ObjectOffset"] = evidence.Address(at)
			row.Cells["NameRaw"] = evidence.Bytes(info.NameEvidence.Raw)
			row.Cells["NameHeader"] = evidence.Address(info.NameEvidence.Header)
			row.Cells["NameInfo"] = evidence.Address(info.NameEvidence.Info)
			row.Cells["NameBuffer"] = evidence.Address(info.NameEvidence.Buffer)
			if info.Name == nil || info.Session == nil {
				row.Cells["RecordType"] = evidence.Text("gui_candidate")
				row.Cells["Name"] = evidence.Missing("station_invalid", cause)
			} else {
				row.Cells["Name"] = evidence.Text(*info.Name)
				row.Cells["SessionId"] = evidence.Number(*info.Session)
				stations++
			}
			if cause != nil {
				row.Cells["Error"] = evidence.Missing("gui_name_read_failed", cause)
			}
			if (opts.mode == "desktops" || opts.mode == "windows") && info.Name != nil && info.Session != nil {
				row.Cells["RecordType"] = evidence.Text("gui_station")
				if err := a.emit(row); err != nil {
					return err
				}
				return reader.Desktops(ctx, at, opts.maxDesktops, func(desktop uint64, name wingui.Name) error {
					var rows uint64
					var err error
					if opts.mode == "windows" {
						rows, err = emitGUIDesktopWindows(ctx, reader, desktop, at, *info.Name, name, opts, a)
					} else {
						rows, err = emitGUIDesktopOwners(ctx, reader, desktop, at, *info.Name, *info.Session, name, opts, a)
					}
					desktopRows += rows
					return err
				})
			}
			return a.emit(row)
		})
		if a.stop != nil || ctx.Err() != nil {
			return evidence.Row{}, false, poolFatalError{errors.Join(err, a.stop, ctx.Err())}
		}
		semantic.add(err)
		return evidence.Row{}, false, nil
	})
	cause := errors.Join(discoveryErr, scanErr, semantic.err("GUI object reads"), a.failures.err("GUI captured reads"), a.stop)
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	summary := poolScannerRow("", 0)
	summary.Cells["RecordType"] = evidence.Text("task_summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Sessions": evidence.Number(uint64(len(spaces))), "PoolCandidates": evidence.Number(candidates), "Stations": evidence.Number(stations), "DesktopOwners": evidence.Number(desktopRows), "UnboundCandidates": evidence.Number(unbound), "ReadFailures": evidence.Number(uint64(a.failures.count)), "Reads": evidence.Number(a.reads), "RequestedBytes": evidence.Number(a.requested), "EvidenceRows": evidence.Number(a.rows), "Completed": evidence.Bool(cause == nil)}}
	if opts.mode == "windows" {
		coverage := summary.Cells["Coverage"].Data.(map[string]evidence.Value)
		delete(coverage, "DesktopOwners")
		coverage["Windows"] = evidence.Number(desktopRows)
	}
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("gui_scan_incomplete", cause)
	}
	return errors.Join(cause, a.emit(summary))
}
