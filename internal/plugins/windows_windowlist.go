package plugins

import (
	"context"
	"errors"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

func windowsWindowsPlugins() []builtin {
	s := windowsWindowStationsPlugins()[0].spec
	s.Name = "windows.windows"
	s.Upstream = "windows.windows.Windows"
	s.Description = "Enumerate GUI windows through native session layers, retaining displayed pointer offsets and actual window addresses"
	s.Columns = append(append([]evidence.Column{}, s.Columns...), evidence.Column{Name: "DesktopNameRaw", Kind: "bytes"})
	s.Parameters = append(append([]plugin.Parameter{}, s.Parameters...), plugin.Parameter{Name: "max-desktops", Kind: "uint", Default: "12", Description: "Per-station desktop bound,0..1000000"}, plugin.Parameter{Name: "max-windows", Kind: "uint", Default: "10000", Description: "Per-desktop original window bound,1..1000000"}, plugin.Parameter{Name: "max-window-steps", Kind: "uint", Default: "1000000", Description: "Per-desktop traversal step bound,1..10000000"}, plugin.Parameter{Name: "max-window-depth", Kind: "uint", Default: "128", Description: "Recursive child depth bound,1..256"})
	for _, c := range []evidence.Column{{Name: "Station", Kind: "string"}, {Name: "StationOffset", Kind: "address"}, {Name: "Desktop", Kind: "string"}, {Name: "DesktopOffset", Kind: "address"}, {Name: "Session", Kind: "uint64"}, {Name: "Window", Kind: "string"}, {Name: "WindowAddress", Kind: "address"}, {Name: "WindowNameRaw", Kind: "bytes"}, {Name: "Procedure", Kind: "address"}, {Name: "Process", Kind: "string"}, {Name: "ProcessRaw", Kind: "bytes"}, {Name: "PID", Kind: "uint64"}, {Name: "Thread", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessInfo", Kind: "address"}} {
		s.Columns = append(s.Columns, c)
	}
	return []builtin{{s, func(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
		return windowsGUIRun(ctx, e, p, out, "windows")
	}}}
}

func emitGUIDesktopWindows(ctx context.Context, reader wingui.Reader, desktop, station uint64, stationName string, desktopName wingui.Name, opts guiScanOptions, a *poolScannerAnalysis) (uint64, error) {
	meta := poolScannerRow(reader.Layer.Name(), desktop)
	meta.Cells["RecordType"] = evidence.Text("gui_desktop")
	meta.Cells["Station"] = evidence.Text(stationName)
	meta.Cells["StationOffset"] = evidence.Address(station)
	meta.Cells["DesktopNameRaw"] = evidence.Bytes(desktopName.Raw)
	if desktopName.Text == nil {
		meta.Cells["Desktop"] = evidence.Missing("desktop_name_unavailable", nil)
	} else {
		meta.Cells["Desktop"] = evidence.Text(*desktopName.Text)
	}
	if err := a.emit(meta); err != nil {
		return 0, err
	}
	var count uint64
	var semantic pluginFailures
	err := reader.Windows(ctx, desktop, wingui.WindowWalkOptions{MaxWindows: opts.maxWindows, MaxSteps: opts.maxWindowSteps, MaxDepth: opts.maxWindowDepth}, func(w wingui.WindowRef) error {
		if a.stop != nil || ctx.Err() != nil {
			return errors.Join(a.stop, ctx.Err())
		}
		row := poolScannerRow(reader.Layer.Name(), w.Offset)
		row.Cells["RecordType"] = evidence.Text("window")
		row.Cells["WindowAddress"] = evidence.Address(w.Address)
		row.Cells["ObjectOffset"] = evidence.Address(w.Address)
		row.Cells["Station"] = evidence.Text(stationName)
		row.Cells["StationOffset"] = evidence.Address(station)
		row.Cells["Desktop"] = meta.Cells["Desktop"]
		row.Cells["DesktopOffset"] = evidence.Address(desktop)
		row.Cells["WindowNameRaw"] = evidence.Bytes(w.Name.Raw)
		row.Cells["NameBuffer"] = evidence.Address(w.Name.Buffer)
		row.Cells["NameInfo"] = evidence.Address(w.Name.Info)
		if w.Name.Text == nil || *w.Name.Text == "" {
			row.Cells["Window"] = evidence.Missing("window_name_unavailable", w.NameError)
		} else {
			row.Cells["Window"] = evidence.Text(*w.Name.Text)
		}
		candidate := func(reason string, cause error) error {
			semantic.add(cause)
			row.Cells["RecordType"] = evidence.Text("gui_candidate")
			row.Cells["Error"] = evidence.Missing(reason, cause)
			return a.emit(row)
		}
		owner, err := reader.WindowOwner(ctx, w.Address)
		if err != nil {
			return candidate("window_process_unavailable", err)
		}
		row.Cells["Thread"] = evidence.Address(owner.Thread)
		row.Cells["ProcessOffset"] = evidence.Address(owner.Process)
		row.Cells["ProcessInfo"] = evidence.Address(owner.ProcessInfo)
		row.Cells["Process"] = evidence.Text(owner.Name)
		row.Cells["ProcessRaw"] = evidence.Bytes(owner.RawName)
		row.Cells["PID"] = evidence.Number(owner.PID)
		sid, err := reader.WindowSession(ctx, w.Address)
		if err != nil || sid == nil {
			return candidate("window_session_unavailable", err)
		}
		row.Cells["Session"] = evidence.Number(*sid)
		row.Cells["SessionId"] = evidence.Number(*sid)
		procedure, procErr := reader.WindowProcedure(ctx, w.Address)
		if procErr != nil {
			row.Cells["Procedure"] = evidence.Missing("window_procedure_unavailable", procErr)
			semantic.add(procErr)
		} else if procedure != 0 && procedure <= 0x1000 {
			return candidate("window_procedure_invalid", nil)
		} else {
			row.Cells["Procedure"] = evidence.Address(procedure)
		}
		if cause := errors.Join(w.NameError, procErr); cause != nil {
			row.Cells["Error"] = evidence.Missing("window_partial_read", cause)
		}
		count++
		return a.emit(row)
	})
	return count, errors.Join(err, semantic.err("GUI window fields"))
}
