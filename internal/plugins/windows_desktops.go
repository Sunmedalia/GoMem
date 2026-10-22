package plugins

import (
	"context"
	"errors"
	"maps"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

func windowsDesktopPlugins() []builtin {
	result := []builtin{}
	for _, mode := range []string{"desktops", "deskscan"} {
		spec := windowsWindowStationsPlugins()[0].spec
		spec.Name = "windows." + mode
		spec.Upstream = "windows.desktops.Desktops"
		spec.Description = "Enumerate station desktops and owning threads through their native session address space"
		run := func(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
			return windowsGUIRun(ctx, e, p, out, mode)
		}
		if mode == "deskscan" {
			spec.Upstream = "windows.deskscan.DeskScan"
			spec.Description = "Scan GUI desktop pool allocations and recover parent station and owning thread processes"
		}
		spec.Parameters = append(append([]plugin.Parameter{}, spec.Parameters...), plugin.Parameter{Name: "max-desktops", Kind: "uint", Default: "12", Description: "Per-station desktop enumeration bound,0..1000000; not used for pool DeskScan"}, plugin.Parameter{Name: "max-threads", Kind: "uint", Default: "131072", Description: "Per-desktop thread node bound,1..1000000"})
		spec.Columns = append(append([]evidence.Column{}, spec.Columns...), evidence.Column{Name: "WindowStation", Kind: "string"}, evidence.Column{Name: "WindowStationOffset", Kind: "address"}, evidence.Column{Name: "Session", Kind: "uint64"}, evidence.Column{Name: "Desktop", Kind: "string"}, evidence.Column{Name: "DesktopNameRaw", Kind: "bytes"}, evidence.Column{Name: "Process", Kind: "string"}, evidence.Column{Name: "PID", Kind: "uint64"}, evidence.Column{Name: "Thread", Kind: "address"}, evidence.Column{Name: "ProcessOffset", Kind: "address"}, evidence.Column{Name: "ProcessInfo", Kind: "address"}, evidence.Column{Name: "ProcessRaw", Kind: "bytes"})
		result = append(result, builtin{spec, run})
	}
	return result
}

// DeskScan preserves independent carved objects; it has no station-global
// deduplication. A desktop must have a nonempty name and a valid parent name.
func scanGUIDesktopOwners(ctx context.Context, reader wingui.Reader, desktop uint64, opts guiScanOptions, a *poolScannerAnalysis) (uint64, error) {
	name, nameErr := reader.ObjectName(ctx, desktop)
	if a.stop != nil || ctx.Err() != nil {
		return 0, errors.Join(nameErr, a.stop, ctx.Err())
	}
	if name.Text == nil || *name.Text == "" {
		return 0, guiDesktopCandidate(a, reader, desktop, "desktop_name_unavailable", nameErr)
	}
	parent, parentErr := reader.DesktopStation(ctx, desktop)
	if parentErr != nil || parent == nil {
		return 0, guiDesktopCandidate(a, reader, desktop, "desktop_parent_unavailable", parentErr)
	}
	station, stationErr := reader.StationInfo(ctx, *parent)
	if a.stop != nil || ctx.Err() != nil {
		return 0, errors.Join(nameErr, stationErr, a.stop, ctx.Err())
	}
	if station.Name == nil || station.Session == nil {
		return 0, guiDesktopCandidate(a, reader, desktop, "station_invalid", stationErr)
	}
	rows, err := emitGUIDesktopOwners(ctx, reader, desktop, *parent, *station.Name, *station.Session, name, opts, a)
	return rows, errors.Join(nameErr, parentErr, stationErr, err)
}
func guiDesktopCandidate(a *poolScannerAnalysis, reader wingui.Reader, at uint64, reason string, cause error) error {
	row := poolScannerRow(reader.Layer.Name(), at)
	row.Cells["RecordType"] = evidence.Text("gui_candidate")
	row.Cells["Error"] = evidence.Missing(reason, cause)
	return errors.Join(cause, a.emit(row))
}
func emitGUIDesktopOwners(ctx context.Context, reader wingui.Reader, desktop, station uint64, stationName string, session uint64, name wingui.Name, opts guiScanOptions, a *poolScannerAnalysis) (uint64, error) {
	var count uint64
	row := poolScannerRow(reader.Layer.Name(), desktop)
	row.Cells["RecordType"] = evidence.Text("gui_desktop")
	row.Cells["ObjectOffset"] = evidence.Address(desktop)
	row.Cells["WindowStation"] = evidence.Text(stationName)
	row.Cells["WindowStationOffset"] = evidence.Address(station)
	row.Cells["Session"] = evidence.Number(session)
	row.Cells["SessionId"] = evidence.Number(session)
	row.Cells["DesktopNameRaw"] = evidence.Bytes(name.Raw)
	row.Cells["NameHeader"] = evidence.Address(name.Header)
	row.Cells["NameInfo"] = evidence.Address(name.Info)
	row.Cells["NameBuffer"] = evidence.Address(name.Buffer)
	if name.Text == nil {
		row.Cells["Desktop"] = evidence.Missing("desktop_name_unavailable", nil)
	} else {
		row.Cells["Desktop"] = evidence.Text(*name.Text)
	}
	if err := a.emit(row); err != nil {
		return 0, err
	}
	base := row
	err := reader.Threads(ctx, desktop, opts.maxThreads, func(owner wingui.ThreadOwner) error {
		row := base
		row.Cells = maps.Clone(base.Cells)
		row.Cells["RecordType"] = evidence.Text("desktop")
		row.Cells["Process"] = evidence.Text(owner.Name)
		row.Cells["ProcessRaw"] = evidence.Bytes(owner.RawName)
		row.Cells["PID"] = evidence.Number(owner.PID)
		row.Cells["Thread"] = evidence.Address(owner.Thread)
		row.Cells["ProcessOffset"] = evidence.Address(owner.Process)
		row.Cells["ProcessInfo"] = evidence.Address(owner.ProcessInfo)
		count++
		return a.emit(row)
	})
	return count, err
}
