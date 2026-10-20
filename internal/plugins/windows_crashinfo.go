package plugins

import (
	"context"
	"fmt"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsCrashInfoPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Signature", Kind: "string"},
		{Name: "MajorVersion", Kind: "uint64"},
		{Name: "MinorVersion", Kind: "uint64"},
		{Name: "DirectoryTableBase", Kind: "address"},
		{Name: "PfnDataBase", Kind: "address"},
		{Name: "PsLoadedModuleList", Kind: "address"},
		{Name: "PsActiveProcessHead", Kind: "address"},
		{Name: "MachineImageType", Kind: "uint64"},
		{Name: "NumberProcessors", Kind: "uint64"},
		{Name: "KdDebuggerDataBlock", Kind: "address"},
		{Name: "DumpType", Kind: "string"},
		{Name: "SystemUpTime", Kind: "string"},
		{Name: "Comment", Kind: "string"},
		{Name: "SystemTime", Kind: "string"},
		{Name: "SystemTimeRaw", Kind: "uint64"},
		{Name: "BitmapHeaderSize", Kind: "uint64"},
		{Name: "BitmapSize", Kind: "uint64"},
		{Name: "BitmapPages", Kind: "uint64"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.crashinfo", Upstream: "windows.crashinfo.Crashinfo", Platform: "windows",
		Description: "Read the Windows crash dump header, including bitmap summary fields when the dump type is 0x5",
		Columns:     columns,
	}, windowsCrashInfo}}
}

func windowsCrashInfo(_ context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	source, ok := e.Physical.(interface{ CrashHeader() memory.CrashHeader })
	if !ok {
		return fmt.Errorf("windows.crashinfo requires a Windows crash dump")
	}
	header := source.CrashHeader()
	if header.Signature == "" && header.DumpType == 0 {
		return fmt.Errorf("windows.crashinfo requires a Windows crash dump")
	}
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: "0x0"}}
	for _, column := range windowsCrashInfoPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Signature"] = evidence.Text(header.Signature)
	row.Cells["MajorVersion"] = evidence.Number(uint64(header.MajorVersion))
	row.Cells["MinorVersion"] = evidence.Number(uint64(header.MinorVersion))
	row.Cells["DirectoryTableBase"] = evidence.Address(header.DirectoryTableBase)
	row.Cells["PfnDataBase"] = evidence.Address(header.PfnDataBase)
	row.Cells["PsLoadedModuleList"] = evidence.Address(header.LoadedModuleList)
	row.Cells["PsActiveProcessHead"] = evidence.Address(header.ActiveProcessHead)
	row.Cells["MachineImageType"] = evidence.Number(uint64(header.Machine))
	row.Cells["NumberProcessors"] = evidence.Number(uint64(header.NumberProcessors))
	row.Cells["KdDebuggerDataBlock"] = evidence.Address(header.DebuggerData)
	switch header.DumpType {
	case 1:
		row.Cells["DumpType"] = evidence.Text("Full Dump (0x1)")
	case 5:
		row.Cells["DumpType"] = evidence.Text("Bitmap Dump (0x5)")
	default:
		row.Cells["DumpType"] = evidence.Text(fmt.Sprintf("Unknown/Unsupported (%#x)", header.DumpType))
	}
	row.Cells["SystemUpTime"] = evidence.Text(crashUpTime(header.SystemUpTime))
	row.Cells["Comment"] = evidence.Text(header.Comment)
	row.Cells["SystemTimeRaw"] = evidence.Number(header.SystemTime)
	row.Cells["SystemTime"] = crashSystemTime(header.SystemTime)
	if header.HasBitmap {
		row.Cells["BitmapHeaderSize"] = evidence.Number(header.BitmapHeaderSize)
		row.Cells["BitmapSize"] = evidence.Number(header.BitmapSize)
		row.Cells["BitmapPages"] = evidence.Number(header.BitmapPages)
	}
	return out(row)
}

func crashUpTime(ticks uint64) string {
	micros := ticks / 10
	if rem := ticks % 10; rem > 5 || rem == 5 && micros%2 == 1 {
		micros++
	}
	const day = uint64(24 * 60 * 60 * 1000000)
	days, rem := micros/day, micros%day
	seconds, us := rem/1000000, rem%1000000
	hh, mm := seconds/3600, (seconds%3600)/60
	ss := seconds % 60
	prefix := ""
	if days == 1 {
		prefix = "1 day, "
	} else if days > 1 {
		prefix = fmt.Sprintf("%d days, ", days)
	}
	text := fmt.Sprintf("%s%d:%02d:%02d", prefix, hh, mm, ss)
	if us != 0 {
		text += fmt.Sprintf(".%06d", us)
	}
	return text
}

func crashSystemTime(ticks uint64) evidence.Value {
	seconds := ticks / 10000000
	if seconds == 0 {
		return evidence.Missing("not_applicable", nil)
	}
	if seconds < 11644473600 {
		return evidence.Missing("unparsable_filetime", nil)
	}
	unix := int64(seconds - 11644473600)
	when := time.Unix(unix, 0).UTC()
	if when.Year() < 1 || when.Year() > 9999 {
		return evidence.Missing("unparsable_filetime", nil)
	}
	return evidence.Text(when.Format("2006-01-02T15:04:05-07:00"))
}
