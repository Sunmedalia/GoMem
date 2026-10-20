package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsPsScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "VirtualOffset", Kind: "address"},
		{Name: "OffsetSpace", Kind: "string"},
		{Name: "PID", Kind: "uint64"},
		{Name: "PPID", Kind: "uint64"},
		{Name: "Name", Kind: "string"},
		{Name: "Created", Kind: "string"},
		{Name: "CreatedRaw", Kind: "uint64"},
		{Name: "Exited", Kind: "string"},
		{Name: "ExitedRaw", Kind: "uint64"},
		{Name: "DTB", Kind: "address"},
		{Name: "Threads", Kind: "uint64"},
		{Name: "Handles", Kind: "uint64"},
		{Name: "SessionId", Kind: "uint64"},
		{Name: "Wow64", Kind: "bool"},
		{Name: "Identity", Kind: "string"},
		{Name: "ImageBase", Kind: "address"},
		{Name: "FileOutput", Kind: "string"},
		{Name: "Patches", Kind: "structure"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.psscan", Upstream: "windows.psscan.PsScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan pool headers for EPROCESS objects and report the same process fields as windows.pslist",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated PID filter"},
			{Name: "physical", Kind: "bool", Default: "false", Description: "Display the translated physical offset of a virtually scanned process"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct main PE images through each process PEB"},
		},
		Columns: columns,
	}, windowsPsScan}}
}

func windowsPsScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if p == nil {
		p = map[string]string{}
	}
	physical, dump, pids, err := psScanOptions(p)
	if err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Pro\xe3", "Proc")
	if err != nil {
		return err
	}
	return scanPoolObjects(ctx, e, constraints, "processes", psScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		return psScanHit(ctx, e, found, physical, dump, pids)
	})
}

func psScanOptions(p map[string]string) (physical, dump bool, pids map[uint64]bool, err error) {
	if p["physical"] == "" {
		p["physical"] = "false"
	}
	if p["dump"] == "" {
		p["dump"] = "false"
	}
	physical, err = strconv.ParseBool(p["physical"])
	if err != nil {
		return false, false, nil, fmt.Errorf("physical: %w", err)
	}
	dump, err = strconv.ParseBool(p["dump"])
	if err != nil {
		return false, false, nil, fmt.Errorf("dump: %w", err)
	}
	if p["pid"] == "" {
		return physical, dump, nil, nil
	}
	pids = map[uint64]bool{}
	for _, token := range strings.Split(p["pid"], ",") {
		value, err := strconv.ParseUint(strings.TrimSpace(token), 0, 32)
		if err != nil {
			return false, false, nil, fmt.Errorf("pid: %w", err)
		}
		pids[value] = true
	}
	return physical, dump, pids, nil
}

func psScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsPsScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func psScanHit(ctx context.Context, e plugin.Environment, found poolHit, physical, dump bool, pids map[uint64]bool) (evidence.Row, bool, error) {
	pid, err := found.scan.Uint(ctx, found.object, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return evidence.Row{}, false, err
	}
	if pids != nil && !pids[pid] {
		return evidence.Row{}, false, nil
	}
	ppid, err := found.scan.Uint(ctx, found.object, "_EPROCESS", "InheritedFromUniqueProcessId")
	if err != nil {
		return evidence.Row{}, false, err
	}
	name, err := processImageName(ctx, found.scan, found.object, false)
	if err != nil {
		return evidence.Row{}, false, err
	}
	threads, err := found.scan.Uint(ctx, found.object, "_EPROCESS", "ActiveThreads")
	if err != nil {
		return evidence.Row{}, false, err
	}
	wow64, err := processWow64(ctx, found.scan, found.object)
	if err != nil {
		return evidence.Row{}, false, err
	}
	scanEnv := e
	scanEnv.Objects = found.scan
	created, createdRaw := windowsTime(ctx, scanEnv, found.object, "_EPROCESS", "CreateTime")
	if created.Kind == "missing" && created.Error != "" {
		return evidence.Row{}, false, fmt.Errorf("%s", created.Error)
	}
	exited, exitedRaw := windowsTime(ctx, scanEnv, found.object, "_EPROCESS", "ExitTime")
	if exited.Kind == "missing" && exited.Error != "" {
		return evidence.Row{}, false, fmt.Errorf("%s", exited.Error)
	}
	dtb, err := processDirectoryTable(ctx, found.scan, found.object)
	if err != nil {
		return evidence.Row{}, false, err
	}
	row := psScanRow(found.layer, found.object)
	virtual := found.layer == e.Kernel.Name()
	row.Cells["VirtualOffset"] = evidence.Address(found.object)
	row.Cells["OffsetSpace"] = evidence.Text("kernel_virtual")
	if !virtual {
		row.Cells["VirtualOffset"] = evidence.Missing("physical_pool", nil)
		row.Cells["OffsetSpace"] = evidence.Text("physical")
	}
	if physical {
		layer, ok := e.Kernel.(*memory.Virtual)
		if !ok || layer.Translator == nil {
			return evidence.Row{}, false, fmt.Errorf("kernel translator is unavailable")
		}
		mapping, err := layer.Translator.Translate(ctx, found.object)
		if err != nil {
			return evidence.Row{}, false, err
		}
		row.Cells["Offset"] = evidence.Address(mapping.Physical)
		row.Cells["OffsetSpace"] = evidence.Text("physical")
	}
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["PPID"] = evidence.Number(ppid)
	row.Cells["Name"] = evidence.Text(name)
	row.Cells["Created"] = created
	row.Cells["CreatedRaw"] = createdRaw
	row.Cells["Exited"] = exited
	row.Cells["ExitedRaw"] = exitedRaw
	row.Cells["DTB"] = evidence.Address(dtb)
	row.Cells["Threads"] = evidence.Number(threads)
	row.Cells["Handles"] = windowsHandleCount(ctx, scanEnv, found.object)
	row.Cells["SessionId"] = windowsSessionID(ctx, scanEnv, found.object)
	row.Cells["Wow64"] = evidence.Value{Kind: "bool", Data: wow64}
	row.Cells["RecordType"] = evidence.Text("process")
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	row.Cells["Identity"] = evidence.Text(evidence.ProcessID(e.ImageHash, found.layer, found.object, pid, stamp))
	row.Cells["FileOutput"] = evidence.Text("Disabled")
	if dump {
		if !virtual {
			row.Cells["FileOutput"] = evidence.Text("Error outputting file")
			row.Cells["ImageBase"] = evidence.Missing("physical_process_not_virtualized", nil)
			row.Cells["Patches"] = evidence.Missing("physical_process_not_virtualized", nil)
		} else if err := dumpProcessPE(ctx, e, found.object, pid, name, row); err != nil {
			row.Cells["FileOutput"] = evidence.Text("Error outputting file")
		}
	}
	return row, true, nil
}

func processObjectValid(ctx context.Context, scan *object.Reader, objectAddress uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	name, err := processImageName(ctx, scan, objectAddress, true)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if name == "" {
		return false, nil
	}
	pid, err := scan.Uint(ctx, objectAddress, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if name != "System" || pid != 4 {
		raw, err := windowsRawTime(ctx, plugin.Environment{Objects: scan}, objectAddress, "_EPROCESS", "CreateTime")
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, nil
		}
		created, ok := windowsComparableTime(raw)
		if !ok || !processYear(created) {
			return false, nil
		}
		exitRaw, err := windowsRawTime(ctx, plugin.Environment{Objects: scan}, objectAddress, "_EPROCESS", "ExitTime")
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, nil
		}
		if exited, ok := windowsComparableTime(exitRaw); ok {
			if !processYear(exited) || created.After(exited) {
				return false, nil
			}
		}
	}
	if pid%4 != 0 || pid == 0 || pid > 0xfffffffc {
		return false, nil
	}
	dtb, err := processDirectoryTable(ctx, scan, objectAddress)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if dtb == 0 || dtb&^0xfff == 0 {
		return false, nil
	}
	flink, err := scan.Uint(ctx, objectAddress, "_EPROCESS", "ThreadListHead.Flink")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	blink, err := scan.Uint(ctx, objectAddress, "_EPROCESS", "ThreadListHead.Blink")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if flink < 0x80000000 || blink < 0x80000000 {
		return false, nil
	}
	return true, nil
}

func processYear(stamp time.Time) bool {
	year := stamp.Year()
	current := time.Now().Year()
	return year > 1998 && year < current+10
}

func windowsComparableTime(stamp uint64) (time.Time, bool) {
	seconds := stamp / 10000000
	if seconds == 0 {
		return time.Time{}, false
	}
	unix := int64(seconds) - 11644473600
	// CPython datetime.fromtimestamp accepts years 1 through 9999 and rejects the rest.
	if unix < -62135596800 || unix > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(unix, 0).UTC(), true
}

func processDirectoryTable(ctx context.Context, scan *object.Reader, objectAddress uint64) (uint64, error) {
	field, err := scan.Field("_EPROCESS", "Pcb.DirectoryTableBase")
	if err != nil {
		return 0, err
	}
	address, err := memory.Add(objectAddress, field.Offset)
	if err != nil {
		return 0, err
	}
	ref := field.Type
	if ref.Kind == "array" {
		if ref.Subtype == nil || ref.Count == 0 {
			return 0, fmt.Errorf("invalid process CR3 array")
		}
		ref = *ref.Subtype
	}
	return scan.Scalar(ctx, address, ref)
}

func processWow64(ctx context.Context, scan *object.Reader, objectAddress uint64) (bool, error) {
	for _, path := range []string{"Wow64Process", "WoW64Process"} {
		if _, err := scan.Field("_EPROCESS", path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return false, err
		}
		value, err := scan.Uint(ctx, objectAddress, "_EPROCESS", path)
		if err != nil {
			return false, err
		}
		return value != 0, nil
	}
	return false, nil
}

func processImageName(ctx context.Context, scan *object.Reader, objectAddress uint64, stopAtReplacement bool) (string, error) {
	field, err := scan.Field("_EPROCESS", "ImageFileName")
	if err != nil {
		return "", err
	}
	if field.Type.Kind != "array" || field.Type.Subtype == nil {
		return "", fmt.Errorf("ImageFileName is not a byte array")
	}
	size, err := scan.Size(field.Type)
	if err != nil {
		return "", err
	}
	if size == 0 || size > 4096 {
		return "", fmt.Errorf("ImageFileName size %d is outside 1..4096", size)
	}
	address, err := memory.Add(objectAddress, field.Offset)
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, scan.Layer, address, int(size))
	if err != nil {
		return "", err
	}
	decoded := string(raw)
	if !utf8.Valid(raw) {
		decoded = strings.ToValidUTF8(decoded, "\uFFFD")
	}
	if stopAtReplacement {
		if index := strings.Index(decoded, "\uFFFD"); index >= 0 {
			decoded = decoded[:index]
		}
	}
	if index := strings.IndexByte(decoded, 0); index >= 0 {
		decoded = decoded[:index]
	}
	return decoded, nil
}
