package plugins

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsThrdScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "PID", Kind: "uint64"},
		{Name: "TID", Kind: "uint64"},
		{Name: "StartAddress", Kind: "address"},
		{Name: "StartPath", Kind: "string"},
		{Name: "Win32StartAddress", Kind: "address"},
		{Name: "Win32StartPath", Kind: "string"},
		{Name: "CreateTime", Kind: "string"},
		{Name: "ExitTime", Kind: "string"},
		{Name: "CreateTimeRaw", Kind: "uint64"},
		{Name: "ExitTimeRaw", Kind: "uint64"},
		{Name: "ProcessOffset", Kind: "address"},
		{Name: "ProcessIdentity", Kind: "string"},
		{Name: "ProcessName", Kind: "string"},
		{Name: "Identity", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.thrdscan", Upstream: "windows.thrdscan.ThrdScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan pool headers for ETHREAD objects and report thread IDs, start addresses, paths and times",
		Parameters: []plugin.Parameter{
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "VAD node limit for one owning process"},
		},
		Columns: columns,
	}, windowsThrdScan}}
}

func windowsThrdScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if p == nil {
		p = map[string]string{}
	}
	if p["max-nodes"] == "" {
		p["max-nodes"] = "131072"
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || maxNodes == 0 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	if err := requireThreadFields(e); err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Thr\xe5", "Thre")
	if err != nil {
		return err
	}
	owners := map[uint64]*threadOwner{}
	return scanPoolObjects(ctx, e, constraints, "threads", thrdScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		return thrdScanHit(ctx, e, found, int(maxNodes), owners)
	})
}

func requireThreadFields(e plugin.Environment) error {
	if e.Objects == nil {
		return fmt.Errorf("thread scan needs kernel symbols")
	}
	for _, path := range []string{"Cid.UniqueProcess", "Cid.UniqueThread", "StartAddress", "Win32StartAddress", "CreateTime", "ExitTime"} {
		if _, err := e.Objects.Field("_ETHREAD", path); err != nil {
			return fmt.Errorf("_ETHREAD.%s: %w", path, err)
		}
	}
	if _, err := e.Objects.Field("_ETHREAD", "ThreadsProcess"); errors.Is(err, object.ErrFieldAbsent) {
		if _, err = e.Objects.Field("_ETHREAD", "Tcb.Process"); err != nil {
			return fmt.Errorf("_ETHREAD has neither ThreadsProcess nor Tcb.Process")
		}
	} else if err != nil {
		return err
	}
	return nil
}

func thrdScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsThrdScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

type threadOwner struct {
	valid     bool
	pid       uint64
	name      string
	created   evidence.Value
	regions   []windowsVADPath
	regionErr error
}

func thrdScanHit(ctx context.Context, e plugin.Environment, found poolHit, maxNodes int, owners map[uint64]*threadOwner) (evidence.Row, bool, error) {
	pid, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "Cid.UniqueProcess")
	if err != nil {
		return evidence.Row{}, false, err
	}
	tid, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "Cid.UniqueThread")
	if err != nil {
		return evidence.Row{}, false, err
	}
	start, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "StartAddress")
	if err != nil {
		return evidence.Row{}, false, err
	}
	win32, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "Win32StartAddress")
	if err != nil {
		return evidence.Row{}, false, err
	}
	created, createdRaw, err := threadDisplayedTime(ctx, found.scan, found.object, "_ETHREAD", "CreateTime", true)
	if err != nil {
		return evidence.Row{}, false, err
	}
	exited, exitedRaw, err := threadDisplayedTime(ctx, found.scan, found.object, "_ETHREAD", "ExitTime", false)
	if err != nil {
		return evidence.Row{}, false, err
	}
	ownerAddress, err := threadOwnerAddress(ctx, found.scan, found.object)
	if err != nil {
		return evidence.Row{}, false, err
	}
	// The pinned gather step drops junk CIDs after the field reads. PID 0 is
	// valid to the pool carver and is removed only here.
	if pid > 0xfffffffc || pid == 0 || pid%4 != 0 {
		return evidence.Row{}, false, nil
	}
	row := thrdScanRow(found.layer, found.object)
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["TID"] = evidence.Number(tid)
	row.Cells["StartAddress"] = evidence.Address(start)
	row.Cells["Win32StartAddress"] = evidence.Address(win32)
	row.Cells["CreateTime"] = created
	row.Cells["ExitTime"] = exited
	row.Cells["CreateTimeRaw"] = createdRaw
	row.Cells["ExitTimeRaw"] = exitedRaw
	row.Cells["RecordType"] = evidence.Text("thread")
	rawStamp := ""
	if createdRaw.Kind != "missing" {
		rawStamp = createdRaw.String()
	}
	row.Cells["Identity"] = evidence.Text(evidence.ThreadID(e.ImageHash, found.layer, found.object, tid, rawStamp))
	owner, err := cachedThreadOwner(ctx, e, ownerAddress, maxNodes, owners)
	if err != nil {
		return evidence.Row{}, false, err
	}
	row.Cells["ProcessOffset"] = evidence.Address(ownerAddress)
	if owner != nil && owner.valid {
		stamp := ""
		if owner.created.Kind != "missing" {
			stamp = owner.created.String()
		}
		row.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), ownerAddress, owner.pid, stamp))
		row.Cells["ProcessName"] = evidence.Text(owner.name)
		if owner.pid == 4 {
			row.Cells["StartPath"] = evidence.Missing("system_thread_mapping_not_applicable", nil)
			row.Cells["Win32StartPath"] = evidence.Missing("system_thread_mapping_not_applicable", nil)
		} else if owner.regionErr != nil {
			row.Cells["StartPath"] = evidence.Missing("vad_index_incomplete", owner.regionErr)
			row.Cells["Win32StartPath"] = evidence.Missing("vad_index_incomplete", owner.regionErr)
		} else {
			row.Cells["StartPath"] = threadPathAt(owner.regions, start)
			row.Cells["Win32StartPath"] = threadPathAt(owner.regions, win32)
		}
	} else {
		row.Cells["StartPath"] = evidence.Missing("owner_not_valid", nil)
		row.Cells["Win32StartPath"] = evidence.Missing("owner_not_valid", nil)
	}
	return row, true, nil
}

func threadOwnerAddress(ctx context.Context, scan *object.Reader, objectAddress uint64) (uint64, error) {
	if _, err := scan.Field("_ETHREAD", "ThreadsProcess"); err == nil {
		return scan.Uint(ctx, objectAddress, "_ETHREAD", "ThreadsProcess")
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return 0, err
	}
	if _, err := scan.Field("_ETHREAD", "Tcb.Process"); err == nil {
		return scan.Uint(ctx, objectAddress, "_ETHREAD", "Tcb.Process")
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return 0, err
	}
	return 0, fmt.Errorf("_ETHREAD has neither ThreadsProcess nor Tcb.Process")
}

func cachedThreadOwner(ctx context.Context, e plugin.Environment, address uint64, maxNodes int, owners map[uint64]*threadOwner) (*threadOwner, error) {
	if found, ok := owners[address]; ok {
		return found, nil
	}
	kernel := e
	kernel.Objects = &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}
	owner := &threadOwner{}
	valid, err := processObjectValid(ctx, kernel.Objects, address)
	if err != nil {
		return nil, err
	}
	owner.valid = valid
	if valid {
		pid, err := kernel.Objects.Uint(ctx, address, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			owner.valid = false
		} else {
			owner.pid = pid
			name, err := processImageName(ctx, kernel.Objects, address, false)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				owner.name = ""
			} else {
				owner.name = name
			}
			created, _ := windowsTime(ctx, kernel, address, "_EPROCESS", "CreateTime")
			owner.created = created
			if pid != 4 {
				regions, err := windowsVADPaths(ctx, kernel, address, maxNodes)
				if err != nil {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					owner.regionErr = err
				} else {
					owner.regions = regions
				}
			}
		}
	}
	owners[address] = owner
	return owner, nil
}

func threadPathAt(regions []windowsVADPath, address uint64) evidence.Value {
	value := windowsPathAt(regions, address)
	if value.Kind != "string" {
		return value
	}
	text := value.String()
	if text == "" || !containsBackslash(text) {
		return evidence.Missing("not_file_backed", nil)
	}
	return value
}

func containsBackslash(text string) bool {
	for _, r := range text {
		if r == '\\' {
			return true
		}
	}
	return false
}

func threadObjectValid(ctx context.Context, scan *object.Reader, objectAddress uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	pid, err := scan.Uint(ctx, objectAddress, "_ETHREAD", "Cid.UniqueProcess")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	tid, err := scan.Uint(ctx, objectAddress, "_ETHREAD", "Cid.UniqueThread")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if pid%4 != 0 || tid%4 != 0 {
		return false, nil
	}
	if pid != 4 {
		when, ok, err := threadCreateInstant(ctx, scan, objectAddress)
		if err != nil {
			return false, err
		}
		if !ok || !processYear(when) {
			return false, nil
		}
	}
	return true, nil
}

func threadCreateInstant(ctx context.Context, scan *object.Reader, objectAddress uint64) (time.Time, bool, error) {
	ticks, ok, err := threadTimeTicks(ctx, scan, objectAddress, "CreateTime", true)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	when, datetime := volatilityFiletime(ticks)
	if !datetime {
		return time.Time{}, false, nil
	}
	return when, true, nil
}

func threadDisplayedTime(ctx context.Context, scan *object.Reader, objectAddress uint64, typ, field string, creation bool) (evidence.Value, evidence.Value, error) {
	raw, err := windowsRawTime(ctx, plugin.Environment{Objects: scan}, objectAddress, typ, field)
	if err != nil {
		return evidence.Value{}, evidence.Value{}, err
	}
	ticks, ok, err := threadTimeTicks(ctx, scan, objectAddress, field, creation)
	if err != nil {
		return evidence.Value{}, evidence.Value{}, err
	}
	if !ok {
		return evidence.Missing("unparsable_filetime", nil), evidence.Number(raw), nil
	}
	when, datetime := volatilityFiletime(ticks)
	if !datetime {
		reason := "unparsable_filetime"
		seconds := floorDivInt64(ticks, 10000000)
		if seconds == 0 {
			reason = "not_set"
		}
		return evidence.Missing(reason, nil), evidence.Number(raw), nil
	}
	frac := int64(0)
	if ticks >= 0 {
		frac = ticks % 10000000
	}
	text := time.Unix(when.Unix(), frac*100).UTC().Format(time.RFC3339Nano)
	return evidence.Text(text), evidence.Number(raw), nil
}

func threadTimeTicks(ctx context.Context, scan *object.Reader, objectAddress uint64, field string, creation bool) (int64, bool, error) {
	raw, err := windowsRawTime(ctx, plugin.Environment{Objects: scan}, objectAddress, "_ETHREAD", field)
	if err != nil {
		return 0, false, err
	}
	signed, err := quadSigned(scan, "_ETHREAD", field)
	if err != nil {
		return 0, false, err
	}
	ticks, ok := interpretedTicks(raw, signed)
	if !ok {
		return 0, false, nil
	}
	if creation {
		if _, err := scan.Field("_ETHREAD", "ThreadsProcess"); err == nil {
			ticks >>= 3
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return 0, false, err
		}
	}
	return ticks, true, nil
}

func quadSigned(scan *object.Reader, typ, field string) (bool, error) {
	member, err := scan.Field(typ, field)
	if err != nil {
		return false, err
	}
	path := field
	if member.Type.Kind == "struct" || member.Type.Kind == "union" {
		path += ".QuadPart"
	}
	quad, err := scan.Field(typ, path)
	if err != nil {
		return false, err
	}
	ref := quad.Type
	for depth := 0; depth < 8; depth++ {
		if ref.Kind == "base" || ref.Kind == "enum" {
			base, err := scan.Symbols.Type(ref.Name)
			if err != nil {
				return false, err
			}
			return base.Signed, nil
		}
		if ref.Kind == "bitfield" && ref.BitType != nil {
			ref = *ref.BitType
			continue
		}
		break
	}
	return false, nil
}

func interpretedTicks(raw uint64, signed bool) (int64, bool) {
	if !signed && raw > math.MaxInt64 {
		return 0, false
	}
	return int64(raw), true
}

func volatilityFiletime(ticks int64) (time.Time, bool) {
	seconds := floorDivInt64(ticks, 10000000)
	if seconds == 0 {
		return time.Time{}, false
	}
	unix := seconds - 11644473600
	if unix < -62135596800 || unix > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(unix, 0).UTC(), true
}

func floorDivInt64(n, d int64) int64 {
	q := n / d
	r := n % d
	if r != 0 && ((n < 0 && d > 0) || (n > 0 && d < 0)) {
		q--
	}
	return q
}
