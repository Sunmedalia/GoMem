package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsSvcScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"}, {Name: "Order", Kind: "uint64"}, {Name: "PID", Kind: "uint64"},
		{Name: "Start", Kind: "string"}, {Name: "State", Kind: "string"}, {Name: "Type", Kind: "string"},
		{Name: "Name", Kind: "string"}, {Name: "Display", Kind: "string"}, {Name: "Binary", Kind: "string"},
		{Name: "BinaryRegistry", Kind: "string"}, {Name: "Dll", Kind: "string"},
		{Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
	}
	var plugins []builtin
	for _, item := range []struct{ name, upstream, description, mode string }{
		{"windows.svcscan", "windows.svcscan.SvcScan", "Scan services.exe for version-selected Windows service records", "scan"},
		{"windows.svclist", "windows.svclist.SvcList", "Walk services from Sc27 headers in the services.exe image VAD", "list"},
		{"windows.svcdiff", "windows.malware.svcdiff.SvcDiff", "Find scanned service names absent from the services.exe list", "diff"},
	} {
		mode := item.mode
		plugins = append(plugins, builtin{plugin.Spec{
			Name: item.name, Upstream: item.upstream, Platform: "windows", NeedsKernel: true,
			Description: item.description,
			Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-process and VAD bound; not an upstream parameter"}},
			Columns:     columns,
		}, func(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
			return windowsServices(ctx, e, p, mode, out)
		}})
	}
	return plugins
}

const svcStringMax = 512

var svcStartNames = map[uint32]string{
	0: "SERVICE_BOOT_START",
	1: "SERVICE_SYSTEM_START",
	2: "SERVICE_AUTO_START",
	3: "SERVICE_DEMAND_START",
	4: "SERVICE_DISABLED",
}

var svcStateNames = map[uint32]string{
	1: "SERVICE_STOPPED",
	2: "SERVICE_START_PENDING",
	3: "SERVICE_STOP_PENDING",
	4: "SERVICE_RUNNING",
	5: "SERVICE_CONTINUE_PENDING",
	6: "SERVICE_PAUSE_PENDING",
	7: "SERVICE_PAUSED",
}

var svcTypeFlags = []struct {
	name string
	bit  uint32
}{
	{"SERVICE_KERNEL_DRIVER", 1},
	{"SERVICE_FILE_SYSTEM_DRIVER", 2},
	{"SERVICE_ADAPTOR", 4},
	{"SERVICE_RECOGNIZER_DRIVER", 8},
	{"SERVICE_WIN32_OWN_PROCESS", 16},
	{"SERVICE_WIN32_SHARE_PROCESS", 32},
	{"SERVICE_INTERACTIVE_PROCESS", 256},
}

type svcBinary struct {
	path, dll string
	pathOK    bool
	dllOK     bool
}

type svcStats struct {
	processes, skipped, headers, records, limited, missingExe uint64
}

func windowsServices(ctx context.Context, e plugin.Environment, p map[string]string, mode string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows services require a kernel layer and symbols")
	}
	layout, err := selectServiceLayout(e.Symbols)
	if err != nil {
		return err
	}
	if mode != "scan" && !serviceListSupported(e) {
		return fmt.Errorf("windows.%s requires Windows 10 15063+ x64", "svc"+mode)
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	binaries, err := serviceRegistryMap(ctx, e)
	if err != nil {
		return err
	}
	var stats svcStats
	var scanNames, listNames, listedRecords, hidden uint64
	if mode == "diff" {
		records := map[string]evidence.Row{}
		scanEmit := func(row evidence.Row) error { return rememberScannedService(records, row) }
		if err = enumerateWindowsServices(ctx, e, layout, max, "scan", binaries, &stats, scanEmit); err != nil {
			return err
		}
		listed := map[string]bool{}
		var listStats svcStats
		if err = enumerateWindowsServices(ctx, e, layout, max, "list", binaries, &listStats, func(row evidence.Row) error {
			if row.Cells["Name"].Kind != "string" {
				return fmt.Errorf("cannot compare an unreadable listed service name at %s", row.Provenance.Offset)
			}
			listed[row.Cells["Name"].String()] = true
			return nil
		}); err != nil {
			return err
		}
		if stats.skipped != 0 || listStats.skipped != 0 || listStats.missingExe != 0 {
			return fmt.Errorf("service comparison incomplete: scan layers skipped %d, list layers skipped %d, executable VADs missing %d", stats.skipped, listStats.skipped, listStats.missingExe)
		}
		scanNames, listNames, listedRecords = uint64(len(records)), uint64(len(listed)), listStats.records
		if err = emitServiceDifference(ctx, records, listed, func(row evidence.Row) error { hidden++; return out(row) }); err != nil {
			return err
		}
	} else if err = enumerateWindowsServices(ctx, e, layout, max, mode, binaries, &stats, out); err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"Offset": evidence.Missing("not_applicable", nil), "Order": evidence.Missing("not_applicable", nil),
		"PID": evidence.Missing("not_applicable", nil), "Start": evidence.Missing("not_applicable", nil),
		"State": evidence.Missing("not_applicable", nil), "Type": evidence.Missing("not_applicable", nil),
		"Name": evidence.Missing("not_applicable", nil), "Display": evidence.Missing("not_applicable", nil),
		"Binary": evidence.Missing("not_applicable", nil), "BinaryRegistry": evidence.Missing("not_applicable", nil),
		"Dll": evidence.Missing("not_applicable", nil), "RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(map[string]string{
			"layout": layout.name, "pointer_size": formatCount(uint64(layout.pointerSize)),
			"services_exe": formatCount(stats.processes), "layers_skipped": formatCount(stats.skipped),
			"headers": formatCount(stats.headers), "records": formatCount(stats.records),
			"registry_services": formatCount(uint64(len(binaries))), "chain_limit": formatCount(stats.limited), "exe_vad_missing": formatCount(stats.missingExe),
			"scan_names": formatCount(scanNames), "list_names": formatCount(listNames), "list_records": formatCount(listedRecords), "hidden": formatCount(hidden),
		}),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func serviceListSupported(e plugin.Environment) bool {
	return e.Symbols.PointerSize() == 8 && matchServiceVersion(e.Symbols, serviceVersion{minimum: [3]int{10, 0, 15063}, checks: serviceWin10Checks(false)})
}

func serviceExecutableRegion(regions []windowsVADPath) (windowsVADPath, bool) {
	for _, region := range regions {
		if region.file.Kind == "string" && strings.HasSuffix(strings.ToLower(region.file.String()), `\services.exe`) {
			return region, true
		}
	}
	return windowsVADPath{}, false
}

func rememberScannedService(records map[string]evidence.Row, row evidence.Row) error {
	if row.Cells["Name"].Kind != "string" {
		return fmt.Errorf("cannot compare an unreadable scanned service name at %s", row.Provenance.Offset)
	}
	records[row.Cells["Name"].String()] = row
	return nil
}

func emitServiceDifference(ctx context.Context, records map[string]evidence.Row, listed map[string]bool, out plugin.Emit) error {
	names := make([]string, 0, len(records))
	for name := range records {
		if !listed[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := out(records[name]); err != nil {
			return err
		}
	}
	return nil
}

func enumerateWindowsServices(ctx context.Context, e plugin.Environment, layout serviceLayout, max int, mode string, binaries map[string]svcBinary, stats *svcStats, out plugin.Emit) error {
	var seen map[string]bool
	if mode == "scan" {
		seen = map[string]bool{}
	}
	err := visitWindowsProcesses(ctx, e, max, nil, func(process, pid uint64, name string, created evidence.Value) error {
		if name != "services.exe" {
			return nil
		}
		stats.processes++
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		layer, layerErr := processMemory(ctx, e, process, 0, identity)
		if layerErr != nil {
			stats.skipped++
			return nil
		}
		regions, regionErr := windowsVADRegions(ctx, e, process, max)
		if regionErr != nil {
			return fmt.Errorf("windows services: services.exe PID %d VAD: %w", pid, regionErr)
		}
		reader := serviceReader{layer: layer, layout: layout}
		tag := []byte("serH")
		direct := !matchServiceVersion(e.Symbols, serviceVersion{minimum: [3]int{6, 0, 0}, checks: []serviceCheck{{"KdCopyDataBlock", "", true}}})
		if direct {
			tag = []byte("sErv")
		}
		if mode == "list" {
			direct = false
			region, found := serviceExecutableRegion(regions)
			if !found {
				stats.missingExe++
				return nil
			}
			regions = []windowsVADPath{region}
			tag = []byte("Sc27")
		}
		for _, region := range regions {
			if region.end < region.start {
				continue
			}
			size := region.end - region.start + 1
			if size == 0 {
				continue
			}
			scanErr := scanServicePattern(ctx, layer, region.start, size, tag, func(offset uint64) error {
				return reader.scanHit(ctx, offset, direct, binaries, seen, stats, out)
			})
			if scanErr != nil {
				return scanErr
			}
		}
		return nil
	})
	return err
}

// The scan tag is chosen independently from the field layout, matching the
// pinned Vista distinguisher even for inconsistent symbol metadata.
func (r serviceReader) scanHit(ctx context.Context, offset uint64, direct bool, binaries map[string]svcBinary, seen map[string]bool, stats *svcStats, out plugin.Emit) error {
	if direct {
		if offset < r.layout.tag {
			return nil
		}
		record := offset - r.layout.tag
		row, valid, _, err := r.readRecord(ctx, record, record, binaries)
		if err != nil || !valid {
			return err
		}
		stats.records++
		return out(row)
	}
	if offset%8 != 0 {
		return nil
	}
	stats.headers++
	return r.walkHeader(ctx, offset, binaries, seen, stats, out)
}

func serviceTypeName(value uint32) string {
	var names []string
	for _, flag := range svcTypeFlags {
		if value&flag.bit != 0 {
			names = append(names, flag.name)
		}
	}
	return strings.Join(names, "|")
}

func (r serviceReader) walkHeader(ctx context.Context, header uint64, binaries map[string]svcBinary, seen map[string]bool, stats *svcStats, out plugin.Emit) error {
	target, ok, err := r.pointer(ctx, header+r.layout.headerPtr)
	if err != nil || !ok {
		return err
	}
	return r.walkRecord(ctx, target, target, binaries, seen, stats, out)
}

func (r serviceReader) walkRecord(ctx context.Context, record, display uint64, binaries map[string]svcBinary, seen map[string]bool, stats *svcStats, out plugin.Emit) error {
	// Detect corrupt chains independently of the reference tuple deduplication.
	visited := map[uint64]bool{}
	for steps := 0; steps < 100000; steps++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited[record] {
			return fmt.Errorf("service PrevEntry cycle at %#x", record)
		}
		visited[record] = true
		row, valid, stable, err := r.readRecord(ctx, record, display, binaries)
		if err != nil || !valid {
			return err
		}
		// Absent PID, binary and registry cells are fresh Python objects unless
		// the registry cell was stored once in the service map. Only a row with
		// a numeric PID, a string binary and a mapped service can be seen again
		// and stop this chain. Other repeats stay, which is why one offset can
		// appear more than once.
		if stable && seen != nil {
			key := svcIdentity(row)
			if seen[key] {
				return nil
			}
			seen[key] = true
		}
		stats.records++
		if err = out(row); err != nil {
			return err
		}
		prevSlot := record + r.layout.prev
		next, ok, err := r.pointer(ctx, prevSlot)
		if err != nil || !ok || next == 0 {
			return err
		}
		display = prevSlot
		record = next
	}
	stats.limited++
	return fmt.Errorf("service chain exceeds 100000 records at %#x", record)
}

func (r serviceReader) readRecord(ctx context.Context, record, display uint64, binaries map[string]svcBinary) (evidence.Row, bool, bool, error) {
	order, ok, err := readSvcU32(ctx, r.layer, record+r.layout.order)
	if err != nil || !ok || order > 0xFFFF {
		return evidence.Row{}, false, false, err
	}
	startRaw, ok, err := readSvcU32(ctx, r.layer, record+r.layout.start)
	if err != nil || !ok {
		return evidence.Row{}, false, false, err
	}
	start, known := svcStartNames[startRaw]
	if !known {
		return evidence.Row{}, false, false, nil
	}
	stateRaw, ok, err := readSvcU32(ctx, r.layer, record+r.layout.state)
	if err != nil || !ok {
		return evidence.Row{}, false, false, err
	}
	state, known := svcStateNames[stateRaw]
	if !known {
		return evidence.Row{}, false, false, nil
	}
	typeRaw, ok, err := readSvcU32(ctx, r.layer, record+r.layout.serviceType)
	if err != nil || !ok {
		return evidence.Row{}, false, false, err
	}
	typeName := serviceTypeName(typeRaw)
	name, nameOK, err := r.textPointer(ctx, record+r.layout.namePtr)
	if err != nil {
		return evidence.Row{}, false, false, err
	}
	displayName, displayOK, err := r.textPointer(ctx, record+r.layout.displayPtr)
	if err != nil {
		return evidence.Row{}, false, false, err
	}
	running := state == "SERVICE_RUNNING"
	processType := strings.Contains(typeName, "PROCESS")
	pid := evidence.Missing("not_applicable", nil)
	binary := evidence.Missing("not_applicable", nil)
	if running {
		slot := r.layout.driverPtr
		if processType {
			slot = r.layout.processPtr
		}
		proc, procOK, err := r.pointer(ctx, record+slot)
		if err != nil {
			return evidence.Row{}, false, false, err
		}
		if processType {
			if !procOK {
				pid = evidence.Missing("unreadable", nil)
				binary = evidence.Missing("unreadable", nil)
			} else {
				pidValue, pidOK, err := readSvcU32(ctx, r.layer, proc+r.layout.pid)
				if err != nil {
					return evidence.Row{}, false, false, err
				}
				if pidOK {
					pid = evidence.Number(uint64(pidValue))
				} else {
					pid = evidence.Missing("unreadable", nil)
				}
				text, textOK, err := r.textPointer(ctx, proc+r.layout.binaryPtr)
				if err != nil {
					return evidence.Row{}, false, false, err
				}
				if textOK {
					binary = evidence.Text(text)
				} else {
					binary = evidence.Missing("unreadable", nil)
				}
			}
		} else if procOK {
			text, textOK, err := readSvcUTF16(ctx, r.layer, proc)
			if err != nil {
				return evidence.Row{}, false, false, err
			}
			if textOK {
				binary = evidence.Text(text)
			} else {
				binary = evidence.Missing("unreadable", nil)
			}
		} else {
			binary = evidence.Missing("unreadable", nil)
		}
	}
	regPath := evidence.Missing("unreadable", nil)
	dll := evidence.Missing("unreadable", nil)
	inMap := false
	if nameOK {
		if info, found := binaries[name]; found {
			inMap = true
			if info.pathOK {
				regPath = evidence.Text(info.path)
			}
			if info.dllOK {
				dll = evidence.Text(info.dll)
			}
		}
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"Offset": evidence.Address(display), "Order": evidence.Number(uint64(order)), "PID": pid,
		"Start": evidence.Text(start), "State": evidence.Text(state), "Type": evidence.Text(typeName),
		"Name": svcText(name, nameOK), "Display": svcText(displayName, displayOK), "Binary": binary,
		"BinaryRegistry": regPath, "Dll": dll, "RecordType": evidence.Text("service"),
	}, Provenance: evidence.Provenance{Layer: r.layer.Name(), Offset: fmt.Sprintf("0x%x", record)}}
	stable := inMap && displayOK && pid.Kind == "uint64" && binary.Kind == "string"
	return row, true, stable, nil
}

func svcText(value string, ok bool) evidence.Value {
	if ok {
		return evidence.Text(value)
	}
	return evidence.Missing("unreadable", nil)
}

func svcIdentity(row evidence.Row) string {
	parts := make([]string, 0, len(row.Cells))
	for _, name := range []string{"Offset", "Order", "PID", "Start", "State", "Type", "Name", "Display", "Binary", "BinaryRegistry", "Dll"} {
		cell := row.Cells[name]
		parts = append(parts, name+"="+cell.Kind+":"+cell.String())
	}
	return strings.Join(parts, "\n")
}

func readSvcU32(ctx context.Context, layer memory.MemoryLayer, address uint64) (uint32, bool, error) {
	raw, err := memory.Read(ctx, layer, address, 4)
	if err != nil {
		if err = ctx.Err(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	return binary.LittleEndian.Uint32(raw), true, nil
}

func (r serviceReader) pointer(ctx context.Context, address uint64) (uint64, bool, error) {
	raw, err := memory.Read(ctx, r.layer, address, r.layout.pointerSize)
	if err != nil {
		if err = ctx.Err(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	if r.layout.pointerSize == 4 {
		return uint64(binary.LittleEndian.Uint32(raw)), true, nil
	}
	return binary.LittleEndian.Uint64(raw) & 0x0000ffffffffffff, true, nil
}

func (r serviceReader) textPointer(ctx context.Context, slot uint64) (string, bool, error) {
	target, ok, err := r.pointer(ctx, slot)
	if err != nil || !ok {
		return "", false, err
	}
	return readSvcUTF16(ctx, r.layer, target)
}

func readSvcUTF16(ctx context.Context, layer memory.MemoryLayer, address uint64) (string, bool, error) {
	raw, err := memory.Read(ctx, layer, address, svcStringMax)
	if err != nil {
		if err = ctx.Err(); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	if len(raw)%2 != 0 {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(units))
	if i := strings.IndexRune(text, 0); i >= 0 {
		text = text[:i]
	}
	return text, true, nil
}

func scanServicePattern(ctx context.Context, layer memory.MemoryLayer, start, size uint64, needle []byte, emit func(uint64) error) error {
	const page = 4096
	var carry []byte
	for off := uint64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := uint64(page)
		if size-off < n {
			n = size - off
		}
		buf := make([]byte, n)
		got, err := layer.ReadAt(ctx, buf, start+off)
		if err != nil || got != int(n) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			carry = nil
			off += n
			continue
		}
		window := buf
		base := start + off
		if len(carry) > 0 {
			window = append(append([]byte{}, carry...), buf...)
			base -= uint64(len(carry))
		}
		for i := 0; i+len(needle) <= len(window); {
			j := bytes.Index(window[i:], needle)
			if j < 0 {
				break
			}
			i += j
			if err = emit(base + uint64(i)); err != nil {
				return err
			}
			i++
		}
		if len(buf) >= len(needle)-1 {
			carry = append([]byte{}, buf[len(buf)-(len(needle)-1):]...)
		} else {
			carry = nil
		}
		off += n
	}
	return nil
}

func serviceRegistryMap(ctx context.Context, e plugin.Environment) (map[string]svcBinary, error) {
	out := map[string]svcBinary{}
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return nil, err
	}
	proc, _, _ := windowsRegistryLayer(ctx, e)
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil && len(hives) == 0 {
		return nil, err
	}
	for _, hive := range hives {
		if !strings.Contains(strings.ToLower(hive.Name), `machine\system`) {
			continue
		}
		reg, openErr := registry.Open(ctx, e.Kernel, proc, hive.Address, hive.Name, layout)
		if openErr != nil {
			continue
		}
		path, keyErr := serviceKey(ctx, reg)
		if keyErr != nil {
			continue
		}
		subs, subErr := reg.Subkeys(ctx, path[len(path)-1])
		if subErr != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		for _, sub := range subs {
			info := svcBinary{}
			values, valErr := reg.Values(ctx, sub)
			if valErr != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			for _, value := range values {
				if value.Name != "ImagePath" {
					continue
				}
				text, ok := registryUTF16(value)
				info.path, info.pathOK = text, ok
				break
			}
			params, paramErr := reg.Subkeys(ctx, sub)
			if paramErr != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			for _, child := range params {
				if child.Name != "Parameters" {
					continue
				}
				paramValues, err := reg.Values(ctx, child)
				if err != nil && ctx.Err() != nil {
					return nil, ctx.Err()
				}
				for _, value := range paramValues {
					if value.Name != "ServiceDll" {
						continue
					}
					text, ok := registryUTF16(value)
					info.dll, info.dllOK = text, ok
					break
				}
				break
			}
			out[sub.Name] = info
		}
		return out, nil
	}
	return out, nil
}

func registryUTF16(value registry.Value) (string, bool) {
	data := value.Data
	if value.DataErr != nil {
		return "", true
	}
	if len(data)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(units)), "\x00"), true
}
