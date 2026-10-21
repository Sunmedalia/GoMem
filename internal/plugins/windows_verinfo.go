package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsVerInfoPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.verinfo", Upstream: "windows.verinfo.VerInfo", Platform: "windows", NeedsKernel: true,
		Description: "List PE product versions for loaded kernel modules and process load-order DLLs",
		Parameters: []plugin.Parameter{
			{Name: "extensive", Kind: "bool", Default: "false", Description: "After a failed module resource parse, scan physical memory for a UTF-16BE OriginalFilename version block"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-process and loaded-module list bound; not an upstream parameter"},
			{Name: "max-modules", Kind: "uint", Default: "1000000", Description: "Total process DLL traversal bound, including entries with an unreadable base; not an upstream parameter"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Base", Kind: "address"},
			{Name: "Name", Kind: "string"}, {Name: "Major", Kind: "uint64"}, {Name: "Minor", Kind: "uint64"},
			{Name: "Product", Kind: "uint64"}, {Name: "Build", Kind: "uint64"},
			{Name: "NameError", Kind: "string"}, {Name: "VersionError", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
		},
	}, windowsVerInfo}}
}

type versionQuad struct{ major, minor, product, build uint64 }

type verStats struct {
	modules, dlls, read, unread, namesUnread, basesSkipped, processesSkipped, sessions, fallback, listsStopped uint64
}

func windowsVerInfo(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.verinfo requires a kernel layer and symbols")
	}
	extensive, err := strconv.ParseBool(p["extensive"])
	if err != nil {
		return fmt.Errorf("extensive: %w", err)
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || maxNodes < 1 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	maxModules, err := strconv.ParseUint(p["max-modules"], 0, 32)
	if err != nil || maxModules < 1 || maxModules > 1000000 {
		return fmt.Errorf("max-modules must be 1..1000000")
	}
	processes, err := collectVerProcesses(ctx, e, int(maxNodes))
	if err != nil {
		return err
	}
	sessions, err := verSessionLayers(ctx, e, processes)
	if err != nil {
		return err
	}
	stats := verStats{sessions: uint64(len(sessions))}
	for _, proc := range processes {
		if proc.skipped {
			stats.processesSkipped++
		}
	}
	if err = emitVerModules(ctx, e, extensive, int(maxNodes), sessions, &stats, out); err != nil {
		return err
	}
	if err = emitVerDLLs(ctx, e, processes, int(maxNodes), maxModules, &stats, out); err != nil {
		return err
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"PID": evidence.Missing("not_applicable", nil), "Process": evidence.Missing("not_applicable", nil),
		"Base": evidence.Missing("not_applicable", nil), "Name": evidence.Missing("not_applicable", nil),
		"Major": evidence.Missing("not_applicable", nil), "Minor": evidence.Missing("not_applicable", nil),
		"Product": evidence.Missing("not_applicable", nil), "Build": evidence.Missing("not_applicable", nil),
		"NameError": evidence.Missing("not_applicable", nil), "VersionError": evidence.Missing("not_applicable", nil),
		"RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(map[string]string{
			"modules": formatCount(stats.modules), "process_dlls": formatCount(stats.dlls),
			"versions_read": formatCount(stats.read), "versions_unreadable": formatCount(stats.unread),
			"names_unreadable": formatCount(stats.namesUnread), "dll_bases_skipped": formatCount(stats.basesSkipped),
			"processes_skipped": formatCount(stats.processesSkipped), "sessions": formatCount(stats.sessions),
			"lists_stopped": formatCount(stats.listsStopped),
			"extensive":     strconv.FormatBool(extensive), "physical_fallbacks": formatCount(stats.fallback),
		}),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	return out(row)
}

type verProcess struct {
	address, pid uint64
	layer        memory.MemoryLayer
	skipped      bool
}

func collectVerProcesses(ctx context.Context, e plugin.Environment, max int) ([]verProcess, error) {
	head, err := e.Symbol("PsActiveProcessHead")
	if err != nil {
		return nil, err
	}
	links, err := e.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return nil, err
	}
	var processes []verProcess
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(address uint64) error {
		pid, pidErr := e.Objects.Uint(ctx, address, "_EPROCESS", "UniqueProcessId")
		item := verProcess{address: address, pid: pid}
		if pidErr != nil {
			item.skipped = true
			processes = append(processes, item)
			return nil
		}
		created, _ := windowsTime(ctx, e, address, "_EPROCESS", "CreateTime")
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), address, pid, stamp)
		layer, layerErr := processMemory(ctx, e, address, 0, identity)
		if layerErr != nil {
			item.skipped = true
		} else {
			item.layer = layer
		}
		processes = append(processes, item)
		return nil
	})
	return processes, err
}

// verSessionLayers keeps the first successfully created process layer for each
// session, in active-list order. A layer that cannot be built is not recorded,
// even when its session identifier is readable. The kernel layer is not a
// candidate; kernel modules are read through one of these session spaces.
func verSessionLayers(ctx context.Context, e plugin.Environment, processes []verProcess) ([]memory.MemoryLayer, error) {
	seen := map[uint64]bool{}
	var layers []memory.MemoryLayer
	for _, proc := range processes {
		if proc.skipped || proc.layer == nil {
			continue
		}
		id, ok, err := verSessionID(ctx, e, proc.address)
		if err != nil {
			return nil, err
		}
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		layers = append(layers, proc.layer)
	}
	return layers, nil
}

func verSessionID(ctx context.Context, e plugin.Environment, process uint64) (uint64, bool, error) {
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Session")
	if err != nil || pointer == 0 {
		return 0, false, nil
	}
	if _, typeErr := e.Symbols.Type("_MM_SESSION_SPACE"); typeErr != nil {
		return verSessionFallback(ctx, e, pointer)
	}
	if _, fieldErr := e.Objects.Field("_MM_SESSION_SPACE", "SessionId"); fieldErr != nil {
		if errors.Is(fieldErr, object.ErrFieldAbsent) {
			return verSessionFallback(ctx, e, pointer)
		}
		return 0, false, nil
	}
	id, err := e.Objects.Uint(ctx, pointer, "_MM_SESSION_SPACE", "SessionId")
	if err != nil {
		return 0, false, nil
	}
	return id, true, nil
}

func verSessionFallback(ctx context.Context, e plugin.Environment, pointer uint64) (uint64, bool, error) {
	address, err := memory.Add(pointer, 8)
	if err != nil {
		return 0, false, nil
	}
	raw, err := memory.Read(ctx, e.Kernel, address, 4)
	if err != nil {
		return 0, false, nil
	}
	return uint64(binary.LittleEndian.Uint32(raw)), true, nil
}

func verSessionForBase(ctx context.Context, layers []memory.MemoryLayer, base uint64) (memory.MemoryLayer, error) {
	for _, layer := range layers {
		_, err := memory.Read(ctx, layer, base, 1)
		if err == nil {
			return layer, nil
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func emitVerModules(ctx context.Context, e plugin.Environment, extensive bool, max int, sessions []memory.MemoryLayer, stats *verStats, out plugin.Emit) error {
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	link, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		link, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return err
	}
	return e.Objects.WalkList(ctx, head, link.Offset, max, func(address uint64) error {
		base, err := e.Objects.Uint(ctx, address, typ, "DllBase")
		if err != nil {
			return fmt.Errorf("windows.verinfo: module %#x DllBase: %w", address, err)
		}
		name, nameErr := unicodeString(ctx, e, address, typ, "BaseDllName")
		// Pointer objects are masked to the layer address bits before they are used.
		// A 64-bit kernel pointer therefore becomes a non-canonical 48-bit value.
		readBase := volatilityAddress(base, e.Symbols.PointerSize())
		layer, err := verSessionForBase(ctx, sessions, readBase)
		if err != nil {
			return err
		}
		var quad versionQuad
		var versionErr error
		if layer == nil {
			versionErr = errors.New("no session layer can read the module base")
		} else {
			quad, versionErr = readProductVersion(ctx, layer, readBase)
		}
		if versionErr != nil {
			if err = ctx.Err(); err != nil {
				return err
			}
			if extensive && nameErr == nil && e.Physical != nil {
				found, ok, scanErr := findExtensiveVersion(ctx, e.Physical, name)
				if scanErr != nil {
					return scanErr
				}
				if ok {
					quad, versionErr = found, nil
					stats.fallback++
				}
			}
		}
		stats.modules++
		return out(verEvidence(e.Kernel.Name(), address, evidence.Missing("not_applicable", nil), evidence.Missing("not_applicable", nil), base, name, nameErr, quad, versionErr, stats))
	})
}

func emitVerDLLs(ctx context.Context, e plugin.Environment, processes []verProcess, max int, maxModules uint64, stats *verStats, out plugin.Emit) error {
	var seen uint64
	for _, proc := range processes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if proc.skipped || proc.layer == nil {
			continue
		}
		name, nameErr := e.Objects.String(ctx, proc.address, "_EPROCESS", "ImageFileName", 64)
		processName := evidence.Text(name)
		var emitted bool
		err := walkVerLoadOrder(ctx, e, proc, max, func(user plugin.Environment, entry, base uint64) error {
			if seen >= maxModules {
				return fmt.Errorf("total DLL traversal exceeds max-modules")
			}
			seen++
			moduleName, moduleErr := unicodeString(ctx, user, entry, "_LDR_DATA_TABLE_ENTRY", "BaseDllName")
			quad, versionErr := readProductVersion(ctx, proc.layer, volatilityAddress(base, user.Symbols.PointerSize()))
			if versionErr != nil {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if !emitted && nameErr != nil {
				return fmt.Errorf("windows.verinfo: process %#x ImageFileName: %w", proc.address, nameErr)
			}
			emitted = true
			stats.dlls++
			return out(verEvidence(proc.layer.Name(), entry, evidence.Number(proc.pid), processName, base, moduleName, moduleErr, quad, versionErr, stats))
		}, stats)
		if err != nil {
			return err
		}
	}
	return nil
}

func walkVerLoadOrder(ctx context.Context, e plugin.Environment, proc verProcess, max int, emit func(plugin.Environment, uint64, uint64) error, stats *verStats) error {
	peb, err := e.Objects.Uint(ctx, proc.address, "_EPROCESS", "Peb")
	if err != nil {
		peb = 0
	}
	var wow uint64
	if e.Symbols.PointerSize() == 8 {
		for _, path := range []string{"WoW64Process", "Wow64Process"} {
			if _, fieldErr := e.Objects.Field("_EPROCESS", path); fieldErr != nil {
				if errors.Is(fieldErr, object.ErrFieldAbsent) {
					continue
				}
				wow = 0
				break
			}
			value, readErr := e.Objects.Uint(ctx, proc.address, "_EPROCESS", path)
			if readErr != nil {
				wow = 0
				break
			}
			wow = value
			break
		}
	}
	type target struct {
		peb uint64
		env plugin.Environment
	}
	var targets []target
	native := e
	native.Kernel = proc.layer
	native.Objects = &object.Reader{Layer: proc.layer, Symbols: e.Symbols}
	if peb != 0 {
		targets = append(targets, target{peb, native})
	}
	if wow != 0 {
		peb32 := wow
		readable := true
		for _, candidate := range []struct{ typ, path string }{{"_EWOW64PROCESS", "Peb"}, {"_WOW64_PROCESS", "Wow64"}} {
			if _, typeErr := e.Symbols.Type(candidate.typ); typeErr != nil {
				continue
			}
			value, readErr := e.Objects.Uint(ctx, wow, candidate.typ, candidate.path)
			if readErr != nil {
				readable = false
			} else {
				peb32 = value
			}
			break
		}
		if readable && peb32 != 0 {
			table, err := wowLoaderSymbols()
			if err != nil {
				return err
			}
			user32 := native
			user32.Symbols = table
			user32.Objects = &object.Reader{Layer: proc.layer, Symbols: table}
			targets = append(targets, target{peb32, user32})
		}
	}
	for _, target := range targets {
		user := target.env
		ldr, err := user.Objects.Uint(ctx, target.peb, "_PEB", "Ldr")
		if err != nil || ldr == 0 {
			continue
		}
		head, err := user.Objects.Field("_PEB_LDR_DATA", "InLoadOrderModuleList")
		if err != nil {
			return err
		}
		list, err := memory.Add(ldr, head.Offset)
		if err != nil {
			return err
		}
		link, err := user.Objects.Field("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
		if err != nil {
			return err
		}
		err = walkVerForwardList(ctx, user, list, link.Offset, max, func(address uint64) error {
			base, baseErr := user.Objects.Uint(ctx, address, "_LDR_DATA_TABLE_ENTRY", "DllBase")
			if baseErr != nil {
				stats.basesSkipped++
				return nil
			}
			return emit(user, address, base)
		}, &stats.listsStopped)
		if err != nil {
			return err
		}
	}
	return nil
}

// walkVerForwardList follows Flink the way LIST_ENTRY.to_list does. An
// unmapped next entry, a zero pointer, or a one-byte-invalid object ends the
// list. The sentinel Flink itself still has to be readable. Blink is not
// consulted, so a missing back link does not fail the task.
func walkVerForwardList(ctx context.Context, user plugin.Environment, head, linkOffset uint64, max int, emit func(uint64) error, stopped *uint64) error {
	if max <= 0 {
		return fmt.Errorf("invalid list limit")
	}
	layer := user.Objects.Layer
	ok, err := verBytesReadable(ctx, layer, head, 1)
	if err != nil {
		return err
	}
	if !ok {
		if stopped != nil {
			*stopped++
		}
		return nil
	}
	next, err := verListPointer(ctx, user, head)
	if err != nil {
		return err
	}
	entrySize := user.Symbols.PointerSize() * 2
	seen := map[uint64]bool{head: true}
	emitted := 0
	for {
		if next == 0 || seen[next] {
			return nil
		}
		ok, err = verBytesReadable(ctx, layer, next, entrySize)
		if err != nil {
			return err
		}
		if !ok || next < linkOffset {
			if stopped != nil {
				*stopped++
			}
			return nil
		}
		objectAddress := next - linkOffset
		ok, err = verBytesReadable(ctx, layer, objectAddress, 1)
		if err != nil {
			return err
		}
		if !ok {
			if stopped != nil {
				*stopped++
			}
			return nil
		}
		if emitted >= max {
			return fmt.Errorf("linked list exceeded %d nodes", max)
		}
		seen[next] = true
		emitted++
		if err = emit(objectAddress); err != nil {
			return err
		}
		next, err = verListPointer(ctx, user, next)
		if err != nil {
			return err
		}
	}
}

func verListPointer(ctx context.Context, user plugin.Environment, address uint64) (uint64, error) {
	value, err := user.Objects.Scalar(ctx, address, symbols.TypeRef{Kind: "pointer"})
	if err != nil {
		return 0, err
	}
	return volatilityAddress(value, user.Symbols.PointerSize()), nil
}

func verBytesReadable(ctx context.Context, layer memory.MemoryLayer, address uint64, size int) (bool, error) {
	if size < 1 {
		return false, fmt.Errorf("invalid readability length %d", size)
	}
	_, err := memory.Read(ctx, layer, address, size)
	if err == nil {
		return true, nil
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func verEvidence(layer string, entry uint64, pid, process evidence.Value, base uint64, name string, nameErr error, quad versionQuad, versionErr error, stats *verStats) evidence.Row {
	nameCell := evidence.Text(name)
	nameError := evidence.Missing("not_applicable", nil)
	if nameErr != nil {
		nameCell = evidence.Missing("unreadable", nil)
		nameError = evidence.Missing("unreadable", nameErr)
		stats.namesUnread++
	}
	major := evidence.Number(quad.major)
	minor := evidence.Number(quad.minor)
	product := evidence.Number(quad.product)
	build := evidence.Number(quad.build)
	versionError := evidence.Missing("not_applicable", nil)
	if versionErr != nil {
		missing := evidence.Missing("unreadable", nil)
		major, minor, product, build = missing, missing, missing, missing
		versionError = evidence.Missing("unreadable", versionErr)
		stats.unread++
	} else {
		stats.read++
	}
	return evidence.Row{Cells: map[string]evidence.Value{
		"PID": pid, "Process": process, "Base": evidence.Address(base), "Name": nameCell,
		"Major": major, "Minor": minor, "Product": product, "Build": build,
		"NameError": nameError, "VersionError": versionError, "RecordType": evidence.Text("version"),
	}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", entry)}}
}

func readProductVersion(ctx context.Context, layer memory.MemoryLayer, base uint64) (versionQuad, error) {
	image, err := pe.Plan(ctx, layer, base)
	if err != nil {
		return versionQuad{}, err
	}
	parser, err := newVerParser(ctx, layer, image)
	if err != nil {
		return versionQuad{}, err
	}
	return parser.productVersion()
}

var errExtensiveDone = errors.New("extensive version scan completed")

func findExtensiveVersion(ctx context.Context, layer memory.MemoryLayer, filename string) (versionQuad, bool, error) {
	needle := utf16BE("OriginalFilename\x00" + filename)
	if len(needle) == 0 || len(needle) > 8192 {
		return versionQuad{}, false, fmt.Errorf("windows.verinfo: extensive filename needle is %d bytes", len(needle))
	}
	var found versionQuad
	var have bool
	err := memory.Scan(ctx, layer, needle, func(offset uint64) error {
		if offset < 0x500 {
			return fmt.Errorf("windows.verinfo: extensive match at physical %#x has no 0x500-byte preamble", offset)
		}
		data, err := memory.Read(ctx, layer, offset-0x500, 0x500)
		if err != nil {
			return fmt.Errorf("windows.verinfo: extensive preamble at physical %#x: %w", offset-0x500, err)
		}
		// A missing marker yields find==-1, then -1+4, and the pinned check is still >= 0.
		start := bytes.Index(data, []byte{0xbd, 0x04, 0xef, 0xfe}) + 4
		if start < 0 || start+20 > len(data) {
			return fmt.Errorf("windows.verinfo: extensive version structure at physical %#x is truncated", offset)
		}
		raw := data[start : start+20]
		found = versionQuad{
			major:   uint64(binary.LittleEndian.Uint16(raw[6:8])),
			minor:   uint64(binary.LittleEndian.Uint16(raw[4:6])),
			product: uint64(binary.LittleEndian.Uint16(raw[10:12])),
			build:   uint64(binary.LittleEndian.Uint16(raw[8:10])),
		}
		have = true
		return errExtensiveDone
	})
	if errors.Is(err, errExtensiveDone) {
		return found, have, nil
	}
	return versionQuad{}, false, err
}

func utf16BE(value string) []byte {
	units := utf16.Encode([]rune(value))
	out := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.BigEndian.PutUint16(out[i*2:], unit)
	}
	return out
}

func volatilityAddress(value uint64, pointerSize int) uint64 {
	switch pointerSize {
	case 8:
		return value & 0x0000ffffffffffff
	case 4:
		return value & 0xffffffff
	default:
		return value
	}
}
