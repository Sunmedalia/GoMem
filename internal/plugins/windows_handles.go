package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const (
	handleLevelMask  = 7
	handlePageSize   = 0x1000
	handleMultiplier = 4
	handleMaxPages   = 100000
	handleMaxSlots   = 2000000
	handleNameLimit  = 128
	keyHiveEntry     = 0x4
)

var errNameInfoAbsent = errors.New("object name header is absent")
var errHandleCycle = errors.New("handle table page repeats")

func windowsHandlePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.handles", Upstream: "windows.handles.Handles", Platform: "windows", NeedsKernel: true,
		Description: "List open handles for active processes, or for one pool-scanned process when offset is set",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Comma-separated PIDs to include; ignored when offset is non-zero"},
			{Name: "offset", Kind: "uint", Default: "0", Description: "Physical EPROCESS address. Non-zero selects the pool scan instead of the active list"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active process list traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "Offset", Kind: "address"},
			{Name: "HandleValue", Kind: "address"},
			{Name: "Type", Kind: "string"},
			{Name: "GrantedAccess", Kind: "address"},
			{Name: "Name", Kind: "string"},
			{Name: "NameError", Kind: "string"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsHandles}}
}

func windowsHandles(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.handles requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	offset, err := parseHandleOffset(p["offset"])
	if err != nil {
		return err
	}
	walker, err := newHandleWalker(ctx, e)
	if err != nil {
		return err
	}
	if offset != 0 {
		walker.mode = "psscan"
		if err := walker.scanOffset(ctx, e, offset, out); err != nil {
			return err
		}
	} else {
		walker.mode = "pslist"
		err = visitWindowsProcesses(ctx, e, max, pids, func(address, pid uint64, name string, _ evidence.Value) error {
			process, err := processImageName(ctx, e.Objects, address, false)
			if err != nil {
				return err
			}
			return walker.emitProcess(ctx, address, pid, process, out)
		})
		if err != nil {
			return err
		}
	}
	return walker.summary(e, out)
}

func parseHandleOffset(raw string) (uint64, error) {
	if raw == "" || raw == "0" {
		return 0, nil
	}
	value, err := parseUintParam("offset", raw)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func parseUintParam(name, raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

type handleWalker struct {
	env            plugin.Environment
	reader         *object.Reader
	pointerSize    int
	body           uint64
	entrySize      uint64
	legacyObject   bool
	hasTypeIndex   bool
	hasType        bool
	hasNameOffset  bool
	hasKeyTrans    bool
	cookie         uint64
	hasCookie      bool
	typeMap        map[int]string
	infoDeltas     []byte
	stack          []uint64
	mode           string
	processes      int
	handles        int
	skippedObjects int
	skippedTables  int
	cycles         int
	pages          int
	slots          int
	levels         [8]int
}

func newHandleWalker(ctx context.Context, e plugin.Environment) (*handleWalker, error) {
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return nil, fmt.Errorf("windows.handles needs a 4- or 8-byte pointer")
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return nil, fmt.Errorf("_OBJECT_HEADER.Body: %w", err)
	}
	entry, err := e.Symbols.Type("_HANDLE_TABLE_ENTRY")
	if err != nil || entry.Size == 0 || entry.Size > handlePageSize {
		return nil, fmt.Errorf("invalid _HANDLE_TABLE_ENTRY size")
	}
	for _, path := range []string{"_EPROCESS.ObjectTable", "_EPROCESS.ImageFileName", "_HANDLE_TABLE.TableCode"} {
		parts := strings.SplitN(path, ".", 2)
		if _, err := e.Objects.Field(parts[0], parts[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	_, typeIndexErr := e.Objects.Field("_OBJECT_HEADER", "TypeIndex")
	_, typeErr := e.Objects.Field("_OBJECT_HEADER", "Type")
	if typeIndexErr != nil && typeErr != nil {
		return nil, fmt.Errorf("_OBJECT_HEADER has neither TypeIndex nor Type")
	}
	_, objectErr := e.Objects.Field("_HANDLE_TABLE_ENTRY", "Object")
	legacy := objectErr == nil
	if !legacy {
		if pointer == 8 {
			if _, err := e.Objects.Field("_HANDLE_TABLE_ENTRY", "ObjectPointerBits"); err != nil {
				return nil, fmt.Errorf("_HANDLE_TABLE_ENTRY.ObjectPointerBits: %w", err)
			}
		} else if _, err := e.Objects.Field("_HANDLE_TABLE_ENTRY", "InfoTable"); err != nil {
			return nil, fmt.Errorf("_HANDLE_TABLE_ENTRY.InfoTable: %w", err)
		}
		if _, err := e.Objects.Field("_HANDLE_TABLE_ENTRY", "GrantedAccessBits"); err != nil {
			return nil, fmt.Errorf("_HANDLE_TABLE_ENTRY.GrantedAccessBits: %w", err)
		}
	} else if _, err := e.Objects.Field("_HANDLE_TABLE_ENTRY", "GrantedAccess"); err != nil {
		return nil, fmt.Errorf("_HANDLE_TABLE_ENTRY.GrantedAccess: %w", err)
	}
	_, nameOffsetErr := e.Objects.Field("_OBJECT_HEADER", "NameInfoOffset")
	deltas := []byte(nil)
	if nameOffsetErr != nil {
		if _, err := e.Objects.Field("_OBJECT_HEADER", "InfoMask"); err != nil {
			return nil, fmt.Errorf("_OBJECT_HEADER.InfoMask: %w", err)
		}
		address, err := e.Symbol("ObpInfoMaskToOffset")
		if err != nil {
			return nil, fmt.Errorf("ObpInfoMaskToOffset: %w", err)
		}
		deltas, err = memory.Read(ctx, e.Kernel, address, 4)
		if err != nil {
			return nil, fmt.Errorf("ObpInfoMaskToOffset: %w", err)
		}
	}
	typeMap, err := windowsObjectTypes(ctx, e)
	if err != nil {
		return nil, err
	}
	cookie, hasCookie, err := windowsHeaderCookie(ctx, e)
	if err != nil {
		return nil, err
	}
	_, transErr := e.Objects.Field("_CM_KEY_BODY", "Trans")
	return &handleWalker{
		env: e, reader: e.Objects, pointerSize: pointer, body: body.Offset,
		entrySize: entry.Size, legacyObject: legacy, hasTypeIndex: typeIndexErr == nil, hasType: typeErr == nil,
		hasNameOffset: nameOffsetErr == nil, hasKeyTrans: transErr == nil, cookie: cookie, hasCookie: hasCookie,
		typeMap: typeMap, infoDeltas: deltas,
	}, nil
}

func (w *handleWalker) scanOffset(ctx context.Context, e plugin.Environment, offset uint64, out plugin.Emit) error {
	constraints, err := builtinPoolConstraints("Pro\xe3", "Proc")
	if err != nil {
		return err
	}
	return scanPoolObjects(ctx, e, constraints, "processes", psScanRow, func(row evidence.Row) error {
		kind := row.Cells["RecordType"].String()
		if kind == "summary" || kind == "diagnostic" {
			return nil
		}
		return nil
	}, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		match, err := handleOffsetMatch(ctx, e, found, offset)
		if err != nil {
			return evidence.Row{}, false, poolFatalError{err}
		}
		if !match {
			return evidence.Row{}, false, nil
		}
		pid, err := found.scan.Uint(ctx, found.object, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			return evidence.Row{}, false, poolFatalError{err}
		}
		name, err := processImageName(ctx, found.scan, found.object, false)
		if err != nil {
			return evidence.Row{}, false, poolFatalError{err}
		}
		saved := w.reader
		w.reader = found.scan
		err = w.emitProcess(ctx, found.object, pid, name, out)
		w.reader = saved
		if err != nil {
			return evidence.Row{}, false, poolFatalError{err}
		}
		return evidence.Row{}, false, nil
	})
}

func handleOffsetMatch(ctx context.Context, e plugin.Environment, found poolHit, offset uint64) (bool, error) {
	if !windows10OrLater(e.Symbols) {
		return found.object == offset, nil
	}
	layer, ok := e.Kernel.(*memory.Virtual)
	if !ok || layer.Translator == nil {
		return false, fmt.Errorf("kernel translator is unavailable for handle offset")
	}
	mapping, err := layer.Translator.Translate(ctx, found.object)
	if err != nil {
		return false, err
	}
	return mapping.Physical == offset, nil
}

func (w *handleWalker) emitProcess(ctx context.Context, address, pid uint64, name string, out plugin.Emit) error {
	w.processes++
	table, err := w.reader.Uint(ctx, address, "_EPROCESS", "ObjectTable")
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		w.skippedObjects++
		return nil
	}
	code, err := w.reader.Uint(ctx, table, "_HANDLE_TABLE", "TableCode")
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		w.skippedTables++
		return nil
	}
	level := int(code & handleLevelMask)
	w.levels[level]++
	base := code &^ handleLevelMask
	return w.walk(ctx, base, level, 0, address, pid, name, out)
}

func (w *handleWalker) walk(ctx context.Context, page uint64, level, depth int, process, pid uint64, name string, out plugin.Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	page = windowsCanonical(w.pointerSize, page)
	if err := w.push(page); err != nil {
		if errors.Is(err, errHandleCycle) {
			return nil
		}
		return err
	}
	defer w.pop()
	if !handleMapped(ctx, w.env.Kernel, page) {
		return nil
	}
	if level > 0 {
		count := handlePageSize / w.pointerSize
		nextDepth := depth
		for index := 0; index < count; index++ {
			slot, err := memory.Add(page, uint64(index*w.pointerSize))
			if err != nil {
				return err
			}
			pointer, err := readLE(ctx, w.env.Kernel, slot, w.pointerSize)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if err := w.walk(ctx, pointer, level-1, nextDepth, process, pid, name, out); err != nil {
				return err
			}
			nextDepth++
		}
		return nil
	}
	count := int(handlePageSize / w.entrySize)
	for index := 0; index < count; index++ {
		w.slots++
		if w.slots > handleMaxSlots {
			return fmt.Errorf("handle table exceeded %d slots", handleMaxSlots)
		}
		slot, err := memory.Add(page, uint64(index)*w.entrySize)
		if err != nil {
			return err
		}
		handle := uint64(index*handleMultiplier) + uint64(depth*count*handleMultiplier)
		item, ok, err := w.decode(ctx, slot, handle)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := w.emitHandle(ctx, item, process, pid, name, out); err != nil {
			return err
		}
	}
	return nil
}

func (w *handleWalker) push(page uint64) error {
	for _, seen := range w.stack {
		if seen == page {
			w.cycles++
			return errHandleCycle
		}
	}
	if w.pages >= handleMaxPages {
		return fmt.Errorf("handle table exceeded %d pages", handleMaxPages)
	}
	w.pages++
	w.stack = append(w.stack, page)
	return nil
}

func (w *handleWalker) pop() {
	w.stack = w.stack[:len(w.stack)-1]
}

type handleItem struct {
	header uint64
	body   uint64
	handle uint64
	access uint64
}

func (w *handleWalker) decode(ctx context.Context, slot, handle uint64) (handleItem, bool, error) {
	if !handleMapped(ctx, w.env.Kernel, slot) {
		return handleItem{}, false, nil
	}
	var header uint64
	var access uint64
	if w.legacyObject {
		pointer, err := w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "Object")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, err
		}
		if !handleMapped(ctx, w.env.Kernel, pointer) {
			return handleItem{}, false, nil
		}
		mask := uint64(7)
		if w.pointerSize == 8 {
			mask = 15
		}
		header = windowsCanonical(w.pointerSize, pointer&^mask)
		access, err = w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "GrantedAccess")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, err
		}
	} else if w.pointerSize == 8 {
		bits, err := w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "ObjectPointerBits")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, nil
		}
		if bits == 0 {
			return handleItem{}, false, nil
		}
		header = windowsCanonical(8, bits<<4)
		access, err = w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "GrantedAccessBits")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, nil
		}
	} else {
		info, err := w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "InfoTable")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, nil
		}
		if info == 0 {
			return handleItem{}, false, nil
		}
		header = windowsCanonical(4, info&^7)
		access, err = w.reader.Uint(ctx, slot, "_HANDLE_TABLE_ENTRY", "GrantedAccessBits")
		if err != nil {
			if ctx.Err() != nil {
				return handleItem{}, false, ctx.Err()
			}
			return handleItem{}, false, nil
		}
	}
	keep, err := w.headerKept(ctx, header)
	if err != nil || !keep {
		return handleItem{}, false, err
	}
	body, err := memory.Add(header, w.body)
	if err != nil {
		return handleItem{}, false, nil
	}
	return handleItem{header: header, body: body, handle: handle, access: access}, true, nil
}

func (w *handleWalker) headerKept(ctx context.Context, header uint64) (bool, error) {
	if w.hasTypeIndex {
		index, err := w.reader.Uint(ctx, header, "_OBJECT_HEADER", "TypeIndex")
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, nil
		}
		return index != 0, nil
	}
	if !w.hasType {
		return false, nil
	}
	pointer, err := w.reader.Uint(ctx, header, "_OBJECT_HEADER", "Type")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if pointer == 0 || !handleMapped(ctx, w.env.Kernel, pointer) {
		return false, nil
	}
	return true, nil
}

func (w *handleWalker) emitHandle(ctx context.Context, item handleItem, process, pid uint64, processName string, out plugin.Emit) error {
	typeName, ok, err := w.objectType(ctx, item.header)
	if err != nil || !ok {
		return err
	}
	label, skip, err := w.objectName(ctx, item, typeName)
	if err != nil || skip {
		return err
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"PID":           evidence.Number(pid),
		"Process":       evidence.Text(processName),
		"Offset":        evidence.Address(item.body),
		"HandleValue":   evidence.Address(item.handle),
		"Type":          evidence.Text(typeName),
		"GrantedAccess": evidence.Address(item.access),
		"Name":          label.value,
		"NameError":     label.detail,
		"ProcessOffset": evidence.Address(process),
		"RecordType":    evidence.Text("handle"),
		"Coverage":      evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: w.env.Kernel.Name(), Offset: fmt.Sprintf("0x%x", item.body)}}
	w.handles++
	return out(row)
}

type handleLabel struct {
	value  evidence.Value
	detail evidence.Value
}

func textLabel(text string) handleLabel {
	return handleLabel{value: evidence.Text(text), detail: evidence.Missing("not_applicable", nil)}
}

func absentLabel(reason string, err error) handleLabel {
	return handleLabel{value: evidence.Missing(reason, nil), detail: evidence.Missing(reason, err)}
}

func (w *handleWalker) objectType(ctx context.Context, header uint64) (string, bool, error) {
	if w.hasType && !w.hasTypeIndex {
		return w.legacyType(ctx, header)
	}
	if _, err := w.reader.Field("_OBJECT_HEADER", "Type"); err == nil && !w.hasTypeIndex {
		return w.legacyType(ctx, header)
	}
	if w.hasTypeIndex {
		// Windows 7 and later encode the type. Windows 10 also mixes in ObHeaderCookie.
		raw, err := w.reader.Uint(ctx, header, "_OBJECT_HEADER", "TypeIndex")
		if err != nil {
			if ctx.Err() != nil {
				return "", false, ctx.Err()
			}
			return "", false, nil
		}
		index := raw
		if w.hasCookie {
			index = ((header >> 8) ^ w.cookie ^ raw) & 0xff
		}
		name, ok := w.typeMap[int(index)]
		return name, ok, nil
	}
	return w.legacyType(ctx, header)
}

func (w *handleWalker) legacyType(ctx context.Context, header uint64) (string, bool, error) {
	pointer, err := w.reader.Uint(ctx, header, "_OBJECT_HEADER", "Type")
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		return "", false, nil
	}
	if pointer == 0 {
		return "", false, nil
	}
	length, err := w.reader.Uint(ctx, pointer, "_OBJECT_TYPE", "Name.Length")
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		return "", false, nil
	}
	if length == 0 || length > 128 {
		return "", false, nil
	}
	text, err := w.unicode(ctx, pointer, "_OBJECT_TYPE", "Name")
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		return "", false, nil
	}
	if text == "" || len(text) > 128 {
		return "", false, nil
	}
	return text, true, nil
}

func (w *handleWalker) objectName(ctx context.Context, item handleItem, typeName string) (handleLabel, bool, error) {
	switch typeName {
	case "File":
		return w.fileName(ctx, item.body)
	case "Process":
		text, err := w.processName(ctx, item.body)
		if err != nil {
			if ctx.Err() != nil {
				return handleLabel{}, false, ctx.Err()
			}
			return handleLabel{}, true, nil
		}
		return textLabel(text), false, nil
	case "Thread":
		text, err := w.threadName(ctx, item.body)
		if err != nil {
			if ctx.Err() != nil {
				return handleLabel{}, false, ctx.Err()
			}
			return handleLabel{}, true, nil
		}
		return textLabel(text), false, nil
	case "Key":
		text, unavailable, err := w.keyName(ctx, item.body)
		if err != nil {
			if ctx.Err() != nil {
				return handleLabel{}, false, ctx.Err()
			}
			return handleLabel{}, true, nil
		}
		if unavailable || text == "" {
			return absentLabel("not_available", nil), false, nil
		}
		return textLabel(text), false, nil
	default:
		text, err := w.headerName(ctx, item.header)
		if err != nil || text == "" {
			if err != nil && ctx.Err() != nil {
				return handleLabel{}, false, ctx.Err()
			}
			reason := "not_available"
			if err != nil && !errors.Is(err, errNameInfoAbsent) {
				reason = "unreadable"
			}
			return absentLabel(reason, err), false, nil
		}
		return textLabel(text), false, nil
	}
}

func (w *handleWalker) fileName(ctx context.Context, body uint64) (handleLabel, bool, error) {
	device, err := w.reader.Uint(ctx, body, "_FILE_OBJECT", "DeviceObject")
	if err != nil {
		if ctx.Err() != nil {
			return handleLabel{}, false, ctx.Err()
		}
		return handleLabel{}, true, nil
	}
	label := absentLabel("unreadable", fmt.Errorf("device object is not resident"))
	named := false
	if handleMapped(ctx, w.env.Kernel, device) {
		if device < w.body {
			return handleLabel{}, true, nil
		}
		text, err := w.headerName(ctx, device-w.body)
		if err != nil && !errors.Is(err, errNameInfoAbsent) {
			if ctx.Err() != nil {
				return handleLabel{}, false, ctx.Err()
			}
			return handleLabel{}, true, nil
		}
		if err == nil {
			label = textLabel(`\Device\` + text)
			named = true
		}
	}
	fileText, err := w.unicode(ctx, body, "_FILE_OBJECT", "FileName")
	if err != nil {
		if ctx.Err() != nil {
			return handleLabel{}, false, ctx.Err()
		}
		return label, false, nil
	}
	if !named {
		return label, false, nil
	}
	label.value = evidence.Text(label.value.String() + fileText)
	return label, false, nil
}

func (w *handleWalker) processName(ctx context.Context, body uint64) (string, error) {
	name, err := processImageName(ctx, w.reader, body, false)
	if err != nil {
		return "", err
	}
	pid, err := w.reader.Uint(ctx, body, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s Pid %d", name, pid), nil
}

func (w *handleWalker) threadName(ctx context.Context, body uint64) (string, error) {
	tid, err := w.reader.Uint(ctx, body, "_ETHREAD", "Cid.UniqueThread")
	if err != nil {
		return "", err
	}
	pid, err := w.reader.Uint(ctx, body, "_ETHREAD", "Cid.UniqueProcess")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Tid %d Pid %d", tid, pid), nil
}

func (w *handleWalker) keyName(ctx context.Context, body uint64) (string, bool, error) {
	kcb, err := w.reader.Uint(ctx, body, "_CM_KEY_BODY", "KeyControlBlock")
	if err != nil {
		return "", false, err
	}
	parentField, err := w.reader.Field("_CM_KEY_CONTROL_BLOCK", "ParentKcb")
	if err != nil {
		return "", false, err
	}
	var output []string
	seen := map[uint64]bool{}
	for {
		parentAddr, err := memory.Add(kcb, parentField.Offset)
		if err != nil {
			return "", false, err
		}
		parent, err := readLE(ctx, w.env.Kernel, parentAddr, w.pointerSize)
		if err != nil {
			return "", false, err
		}
		if parent == 0 {
			break
		}
		if seen[parentAddr] {
			return "", true, nil
		}
		seen[parentAddr] = true
		if len(output) > handleNameLimit {
			return "", true, nil
		}
		flags, err := w.reader.Uint(ctx, kcb, "_CM_KEY_CONTROL_BLOCK", "Flags")
		if err != nil {
			return "", false, err
		}
		if w.hasKeyTrans && flags&keyHiveEntry == keyHiveEntry {
			kcb = parent
			if kcb == 0 {
				break
			}
		}
		nameBlock, err := w.reader.Uint(ctx, kcb, "_CM_KEY_CONTROL_BLOCK", "NameBlock")
		if err != nil {
			return "", false, err
		}
		if nameBlock == 0 {
			return "", false, fmt.Errorf("key name block is null")
		}
		component, err := w.keyComponent(ctx, nameBlock)
		if err != nil {
			return "", false, err
		}
		output = append(output, component)
		nextAddr, err := memory.Add(kcb, parentField.Offset)
		if err != nil {
			return "", false, err
		}
		next, err := readLE(ctx, w.env.Kernel, nextAddr, w.pointerSize)
		if err != nil {
			return "", false, err
		}
		kcb = next
	}
	for left, right := 0, len(output)-1; left < right; left, right = left+1, right-1 {
		output[left], output[right] = output[right], output[left]
	}
	return strings.Join(output, `\`), false, nil
}

func (w *handleWalker) keyComponent(ctx context.Context, nameBlock uint64) (string, error) {
	length, err := w.reader.Uint(ctx, nameBlock, "_CM_NAME_CONTROL_BLOCK", "NameLength")
	if err != nil {
		return "", err
	}
	if length > 65535 {
		return "", fmt.Errorf("key name length %d is invalid", length)
	}
	field, err := w.reader.Field("_CM_NAME_CONTROL_BLOCK", "Name")
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	address, err := memory.Add(nameBlock, field.Offset)
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, w.env.Kernel, address, int(length))
	if err != nil {
		return "", err
	}
	if index := indexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	if !utf8.Valid(raw) {
		return strings.ToValidUTF8(string(raw), "\uFFFD"), nil
	}
	return string(raw), nil
}

func (w *handleWalker) headerName(ctx context.Context, header uint64) (string, error) {
	delta, err := w.nameDelta(ctx, header)
	if err != nil {
		return "", err
	}
	if delta == 0 {
		return "", errNameInfoAbsent
	}
	if header < delta {
		return "", fmt.Errorf("name info precedes the address space")
	}
	return w.unicode(ctx, header-delta, "_OBJECT_HEADER_NAME_INFO", "Name")
}

func (w *handleWalker) nameDelta(ctx context.Context, header uint64) (uint64, error) {
	if w.hasNameOffset {
		return w.reader.Uint(ctx, header, "_OBJECT_HEADER", "NameInfoOffset")
	}
	mask, err := w.reader.Uint(ctx, header, "_OBJECT_HEADER", "InfoMask")
	if err != nil {
		return 0, err
	}
	index := int(mask & 0x3)
	if index >= len(w.infoDeltas) {
		return 0, fmt.Errorf("name info index %d is outside ObpInfoMaskToOffset", index)
	}
	return uint64(w.infoDeltas[index]), nil
}

func (w *handleWalker) unicode(ctx context.Context, base uint64, typ, field string) (string, error) {
	member, err := w.reader.Field(typ, field)
	if err != nil {
		return "", err
	}
	address, err := memory.Add(base, member.Offset)
	if err != nil {
		return "", err
	}
	length, err := w.reader.Uint(ctx, address, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	if length > 65535 {
		return "", fmt.Errorf("unicode length %d is invalid", length)
	}
	buffer, err := w.reader.Uint(ctx, address, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, w.env.Kernel, buffer, int(length))
	if err != nil {
		return "", err
	}
	return poolUTF16(raw), nil
}

func (w *handleWalker) summary(e plugin.Environment, out plugin.Emit) error {
	coverage := map[string]string{
		"mode":                  w.mode,
		"processes":             formatCount(uint64(w.processes)),
		"handles":               formatCount(uint64(w.handles)),
		"skipped_object_tables": formatCount(uint64(w.skippedObjects)),
		"skipped_handle_tables": formatCount(uint64(w.skippedTables)),
		"cycles":                formatCount(uint64(w.cycles)),
		"pages":                 formatCount(uint64(w.pages)),
		"slots":                 formatCount(uint64(w.slots)),
		"level0":                formatCount(uint64(w.levels[0])),
		"level1":                formatCount(uint64(w.levels[1])),
		"level2":                formatCount(uint64(w.levels[2])),
		"level3plus":            formatCount(uint64(w.levels[3] + w.levels[4] + w.levels[5] + w.levels[6] + w.levels[7])),
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"PID":           evidence.Missing("not_applicable", nil),
		"Process":       evidence.Missing("not_applicable", nil),
		"Offset":        evidence.Missing("not_applicable", nil),
		"HandleValue":   evidence.Missing("not_applicable", nil),
		"Type":          evidence.Missing("not_applicable", nil),
		"GrantedAccess": evidence.Missing("not_applicable", nil),
		"Name":          evidence.Missing("not_applicable", nil),
		"NameError":     evidence.Missing("not_applicable", nil),
		"ProcessOffset": evidence.Missing("not_applicable", nil),
		"RecordType":    evidence.Text("summary"),
		"Coverage":      poolCoverage(coverage),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	return out(row)
}

func windowsCanonical(pointerSize int, addr uint64) uint64 {
	if pointerSize == 8 {
		addr &= 0x0000ffffffffffff
		if addr&(1<<47) != 0 {
			return addr | 0xffff000000000000
		}
		return addr
	}
	return addr & 0xffffffff
}

func handleMapped(ctx context.Context, layer memory.MemoryLayer, addr uint64) bool {
	if ctx.Err() != nil {
		return false
	}
	_, err := memory.Read(ctx, layer, addr, 1)
	return err == nil
}

func indexByte(raw []byte, value byte) int {
	for i, item := range raw {
		if item == value {
			return i
		}
	}
	return -1
}
