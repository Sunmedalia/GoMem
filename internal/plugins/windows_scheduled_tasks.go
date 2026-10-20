package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsScheduledTaskPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"string", "TaskName PrincipalID DisplayName CreationTime LastRunTime LastSuccessfulRunTime TriggerType TriggerDescription ActionType Action ActionArguments ActionContext WorkingDirectory KeyName HiveName RecordType Error"},
		{"bool", "Enabled"},
		{"address", "HiveOffset"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.scheduledtasks", Upstream: "windows.registry.scheduled_tasks.ScheduledTasks", Platform: "windows", NeedsKernel: true,
		Description: "Decode scheduled task actions, triggers and run times from the SOFTWARE hive",
		Columns:     columns,
	}, windowsScheduledTasks}}
}

const (
	taskCacheTasks = `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
	taskCacheTree  = `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
)

func windowsScheduledTasks(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return err
	}
	proc, _, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return err
	}
	var hive *registry.Hive
	var item listedHive
	for _, candidate := range hives {
		if !strings.Contains(strings.ToLower(candidate.Name), "software") {
			continue
		}
		opened, openErr := registry.Open(ctx, e.Kernel, proc, candidate.Address, candidate.Name, layout)
		if openErr != nil {
			continue
		}
		hive, item = opened, candidate
		break
	}
	if hive == nil {
		return out(taskDiagnostic(e, "software_hive_not_found", fmt.Errorf("no readable hive name contains software")))
	}
	tasks, ok, err := amSection(ctx, hive, taskCacheTasks)
	if err != nil {
		return err
	}
	if !ok {
		return out(taskDiagnostic(e, "tasks_key_not_found", fmt.Errorf("TaskCache\\Tasks is absent")))
	}
	names := map[string]string{}
	if tree, treeOK, treeErr := amSection(ctx, hive, taskCacheTree); treeErr != nil {
		return treeErr
	} else if treeOK {
		names = taskGUIDNames(ctx, hive, tree, map[uint32]bool{}, 0)
	}
	subs, subErr := hive.Subkeys(ctx, tasks)
	if subErr != nil && len(subs) == 0 {
		row := taskDiagnostic(e, "tasks_unreadable", subErr)
		row.Cells["HiveOffset"] = evidence.Address(item.Address)
		row.Cells["HiveName"] = evidence.Text(item.Name)
		row.Cells["RecordType"] = evidence.Text("unreadable")
		return out(row)
	}
	for _, key := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emitScheduledTask(ctx, e, hive, item, key, names, out); err != nil {
			return err
		}
	}
	return nil
}

func taskGUIDNames(ctx context.Context, hive *registry.Hive, key registry.Key, stack map[uint32]bool, depth int) map[string]string {
	out := map[string]string{}
	if depth > 128 || stack[key.Index] {
		return out
	}
	stack[key.Index] = true
	defer delete(stack, key.Index)
	if values, _ := hive.Values(ctx, key); values != nil {
		for _, value := range values {
			if value.Name != "Id" || value.Type != regSZ || value.DataErr != nil {
				continue
			}
			out[strings.TrimRight(taskUTF16Replace(value.Data), "\x00")] = key.Name
			break
		}
	}
	subs, _ := hive.Subkeys(ctx, key)
	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return out
		}
		for id, name := range taskGUIDNames(ctx, hive, sub, stack, depth+1) {
			out[id] = name
		}
	}
	return out
}

func emitScheduledTask(ctx context.Context, e plugin.Environment, hive *registry.Hive, item listedHive, key registry.Key, names map[string]string, out plugin.Emit) error {
	values, _ := amValues(ctx, hive, key)
	actions, actionErr := taskBlob(values["Actions"], true)
	triggers, triggerErr := taskBlob(values["Triggers"], true)
	dynamic, dynamicErr := taskBlob(values["DynamicInfo"], true)
	var actionSet *taskActionSet
	var triggerSet *taskTriggerSet
	var info *taskDynamic
	var parseErr error
	if actionErr == nil && actions != nil {
		actionSet, parseErr = decodeTaskActions(actions)
	}
	if triggerErr == nil && triggers != nil && parseErr == nil {
		triggerSet = decodeTaskTriggers(triggers)
	}
	if dynamicErr == nil && dynamic != nil {
		info = decodeTaskDynamic(dynamic)
	}
	cause := actionErr
	if cause == nil {
		cause = triggerErr
	}
	if cause == nil {
		cause = dynamicErr
	}
	if cause == nil {
		cause = parseErr
	}
	rows := combineTaskRows(names, key.Name, actionSet, triggerSet, info)
	layer := amLayer(hive, key.Address)
	for _, cells := range rows {
		row := evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", key.Address)}}
		row.Cells["HiveOffset"] = evidence.Address(item.Address)
		row.Cells["HiveName"] = evidence.Text(item.Name)
		row.Cells["RecordType"] = evidence.Text("task")
		if cause != nil {
			row.Cells["Error"] = evidence.Missing("registry_value_unreadable", cause)
		} else {
			row.Cells["Error"] = evidence.Missing("not_applicable", nil)
		}
		if err := out(row); err != nil {
			return err
		}
	}
	return nil
}

func taskBlob(value registry.Value, present bool) ([]byte, error) {
	if !present || value.Index == 0 && value.Name == "" && value.Type == 0 && value.Data == nil && value.DataErr == nil {
		return nil, nil
	}
	if value.DataErr != nil {
		return nil, value.DataErr
	}
	switch value.Type {
	case regNone:
		return []byte{}, nil
	case regDWORD, regDWORDBE, regQWORD:
		return nil, nil
	default:
		return append([]byte(nil), value.Data...), nil
	}
}

func taskDiagnostic(e plugin.Environment, reason string, cause error) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	for _, column := range windowsScheduledTaskPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["RecordType"] = evidence.Text("absent")
	row.Cells["Error"] = evidence.Missing(reason, cause)
	return row
}

func combineTaskRows(names map[string]string, keyName string, actions *taskActionSet, triggers *taskTriggerSet, info *taskDynamic) []map[string]evidence.Value {
	taskName := evidence.Missing("not_available", nil)
	if name, ok := names[keyName]; ok {
		taskName = evidence.Text(name)
	}
	key := evidence.Text(keyName)
	if keyName == "" {
		key = evidence.Missing("not_available", nil)
	}
	principal := evidence.Missing("not_available", nil)
	display := evidence.Missing("not_available", nil)
	if triggers != nil {
		if triggers.principalOK && triggers.principal != "" {
			principal = evidence.Text(triggers.principal)
		}
		if triggers.displayOK && triggers.display != "" {
			display = evidence.Text(triggers.display)
		}
	}
	creation := taskTime(info, 0)
	lastRun := taskTime(info, 1)
	success := taskTime(info, 2)
	context := evidence.Missing("not_available", nil)
	if actions != nil && actions.contextOK {
		context = evidence.Text(actions.context)
	}
	actionList := []*taskAction{nil}
	if actions != nil && len(actions.actions) > 0 {
		actionList = actions.actions
	}
	triggerList := []*taskTrigger{nil}
	if triggers != nil && len(triggers.triggers) > 0 {
		triggerList = triggers.triggers
	}
	var rows []map[string]evidence.Value
	for _, action := range actionList {
		for _, trigger := range triggerList {
			enabled := evidence.Missing("not_available", nil)
			triggerType := evidence.Missing("not_available", nil)
			triggerDesc := evidence.Missing("not_available", nil)
			if trigger != nil {
				if trigger.enabledOK {
					enabled = boolValue(trigger.enabled)
				}
				triggerType = evidence.Text(trigger.kind)
				if trigger.descOK && trigger.description != "" {
					triggerDesc = evidence.Text(trigger.description)
				}
			}
			actionType := evidence.Missing("not_available", nil)
			actionText := evidence.Missing("not_available", nil)
			args := evidence.Missing("not_available", nil)
			workdir := evidence.Missing("not_available", nil)
			if action != nil {
				actionType = evidence.Text(action.kind)
				actionText = evidence.Text(action.action)
				if action.kind == "Exe" || action.kind == "ComHandler" {
					if action.argsOK {
						args = evidence.Text(action.args)
					}
				} else {
					args = evidence.Missing("not_applicable", nil)
				}
				if action.kind == "Exe" {
					if action.workOK && action.workdir != "" {
						workdir = evidence.Text(action.workdir)
					}
				} else {
					workdir = evidence.Missing("not_applicable", nil)
				}
			}
			rows = append(rows, map[string]evidence.Value{
				"TaskName": taskName, "PrincipalID": principal, "DisplayName": display, "Enabled": enabled,
				"CreationTime": creation, "LastRunTime": lastRun, "LastSuccessfulRunTime": success,
				"TriggerType": triggerType, "TriggerDescription": triggerDesc,
				"ActionType": actionType, "Action": actionText, "ActionArguments": args,
				"ActionContext": context, "WorkingDirectory": workdir, "KeyName": key,
			})
		}
	}
	return rows
}

func taskTime(info *taskDynamic, field int) evidence.Value {
	if info == nil {
		return evidence.Missing("not_available", nil)
	}
	var text string
	var ok bool
	switch field {
	case 0:
		text, ok = info.creation, info.creationOK
	case 1:
		text, ok = info.lastRun, info.lastRunOK
	default:
		text, ok = info.success, info.successOK
	}
	if !ok {
		return evidence.Missing("not_available", nil)
	}
	return evidence.Text(text)
}

type taskAction struct {
	kind, action, args, workdir string
	argsOK, workOK              bool
}

type taskActionSet struct {
	actions   []*taskAction
	context   string
	contextOK bool
}

type taskTrigger struct {
	kind, description, start, end                          string
	interval                                               uint64
	intervalOK, enabled, enabledOK, descOK, startOK, endOK bool
}

type taskTriggerSet struct {
	principal, display     string
	principalOK, displayOK bool
	triggers               []*taskTrigger
}

type taskDynamic struct {
	creation, lastRun, success       string
	creationOK, lastRunOK, successOK bool
}

type taskReader struct {
	b []byte
	i int
}

func (r *taskReader) read(n int) []byte {
	if n < 0 || r.i >= len(r.b) {
		return []byte{}
	}
	end := r.i + n
	if end < r.i || end > len(r.b) {
		end = len(r.b)
	}
	out := append([]byte(nil), r.b[r.i:end]...)
	r.i = end
	return out
}

func (r *taskReader) seek(delta int) {
	r.i += delta
	if r.i < 0 {
		r.i = 0
	}
}

func (r *taskReader) uint(size int, aligned bool) (uint64, bool) {
	raw := r.read(size)
	if len(raw) != size {
		return 0, false
	}
	var value uint64
	for i, b := range raw {
		value |= uint64(b) << (8 * i)
	}
	if aligned {
		r.seek(8 - size)
	}
	return value, true
}

func (r *taskReader) readBool() (bool, bool) {
	raw := r.read(1)
	if len(raw) != 1 {
		return false, false
	}
	return raw[0] != 0, true
}

func (r *taskReader) filetime() (string, bool) {
	value, ok := r.uint(8, false)
	if !ok {
		return "", false
	}
	return taskFiletime(value)
}

func taskFiletime(value uint64) (string, bool) {
	if value == 0 || value == ^uint64(0) {
		return "", false
	}
	seconds := value / 10000000
	if seconds == 0 {
		return "", false
	}
	unix := int64(seconds) - 11644473600
	if unix < -62135596800 || unix > 253402300799 {
		return "", false
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339), true
}

func (r *taskReader) schedulerTime() (string, bool) {
	_, _ = r.uint(1, true)
	return r.filetime()
}

func (r *taskReader) bstring(aligned bool) (string, bool) {
	var size uint64
	var ok bool
	if aligned {
		size, ok = r.uint(4, true)
	} else {
		size, ok = r.uint(4, false)
	}
	if !ok {
		return "", false
	}
	raw := r.read(int(size))
	if aligned {
		r.seek(int((8 - (size % 8)) % 8))
	}
	text := strings.TrimRight(taskUTF16Replace(raw), "\x00")
	if text == "" {
		return "", false
	}
	return text, true
}

func (r *taskReader) buffer(aligned bool) ([]byte, bool) {
	var count uint64
	var ok bool
	if aligned {
		count, ok = r.uint(4, true)
	} else {
		count, ok = r.uint(4, false)
	}
	if !ok {
		return nil, false
	}
	data := r.read(int(count))
	if aligned {
		r.seek(int((8 - (count % 8)) % 8))
	}
	return data, true
}

func (r *taskReader) expandString() (string, bool) {
	size, ok := r.uint(4, true)
	if !ok || size == 0 {
		return "", false
	}
	byteCount := size*2 + 2
	raw := r.read(int(byteCount))
	r.seek(int((8 - (byteCount % 8)) % 8))
	text, ok := taskUTF16Strict(raw)
	if !ok {
		return "", false
	}
	return strings.TrimRight(text, "\x00"), true
}

func taskUTF16Replace(data []byte) string {
	body := data
	odd := false
	if len(body)%2 == 1 {
		odd = true
		body = body[:len(body)-1]
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[i*2:])
	}
	text := string(utf16.Decode(units))
	if odd {
		text += "\uFFFD"
	}
	return text
}

func taskUTF16Strict(data []byte) (string, bool) {
	if len(data)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", false
			}
			i++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return "", false
		}
	}
	return string(utf16.Decode(units)), true
}

func decodeTaskDynamic(data []byte) *taskDynamic {
	reader := &taskReader{b: data}
	magic, ok := reader.uint(4, false)
	if !ok || magic != 3 {
		return nil
	}
	first, firstOK := reader.filetime()
	second, secondOK := reader.filetime()
	reader.seek(4)
	_, _ = reader.uint(4, false)
	third, thirdOK := reader.filetime()
	// The pinned constructor passes the second FILETIME as creation time and
	// the first as last run time. The output columns follow that swap.
	return &taskDynamic{creation: second, creationOK: secondOK, lastRun: first, lastRunOK: firstOK, success: third, successOK: thirdOK}
}

func decodeTaskActions(data []byte) (*taskActionSet, error) {
	reader := &taskReader{b: data}
	version, ok := reader.uint(2, false)
	if !ok {
		return nil, nil
	}
	set := &taskActionSet{}
	if version == 2 || version == 3 {
		if text, ok := reader.bstring(false); ok {
			set.context = text
			set.contextOK = true
		}
	}
	for {
		magic, ok := reader.uint(2, false)
		if !ok {
			break
		}
		_, _ = reader.bstring(false)
		var action *taskAction
		switch magic {
		case 0x8888:
			if err := reader.emailAction(); err != nil {
				return nil, err
			}
		case 0x6666:
			action = reader.exeAction(version)
		case 0x7777:
			decoded, err := reader.comAction()
			if err != nil {
				return nil, err
			}
			action = decoded
		case 0x9999:
			action = reader.messageAction()
		default:
			return set, nil
		}
		set.actions = append(set.actions, action)
	}
	return set, nil
}

func (r *taskReader) emailAction() error {
	for i := 0; i < 8; i++ {
		_, _ = r.bstring(false)
	}
	if count, ok := r.uint(4, false); ok {
		if count > 100000 {
			return fmt.Errorf("email attachment count %d", count)
		}
		for i := uint64(0); i < count; i++ {
			_, _ = r.bstring(false)
		}
	}
	count, ok := r.uint(4, false)
	if !ok {
		return nil
	}
	if count > 100000 {
		return fmt.Errorf("email header count %d", count)
	}
	for i := uint64(0); i < count; i++ {
		_, _ = r.bstring(false)
		_, _ = r.bstring(false)
	}
	return nil
}

func (r *taskReader) exeAction(version uint64) *taskAction {
	command, commandOK := r.bstring(false)
	args, argsOK := r.bstring(false)
	if !commandOK || !argsOK {
		return nil
	}
	workdir, workOK := r.bstring(false)
	if version == 3 {
		_, _ = r.uint(2, false)
	}
	return &taskAction{kind: "Exe", action: command, args: args, argsOK: argsOK, workdir: workdir, workOK: workOK}
}

func (r *taskReader) comAction() (*taskAction, error) {
	raw := r.read(16)
	if len(raw) != 16 {
		return nil, fmt.Errorf("COM handler CLSID has %d bytes", len(raw))
	}
	clsid, err := windowsTaskGUID(raw)
	if err != nil {
		return nil, err
	}
	args, argsOK := r.bstring(false)
	return &taskAction{kind: "ComHandler", action: clsid, args: args, argsOK: argsOK}, nil
}

func (r *taskReader) messageAction() *taskAction {
	caption, captionOK := r.bstring(false)
	content, contentOK := r.bstring(false)
	if !captionOK {
		caption = "<Unknown>"
	}
	if !contentOK {
		content = "<Unknown>"
	}
	return &taskAction{kind: "MessageBox", action: `"` + caption + `": ` + content}
}

func windowsTaskGUID(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("guid length %d", len(raw))
	}
	data1 := binary.LittleEndian.Uint32(raw[0:4])
	data2 := binary.LittleEndian.Uint16(raw[4:6])
	data3 := binary.LittleEndian.Uint16(raw[6:8])
	data4 := binary.BigEndian.Uint16(raw[8:10])
	var tail uint64
	for _, b := range raw[10:16] {
		tail = tail<<8 | uint64(b)
	}
	return fmt.Sprintf("{%x-%x-%x-%x-%x}", data1, data2, data3, data4, tail), nil
}

func decodeTaskSID(data []byte) (string, bool) {
	if len(data) < 8 {
		return "", false
	}
	count := int(data[1])
	if count < 0 || len(data) < 8+count*4 {
		return "", false
	}
	var authority uint64
	for _, b := range data[2:8] {
		authority = authority<<8 | uint64(b)
	}
	parts := []string{fmt.Sprint(data[0]), fmt.Sprint(authority)}
	for i := 0; i < count; i++ {
		parts = append(parts, fmt.Sprint(binary.LittleEndian.Uint32(data[8+i*4:])))
	}
	return "S-" + strings.Join(parts, "-"), true
}

func decodeTaskTriggers(data []byte) *taskTriggerSet {
	reader := &taskReader{b: data}
	version, versionOK := reader.uint(1, true)
	_, _ = reader.schedulerTime()
	_, _ = reader.schedulerTime()
	if !versionOK {
		return nil
	}
	bucket, ok := reader.jobBucket(version)
	if !ok {
		return nil
	}
	set := &taskTriggerSet{principal: bucket.principal, principalOK: bucket.principalOK, display: bucket.display, displayOK: bucket.displayOK}
	for {
		magic, ok := reader.uint(4, true)
		if !ok {
			break
		}
		var trigger *taskTrigger
		switch magic {
		case 0xAAAA:
			trigger = reader.logonTrigger(version)
		case 0x7777:
			trigger = reader.sessionTrigger(version)
		case 0x6666:
			decoded, ok := reader.wnfTrigger(version)
			if !ok {
				return nil
			}
			trigger = decoded
		case 0xFFFF:
			trigger = reader.genericTrigger(version, "Boot")
		case 0x8888, 0xEEEE:
			// Registration and idle are dispatched separately, then stored as Logon.
			trigger = reader.genericTrigger(version, "Logon")
		case 0xCCCC:
			trigger = reader.eventTrigger(version)
		case 0xDDDD:
			trigger = reader.timeTrigger(version)
		default:
			return set
		}
		set.triggers = append(set.triggers, trigger)
	}
	return set
}

type taskBucket struct {
	principal, display     string
	principalOK, displayOK bool
}

func (r *taskReader) jobBucket(version uint64) (taskBucket, bool) {
	if _, ok := r.uint(4, true); !ok {
		return taskBucket{}, false
	}
	if _, ok := r.uint(4, true); !ok {
		return taskBucket{}, false
	}
	var bucket taskBucket
	if version >= 0x16 {
		if text, ok := r.bstring(true); ok {
			bucket.principal = text
			bucket.principalOK = true
		}
	}
	if version >= 0x17 {
		if text, ok := r.bstring(true); ok {
			bucket.display = text
			bucket.displayOK = true
		}
	}
	// A missing user record is None. Optional settings still follow it.
	_ = r.userInfo()
	r.optionalSettings()
	return bucket, true
}

func (r *taskReader) userInfo() bool {
	skipRaw, skipOK := r.uint(1, true)
	skipUser := !skipOK || skipRaw != 0
	skipSid := true
	if !skipUser {
		sidRaw, sidOK := r.uint(1, true)
		skipSid = !sidOK || sidRaw != 0
	}
	if !skipUser && !skipSid {
		_, _ = r.uint(4, true)
		if _, ok := r.buffer(true); !ok {
			return false
		}
	}
	if !skipUser {
		_, _ = r.bstring(true)
	}
	return true
}

func (r *taskReader) optionalSettings() {
	length, lengthOK := r.uint(4, true)
	if lengthOK && length == 0 {
		return
	}
	failed := false
	for i := 0; i < 7; i++ {
		if _, ok := r.uint(4, false); !ok {
			failed = true
		}
	}
	_ = r.read(16)
	if failed {
		return
	}
	r.seek(4)
	if length == 0x38 || length == 0x58 {
		if _, ok := r.uint(8, false); !ok {
			return
		}
	}
	if length == 0x58 {
		for i := 0; i < 14; i++ {
			_, _ = r.uint(2, false)
		}
		_, _ = r.readBool()
		r.seek(3)
	}
}

func (r *taskReader) genericTrigger(version uint64, kind string) *taskTrigger {
	start, startOK := r.schedulerTime()
	end, endOK := r.schedulerTime()
	_, _ = r.uint(4, false)
	_, _ = r.uint(4, false)
	interval, intervalOK := r.uint(4, false)
	_, _ = r.uint(4, false)
	_, _ = r.uint(4, false)
	_, _ = r.readBool()
	r.seek(3)
	enabledRaw, enabledRead := r.uint(1, true)
	r.seek(8)
	if version >= 0x16 {
		cursor := r.i
		_, _ = r.bstring(false)
		r.seek((8 - ((r.i - cursor) % 8)) % 8)
	}
	return &taskTrigger{
		kind: kind, description: kind + " trigger", descOK: true,
		start: start, startOK: startOK, end: end, endOK: endOK,
		interval: interval, intervalOK: intervalOK,
		enabled: enabledRead && enabledRaw != 0, enabledOK: true,
	}
}

func (r *taskReader) logonTrigger(version uint64) *taskTrigger {
	base := r.genericTrigger(version, "Logon")
	user := r.readUser()
	if user.usernameOK {
		sid := "None"
		if user.sidOK {
			sid = user.sid
		}
		base.description = fmt.Sprintf("%s: %s (%s)", user.username, sid, user.sidType)
		base.descOK = true
	}
	return base
}

type taskUser struct {
	username, sid, sidType string
	usernameOK, sidOK      bool
}

func (r *taskReader) readUser() taskUser {
	skipRaw, skipOK := r.uint(1, true)
	skipUser := !skipOK || skipRaw != 0
	skipSid := true
	if !skipUser {
		sidRaw, sidOK := r.uint(1, true)
		skipSid = !sidOK || sidRaw != 0
	}
	var user taskUser
	if !skipUser && !skipSid {
		typeRaw, typeOK := r.uint(4, true)
		user.sidType = taskSIDType(typeRaw, typeOK)
		raw, ok := r.buffer(true)
		if !ok {
			return taskUser{}
		}
		if sid, ok := decodeTaskSID(raw); ok {
			user.sid = sid
			user.sidOK = true
		}
	}
	if !skipUser {
		if text, ok := r.bstring(true); ok {
			user.username = text
			user.usernameOK = true
		}
	}
	return user
}

func taskSIDType(value uint64, ok bool) string {
	names := []string{"", "User", "Group", "Domain", "Alias", "WellKnownGroup", "DeletedAccount", "Invalid", "Unknown", "Computer", "Label", "LogonSession"}
	if ok && value < uint64(len(names)) && names[value] != "" {
		return "SidType." + names[value]
	}
	return "SidType.Unknown"
}

func (r *taskReader) sessionTrigger(version uint64) *taskTrigger {
	base := r.genericTrigger(version, "Session")
	raw, ok := r.uint(4, false)
	r.seek(4)
	state := "Unknown"
	switch {
	case ok && raw == 1:
		state = "ConsoleConnect"
	case ok && raw == 2:
		state = "ConsoleDisconnect"
	case ok && raw == 3:
		state = "RemoteConnect"
	case ok && raw == 4:
		state = "RemoteDisconnect"
	case ok && raw == 5:
		state = "SessionLock"
	case ok && raw == 6:
		state = "SessionUnlock"
	}
	user := r.readUser()
	if user.usernameOK {
		base.description = state + " for user " + user.username
	} else {
		base.description = state
	}
	base.descOK = true
	return base
}

func (r *taskReader) eventTrigger(version uint64) *taskTrigger {
	base := r.genericTrigger(version, "Event")
	subscription, subscriptionOK := r.expandString()
	r.seek(8)
	_, _ = r.expandString()
	count, ok := r.uint(4, true)
	if !ok {
		return base
	}
	if count > 100000 {
		return base
	}
	var pairs [][2]string
	for i := uint64(0); i < count; i++ {
		key, keyOK := r.expandString()
		value, valueOK := r.expandString()
		if keyOK && valueOK {
			pairs = append(pairs, [2]string{key, value})
		}
	}
	shown := "None"
	if subscriptionOK {
		shown = subscription
	}
	base.description += ": Subscription: " + shown + ", Queries: " + pythonTupleList(pairs)
	base.descOK = true
	return base
}

func pythonTupleList(pairs [][2]string) string {
	if len(pairs) == 0 {
		return "[]"
	}
	parts := make([]string, len(pairs))
	for i, pair := range pairs {
		parts[i] = "(" + pythonRepr(pair[0]) + ", " + pythonRepr(pair[1]) + ")"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pythonRepr(text string) string {
	quote := byte('\'')
	if strings.Contains(text, "'") && !strings.Contains(text, "\"") {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range text {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case rune(quote):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, "\\x%02x", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte(quote)
	return b.String()
}

func (r *taskReader) wnfTrigger(version uint64) (*taskTrigger, bool) {
	base := r.genericTrigger(version, "WindowsNotificationFacility")
	state := hex.EncodeToString(r.read(8))
	count, ok := r.uint(4, true)
	if !ok {
		return nil, false
	}
	if count > uint64(len(r.b))+8 {
		return nil, false
	}
	_ = r.read(int(count))
	base.description = "WNF state " + state
	base.descOK = true
	return base, true
}

func (r *taskReader) timeTrigger(version uint64) *taskTrigger {
	start, startOK := r.schedulerTime()
	end, endOK := r.schedulerTime()
	_, _ = r.schedulerTime()
	interval, intervalOK := r.uint(4, false)
	_, _ = r.uint(4, false)
	_, _ = r.uint(4, false)
	modeIndex, modeOK := r.uint(4, false)
	data1, data1OK := r.uint(2, false)
	data2, data2OK := r.uint(2, false)
	data3, data3OK := r.uint(2, false)
	r.seek(2)
	_, _ = r.readBool()
	enabled, enabledOK := r.readBool()
	r.seek(6)
	_, _ = r.uint(4, false)
	r.seek(4)
	if version >= 0x16 {
		cursor := r.i
		_, _ = r.bstring(false)
		r.seek((8 - ((r.i - cursor) % 8)) % 8)
	}
	mode := timeModeFromIndex(modeIndex, modeOK)
	description, descOK := timeDescription(mode, start, startOK, data1, data2, data3, data1OK, data2OK, data3OK)
	return &taskTrigger{
		kind: "Time", description: description, descOK: descOK,
		start: start, startOK: startOK, end: end, endOK: endOK,
		interval: interval, intervalOK: intervalOK, enabled: enabled, enabledOK: enabledOK,
	}
}

// timeModeFromIndex preserves the pinned TimeMode enum. Its members are
// strings, so an integer schedule mode never matches and every time trigger
// description stays unavailable.
func timeModeFromIndex(uint64, bool) string { return "Unknown" }

func timeDescription(mode, start string, startOK bool, data1, data2, data3 uint64, data1OK, data2OK, data3OK bool) (string, bool) {
	shown := "<UNKNOWN>"
	if startOK && start != "" {
		shown = start
	}
	switch mode {
	case "Once":
		return "Run one time starting at " + shown, true
	case "Daily":
		if !data1OK {
			return "", false
		}
		return fmt.Sprintf("Run at %s and repeat every %d days", shown, data1), true
	case "Weekly":
		if !data2OK {
			return "", false
		}
		days := weekdayNames(data2)
		count := "None"
		if data1OK {
			count = fmt.Sprint(data1)
		}
		return fmt.Sprintf("Run on %s every %s weeks starting at %s", strings.Join(days, ", "), count, shown), true
	case "DaysInMonths":
		if !data1OK || !data2OK || !data3OK {
			return "", false
		}
		months := monthNames(data3)
		bitmap := (data2 << 16) + data1
		var days []string
		for v := 0; v < 31; v++ {
			if bitmap&(1<<v) != 0 {
				days = append(days, fmt.Sprint(v+1))
			}
		}
		return fmt.Sprintf("Run in months %s on days %s starting at %s", strings.Join(months, ", "), strings.Join(days, ", "), shown), true
	case "DaysInWeeksInMonths":
		if !data1OK || !data2OK || !data3OK {
			return "", false
		}
		months := monthNames(data3)
		var weeks []string
		for v := 0; v < 5; v++ {
			if data2&(uint64(v)<<1) != 0 {
				weeks = append(weeks, fmt.Sprint(v+1))
			}
		}
		return fmt.Sprintf("Run in months %s in weeks %s on days %s starting at %s", strings.Join(months, ", "), strings.Join(weeks, ", "), strings.Join(weekdayNames(data1), ", "), shown), true
	default:
		return "", false
	}
}

func weekdayNames(bitmap uint64) []string {
	type day struct {
		name  string
		value uint64
	}
	days := []day{{"Sunday", 0x1}, {"Monday", 0x2}, {"Tuesday", 0x4}, {"Wednesday", 0x8}, {"Thursday", 0x10}, {"Friday", 0x20}, {"Saturday", 0x40}}
	var names []string
	for _, day := range days {
		if bitmap&day.value != 0 {
			names = append(names, day.name)
		}
	}
	return names
}

func monthNames(bitmap uint64) []string {
	months := []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
	var names []string
	for i, name := range months {
		if bitmap&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	return names
}
