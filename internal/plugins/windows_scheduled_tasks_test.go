package plugins

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsTaskGUIDAndSID(t *testing.T) {
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i)
	}
	guid, err := windowsTaskGUID(raw)
	if err != nil || guid != "{3020100-504-706-809-a0b0c0d0e0f}" {
		t.Fatalf("guid %s %v", guid, err)
	}
	sid, ok := decodeTaskSID([]byte{1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0})
	if !ok || sid != "S-1-5-18" {
		t.Fatalf("sid %s %v", sid, ok)
	}
	if _, ok := decodeTaskSID([]byte{1, 2}); ok {
		t.Fatal("short sid decoded")
	}
}

func TestScheduledTaskTimeModeIsUnreachable(t *testing.T) {
	if timeModeFromIndex(0, true) != "Unknown" || timeModeFromIndex(1, false) != "Unknown" {
		t.Fatal("integer time mode matched")
	}
	if _, ok := timeDescription("Unknown", "2020-01-01T00:00:00+00:00", true, 1, 1, 1, true, true, true); ok {
		t.Fatal("unknown mode produced a description")
	}
	got, ok := timeDescription("Once", "2020-01-01T00:00:00+00:00", true, 0, 0, 0, false, false, false)
	if !ok || got != "Run one time starting at 2020-01-01T00:00:00+00:00" {
		t.Fatalf("once %q %v", got, ok)
	}
	got, ok = timeDescription("Weekly", "", false, 2, 0x3, 0, true, true, false)
	if !ok || got != "Run on Sunday, Monday every 2 weeks starting at <UNKNOWN>" {
		t.Fatalf("weekly %q %v", got, ok)
	}
	got, ok = timeDescription("DaysInMonths", "start", true, 0x5, 0, 0x3, true, true, true)
	if !ok || got != "Run in months January, February on days 1, 3 starting at start" {
		t.Fatalf("months %q %v", got, ok)
	}
}

func TestScheduledTaskDynamicInfoSwap(t *testing.T) {
	first := taskTestFiletime(t, "2019-01-01T00:00:00Z")
	second := taskTestFiletime(t, "2020-01-01T00:00:00Z")
	third := taskTestFiletime(t, "2021-01-01T00:00:00Z")
	var blob []byte
	blob = append(blob, taskU32(3)...)
	blob = append(blob, first...)
	blob = append(blob, second...)
	blob = append(blob, taskU32(0)...)
	blob = append(blob, taskU32(5)...)
	blob = append(blob, third...)
	info := decodeTaskDynamic(blob)
	if info == nil || !info.creationOK || info.creation != "2020-01-01T00:00:00Z" || info.lastRun != "2019-01-01T00:00:00Z" || info.success != "2021-01-01T00:00:00Z" {
		t.Fatalf("%+v", info)
	}
	if decodeTaskDynamic([]byte{1, 0, 0, 0}) != nil {
		t.Fatal("bad magic decoded")
	}
}

func TestScheduledTaskRowProduct(t *testing.T) {
	actions := &taskActionSet{actions: []*taskAction{
		nil,
		{kind: "Exe", action: `C:\a.exe`, args: "", argsOK: true, workdir: "", workOK: false},
		{kind: "ComHandler", action: "{abc}", argsOK: false},
		{kind: "MessageBox", action: `"hi": there`},
	}, context: "", contextOK: true}
	triggers := &taskTriggerSet{principal: "", principalOK: true, triggers: []*taskTrigger{
		{kind: "Time", enabled: true, enabledOK: true},
		nil,
	}}
	rows := combineTaskRows(map[string]string{"{guid}": ""}, "{guid}", actions, triggers, nil)
	if len(rows) != 8 {
		t.Fatalf("rows %d", len(rows))
	}
	if rows[0]["TaskName"].Kind != "string" || rows[0]["TaskName"].String() != "" {
		t.Fatalf("empty mapped name %+v", rows[0]["TaskName"])
	}
	if rows[0]["PrincipalID"].Reason != "not_available" || rows[0]["CreationTime"].Reason != "not_available" {
		t.Fatalf("empty principal or time %+v", rows[0])
	}
	if rows[0]["ActionType"].Reason != "not_available" || rows[0]["WorkingDirectory"].Reason != "not_available" {
		t.Fatalf("nil action %+v", rows[0])
	}
	if rows[2]["ActionArguments"].Kind != "string" || rows[2]["WorkingDirectory"].Reason != "not_available" {
		t.Fatalf("empty exe args %+v", rows[2])
	}
	if rows[4]["ActionArguments"].Reason != "not_available" || rows[4]["WorkingDirectory"].Reason != "not_applicable" {
		t.Fatalf("com reasons %+v", rows[4])
	}
	if rows[6]["ActionArguments"].Reason != "not_applicable" || rows[6]["ActionContext"].Kind != "string" {
		t.Fatalf("message or empty context %+v", rows[6])
	}
	if rows[1]["Enabled"].Reason != "not_available" || rows[0]["Enabled"].Kind != "bool" || rows[0]["Enabled"].String() != "true" {
		t.Fatalf("enabled %+v %+v", rows[0]["Enabled"], rows[1]["Enabled"])
	}
	missing := combineTaskRows(map[string]string{}, "key", nil, nil, nil)
	if len(missing) != 1 || missing[0]["TaskName"].Reason != "not_available" || missing[0]["KeyName"].String() != "key" {
		t.Fatalf("missing name %+v", missing)
	}
}

func TestScheduledTaskOracle(t *testing.T) {
	root := taskRepoRoot(t)
	python := filepath.Join(root, ".cache/reference-venv/bin/python")
	source := filepath.Join(root, ".cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75")
	if _, err := os.Stat(python); err != nil {
		t.Skip("pinned Volatility oracle is not available")
	}
	cmd := exec.Command(python, "-c", taskOracleScript, source)
	out, err := cmd.Output()
	if err != nil {
		stderr := []byte{}
		if exit, ok := err.(*exec.ExitError); ok {
			stderr = exit.Stderr
		}
		t.Fatalf("oracle failed: %v\n%s", err, stderr)
	}
	var cases []taskOracleCase
	if err := json.Unmarshal(out, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 6 {
		t.Fatalf("oracle cases %d", len(cases))
	}
	for _, item := range cases {
		switch item.Kind {
		case "triggers":
			got := decodeTaskTriggers(item.raw(t))
			if !taskTriggersEqual(t, item.Name, got, item.Triggers) {
				continue
			}
		case "actions":
			got, err := decodeTaskActions(item.raw(t))
			if err != nil {
				t.Fatalf("%s: %v", item.Name, err)
			}
			taskActionsEqual(t, item.Name, got, item.Actions)
		case "dynamic":
			got := decodeTaskDynamic(item.raw(t))
			taskDynamicEqual(t, item.Name, got, item.Dynamic)
		default:
			t.Fatalf("unknown oracle kind %s", item.Kind)
		}
	}
}

func FuzzScheduledTaskBlobs(f *testing.F) {
	f.Add([]byte{3, 0, 0, 0})
	f.Add([]byte{2, 0})
	f.Add([]byte{0x17})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = decodeTaskDynamic(data)
		_, _ = decodeTaskActions(data)
		_ = decodeTaskTriggers(data)
		_ = taskUTF16Replace(data)
		_, _ = taskUTF16Strict(data)
		if len(data) >= 16 {
			_, _ = windowsTaskGUID(data[:16])
		}
		_, _ = decodeTaskSID(data)
	})
}

func taskTestFiletime(t *testing.T, stamp string) []byte {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatal(err)
	}
	value := uint64(parsed.Unix()+11644473600) * 10000000
	var out [8]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(value >> (8 * i))
	}
	return out[:]
}

func taskU32(value uint32) []byte {
	return []byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}
}

func taskRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

type taskOracleCase struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Hex      string          `json:"hex"`
	Triggers json.RawMessage `json:"triggers"`
	Actions  json.RawMessage `json:"actions"`
	Dynamic  json.RawMessage `json:"dynamic"`
}

func (c taskOracleCase) raw(t *testing.T) []byte {
	t.Helper()
	text := c.Hex
	out := make([]byte, len(text)/2)
	for i := 0; i < len(out); i++ {
		var value byte
		for _, ch := range text[i*2 : i*2+2] {
			value <<= 4
			switch {
			case ch >= '0' && ch <= '9':
				value |= byte(ch - '0')
			case ch >= 'a' && ch <= 'f':
				value |= byte(ch-'a') + 10
			default:
				t.Fatalf("bad hex %s", text)
			}
		}
		out[i] = value
	}
	return out
}

func taskTriggersEqual(t *testing.T, name string, got *taskTriggerSet, raw json.RawMessage) bool {
	t.Helper()
	var want *struct {
		Principal *string `json:"principal"`
		Display   *string `json:"display"`
		Triggers  []struct {
			Type        *string `json:"type"`
			Description *string `json:"description"`
			Enabled     *bool   `json:"enabled"`
			Start       *string `json:"start"`
			End         *string `json:"end"`
			Interval    *int    `json:"interval"`
		} `json:"triggers"`
	}
	if string(raw) != "null" {
		want = &struct {
			Principal *string `json:"principal"`
			Display   *string `json:"display"`
			Triggers  []struct {
				Type        *string `json:"type"`
				Description *string `json:"description"`
				Enabled     *bool   `json:"enabled"`
				Start       *string `json:"start"`
				End         *string `json:"end"`
				Interval    *int    `json:"interval"`
			} `json:"triggers"`
		}{}
		if err := json.Unmarshal(raw, want); err != nil {
			t.Fatal(err)
		}
	}
	if want == nil || got == nil {
		if (want == nil) != (got == nil) {
			t.Fatalf("%s trigger presence got %#v want %#v", name, got != nil, want != nil)
		}
		return false
	}
	if (want.Principal == nil) != !got.principalOK || (want.Principal != nil && *want.Principal != got.principal) {
		t.Fatalf("%s principal got %q/%v want %v", name, got.principal, got.principalOK, want.Principal)
	}
	if (want.Display == nil) != !got.displayOK || (want.Display != nil && *want.Display != got.display) {
		t.Fatalf("%s display got %q/%v want %v", name, got.display, got.displayOK, want.Display)
	}
	if len(want.Triggers) != len(got.triggers) {
		t.Fatalf("%s trigger count %d != %d", name, len(got.triggers), len(want.Triggers))
	}
	for i, item := range want.Triggers {
		trigger := got.triggers[i]
		if item.Type == nil {
			if trigger != nil {
				t.Fatalf("%s trigger %d present", name, i)
			}
			continue
		}
		if trigger == nil || trigger.kind != *item.Type {
			t.Fatalf("%s trigger %d type %+v want %v", name, i, trigger, item.Type)
		}
		if (item.Description == nil) != (!trigger.descOK || trigger.description == "") || (item.Description != nil && *item.Description != trigger.description) {
			t.Fatalf("%s trigger %d description %q/%v want %v", name, i, trigger.description, trigger.descOK, item.Description)
		}
		if (item.Enabled == nil) != !trigger.enabledOK || (item.Enabled != nil && *item.Enabled != trigger.enabled) {
			t.Fatalf("%s trigger %d enabled %v/%v want %v", name, i, trigger.enabled, trigger.enabledOK, item.Enabled)
		}
		if !taskTimeEqual(trigger.start, trigger.startOK, item.Start) || !taskTimeEqual(trigger.end, trigger.endOK, item.End) {
			t.Fatalf("%s trigger %d bounds %s %s want %v %v", name, i, trigger.start, trigger.end, item.Start, item.End)
		}
		if (item.Interval == nil) != !trigger.intervalOK || (item.Interval != nil && uint64(*item.Interval) != trigger.interval) {
			t.Fatalf("%s trigger %d interval %d/%v want %v", name, i, trigger.interval, trigger.intervalOK, item.Interval)
		}
	}
	return true
}

func taskActionsEqual(t *testing.T, name string, got *taskActionSet, raw json.RawMessage) {
	t.Helper()
	var want *struct {
		Context *string `json:"context"`
		Actions []struct {
			Type    *string `json:"type"`
			Action  *string `json:"action"`
			Args    *string `json:"args"`
			Workdir *string `json:"workdir"`
		} `json:"actions"`
	}
	if string(raw) != "null" {
		want = &struct {
			Context *string `json:"context"`
			Actions []struct {
				Type    *string `json:"type"`
				Action  *string `json:"action"`
				Args    *string `json:"args"`
				Workdir *string `json:"workdir"`
			} `json:"actions"`
		}{}
		if err := json.Unmarshal(raw, want); err != nil {
			t.Fatal(err)
		}
	}
	if want == nil || got == nil {
		if (want == nil) != (got == nil) {
			t.Fatalf("%s action presence", name)
		}
		return
	}
	if (want.Context == nil) != !got.contextOK || (want.Context != nil && *want.Context != got.context) {
		t.Fatalf("%s context %q/%v want %v", name, got.context, got.contextOK, want.Context)
	}
	if len(want.Actions) != len(got.actions) {
		t.Fatalf("%s action count %d != %d", name, len(got.actions), len(want.Actions))
	}
	for i, item := range want.Actions {
		action := got.actions[i]
		if item.Type == nil {
			if action != nil {
				t.Fatalf("%s action %d present", name, i)
			}
			continue
		}
		if action == nil || action.kind != *item.Type || action.action != deref(item.Action) {
			t.Fatalf("%s action %d %+v want %+v", name, i, action, item)
		}
		if (item.Args == nil) != !action.argsOK || (item.Args != nil && *item.Args != action.args) {
			t.Fatalf("%s args %+v want %v", name, action, item.Args)
		}
		if (item.Workdir == nil) != (!action.workOK || action.workdir == "") || (item.Workdir != nil && *item.Workdir != action.workdir) {
			t.Fatalf("%s workdir %+v want %v", name, action, item.Workdir)
		}
	}
}

func taskDynamicEqual(t *testing.T, name string, got *taskDynamic, raw json.RawMessage) {
	t.Helper()
	var want *struct {
		Creation *string `json:"creation"`
		LastRun  *string `json:"last_run"`
		Success  *string `json:"success"`
	}
	if string(raw) != "null" {
		want = &struct {
			Creation *string `json:"creation"`
			LastRun  *string `json:"last_run"`
			Success  *string `json:"success"`
		}{}
		if err := json.Unmarshal(raw, want); err != nil {
			t.Fatal(err)
		}
	}
	if want == nil || got == nil {
		if (want == nil) != (got == nil) {
			t.Fatalf("%s dynamic presence", name)
		}
		return
	}
	if !taskTimeEqual(got.creation, got.creationOK, want.Creation) || !taskTimeEqual(got.lastRun, got.lastRunOK, want.LastRun) || !taskTimeEqual(got.success, got.successOK, want.Success) {
		t.Fatalf("%s dynamic %+v want %+v", name, got, want)
	}
}

func taskTimeEqual(got string, ok bool, want *string) bool {
	if want == nil {
		return !ok
	}
	parsed, err := time.Parse(time.RFC3339, *want)
	if err != nil {
		return false
	}
	have, err := time.Parse(time.RFC3339, got)
	return err == nil && ok && have.Equal(parsed)
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

const taskOracleScript = `
import datetime, json, struct, sys
sys.path.insert(0, sys.argv[1])
from volatility3.plugins.windows.registry.scheduled_tasks import ActionSet, TriggerSet, DynamicInfo

def u1a(n):
    return bytes([n]) + b"\x00"*7
def u2(n):
    return struct.pack("<H", n)
def u4(n):
    return struct.pack("<I", n)
def u4a(n):
    return struct.pack("<I", n) + b"\x00"*4
def u8(n):
    return struct.pack("<Q", n)
def bstring(text, aligned=False):
    raw = text.encode("utf-16le")
    size = u4a(len(raw)) if aligned else u4(len(raw))
    pad = b"\x00" * ((8 - (len(raw) % 8)) % 8) if aligned else b""
    return size + raw + pad
def filetime(year):
    unix = int(datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
    return u8((unix + 11644473600) * 10000000)
def sched(year):
    return u1a(0) + filetime(year)

def boot():
    blob = u1a(0x17) + sched(2020) + sched(2021) + u4a(0x400000) + u4a(0x1234)
    blob += bstring("principal", True) + bstring("display", True) + u1a(1) + u4a(0)
    blob += u4a(0xFFFF) + sched(2022) + sched(2023) + u4(5)+u4(6)+u4(7)+u4(8)+u4(9)
    blob += bytes([1]) + b"\x00"*3 + u1a(1) + b"\x00"*8
    ident = bstring("id", False)
    blob += ident + b"\x00" * ((8 - (len(ident) % 8)) % 8)
    return blob

def time_trigger():
    blob = u1a(0x16) + sched(2020) + sched(2021) + u4a(0) + u4a(1) + bstring("System", True) + u1a(1) + u4a(0)
    blob += u4a(0xDDDD)
    blob += sched(2024) + sched(2025) + sched(2026) + u4(60)+u4(120)+u4(30)+u4(0)+u2(1)+u2(2)+u2(4)
    blob += b"\x00\x00" + bytes([0, 1]) + b"\x00"*6 + u4(0) + b"\x00"*4
    ident = bstring("time", False)
    blob += ident + b"\x00" * ((8 - (len(ident) % 8)) % 8)
    return blob

def event_trigger():
    blob = u1a(0x17) + sched(2020) + sched(2021) + u4a(0) + u4a(1) + bstring("p", True) + bstring("d", True) + u1a(1) + u4a(0)
    blob += u4a(0xCCCC) + sched(2022) + sched(2023) + u4(0)*5 + bytes([0]) + b"\x00"*3 + u1a(0) + b"\x00"*8
    ident = bstring("", False)
    blob += ident + b"\x00" * ((8 - (len(ident) % 8)) % 8)
    sub = "a'b"
    raw = sub.encode("utf-16le")
    blob += u4a(len(raw)//2) + raw + b"\x00\x00" + b"\x00" * ((8 - ((len(raw)+2) % 8)) % 8)
    blob += b"\x00"*8
    blob += u4a(0)
    blob += u4a(1)
    for text in ("k\"v", "value"):
        body = text.encode("utf-16le")
        blob += u4a(len(body)//2) + body + b"\x00\x00" + b"\x00" * ((8 - ((len(body)+2) % 8)) % 8)
    return blob

def wnf():
    blob = u1a(0x15) + sched(2020) + sched(2021) + u4a(0) + u4a(1) + u1a(1) + u4a(0)
    blob += u4a(0x6666) + sched(2022) + sched(2023) + u4(1)+u4(2)+u4(3)+u4(4)+u4(5)
    blob += bytes([1]) + b"\x00"*3 + u1a(1) + b"\x00"*8
    blob += bytes.fromhex("7528bda33e06830d") + u4a(2) + b"AB"
    return blob

def idle_then_boot():
    blob = u1a(0x15) + sched(2020) + sched(2021) + u4a(0) + u4a(1) + u1a(1) + u4a(0)
    def generic():
        return sched(2022)+sched(2023)+u4(0)*5 + bytes([0]) + b"\x00"*3 + u1a(1) + b"\x00"*8
    blob += u4a(0xEEEE) + generic() + u4a(0xFFFF) + generic()
    return blob

def exe():
    return u2(3)+bstring("ctx", False)+u2(0x6666)+bstring("", False)+bstring("cmd", False)+bstring("args", False)+bstring("C:\\work", False)+u2(7)

def email_and_empty_args():
    blob = u2(2)+bstring("c", False)+u2(0x8888)+bstring("id", False)
    for _ in range(8):
        blob += bstring("x", False)
    blob += u4(0)+u4(0)
    blob += u2(0x6666)+bstring("", False)+bstring("cmd2", False)+bstring("", False)
    return blob

def com():
    return u2(2)+bstring("System", False)+u2(0x7777)+bstring("id", False)+bytes(range(16))+bstring("-Wns", False)

def message():
    return u2(1)+u2(0x9999)+bstring("", False)+bstring("", False)+bstring("body", False)

def dynamic():
    return u4(3)+filetime(2019)+filetime(2020)+u4(9)+u4(5)+filetime(2021)

def show_time(value):
    return value.isoformat() if isinstance(value, datetime.datetime) else None

def show_triggers(data):
    parsed = TriggerSet.decode(data)
    if parsed is None:
        return None
    triggers = []
    for item in parsed.triggers:
        triggers.append(None if item is None else {
            "type": item.trigger_type.name,
            "description": item.description,
            "enabled": item.enabled,
            "start": show_time(item.start_boundary),
            "end": show_time(item.end_boundary),
            "interval": item.repetition_interval_seconds,
        })
    return {"principal": parsed.job_bucket.principal_id, "display": parsed.job_bucket.display_name, "triggers": triggers}

def show_actions(data):
    parsed = ActionSet.decode(data)
    if parsed is None:
        return None
    actions = []
    for item in parsed.actions:
        actions.append(None if item is None else {"type": item.action_type.name, "action": item.action, "args": item.action_args, "workdir": item.working_directory})
    return {"context": parsed.context, "actions": actions}

def show_dynamic(data):
    parsed = DynamicInfo.decode(data)
    if parsed is None:
        return None
    return {"creation": show_time(parsed.creation_time), "last_run": show_time(parsed.last_run_time), "success": show_time(parsed.last_successful_run_time)}

cases = []
for name, blob in (("boot", boot()), ("time", time_trigger()), ("event", event_trigger()), ("wnf", wnf()), ("idle", idle_then_boot())):
    cases.append({"name": name, "kind": "triggers", "hex": blob.hex(), "triggers": show_triggers(blob)})
for name, blob in (("exe", exe()), ("email", email_and_empty_args()), ("com", com()), ("message", message())):
    cases.append({"name": name, "kind": "actions", "hex": blob.hex(), "actions": show_actions(blob)})
cases.append({"name": "dynamic", "kind": "dynamic", "hex": dynamic().hex(), "dynamic": show_dynamic(dynamic())})
json.dump(cases, sys.stdout)
`
