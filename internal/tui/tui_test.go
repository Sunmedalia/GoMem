package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/charmbracelet/x/ansi"
)

func fixtureModel(t testing.TB) model {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, CaseDir: t.TempDir(), Symbols: f.Symbols, OS: "linux", Arch: "x64", DTB: f.DTB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return New(context.Background(), e).(model)
}

func press(t testing.TB, m model, keys ...string) (model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		msg := tea.KeyPressMsg{Text: k, Code: []rune(k)[0]}
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "up":
			msg = tea.KeyPressMsg{Code: tea.KeyUp}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		}
		updated, c := m.Update(msg)
		m, cmd = updated.(model), c
	}
	return m, cmd
}

// deliver runs a command and feeds its message back, as the runtime would.
func deliver(t testing.TB, m model, cmd tea.Cmd) model {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a command")
	}
	updated, _ := m.Update(cmd())
	return updated.(model)
}

func fits(t testing.TB, m model) string {
	t.Helper()
	v := m.View()
	if got := lipgloss.Width(v.Content); got > m.width {
		t.Fatalf("width %d rendered %d\n%s", m.width, got, v.Content)
	}
	if got := lipgloss.Height(v.Content); got > m.height {
		t.Fatalf("height %d rendered %d\n%s", m.height, got, v.Content)
	}
	return v.Content
}

func runPslist(t testing.TB, m model) model {
	t.Helper()
	res, err := m.engine.Run(m.ctx, "linux.pslist", nil, engine.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m.res.task = res.Task
	m.resize()
	return deliver(t, m, m.query())
}

func TestLayoutPagingFilterAndStaleMessages(t *testing.T) {
	m := fixtureModel(t)
	m = runPslist(t, m)
	for _, view := range []func(*model){
		func(m *model) {},
		func(m *model) { m.focus = focusResults },
		func(m *model) { m.showHelp = true },
		func(m *model) { m.expanded = true },
	} {
		v := m
		view(&v)
		for _, height := range []int{18, 30} {
			for _, width := range []int{85, 100, 120, 160} {
				v.width, v.height = width, height
				v.resize()
				if out := fits(t, v); !strings.HasSuffix(ansi.Strip(strings.Split(out, "\n")[height-7]), "╯") {
					t.Fatalf("panel bottom border clipped at %d×%d\n%s", width, height, out)
				}
			}
		}
	}
	m.width, m.height = 120, 30
	m.resize()
	if len(m.res.rows) != 2 {
		t.Fatal(len(m.res.rows))
	}
	updated, _ := m.Update(pageMsg{task: "other", rows: []evidence.Row{{ID: "wrong"}}})
	m = updated.(model)
	if len(m.res.rows) != 2 {
		t.Fatal("stale query overwrote current task")
	}
	m, _ = press(t, m, "tab", "/")
	m.prompt.input.SetValue("worker")
	m, cmd := press(t, m, "enter")
	m = deliver(t, m, cmd)
	if len(m.res.rows) != 1 || m.res.rows[0].Cells["Name"].String() != "worker" {
		t.Fatal(m.res.rows)
	}
	m, _ = press(t, m, "b")
	notes, err := m.engine.Store.Investigation(m.ctx)
	if err != nil || len(notes["bookmarks"].([]map[string]string)) != 1 {
		t.Fatal(notes, err)
	}
	m.generation = 2
	m.running = false
	updated, _ = m.Update(started{task: evidence.Task{ID: "late"}, generation: 1})
	m = updated.(model)
	if m.res.task.ID == "late" {
		t.Fatal("late start overwrote completed task")
	}
}

func BenchmarkLocalNavigation(b *testing.B) {
	m := fixtureModel(b)
	rows := make([]evidence.Row, 100)
	for i := range rows {
		rows[i] = evidence.Row{ID: fmt.Sprint(i), Cells: map[string]evidence.Value{"Name": evidence.Text(strings.Repeat("X", 32))}}
	}
	m.res.setRows(rows)
	m.focus = focusResults
	m.res.grid.Focus()
	b.ResetTimer()
	for b.Loop() {
		updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		m = updated.(model)
		_ = m.View()
	}
}

func TestStartedTaskSelectsFirstEvidence(t *testing.T) {
	m := fixtureModel(t)
	m.caps.selectName("linux.pslist")
	run := m.start("linux.pslist", nil)
	updated, query := m.Update(run())
	m = updated.(model)
	updated, _ = m.Update(query())
	m = updated.(model)
	if m.res.grid.Cursor() != 0 || !strings.Contains(m.detail.GetContent(), "image_sha256") {
		t.Fatal("first result was not selected", m.res.grid.Cursor(), m.detail.GetContent())
	}
}

func TestCapabilityListScrollsAndSearches(t *testing.T) {
	m := fixtureModel(t)
	m.width, m.height = 100, minHeight
	m.resize()
	last := m.caps.specs[len(m.caps.specs)-1].Name
	for range m.caps.specs {
		m, _ = press(t, m, "down")
	}
	if m.caps.spec().Name != last || !strings.Contains(fits(t, m), "› "+last[:12]) {
		t.Fatal("last capability is not visible", m.caps.spec().Name)
	}
	m, _ = press(t, m, "/", "p", "s", "l")
	if m.caps.query != "psl" || m.caps.matches() == 0 || !strings.Contains(m.caps.spec().Name, "psl") {
		t.Fatal(m.caps.query, m.caps.spec().Name)
	}
	m, _ = press(t, m, "enter")
	if m.prompt.active() || m.caps.query != "psl" {
		t.Fatal("search was not kept")
	}
	m, _ = press(t, m, "esc")
	if m.caps.query != "" {
		t.Fatal("esc did not clear the search")
	}
	g := capabilities{specs: []plugin.Spec{{Name: "linux.a"}, {Name: "windows.b"}, {Name: "linux.c"}}}
	g.rebuild()
	if len(g.items) != 5 || g.items[0].spec >= 0 || g.items[2].spec != 2 || g.items[3].group != "windows" {
		t.Fatal(g.items)
	}
	g.move(1)
	if g.spec().Name != "linux.c" {
		t.Fatal(g.spec().Name)
	}
}

func TestColumnWindowAndSort(t *testing.T) {
	m := fixtureModel(t)
	m = runPslist(t, m)
	if len(m.res.spec.Columns) <= visibleColumns {
		t.Skip("pslist fits without a column window")
	}
	first := m.res.visible[0].Name
	m, _ = press(t, m, "]")
	if m.res.colStart != 1 || m.res.visible[0].Name == first || !strings.Contains(fits(t, m), "cols 2–") {
		t.Fatal("column window did not move", m.res.colStart)
	}
	m, _ = press(t, m, "[", "[")
	if m.res.colStart != 0 {
		t.Fatal(m.res.colStart)
	}
	var name string
	for _, c := range m.res.visible {
		if c.Name == "Name" {
			name = c.Name
		}
	}
	for m.res.sort != name {
		var cmd tea.Cmd
		m, cmd = press(t, m, "o")
		m = deliver(t, m, cmd)
	}
	if len(m.res.rows) != 2 || m.res.rows[0].Cells["Name"].String() > m.res.rows[1].Cells["Name"].String() {
		t.Fatal("rows not sorted ascending")
	}
	m, cmd := press(t, m, "s")
	m = deliver(t, m, cmd)
	if m.res.rows[0].Cells["Name"].String() < m.res.rows[1].Cells["Name"].String() || !strings.Contains(fits(t, m), "Name ▼") {
		t.Fatal("rows not sorted descending")
	}
}

func TestTaskPickerReopensEvidence(t *testing.T) {
	m := fixtureModel(t)
	m = runPslist(t, m)
	id := m.res.task.ID
	m.res.reset(evidence.Task{})
	m.caps.selectName(m.caps.specs[0].Name)
	m, cmd := press(t, m, "t")
	m = deliver(t, m, cmd)
	if !m.picker.open || len(m.picker.tasks) != 1 || !strings.Contains(fits(t, m), "TASKS") {
		t.Fatal("task picker did not open", m.picker.tasks)
	}
	m, cmd = press(t, m, "enter")
	m = deliver(t, m, cmd)
	if m.picker.open || m.res.task.ID != id || len(m.res.rows) != 2 || m.caps.spec().Name != "linux.pslist" {
		t.Fatal("task was not reopened", m.res.task.ID, len(m.res.rows))
	}
}

func TestCommandHistoryHelpAndExpand(t *testing.T) {
	m := fixtureModel(t)
	updated, _ := m.Update(historyMsg{"help", "use physical"})
	m = updated.(model)
	m, _ = press(t, m, ":")
	m.prompt.input.SetValue("hex 0x")
	m, _ = press(t, m, "up")
	if m.prompt.input.Value() != "use physical" {
		t.Fatal(m.prompt.input.Value())
	}
	m, _ = press(t, m, "up", "up", "down", "down")
	if m.prompt.input.Value() != "hex 0x" {
		t.Fatal("draft not restored", m.prompt.input.Value())
	}
	m.prompt.input.SetValue("help")
	m, cmd := press(t, m, "enter")
	m = deliver(t, m, cmd)
	if !m.showCommand || len(m.prompt.history) != 3 {
		t.Fatal("command not recorded or not executed", m.prompt.history)
	}
	m, _ = press(t, m, "?")
	if !m.showHelp || !strings.Contains(fits(t, m), "KEYS") {
		t.Fatal("help not shown")
	}
	m, _ = press(t, m, "?")
	m = runPslist(t, m)
	m, _ = press(t, m, "tab", "enter")
	if !m.expanded || !strings.Contains(fits(t, m), "esc or enter to restore") {
		t.Fatal("detail not expanded")
	}
	m, _ = press(t, m, "esc")
	if m.expanded {
		t.Fatal("esc did not restore")
	}
	m, cmd = press(t, m, "y")
	if cmd == nil || !strings.HasPrefix(m.status, "Copied evidence ID") {
		t.Fatal(m.status)
	}
}
