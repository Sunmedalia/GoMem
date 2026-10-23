package tui

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/spinner"
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
	cfg := engine.Config{Image: f.Image, CaseDir: t.TempDir(), Symbols: f.Symbols, OS: "linux", Arch: "x64", DTB: f.DTB}
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	m := New(context.Background(), Options{Config: cfg, Engine: e}).(model)
	// The TUI may switch images; close whichever engine it ends with.
	t.Cleanup(func() { Close(m) })
	return m
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
		case "space":
			msg = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
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
	m, _ = feed(t, m, cmd)
	return m
}

// feed runs a command, expanding batches, and delivers every message except
// spinner ticks, returning the model and the commands the messages produced.
func feed(t testing.TB, m model, cmd tea.Cmd) (model, []tea.Cmd) {
	t.Helper()
	var out []tea.Cmd
	if cmd == nil {
		return m, nil
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			var more []tea.Cmd
			m, more = feed(t, m, c)
			out = append(out, more...)
		}
	case spinner.TickMsg, nil:
	default:
		updated, next := m.Update(msg)
		m = updated.(model)
		out = append(out, next)
	}
	return m, out
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
	m.layout()
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
		func(m *model) { m.openForm(m.caps.specs[0]) },
		func(m *model) {
			for _, s := range m.caps.specs {
				if len(s.Parameters) > 10 {
					m.openForm(s)
				}
			}
		},
		func(m *model) { m.setTheme(false) },
		func(m *model) { m.showLauncher() },
	} {
		v := m
		view(&v)
		for _, height := range []int{18, 30} {
			for _, width := range []int{85, 100, 120, 160} {
				v.width, v.height = width, height
				v.layout()
				if out := fits(t, v); !strings.HasSuffix(ansi.Strip(strings.Split(out, "\n")[height-7]), "╯") {
					t.Fatalf("panel bottom border clipped at %d×%d\n%s", width, height, out)
				}
			}
		}
	}
	m.width, m.height = 120, 30
	m.layout()
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
	m, next := feed(t, m, m.start("linux.pslist", nil))
	if m.running || m.level != levelSuccess || !strings.Contains(m.statusLine(), "rows") {
		t.Fatal("task did not finish successfully", m.status)
	}
	for _, c := range next {
		m, _ = feed(t, m, c)
	}
	if m.res.grid.Cursor() != 0 || !strings.Contains(m.detail.GetContent(), "PROVENANCE") {
		t.Fatal("first result was not selected", m.res.grid.Cursor(), m.detail.GetContent())
	}
}

func TestCapabilityListScrollsAndSearches(t *testing.T) {
	m := fixtureModel(t)
	m.width, m.height = 100, minHeight
	m.layout()
	last := m.caps.specs[m.caps.items[len(m.caps.items)-1].spec].Name
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
	g := capabilities{specs: []plugin.Spec{{Name: "linux.a"}, {Name: "windows.b"}, {Name: "linux.c"}}, tab: tabFor("")}
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

func specNamed(t testing.TB, m model, name string) plugin.Spec {
	t.Helper()
	for _, s := range m.caps.specs {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no capability %s", name)
	return plugin.Spec{}
}

func TestStructuredDetailAndRawToggle(t *testing.T) {
	m := fixtureModel(t)
	m.caps.selectName("linux.kthreads")
	m.layout()
	if got := m.detail.GetContent(); !strings.Contains(got, "PARAMETERS") || !strings.Contains(got, "max-nodes") {
		t.Fatal("spec detail lacks parameters", got)
	}
	m = runPslist(t, m)
	m, _ = press(t, m, "tab")
	got := m.detail.GetContent()
	if !strings.Contains(got, "EVIDENCE") || !strings.Contains(got, "PROVENANCE") || !strings.Contains(got, "linux.pslist") || strings.Contains(got, `"cells"`) {
		t.Fatal("row detail is not structured", got)
	}
	m, _ = press(t, m, "r")
	if !strings.Contains(m.detail.GetContent(), `"cells"`) {
		t.Fatal("raw toggle did not show JSON")
	}
	m, _ = press(t, m, "r")
	row := evidence.Row{ID: "x", Cells: map[string]evidence.Value{"Name": evidence.Missing("paged_out", fmt.Errorf("no page")), "Raw": evidence.Bytes([]byte{0xde, 0xad})}}
	got = ansi.Strip(rowView(m.st, row, m.res.spec, 80))
	if !strings.Contains(got, "<paged_out: no page>") || !strings.Contains(got, "dead  (2 bytes)") {
		t.Fatal(got)
	}
}

func TestEnterRunsDefaultsAndPromptsForRequiredParameters(t *testing.T) {
	base := fixtureModel(t)
	for _, spec := range base.caps.specs {
		t.Run(spec.Name, func(t *testing.T) {
			m := base
			m.caps = newCapabilities(base.caps.specs, "linux")
			m.caps.setTab(len(platformTabs) - 1)
			if !m.caps.selectName(spec.Name) {
				t.Fatal("plugin missing from capability list")
			}
			m.layout()
			m, cmd := press(t, m, "enter")
			required := false
			for _, p := range spec.Parameters {
				required = required || p.Required
			}
			if required {
				if !m.form.open || m.running {
					t.Fatal("missing required input did not open parameter form")
				}
				return
			}
			if _, err := plugin.Parameters(spec, nil); err != nil {
				t.Fatalf("invalid declared defaults: %v", err)
			}
			if !m.running || m.form.open || cmd == nil {
				t.Fatal("Enter did not start plugin with defaults")
			}
			m.cancel()
		})
	}
}

func TestParameterFormValidatesAndRuns(t *testing.T) {
	m := fixtureModel(t)
	m.caps.selectName("linux.modxview")
	m.layout()
	m, _ = press(t, m, "e")
	if !m.form.open || m.running || !strings.Contains(fits(t, m), "plain-taints") {
		t.Fatal("parameter form did not open")
	}
	before := m.form.inputs[0].Value()
	m, _ = press(t, m, "space")
	if m.form.inputs[0].Value() == before {
		t.Fatal("bool did not toggle")
	}
	m, _ = press(t, m, "esc")
	if m.form.open {
		t.Fatal("esc did not close the form")
	}

	m.caps.selectName("linux.kthreads")
	m, _ = press(t, m, "e")
	m.form.inputs[0].SetValue("abc")
	updated, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	m = updated.(model)
	if cmd != nil || !m.form.open || m.form.err == "" || m.running || !strings.Contains(fits(t, m), "max-nodes") {
		t.Fatal("invalid parameter accepted", m.form.err)
	}
	m.form.inputs[0].SetValue("7")
	for !m.form.last() {
		m, _ = press(t, m, "tab")
	}
	m, cmd = press(t, m, "enter")
	if !m.running || m.form.open || m.prompt.history[len(m.prompt.history)-1] != "run linux.kthreads max-nodes=7" {
		t.Fatal("form did not start the task", m.prompt.history)
	}
	m, _ = feed(t, m, cmd)
	if m.running {
		t.Fatal("task did not finish")
	}
}

func TestStatusLevelsProgressAndTheme(t *testing.T) {
	m := fixtureModel(t)
	m.running, m.res.task.ID, m.runStarted = true, "a", time.Now()
	updated, _ := m.Update(progressMsg{"a", 42})
	m = updated.(model)
	if !strings.Contains(m.statusLine(), "42 rows") || !strings.Contains(m.res.View(m.st, false, m.activity(), ""), "42 rows") {
		t.Fatal(m.statusLine())
	}
	m.generation = 5
	updated, _ = m.Update(done{err: context.Canceled, generation: 5})
	m = updated.(model)
	if m.level != levelWarn || m.running {
		t.Fatal(m.level, m.status)
	}
	updated, _ = m.Update(done{err: fmt.Errorf("broken"), generation: 5})
	m = updated.(model)
	if m.level != levelError || m.status != "broken" {
		t.Fatal(m.level, m.status)
	}
	updated, _ = m.Update(tea.BackgroundColorMsg{Color: color.White})
	m = updated.(model)
	if m.st.dark {
		t.Fatal("light background kept the dark palette")
	}
	fits(t, m)
}

func TestMouseSelectsCapabilitiesAndRows(t *testing.T) {
	m := fixtureModel(t)
	m = runPslist(t, m)
	left, _, _, _ := m.sizes()
	// Capability items start on the fourth line inside the panel: y = 1 header + 1 border + 3.
	for i, it := range m.caps.items {
		if it.spec >= 0 && it.spec != m.caps.selected && i < m.caps.height {
			updated, _ := m.Update(tea.MouseClickMsg{X: 3, Y: 5 + i, Button: tea.MouseLeft})
			m = updated.(model)
			if m.caps.selected != it.spec || m.focus != focusNav {
				t.Fatal("click did not select capability", i)
			}
			break
		}
	}
	// Result rows start below the title, a blank line and the column header.
	updated, _ := m.Update(tea.MouseClickMsg{X: left + 3, Y: 6, Button: tea.MouseLeft})
	m = updated.(model)
	if m.focus != focusResults || m.res.grid.Cursor() != 1 {
		t.Fatal("click did not select row", m.res.grid.Cursor())
	}
	updated, _ = m.Update(tea.MouseWheelMsg{X: left + 3, Y: 6, Button: tea.MouseWheelUp})
	m = updated.(model)
	if m.res.grid.Cursor() != 0 {
		t.Fatal("wheel did not move the row", m.res.grid.Cursor())
	}
}

func TestImporterOpensSwitchesAndRestoresImages(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	caseDir := t.TempDir()
	cfg := engine.Config{CaseDir: caseDir, Symbols: f.Symbols, OS: "linux", Arch: "x64", DTB: f.DTB}
	m := New(context.Background(), Options{Config: cfg}).(model)
	defer func() { Close(m) }()
	out := fits(t, m)
	if !m.launcher.open || m.engine != nil || !strings.Contains(out, "IMPORT IMAGE") || !strings.Contains(out, "no image") {
		t.Fatal("importer not shown without an image\n" + out)
	}
	m, _ = press(t, m, "esc")
	if !m.launcher.open {
		t.Fatal("esc left the importer with no image open")
	}
	m.launcher.path.SetValue(f.Image)
	m, cmd := press(t, m, "enter")
	if !m.launcher.opening || !strings.Contains(fits(t, m), "opening") {
		t.Fatal("open did not start")
	}
	m = deliver(t, m, cmd)
	if m.engine == nil || m.launcher.open || m.level != levelSuccess || platformTabs[m.caps.tab] != "linux" {
		t.Fatal("image did not open", m.launcher.err, m.status)
	}
	for _, it := range m.caps.items {
		if it.spec >= 0 && platformOf(m.caps.specs[it.spec]) == "windows" {
			t.Fatal("windows capability listed for a linux image", m.caps.specs[it.spec].Name)
		}
	}

	// The case remembers the image; reopening it from the recent list closes
	// the current engine first, or the case lock would refuse the open.
	m, _ = press(t, m, "i")
	if !m.launcher.open || len(m.launcher.recent) != 1 || m.launcher.recent[0].Path != f.Image {
		t.Fatal("recent images", m.launcher.recent)
	}
	first := m.engine
	m, _ = press(t, m, "tab", "tab")
	if m.launcher.section != sectionRecent {
		t.Fatal(m.launcher.section)
	}
	m, cmd = press(t, m, "enter")
	m = deliver(t, m, cmd)
	if m.engine == nil || m.engine == first || m.launcher.open {
		t.Fatal("recent image did not reopen", m.launcher.err)
	}

	m, _ = press(t, m, "i")
	m.launcher.section = sectionPath
	m.launcher.path.SetValue(filepath.Join(t.TempDir(), "missing.raw"))
	m, cmd = press(t, m, "enter")
	m = deliver(t, m, cmd)
	if m.engine == nil || !m.launcher.open || !strings.Contains(m.launcher.err, "previous image is open again") {
		t.Fatal("failed open did not restore the previous image", m.launcher.err)
	}
	m, _ = press(t, m, "esc")
	if m.launcher.open || m.engine.Config.Image != f.Image {
		t.Fatal("could not return to the restored image")
	}
}

func TestImporterCompletionAndBrowser(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"alphabet", ".hidden"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "alpha.raw"), make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newLauncher("")
	l.path.SetValue(filepath.Join(dir, "al"))
	if !l.complete() || l.path.Value() != filepath.Join(dir, "alpha") {
		t.Fatal(l.path.Value())
	}
	if l.complete() {
		t.Fatal("ambiguous completion changed the path", l.path.Value())
	}
	l.path.SetValue(filepath.Join(dir, "alphab"))
	if !l.complete() || l.path.Value() != filepath.Join(dir, "alphabet")+string(os.PathSeparator) || l.dir != filepath.Join(dir, "alphabet") {
		t.Fatal(l.path.Value(), l.dir)
	}

	l.chdir(dir)
	var names []string
	for _, e := range l.entries {
		names = append(names, e.name)
	}
	if strings.Join(names, ",") != "..,alphabet,alpha.raw" {
		t.Fatal(names)
	}
	l.hidden = true
	l.chdir(dir)
	if len(l.entries) != 4 {
		t.Fatal("hidden entries not shown", l.entries)
	}
	l.hidden = false
	l.chdir(dir)
	l.section, l.cursor = sectionBrowse, 1
	if _, ok := l.choose(); ok || l.dir != filepath.Join(dir, "alphabet") {
		t.Fatal("did not enter directory", l.dir)
	}
	l.up()
	if l.dir != dir || l.entries[l.cursor].name != "alphabet" {
		t.Fatal("parent did not reselect the directory", l.dir, l.cursor)
	}
	l.cursor = 2
	if path, ok := l.choose(); !ok || path != filepath.Join(dir, "alpha.raw") || l.path.Value() != path {
		t.Fatal(path, ok)
	}
	if !strings.Contains(ansi.Strip(l.View(newStyles(true), engine.Config{}, 100, 20, "")), "2.0 KiB") {
		t.Fatal("file size not shown")
	}
}

func TestPlatformTabsAndTaskScope(t *testing.T) {
	m := fixtureModel(t)
	if platformTabs[m.caps.tab] != "linux" {
		t.Fatal(m.caps.tab)
	}
	count := func(platform string) int {
		n := 0
		for _, it := range m.caps.items {
			if it.spec >= 0 && platformOf(m.caps.specs[it.spec]) == platform {
				n++
			}
		}
		return n
	}
	if count("linux") == 0 || count("other") == 0 || count("windows") != 0 {
		t.Fatal("linux tab", count("linux"), count("other"), count("windows"))
	}
	m, _ = press(t, m, "right")
	if count("windows") == 0 || count("linux") != 0 {
		t.Fatal("windows tab")
	}
	m, _ = press(t, m, "right")
	if count("other") == 0 || count("windows") != 0 || count("linux") != 0 {
		t.Fatal("other tab")
	}
	m, _ = press(t, m, "right", "/", "p", "s", "l", "i", "s", "t", "enter")
	if platformTabs[m.caps.tab] != "all" || count("linux") == 0 || count("windows") == 0 {
		t.Fatal("search across all platforms")
	}
	m, _ = press(t, m, "left", "left", "left")
	if platformTabs[m.caps.tab] != "linux" || count("windows") != 0 || !strings.Contains(m.caps.spec().Name, "pslist") {
		t.Fatal("tab and search do not combine", m.caps.spec().Name)
	}
	// The tab line is the second line inside the panel; "win" starts after "linux ".
	updated, _ := m.Update(tea.MouseClickMsg{X: 2 + len("linux "), Y: 3, Button: tea.MouseLeft})
	m = updated.(model)
	if platformTabs[m.caps.tab] != "windows" {
		t.Fatal("tab click", m.caps.tab)
	}

	m.picker.show([]evidence.Task{{ID: "mine", Provenance: evidence.Provenance{ImageSHA256: m.engine.Hash}}, {ID: "other", Provenance: evidence.Provenance{ImageSHA256: "other"}}}, m.engine.Hash)
	if len(m.picker.tasks) != 1 || m.picker.tasks[0].ID != "mine" {
		t.Fatal(m.picker.tasks)
	}
	m, _ = press(t, m, "a")
	if len(m.picker.tasks) != 2 || !strings.Contains(fits(t, m), "all images") {
		t.Fatal("a did not show every image's tasks")
	}
}

func TestResultTabsKeepTasksAndRouteRuns(t *testing.T) {
	m := fixtureModel(t)
	m, next := feed(t, m, m.start("linux.pslist", nil))
	for _, c := range next {
		m, _ = feed(t, m, c)
	}
	if len(m.tabs) != 1 || m.res.task.Plugin != "linux.pslist" || len(m.res.rows) != 2 {
		t.Fatal("first run did not fill the first tab", len(m.tabs), m.res.task.Plugin)
	}
	m.res.filter = "worker"
	// A second run opens a second tab; switching away before it finishes
	// still delivers its result to its own tab.
	run := m.start("generic.info", nil)
	if len(m.tabs) != 2 || m.active != 1 {
		t.Fatal("second run did not open a tab", len(m.tabs), m.active)
	}
	m, _ = press(t, m, "1")
	if m.active != 0 || m.res.task.Plugin != "linux.pslist" || m.res.filter != "worker" {
		t.Fatal("tab 1 lost its state", m.res.task.Plugin, m.res.filter)
	}
	m, _ = feed(t, m, run)
	if m.running || m.tabs[1].task.Plugin != "generic.info" || m.res.task.Plugin != "linux.pslist" {
		t.Fatal("run result reached the wrong tab", m.tabs[1].task.Plugin, m.res.task.Plugin)
	}
	out := fits(t, m)
	if !strings.Contains(out, "1 pslist") || !strings.Contains(out, "2 info") {
		t.Fatal("tab bar missing\n" + out)
	}
	left, _, _, _ := m.sizes()
	updated, cmd := m.Update(tea.MouseClickMsg{X: left + 2 + len("1 pslist "), Y: 3, Button: tea.MouseLeft})
	m = updated.(model)
	if m.active != 1 || cmd == nil {
		t.Fatal("tab click", m.active)
	}
	m, _ = press(t, m, "w")
	if len(m.tabs) != 1 || m.res.task.Plugin != "linux.pslist" {
		t.Fatal("close tab", len(m.tabs), m.res.task.Plugin)
	}
}

func TestColumnFilters(t *testing.T) {
	cols := []evidence.Column{{Name: "Symbol Name"}, {Name: "PID"}, {Name: "Name"}}
	plain, terms := parseFilter(`"symbol name":abc foo pid=1 other:x name:`, cols)
	if plain != "foo other:x" || len(terms) != 3 || terms[0] != (evidence.ColumnFilter{Column: "Symbol Name", Value: "abc"}) || terms[1] != (evidence.ColumnFilter{Column: "PID", Value: "1", Exact: true}) || terms[2].Column != "Name" {
		t.Fatal(plain, terms)
	}
	m := fixtureModel(t)
	m = runPslist(t, m)
	for filter, want := range map[string]int{"Name:WORK": 1, "PID=100": 1, "name=WORKER": 0, "ppid=100 init": 0, "ppid:0": 2, "ppid=0": 1} {
		m, _ = press(t, m, "tab")
		m.focus = focusResults
		m, _ = press(t, m, "/")
		m.prompt.input.SetValue(filter)
		m, cmd := press(t, m, "enter")
		m = deliver(t, m, cmd)
		if len(m.res.rows) != want {
			t.Fatalf("%q: %d rows", filter, len(m.res.rows))
		}
	}
}

func TestTreeLayoutFilterAndCycles(t *testing.T) {
	row := func(id, parent, name string) evidence.Row {
		return evidence.Row{ID: id, ParentID: parent, Cells: map[string]evidence.Value{"Name": evidence.Text(name)}}
	}
	var tr tree
	tr.build([]evidence.Row{
		row("1", "", "init"), row("2", "1", "sshd"), row("3", "2", "bash"), row("4", "1", "cron"),
		row("5", "missing", "orphan"), row("6", "7", "loop-a"), row("7", "6", "loop-b"),
	})
	all := func(evidence.Row) bool { return true }
	draw := func() string {
		var b strings.Builder
		for _, l := range tr.lines {
			b.WriteString(l.prefix + tr.all[l.row].Cells["Name"].String() + "\n")
		}
		return b.String()
	}
	tr.flatten(all, false)
	want := "▾ init\n├─▾ sshd\n│ └─  bash\n└─  cron\n  orphan\n▾ loop-a\n└─  loop-b\n"
	if got := draw(); got != want {
		t.Fatalf("tree:\n%s\nwant:\n%s", got, want)
	}
	tr.collapsed["2"] = true
	tr.flatten(all, false)
	if got := draw(); !strings.Contains(got, "├─▸ sshd\n└─  cron") {
		t.Fatal(got)
	}
	tr.flatten(matcher("bash", []evidence.Column{{Name: "Name"}}), true)
	if got := draw(); got != "▾ init\n└─▾ sshd\n  └─  bash\n" {
		t.Fatalf("filter keeps ancestors and opens collapsed nodes:\n%s", got)
	}
}

func TestTreeViewToggleExpandAndCollapse(t *testing.T) {
	m := fixtureModel(t)
	res, err := m.engine.Run(m.ctx, "linux.pstree", nil, engine.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m.res.task = res.Task
	m.layout()
	m = deliver(t, m, m.query())
	m.focus = focusResults
	m, cmd := press(t, m, "T")
	m = deliver(t, m, cmd)
	if !m.res.tree.on || len(m.res.tree.all) != int(res.Task.Rows) || len(m.res.rows) == 0 || !strings.Contains(fits(t, m), "TREE") {
		t.Fatal("tree did not load", len(m.res.tree.all), len(m.res.rows))
	}
	m, cmd = press(t, m, "n")
	if cmd != nil {
		t.Fatal("paging in a tree")
	}
	// Collapse every parent, then expand them all again.
	shown := len(m.res.rows)
	m, _ = press(t, m, "-")
	if m.res.tree.linked && len(m.res.rows) >= shown {
		t.Fatal("collapse all kept every row", len(m.res.rows), shown)
	}
	m, _ = press(t, m, "+")
	if len(m.res.rows) != shown {
		t.Fatal("expand all", len(m.res.rows), shown)
	}
	m, cmd = press(t, m, "T")
	m = deliver(t, m, cmd)
	if m.res.tree.on || m.res.prefix != nil || len(m.res.rows) != int(res.Task.Rows) {
		t.Fatal("tree did not switch back to pages")
	}
}
