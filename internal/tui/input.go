package tui

import (
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// key routes a key press to the innermost open layer, then to global keys,
// then to whichever panel has focus. ok is false when the detail viewport
// should receive the key instead.
func (m model) key(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	switch {
	case key.Matches(msg, keys.ForceQuit):
		if m.launcher.cancel != nil {
			m.launcher.cancel()
		}
		return m, m.quit(), true
	case m.launcher.open:
		return m.launcherKey(msg)
	case m.prompt.active():
		next, cmd := m.promptKey(msg)
		return next, cmd, true
	case m.showHelp:
		if key.Matches(msg, keys.Help, keys.Back, keys.Quit) {
			m.showHelp = false
		}
		return m, nil, true
	case m.form.open:
		next, cmd := m.formKey(msg)
		return next, cmd, true
	case m.picker.open:
		next, cmd := m.pickerKey(msg)
		return next, cmd, true
	}
	if next, cmd, ok := m.globalKey(msg); ok {
		return next, cmd, true
	}
	if m.focus == focusNav {
		return m.navKey(msg)
	}
	return m.resultKey(msg)
}

func (m model) globalKey(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	switch {
	case key.Matches(msg, keys.Quit):
		return m, m.quit(), true
	case key.Matches(msg, keys.Cancel):
		if m.cancel != nil {
			m.cancel()
			m.canceling = true
			m.say(levelWarn, "Canceling; partial evidence will be retained")
		}
	case key.Matches(msg, keys.ScrollUp):
		m.detail.ScrollUp(3)
	case key.Matches(msg, keys.ScrollDown):
		m.detail.ScrollDown(3)
	case key.Matches(msg, keys.ScrollLeft):
		m.detail.ScrollLeft(4)
	case key.Matches(msg, keys.ScrollRight):
		m.detail.ScrollRight(4)
	case key.Matches(msg, keys.Help):
		m.showHelp = true
	case key.Matches(msg, keys.Import):
		if m.running || m.commandRunning {
			m.say(levelWarn, "Wait for the running task or cancel with ctrl+x before importing")
			return m, nil, true
		}
		m.showLauncher()
	case key.Matches(msg, keys.Focus):
		m.focus = 1 - m.focus
	case key.Matches(msg, keys.Raw):
		m.rawDetail = !m.rawDetail
		m.refreshDetail()
	case key.Matches(msg, keys.Command):
		return m, m.prompt.open(promptCommand, "run linux.pslist · hex 0x1000 · use kernel · help  (↑/↓ history)", ""), true
	case key.Matches(msg, keys.Filter):
		if m.focus == focusNav {
			return m, m.prompt.open(promptSearch, "Search capabilities", m.caps.query), true
		}
		return m, m.prompt.open(promptFilter, "Filter current task", m.res.filter), true
	case key.Matches(msg, keys.Tasks):
		if m.running || m.commandRunning {
			m.say(levelWarn, "Wait for the running task or cancel with ctrl+x")
			return m, nil, true
		}
		return m, m.loadTasks(), true
	case key.Matches(msg, keys.Back):
		if m.expanded {
			m.expanded = false
			m.layout()
		} else if m.caps.query != "" {
			m.caps.setQuery("")
			m.layout()
		}
	case key.Matches(msg, keys.Next):
		if len(m.res.rows) == pageSize {
			m.res.offset += pageSize
			return m, m.query(), true
		}
	case key.Matches(msg, keys.Prev):
		m.res.offset = max(0, m.res.offset-pageSize)
		return m, m.query(), true
	case key.Matches(msg, keys.Reverse):
		m.res.desc = !m.res.desc
		m.res.offset = 0
		m.layout()
		return m, m.query(), true
	case key.Matches(msg, keys.Sort):
		m.res.cycleSort()
		m.layout()
		m.say(levelInfo, "Insertion order")
		if m.res.sort != "" {
			m.say(levelInfo, "Sorted by "+render.Safe(m.res.sort))
		}
		return m, m.query(), true
	case key.Matches(msg, keys.ColLeft, keys.ColRight):
		delta := -1
		if key.Matches(msg, keys.ColRight) {
			delta = 1
		}
		if m.res.shift(delta) {
			m.layout()
		}
	case key.Matches(msg, keys.Bookmark):
		if row, ok := m.res.current(); ok {
			if err := m.engine.Store.Bookmark(m.ctx, row.ID, "TUI bookmark"); err != nil {
				m.say(levelError, err.Error())
			} else {
				m.say(levelSuccess, "Evidence bookmarked")
			}
		}
	case key.Matches(msg, keys.CopyID, keys.CopyAddr):
		row, ok := m.res.current()
		if !ok {
			return m, nil, true
		}
		text, what := row.ID, "evidence ID"
		if key.Matches(msg, keys.CopyAddr) {
			text, what = row.Provenance.Offset, "address"
		}
		if text == "" {
			m.say(levelWarn, "Selected row has no "+what)
			return m, nil, true
		}
		m.say(levelSuccess, "Copied "+what+" "+render.Safe(text))
		return m, tea.SetClipboard(text), true
	case key.Matches(msg, keys.Hex):
		return m.hexJump()
	default:
		return m, nil, false
	}
	return m, nil, true
}

func (m model) hexJump() (model, tea.Cmd, bool) {
	if m.commandRunning {
		m.say(levelWarn, "Wait for the exploration command to finish")
		return m, nil, true
	}
	row, ok := m.res.current()
	if !ok {
		return m, nil, false
	}
	if row.Provenance.Offset == "" {
		m.say(levelWarn, "Selected row has no address")
		return m, nil, true
	}
	layer := row.Provenance.Layer
	if m.engine.Env.Kernel != nil && layer == m.engine.Env.Kernel.Name() {
		m.explorer.Layer = m.engine.Env.Kernel
	} else if layer == m.engine.Env.Physical.Name() {
		m.explorer.Layer = m.engine.Env.Physical
	}
	return m, m.prompt.open(promptCommand, "", "hex "+row.Provenance.Offset+" 256"), true
}

func (m model) navKey(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	switch {
	case key.Matches(msg, keys.Run, keys.Edit):
		if m.caps.position() < 0 {
			m.say(levelWarn, "No capability matches the search")
			return m, nil, true
		}
		spec := m.caps.spec()
		if key.Matches(msg, keys.Run) && len(spec.Parameters) == 0 {
			return m, m.start(spec.Name, nil), true
		}
		return m, m.openForm(spec), true
	case key.Matches(msg, keys.Up, keys.Down):
		delta := -1
		if key.Matches(msg, keys.Down) {
			delta = 1
		}
		m.caps.move(delta)
		m.layout()
		return m, nil, true
	case key.Matches(msg, keys.TabLeft, keys.TabRight):
		delta := -1
		if key.Matches(msg, keys.TabRight) {
			delta = 1
		}
		m.caps.setTab(m.caps.tab + delta)
		m.layout()
		return m, nil, true
	}
	return m, nil, false
}

func (m model) launcherKey(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	l := &m.launcher
	_, _, _, height := m.sizes()
	rows := launcherRows(height)
	if l.opening {
		if key.Matches(msg, keys.Back) && l.cancel != nil {
			l.cancel()
		}
		return m, nil, true
	}
	switch {
	case key.Matches(msg, keys.Back):
		if m.engine != nil {
			l.open = false
			l.path.Blur()
		}
	case key.Matches(msg, keys.NextSection) && l.section == sectionPath && l.complete():
	case key.Matches(msg, keys.NextSection):
		return m, l.focusSection(l.section + 1), true
	case key.Matches(msg, keys.PrevSection):
		return m, l.focusSection(l.section - 1), true
	case l.section == sectionPath:
		if key.Matches(msg, keys.Run) {
			return m, m.openImage(l.path.Value()), true
		}
		var cmd tea.Cmd
		l.path, cmd = l.path.Update(msg)
		l.err = ""
		return m, cmd, true
	case key.Matches(msg, keys.Run):
		if path, ok := l.choose(); ok {
			return m, m.openImage(path), true
		}
	case key.Matches(msg, keys.Up):
		l.move(-1, rows)
	case key.Matches(msg, keys.Down):
		l.move(1, rows)
	case key.Matches(msg, keys.Home):
		l.move(-1<<30, rows)
	case key.Matches(msg, keys.End):
		l.move(1<<30, rows)
	case l.section == sectionBrowse && key.Matches(msg, keys.Parent):
		l.up()
	case l.section == sectionBrowse && key.Matches(msg, keys.Hidden):
		l.hidden = !l.hidden
		l.chdir(l.dir)
	case key.Matches(msg, keys.Quit):
		return m, m.quit(), true
	}
	return m, nil, true
}

func (m model) resultKey(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	half := max(1, m.res.grid.rows()/2)
	switch {
	case key.Matches(msg, keys.Expand):
		m.expanded = !m.expanded
		m.layout()
		return m, nil, true
	case key.Matches(msg, keys.Up):
		m.res.grid.move(-1)
	case key.Matches(msg, keys.Down):
		m.res.grid.move(1)
	case key.Matches(msg, keys.HalfUp):
		m.res.grid.move(-half)
	case key.Matches(msg, keys.HalfDown):
		m.res.grid.move(half)
	case key.Matches(msg, keys.Home):
		m.res.grid.setCursor(0)
	case key.Matches(msg, keys.End):
		m.res.grid.setCursor(len(m.res.rows))
	default:
		return m, nil, false
	}
	m.showCommand = false
	m.refreshDetail()
	return m, nil, true
}

func (m *model) openForm(spec plugin.Spec) tea.Cmd {
	_, middle, _, _ := m.sizes()
	m.form = newForm(spec, middle-4)
	m.picker.open = false
	return m.form.focusField(0)
}

func (m model) formKey(msg tea.KeyPressMsg) (model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Back):
		m.form.open = false
		return m, nil
	case key.Matches(msg, keys.Submit), key.Matches(msg, keys.Run) && m.form.last():
		return m.submitForm()
	case key.Matches(msg, keys.Run), key.Matches(msg, keys.NextField):
		return m, m.form.focusField(m.form.focus + 1)
	case key.Matches(msg, keys.PrevField):
		return m, m.form.focusField(m.form.focus - 1)
	case key.Matches(msg, keys.Toggle) && m.form.toggle():
		return m, nil
	}
	return m, m.form.update(msg)
}

// submitForm validates parameters exactly as the engine will, then runs.
func (m model) submitForm() (model, tea.Cmd) {
	if m.running || m.commandRunning {
		m.form.err = "A task is running. Press ctrl+x to cancel it."
		return m, nil
	}
	values := m.form.values()
	if _, err := plugin.Parameters(m.form.spec, values); err != nil {
		m.form.err = err.Error()
		return m, nil
	}
	line := m.form.commandLine()
	m.prompt.record(line)
	if err := m.engine.Store.History(m.ctx, line); err != nil {
		m.form.err = err.Error()
		return m, nil
	}
	return m, m.start(m.form.spec.Name, values)
}

func (m model) promptKey(msg tea.KeyPressMsg) (model, tea.Cmd) {
	mode := m.prompt.mode
	switch {
	case key.Matches(msg, keys.Back):
		if mode == promptSearch {
			m.caps.setQuery("")
			m.layout()
		}
		m.prompt.close()
		return m, nil
	case key.Matches(msg, keys.Run):
		line := m.prompt.input.Value()
		m.prompt.close()
		switch mode {
		case promptSearch:
			m.caps.setQuery(line)
			m.layout()
			return m, nil
		case promptFilter:
			m.res.filter = line
			m.res.offset = 0
			return m, m.query()
		}
		return m.execute(line)
	case mode == promptCommand && msg.String() == "up":
		m.prompt.recall(-1)
		return m, nil
	case mode == promptCommand && msg.String() == "down":
		m.prompt.recall(1)
		return m, nil
	}
	var cmd tea.Cmd
	m.prompt.input, cmd = m.prompt.input.Update(msg)
	if mode == promptSearch {
		m.caps.setQuery(m.prompt.input.Value())
		m.layout()
	}
	return m, cmd
}

// execute runs a command line: run and quit are handled here, the rest by explore.
func (m model) execute(line string) (model, tea.Cmd) {
	args, err := explore.Split(line)
	if err != nil {
		m.say(levelError, err.Error())
		return m, nil
	}
	if len(args) == 0 {
		return m, nil
	}
	m.prompt.record(line)
	if args[0] == "quit" {
		return m, m.quit()
	}
	if args[0] == "run" && len(args) > 1 {
		name, params, err := runArgs(args[1:])
		if err != nil {
			m.say(levelError, err.Error())
			return m, nil
		}
		if !m.caps.selectName(name) {
			m.say(levelError, "Plugin is not implemented")
			return m, nil
		}
		// explore records its own commands; run never reaches it.
		if err := m.engine.Store.History(m.ctx, line); err != nil {
			m.say(levelError, err.Error())
			return m, nil
		}
		m.layout()
		return m, m.start(name, params)
	}
	if m.running || m.commandRunning {
		m.say(levelWarn, "Wait for the running task or cancel with ctrl+x")
		return m, nil
	}
	session := m.explorer
	ctx := m.ctx
	m.commandRunning = true
	return m, tea.Batch(func() tea.Msg {
		var text strings.Builder
		err := session.Execute(ctx, line, &limitedWriter{w: &text, remaining: 65536})
		return commandMsg{text.String(), err}
	}, m.spin.Tick)
}

func (m model) pickerKey(msg tea.KeyPressMsg) (model, tea.Cmd) {
	_, _, _, height := m.sizes()
	switch {
	case key.Matches(msg, keys.Back, keys.Tasks):
		m.picker.open = false
	case key.Matches(msg, keys.AllTasks):
		m.picker.toggleEvery()
	case key.Matches(msg, keys.Quit):
		return m, m.quit()
	case key.Matches(msg, keys.Up):
		m.picker.move(-1, height-4)
	case key.Matches(msg, keys.Down):
		m.picker.move(1, height-4)
	case key.Matches(msg, keys.Run):
		if t, ok := m.picker.selected(); ok {
			return m, m.openTask(t)
		}
	}
	return m, nil
}

// region names the panel under a screen cell and the content line within it.
type region int

const (
	regionNone region = iota
	regionCaps
	regionCenter
	regionDetail
)

// at maps a cell to a panel; line counts from the first line inside the border.
func (m model) at(x, y int) (region, int) {
	left, middle, _, height := m.sizes()
	line := y - 2 // header row, then the top border
	if m.showHelp || m.expanded || m.prompt.active() || line < 0 || line >= height-2 {
		return regionNone, line
	}
	switch {
	case x < left:
		return regionCaps, line
	case x < left+middle:
		return regionCenter, line
	}
	return regionDetail, line
}

// click selects what is under the pointer; a click on the selected task opens it.
func (m model) click(mouse tea.Mouse) (model, tea.Cmd, bool) {
	if mouse.Button != tea.MouseLeft {
		return m, nil, false
	}
	if m.launcher.open {
		return m.launcherClick(mouse)
	}
	r, line := m.at(mouse.X, mouse.Y)
	switch {
	case r == regionCaps && !m.form.open:
		m.focus = focusNav
		if line == 1 && m.caps.clickTab(mouse.X-2) || m.caps.clickLine(line-3) {
			m.layout()
		}
	case r == regionCenter && m.picker.open:
		before := m.picker.cursor
		if m.picker.clickLine(line-2) && m.picker.cursor == before {
			if t, ok := m.picker.selected(); ok {
				return m, m.openTask(t), true
			}
		}
	case r == regionCenter && !m.form.open:
		m.focus = focusResults
		if i := m.res.grid.top + line - 3; line >= 3 && i < len(m.res.rows) {
			m.res.grid.setCursor(i)
			m.showCommand = false
			m.refreshDetail()
		}
	default:
		return m, nil, false
	}
	return m, nil, true
}

// wheel moves the selection of the list under the pointer; the detail
// viewport scrolls itself when this reports false.
func (m model) wheel(mouse tea.Mouse) (model, tea.Cmd, bool) {
	delta := 0
	switch mouse.Button {
	case tea.MouseWheelUp:
		delta = -1
	case tea.MouseWheelDown:
		delta = 1
	default:
		return m, nil, false
	}
	if m.launcher.open {
		if r, _ := m.launcherAt(mouse.X, mouse.Y); r != sectionCount {
			m.launcher.section = r
			_, _, _, height := m.sizes()
			m.launcher.move(delta, launcherRows(height))
			return m, nil, true
		}
		return m, nil, false
	}
	switch r, _ := m.at(mouse.X, mouse.Y); {
	case r == regionCaps && !m.form.open:
		m.caps.move(delta)
		m.layout()
	case r == regionCenter && m.picker.open:
		_, _, _, height := m.sizes()
		m.picker.move(delta, height-4)
	case r == regionCenter && !m.form.open:
		m.res.grid.move(delta)
		m.showCommand = false
		m.refreshDetail()
	default:
		return m, nil, false
	}
	return m, nil, true
}

// launcherAt maps a cell to the importer list under it and the entry index
// within that list's visible window; sectionCount means no list.
func (m model) launcherAt(x, y int) (launcherSection, int) {
	_, _, _, height := m.sizes()
	line := y - 2 - 4 // header row and border, then title, path, message, list header
	if line < 0 || line >= launcherRows(height) {
		return sectionCount, 0
	}
	half := (m.width - 4 - 2) / 2
	switch x -= 2; {
	case x >= 0 && x < half:
		return sectionBrowse, line
	case x >= half+2:
		return sectionRecent, line
	}
	return sectionCount, 0
}

// launcherClick focuses what was clicked; clicking the selected entry again
// activates it, as enter would.
func (m model) launcherClick(mouse tea.Mouse) (model, tea.Cmd, bool) {
	l := &m.launcher
	if l.opening {
		return m, nil, true
	}
	if mouse.Y == 3 {
		return m, l.focusSection(sectionPath), true
	}
	r, line := m.launcherAt(mouse.X, mouse.Y)
	if r == sectionCount {
		return m, nil, true
	}
	cmd := l.focusSection(r)
	cursor, top, n := &l.cursor, l.top, len(l.entries)
	if r == sectionRecent {
		cursor, top, n = &l.rcursor, l.rtop, len(l.recent)
	}
	i := top + line
	if i >= n {
		return m, cmd, true
	}
	if *cursor != i {
		*cursor = i
		return m, cmd, true
	}
	if path, ok := l.choose(); ok {
		return m, m.openImage(path), true
	}
	return m, cmd, true
}
