// Package tui is the asynchronous, paged investigation interface.
//
// The root model routes focus and coordinates tasks; capabilities, results,
// prompt and taskPicker each own their state and rendering.
package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const minWidth, minHeight = 85, 18

type focus int

const (
	focusNav focus = iota
	focusResults
)

type model struct {
	ctx            context.Context
	engine         *engine.Engine
	explorer       *explore.Session
	caps           capabilities
	res            results
	detail         viewport.Model
	prompt         prompt
	picker         taskPicker
	help           help.Model
	focus          focus
	showHelp       bool
	expanded       bool
	width, height  int
	running        bool
	cancel         context.CancelFunc
	events         chan tea.Msg
	status         string
	commandView    string
	showCommand    bool
	generation     uint64
	commandRunning bool
}

func New(ctx context.Context, e *engine.Engine) tea.Model {
	m := model{ctx: ctx, engine: e, explorer: explore.New(e), caps: newCapabilities(e.Registry.List()), res: newResults(), prompt: newPrompt(), help: help.New(), width: 120, height: 30, events: make(chan tea.Msg, 4), status: "Select a capability and press enter. Results are persisted and paged. ? for help."}
	m.detail = viewport.New()
	m.resize()
	return m
}
func (m model) Init() tea.Cmd { return tea.Batch(m.waitEvent(), pulse(), m.loadHistory()) }

func (m model) loadHistory() tea.Cmd {
	return func() tea.Msg {
		cmds, _ := m.engine.Store.Commands(m.ctx, historyLimit)
		return historyMsg(cmds)
	}
}
func (m model) loadTasks() tea.Cmd {
	return func() tea.Msg {
		tasks, err := m.engine.Store.Tasks(m.ctx)
		return tasksMsg{tasks, err}
	}
}
func (m model) query() tea.Cmd { return m.res.query(m.ctx, m.engine.Store) }

// sizes returns the total widths of the three panels and their shared height.
func (m model) sizes() (left, middle, right, height int) {
	left = 24
	right = min(40, max(26, m.width/3))
	middle = m.width - left - right
	height = max(8, m.height-7)
	return
}

// resultSpec is the shown task's plugin, or the selected capability before any run.
func (m model) resultSpec() plugin.Spec {
	if m.res.task.ID != "" {
		if p, err := m.engine.Registry.Get(m.res.task.Plugin); err == nil {
			return p.Spec()
		}
	}
	return m.caps.spec()
}
func (m *model) resize() {
	_, middle, right, height := m.sizes()
	m.caps.setHeight(height - 4)
	m.res.setSpec(m.resultSpec())
	m.res.layout(middle-4, height-4)
	if m.expanded {
		right = m.width
	}
	m.detail.SetWidth(right - 4)
	m.detail.SetHeight(height - 4)
	m.prompt.input.SetWidth(max(20, m.width-8))
	m.help.SetWidth(m.width)
	m.refreshDetail()
}
func (m *model) refreshDetail() {
	switch row, ok := m.res.current(); {
	case m.showCommand:
		m.detail.SetContent(commandText(m.commandView))
	case ok:
		m.detail.SetContent(detailText(row))
	default:
		m.detail.SetContent(detailText(m.caps.spec()))
	}
}
func (m *model) start(name string, params map[string]string) tea.Cmd {
	if m.running || m.commandRunning {
		m.status = "A task is running. Press ctrl+x to cancel it."
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.running = true
	m.showCommand = false
	m.picker.open = false
	m.status = "Running " + name
	m.generation++
	generation := m.generation
	m.res.reset(evidence.Task{})
	m.resize()
	eng, events := m.engine, m.events
	return func() tea.Msg {
		res, err := eng.Run(ctx, name, params, engine.RunOptions{OnStart: func(t evidence.Task) {
			select {
			case events <- started{t, generation}:
			case <-ctx.Done():
			}
		}})
		cancel()
		return done{res, err, generation}
	}
}

// openTask shows a persisted task's evidence without running it again.
func (m *model) openTask(t evidence.Task) tea.Cmd {
	m.picker.open = false
	m.showCommand = false
	m.caps.selectName(t.Plugin)
	m.res.reset(t)
	m.resize()
	m.status = fmt.Sprintf("%s · %s · %d rows", t.Plugin, t.State, t.Rows)
	return m.query()
}
func (m *model) quit() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	return tea.Quit
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = x.Width, x.Height
		m.resize()
		return m, nil
	case historyMsg:
		m.prompt.history = append([]string(x), m.prompt.history...)
		m.prompt.pos = len(m.prompt.history)
		return m, nil
	case started:
		if x.generation != m.generation || !m.running {
			return m, m.waitEvent()
		}
		m.res.task = x.task
		m.status = "Running " + x.task.Plugin
		return m, tea.Batch(m.query(), m.waitEvent())
	case done:
		if x.generation != m.generation {
			return m, nil
		}
		m.running = false
		m.cancel = nil
		m.res.task = x.result.Task
		m.status = fmt.Sprintf("%s · %d rows · cached %t", m.res.task.State, m.res.task.Rows, x.result.Reused)
		if x.err != nil {
			m.status = x.err.Error()
		}
		return m, m.query()
	case tick:
		if m.running && m.res.task.ID != "" {
			return m, tea.Batch(pulse(), m.query())
		}
		return m, pulse()
	case pageMsg:
		if !m.res.accepts(x) {
			return m, nil
		}
		if x.err != nil {
			m.status = x.err.Error()
			return m, nil
		}
		m.res.setRows(x.rows)
		m.refreshDetail()
		return m, nil
	case commandMsg:
		m.commandRunning = false
		m.commandView = x.text
		m.showCommand = true
		if x.err != nil {
			m.status = x.err.Error()
		} else {
			m.status = "Command complete · " + m.explorer.Layer.Name()
		}
		m.refreshDetail()
		return m, nil
	case tasksMsg:
		if x.err != nil {
			m.status = x.err.Error()
			return m, nil
		}
		m.picker.show(x.tasks)
		return m, nil
	case tea.KeyPressMsg:
		if next, cmd, ok := m.key(x); ok {
			return next, cmd
		}
	}
	// Details scroll independently with mouse wheel and ctrl+arrows.
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(msg)
	return m, cmd
}

// key handles a key press; ok is false when the detail viewport should get it.
func (m model) key(msg tea.KeyPressMsg) (model, tea.Cmd, bool) {
	if key.Matches(msg, keys.ForceQuit) {
		return m, m.quit(), true
	}
	if m.prompt.active() {
		next, cmd := m.promptKey(msg)
		return next, cmd, true
	}
	if m.showHelp {
		if key.Matches(msg, keys.Help, keys.Back, keys.Quit) {
			m.showHelp = false
		}
		return m, nil, true
	}
	if m.picker.open {
		next, cmd := m.pickerKey(msg)
		return next, cmd, true
	}
	switch {
	case key.Matches(msg, keys.Quit):
		return m, m.quit(), true
	case key.Matches(msg, keys.Cancel):
		if m.cancel != nil {
			m.cancel()
			m.status = "Canceling; partial evidence will be retained"
		}
		return m, nil, true
	case key.Matches(msg, keys.ScrollUp):
		m.detail.ScrollUp(3)
		return m, nil, true
	case key.Matches(msg, keys.ScrollDown):
		m.detail.ScrollDown(3)
		return m, nil, true
	case key.Matches(msg, keys.ScrollLeft):
		m.detail.ScrollLeft(4)
		return m, nil, true
	case key.Matches(msg, keys.ScrollRight):
		m.detail.ScrollRight(4)
		return m, nil, true
	case key.Matches(msg, keys.Help):
		m.showHelp = true
		return m, nil, true
	case key.Matches(msg, keys.Focus):
		if m.focus == focusNav {
			m.focus = focusResults
			m.res.grid.Focus()
		} else {
			m.focus = focusNav
			m.res.grid.Blur()
		}
		return m, nil, true
	case key.Matches(msg, keys.Command):
		return m, m.prompt.open(promptCommand, "run linux.pslist · hex 0x1000 · use kernel · help  (↑/↓ history)", ""), true
	case key.Matches(msg, keys.Filter):
		if m.focus == focusNav {
			return m, m.prompt.open(promptSearch, "Search capabilities", m.caps.query), true
		}
		return m, m.prompt.open(promptFilter, "Filter current task", m.res.filter), true
	case key.Matches(msg, keys.Tasks):
		if m.running || m.commandRunning {
			m.status = "Wait for the running task or cancel with ctrl+x"
			return m, nil, true
		}
		return m, m.loadTasks(), true
	case key.Matches(msg, keys.Back):
		if m.expanded {
			m.expanded = false
			m.resize()
		} else if m.caps.query != "" {
			m.caps.setQuery("")
			m.resize()
		}
		return m, nil, true
	case key.Matches(msg, keys.Next):
		if len(m.res.rows) == pageSize {
			m.res.offset += pageSize
			return m, m.query(), true
		}
		return m, nil, true
	case key.Matches(msg, keys.Prev):
		m.res.offset = max(0, m.res.offset-pageSize)
		return m, m.query(), true
	case key.Matches(msg, keys.Reverse):
		m.res.desc = !m.res.desc
		m.res.offset = 0
		m.resize()
		return m, m.query(), true
	case key.Matches(msg, keys.Sort):
		m.res.cycleSort()
		m.resize()
		m.status = "Insertion order"
		if m.res.sort != "" {
			m.status = "Sorted by " + render.Safe(m.res.sort)
		}
		return m, m.query(), true
	case key.Matches(msg, keys.ColLeft, keys.ColRight):
		delta := -1
		if key.Matches(msg, keys.ColRight) {
			delta = 1
		}
		if m.res.shift(delta) {
			m.resize()
		}
		return m, nil, true
	case key.Matches(msg, keys.Bookmark):
		if row, ok := m.res.current(); ok {
			if err := m.engine.Store.Bookmark(m.ctx, row.ID, "TUI bookmark"); err != nil {
				m.status = err.Error()
			} else {
				m.status = "Evidence bookmarked"
			}
		}
		return m, nil, true
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
			m.status = "Selected row has no " + what
			return m, nil, true
		}
		m.status = "Copied " + what + " " + render.Safe(text)
		return m, tea.SetClipboard(text), true
	case key.Matches(msg, keys.Hex):
		if m.commandRunning {
			m.status = "Wait for the exploration command to finish"
			return m, nil, true
		}
		row, ok := m.res.current()
		if !ok {
			return m, nil, false
		}
		if row.Provenance.Offset == "" {
			m.status = "Selected row has no address"
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
	if m.focus == focusNav {
		switch {
		case key.Matches(msg, keys.Run):
			if m.caps.position() < 0 {
				m.status = "No capability matches the search"
				return m, nil, true
			}
			return m, m.start(m.caps.spec().Name, nil), true
		case key.Matches(msg, keys.Up, keys.Down):
			delta := -1
			if key.Matches(msg, keys.Down) {
				delta = 1
			}
			m.caps.move(delta)
			m.resize()
			return m, nil, true
		}
		return m, nil, false
	}
	if key.Matches(msg, keys.Expand) {
		m.expanded = !m.expanded
		m.resize()
		return m, nil, true
	}
	var cmd tea.Cmd
	m.res.grid, cmd = m.res.grid.Update(msg)
	m.showCommand = false
	m.refreshDetail()
	return m, cmd, true
}

func (m model) promptKey(msg tea.KeyPressMsg) (model, tea.Cmd) {
	mode := m.prompt.mode
	switch {
	case key.Matches(msg, keys.Back):
		if mode == promptSearch {
			m.caps.setQuery("")
			m.resize()
		}
		m.prompt.close()
		return m, nil
	case key.Matches(msg, keys.Run):
		line := m.prompt.input.Value()
		m.prompt.close()
		switch mode {
		case promptSearch:
			m.caps.setQuery(line)
			m.resize()
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
		m.resize()
	}
	return m, cmd
}

// execute runs a command line: run and quit are handled here, the rest by explore.
func (m model) execute(line string) (model, tea.Cmd) {
	args, err := explore.Split(line)
	if err != nil {
		m.status = err.Error()
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
			m.status = err.Error()
			return m, nil
		}
		if !m.caps.selectName(name) {
			m.status = "Plugin is not implemented"
			return m, nil
		}
		// explore records its own commands; run never reaches it.
		if err := m.engine.Store.History(m.ctx, line); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.resize()
		return m, m.start(name, params)
	}
	if m.running || m.commandRunning {
		m.status = "Wait for the running task or cancel with ctrl+x"
		return m, nil
	}
	session := m.explorer
	ctx := m.ctx
	m.commandRunning = true
	return m, func() tea.Msg {
		var text strings.Builder
		err := session.Execute(ctx, line, &limitedWriter{w: &text, remaining: 65536})
		return commandMsg{text.String(), err}
	}
}

func (m model) pickerKey(msg tea.KeyPressMsg) (model, tea.Cmd) {
	_, _, _, height := m.sizes()
	switch {
	case key.Matches(msg, keys.Back, keys.Tasks):
		m.picker.open = false
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

func (m model) View() tea.View {
	if m.width < minWidth || m.height < minHeight {
		v := tea.NewView(fmt.Sprintf("GoMem needs at least %d columns × %d rows. Resize the terminal, or q to quit.", minWidth, minHeight))
		v.AltScreen = true
		return v
	}
	header := strong.Render(" GoMem ") + muted.Render(version.Version+"  /  "+m.engine.Format+"  /  "+m.engine.Hash[:16]+"…  /  development preview")
	header = ansi.Truncate(header, m.width, "…")
	left, middle, right, height := m.sizes()
	var body string
	switch {
	case m.showHelp:
		body = panel(accent.Render("KEYS")+"\n"+m.help.FullHelpView(keys.FullHelp()), m.width, height, true)
	case m.expanded:
		body = panel(accent.Render("DETAIL / EVIDENCE")+muted.Render("  esc or enter to restore")+"\n\n"+m.detail.View(), m.width, height, true)
	default:
		center := m.res.View()
		if m.picker.open {
			center = m.picker.View(middle-4, height-4)
		}
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			panel(m.caps.View(left-4), left, height, m.focus == focusNav),
			panel(center, middle, height, m.focus == focusResults || m.picker.open),
			panel(accent.Render("DETAIL / EVIDENCE")+"\n\n"+m.detail.View(), right, height, false))
	}
	footer := muted.Render(ansi.Truncate(render.Safe(m.status), m.width, "…"))
	if m.prompt.active() {
		footer = m.prompt.input.View()
	}
	hints := keys.navHelp()
	if m.focus == focusResults {
		hints = keys.resultHelp()
	}
	// ShortHelpView can overrun its width when the ellipsis does not fit.
	content := header + "\n" + body + "\n" + footer + "\n" + ansi.Truncate(m.help.ShortHelpView(hints), m.width, "…")
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "GoMem — Memory investigation"
	return v
}
