// Package tui is the asynchronous, paged investigation interface.
//
// The root model dispatches messages and composes the view; capabilities,
// results, prompt, paramForm and taskPicker own their state and rendering,
// and input.go routes key presses and clicks by what has focus.
package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
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

type level int

const (
	levelInfo level = iota
	levelSuccess
	levelWarn
	levelError
)

type model struct {
	ctx            context.Context
	engine         *engine.Engine
	explorer       *explore.Session
	st             styles
	caps           capabilities
	res            results
	detail         viewport.Model
	prompt         prompt
	picker         taskPicker
	form           paramForm
	help           help.Model
	spin           spinner.Model
	focus          focus
	showHelp       bool
	expanded       bool
	rawDetail      bool
	detailAt       string
	width, height  int
	running        bool
	canceling      bool
	runStarted     time.Time
	progress       int64
	cancel         context.CancelFunc
	events         chan tea.Msg
	status         string
	level          level
	commandView    string
	commandSeq     int
	showCommand    bool
	generation     uint64
	commandRunning bool
}

func New(ctx context.Context, e *engine.Engine) tea.Model {
	m := model{ctx: ctx, engine: e, explorer: explore.New(e), caps: newCapabilities(e.Registry.List()), prompt: newPrompt(), help: help.New(), spin: spinner.New(spinner.WithSpinner(spinner.Dot)), width: 120, height: 30, events: make(chan tea.Msg, 4)}
	m.say(levelInfo, "Select a capability and press enter. Results are persisted and paged. ? for help.")
	m.detail = viewport.New()
	m.setTheme(true)
	return m
}
func (m model) Init() tea.Cmd {
	return tea.Batch(m.waitEvent(), pulse(), m.loadHistory(), tea.RequestBackgroundColor)
}

func (m *model) say(l level, text string) { m.status, m.level = text, l }

func (m *model) setTheme(dark bool) {
	m.st = newStyles(dark)
	m.spin.Style = m.st.accent
	m.help.Styles = m.st.help
	m.detailAt = ""
	m.layout()
}

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
func (m model) countRows() tea.Cmd {
	id := m.res.task.ID
	return func() tea.Msg {
		n, err := m.engine.Store.TaskRows(m.ctx, id)
		if err != nil {
			return nil
		}
		return progressMsg{id, n}
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

// layout applies the current size and selection to every component. Each part
// skips work when its inputs did not change, so this is cheap to call per key.
func (m *model) layout() {
	_, middle, right, height := m.sizes()
	m.caps.setHeight(height - 4)
	m.res.setSpec(m.resultSpec())
	m.res.layout(middle-4, height-4)
	if m.expanded {
		right = m.width
	}
	if m.detail.Width() != right-4 || m.detail.Height() != height-4 {
		m.detail.SetWidth(right - 4)
		m.detail.SetHeight(height - 4)
		m.detailAt = ""
	}
	m.prompt.input.SetWidth(max(20, m.width-8))
	m.help.SetWidth(m.width)
	m.refreshDetail()
}

// refreshDetail sets the detail content when what it shows has changed.
func (m *model) refreshDetail() {
	row, ok := m.res.current()
	spec := m.caps.spec()
	var at string
	switch {
	case m.showCommand:
		at = fmt.Sprint("command", m.commandSeq)
	case ok:
		at = fmt.Sprint("row", row.ID, m.rawDetail)
	default:
		at = fmt.Sprint("spec", spec.Name, m.rawDetail)
	}
	if at == m.detailAt {
		return
	}
	m.detailAt = at
	switch {
	case m.showCommand:
		m.detail.SetContent(commandText(m.commandView))
	case ok && m.rawDetail:
		m.detail.SetContent(detailText(row))
	case ok:
		m.detail.SetContent(rowView(m.st, row, m.res.spec, m.detail.Width()))
	case m.rawDetail:
		m.detail.SetContent(detailText(spec))
	default:
		m.detail.SetContent(specView(m.st, spec, m.detail.Width()))
	}
	m.detail.GotoTop()
}

func (m *model) start(name string, params map[string]string) tea.Cmd {
	if m.running || m.commandRunning {
		m.say(levelWarn, "A task is running. Press ctrl+x to cancel it.")
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.running, m.canceling = true, false
	m.runStarted = time.Now()
	m.progress = 0
	m.showCommand = false
	m.picker.open = false
	m.form.open = false
	m.say(levelInfo, "Running "+name)
	m.generation++
	generation := m.generation
	m.res.reset(evidence.Task{})
	m.layout()
	eng, events := m.engine, m.events
	run := func() tea.Msg {
		res, err := eng.Run(ctx, name, params, engine.RunOptions{OnStart: func(t evidence.Task) {
			select {
			case events <- started{t, generation}:
			case <-ctx.Done():
			}
		}})
		cancel()
		return done{res, err, generation}
	}
	return tea.Batch(run, m.spin.Tick)
}

// openTask shows a persisted task's evidence without running it again.
func (m *model) openTask(t evidence.Task) tea.Cmd {
	m.picker.open = false
	m.showCommand = false
	m.caps.selectName(t.Plugin)
	m.res.reset(t)
	m.layout()
	m.say(levelInfo, fmt.Sprintf("%s · %s · %d rows", t.Plugin, t.State, t.Rows))
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
		m.layout()
		return m, nil
	case tea.BackgroundColorMsg:
		m.setTheme(x.IsDark())
		return m, nil
	case spinner.TickMsg:
		if !m.running && !m.commandRunning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(x)
		return m, cmd
	case historyMsg:
		m.prompt.history = append([]string(x), m.prompt.history...)
		m.prompt.pos = len(m.prompt.history)
		return m, nil
	case started:
		if x.generation != m.generation || !m.running {
			return m, m.waitEvent()
		}
		m.res.task = x.task
		return m, tea.Batch(m.query(), m.waitEvent())
	case progressMsg:
		if m.running && x.task == m.res.task.ID {
			m.progress = x.rows
		}
		return m, nil
	case done:
		if x.generation != m.generation {
			return m, nil
		}
		m.running, m.canceling = false, false
		m.cancel = nil
		m.res.task = x.result.Task
		elapsed := time.Since(m.runStarted).Round(time.Millisecond)
		switch {
		case errors.Is(x.err, context.Canceled):
			m.say(levelWarn, fmt.Sprintf("Canceled after %s · %d rows retained", elapsed, m.res.task.Rows))
		case x.err != nil:
			m.say(levelError, x.err.Error())
		default:
			m.say(levelSuccess, fmt.Sprintf("%s · %d rows · %s · cached %t", m.res.task.State, m.res.task.Rows, elapsed, x.result.Reused))
		}
		return m, m.query()
	case tick:
		if m.running && m.res.task.ID != "" {
			return m, tea.Batch(pulse(), m.query(), m.countRows())
		}
		return m, pulse()
	case pageMsg:
		if !m.res.accepts(x) {
			return m, nil
		}
		if x.err != nil {
			m.say(levelError, x.err.Error())
			return m, nil
		}
		m.res.setRows(x.rows)
		m.refreshDetail()
		return m, nil
	case commandMsg:
		m.commandRunning = false
		m.commandView = x.text
		m.commandSeq++
		m.showCommand = true
		if x.err != nil {
			m.say(levelError, x.err.Error())
		} else {
			m.say(levelSuccess, "Command complete · "+m.explorer.Layer.Name())
		}
		m.refreshDetail()
		return m, nil
	case tasksMsg:
		if x.err != nil {
			m.say(levelError, x.err.Error())
			return m, nil
		}
		m.picker.show(x.tasks)
		return m, nil
	case tea.KeyPressMsg:
		if next, cmd, ok := m.key(x); ok {
			return next, cmd
		}
	case tea.MouseClickMsg:
		if next, cmd, ok := m.click(x.Mouse()); ok {
			return next, cmd
		}
	case tea.MouseWheelMsg:
		if next, cmd, ok := m.wheel(x.Mouse()); ok {
			return next, cmd
		}
	}
	// Details scroll independently with mouse wheel and ctrl+arrows.
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(msg)
	return m, cmd
}

// activity describes a running task or command, or is empty when idle.
func (m model) activity() string {
	switch {
	case m.canceling:
		return m.spin.View() + " " + m.st.warn.Render("canceling…")
	case m.running:
		return m.spin.View() + " " + m.st.muted.Render(fmt.Sprintf("%d rows · %s", m.progress, time.Since(m.runStarted).Round(time.Second)))
	case m.commandRunning:
		return m.spin.View() + " " + m.st.muted.Render("command")
	}
	return ""
}

func (m model) statusLine() string {
	text := render.Safe(m.status)
	switch m.level {
	case levelSuccess:
		text = m.st.success.Render(text)
	case levelWarn:
		text = m.st.warn.Render(text)
	case levelError:
		text = m.st.err.Render(text)
	default:
		text = m.st.muted.Render(text)
	}
	if a := m.activity(); a != "" {
		text = a + "  " + text
	}
	return ansi.Truncate(text, m.width, "…")
}

func (m model) View() tea.View {
	if m.width < minWidth || m.height < minHeight {
		v := tea.NewView(fmt.Sprintf("GoMem needs at least %d columns × %d rows. Resize the terminal, or q to quit.", minWidth, minHeight))
		v.AltScreen = true
		return v
	}
	header := m.st.strong.Render(" GoMem ") + m.st.muted.Render(version.Version+"  /  "+m.engine.Format+"  /  "+m.engine.Hash[:16]+"…  /  development preview")
	header = ansi.Truncate(header, m.width, "…")
	left, middle, right, height := m.sizes()
	var body string
	switch {
	case m.showHelp:
		body = row(m.st.panel(m.st.accent.Render("KEYS")+"\n"+m.help.FullHelpView(keys.FullHelp()), m.width, height, true))
	case m.expanded:
		body = row(m.st.panel(m.st.accent.Render("DETAIL / EVIDENCE")+m.st.muted.Render("  esc or enter to restore · r raw")+"\n\n"+m.detail.View(), m.width, height, true))
	default:
		var center string
		switch {
		case m.form.open:
			center = m.form.View(m.st, middle-4, height-2)
		case m.picker.open:
			center = m.picker.View(m.st, middle-4, height-4)
		default:
			center = m.res.View(m.st, m.focus == focusResults, m.activity())
		}
		body = row(
			m.st.panel(m.caps.View(m.st, left-4), left, height, m.focus == focusNav && !m.form.open),
			m.st.panel(center, middle, height, m.focus == focusResults || m.picker.open || m.form.open),
			m.st.panel(m.st.accent.Render("DETAIL / EVIDENCE")+"\n\n"+m.detail.View(), right, height, false))
	}
	footer := m.statusLine()
	if m.prompt.active() {
		footer = m.prompt.input.View()
	}
	hints := keys.navHelp()
	if m.focus == focusResults {
		hints = keys.resultHelp()
	}
	// ShortHelpView can overrun its width when the ellipsis does not fit.
	v := tea.NewView(header + "\n" + body + "\n" + footer + "\n" + ansi.Truncate(m.help.ShortHelpView(hints), m.width, "…"))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "GoMem — Memory investigation"
	return v
}
