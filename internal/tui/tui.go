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
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/internal/plugins"
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

// Options configures the TUI. Engine may be nil, in which case it starts in
// the image importer.
type Options struct {
	// Config is the base for images opened from the importer; only Image is
	// replaced, so symbols, DTB, case and network settings carry over.
	Config engine.Config
	Engine *engine.Engine
	// Open opens an image; nil means engine.Open. A caller can wrap it to
	// resolve or download symbols before the image is opened.
	Open func(context.Context, engine.Config) (*engine.Engine, error)
}

type model struct {
	ctx            context.Context
	engine         *engine.Engine
	base           engine.Config
	opener         func(context.Context, engine.Config) (*engine.Engine, error)
	launcher       launcher
	explorer       *explore.Session
	st             styles
	caps           capabilities
	res            results
	tabs           []results
	active         int
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

func New(ctx context.Context, o Options) tea.Model {
	if o.Open == nil {
		o.Open = engine.Open
	}
	m := model{ctx: ctx, base: o.Config, opener: o.Open, prompt: newPrompt(), help: help.New(), spin: spinner.New(spinner.WithSpinner(spinner.Dot)), width: 120, height: 30, events: make(chan tea.Msg, 4)}
	m.detail = viewport.New()
	m.launcher = newLauncher(o.Config.Image)
	if o.Engine != nil {
		m.setEngine(o.Engine)
	} else {
		m.caps = newCapabilities(registry().List(), o.Config.OS)
		m.showLauncher()
	}
	m.setTheme(true)
	return m
}

// registry lists capabilities before any image is open.
func registry() *plugin.Registry {
	r := plugin.NewRegistry()
	if err := plugins.Register(r); err != nil {
		panic(err)
	}
	return r
}

// Close releases the engine a finished TUI holds; the TUI may have switched
// images, so this is not necessarily the engine it started with.
func Close(final tea.Model) error {
	if m, ok := final.(model); ok && m.engine != nil {
		return m.engine.Close()
	}
	return nil
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.waitEvent(), pulse(), m.loadHistory(), tea.RequestBackgroundColor)
}

// setEngine makes eng the investigated image and resets everything derived
// from the previous one.
func (m *model) setEngine(eng *engine.Engine) {
	m.engine = eng
	m.explorer = explore.New(eng)
	m.caps = newCapabilities(eng.Registry.List(), eng.Env.OS)
	m.res, m.tabs, m.active = results{}, nil, 0
	m.picker = taskPicker{}
	m.form = paramForm{}
	m.showCommand, m.expanded = false, false
	m.prompt.history = nil
	m.launcher.open = false
	m.focus = focusNav
	m.detailAt = ""
	m.say(levelInfo, "Select a capability and press enter. Results are persisted and paged. i imports another image · ? for help.")
	m.layout()
}

// showLauncher opens the importer with a fresh directory listing and the
// case's image history.
func (m *model) showLauncher() {
	m.launcher.open = true
	m.launcher.err = ""
	m.launcher.chdir(m.launcher.dir)
	m.launcher.setRecent(recentImages(m.ctx, m.engine, m.base.CaseDir))
	m.launcher.section = sectionPath
	m.launcher.path.Focus()
}

// openImage closes the current image, opens path in its place and, if that
// fails, reopens the previous image so the case stays usable.
func (m *model) openImage(path string) tea.Cmd {
	path = strings.TrimSpace(expandHome(path))
	if path == "" {
		m.launcher.err = "Enter the path of a memory image"
		return nil
	}
	if m.running || m.commandRunning {
		m.launcher.err = "Wait for the running task or cancel it with ctrl+x first"
		return nil
	}
	cfg := m.base
	cfg.Image = path
	ctx, cancel := context.WithCancel(m.ctx)
	m.launcher.opening, m.launcher.cancel = true, cancel
	m.launcher.target, m.launcher.started, m.launcher.err = path, time.Now(), ""
	prev, open, life := m.engine, m.opener, m.ctx
	run := func() tea.Msg {
		defer cancel()
		var prevCfg engine.Config
		if prev != nil {
			prevCfg = prev.Config
			// The case lock must be released before the case is opened again.
			if err := prev.Close(); err != nil {
				return openedMsg{err: err}
			}
		}
		eng, err := open(ctx, cfg)
		if err == nil {
			return openedMsg{eng: eng}
		}
		msg := openedMsg{err: err}
		if prev != nil {
			msg.eng, msg.restoreErr = open(life, prevCfg)
			msg.restored = msg.restoreErr == nil
		}
		return msg
	}
	return tea.Batch(run, m.spin.Tick)
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
	if m.engine == nil {
		return nil
	}
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
	id := m.runningTask()
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
	if m.engine != nil && m.res.task.ID != "" {
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
	m.caps.setHeight(height - 5)
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
	m.openTab()
	m.res.reset(evidence.Task{})
	m.res.gen = generation
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

const maxTabs = 9

// stash saves the live tab into its slot.
func (m *model) stash() {
	if len(m.tabs) == 0 {
		m.tabs, m.active = []results{m.res}, 0
	}
	m.tabs[m.active] = m.res
}

// openTab makes room for new evidence: an empty current tab is reused,
// otherwise a tab is added, dropping the oldest idle tab at the limit.
func (m *model) openTab() {
	m.stash()
	if m.res.task.ID == "" && m.res.gen == 0 {
		return
	}
	if len(m.tabs) >= maxTabs {
		for i, t := range m.tabs {
			if !(m.running && t.gen == m.generation) {
				m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)
				break
			}
		}
	}
	m.tabs = append(m.tabs, results{})
	m.active = len(m.tabs) - 1
	m.res = results{}
}

// selectTab shows tab i and refreshes its page.
func (m *model) selectTab(i int) tea.Cmd {
	if i < 0 || i >= len(m.tabs) || i == m.active {
		return nil
	}
	m.stash()
	m.active = i
	m.res = m.tabs[i]
	m.res.layoutAt = ""
	m.showCommand = false
	m.layout()
	if m.res.task.ID == "" {
		return nil
	}
	return m.query()
}

// closeTab removes the current tab unless its task is still running.
func (m *model) closeTab() tea.Cmd {
	if m.running && m.res.gen == m.generation {
		m.say(levelWarn, "Cancel the running task with ctrl+x before closing its tab")
		return nil
	}
	m.stash()
	if len(m.tabs) <= 1 {
		m.res, m.tabs, m.active = results{}, nil, 0
		m.layout()
		return nil
	}
	m.tabs = append(m.tabs[:m.active], m.tabs[m.active+1:]...)
	m.active = min(m.active, len(m.tabs)-1)
	m.res = m.tabs[m.active]
	m.res.layoutAt = ""
	m.layout()
	if m.res.task.ID == "" {
		return nil
	}
	return m.query()
}

// tabFor finds the tab a run fills, live or stashed.
func (m *model) tabFor(gen uint64) *results {
	if m.res.gen == gen {
		return &m.res
	}
	for i := range m.tabs {
		if i != m.active && m.tabs[i].gen == gen {
			return &m.tabs[i]
		}
	}
	return nil
}

// runningTask is the ID of the running task, wherever its tab is.
func (m *model) runningTask() string {
	if t := m.tabFor(m.generation); m.running && t != nil {
		return t.task.ID
	}
	return ""
}

// tabBar labels each tab with its number and plugin, without the platform.
func (m model) tabBar(width int) string {
	if len(m.tabs) <= 1 {
		return ""
	}
	parts := make([]string, len(m.tabs))
	for i, t := range m.tabs {
		if i == m.active {
			t = m.res
		}
		name := t.task.Plugin
		if _, rest, ok := strings.Cut(name, "."); ok {
			name = rest
		}
		if name == "" {
			name = "…"
		}
		label := fmt.Sprintf("%d %s", i+1, render.Safe(name))
		if m.running && t.gen == m.generation {
			label += "*"
		}
		if i == m.active {
			parts[i] = m.st.selected.Render(label)
		} else {
			parts[i] = m.st.muted.Render(label)
		}
	}
	return ansi.Truncate(strings.Join(parts, " "), width, "…")
}

// tabAt returns the tab whose label covers column x of the tab bar.
func (m model) tabAt(x int) int {
	for i, t := range m.tabs {
		if i == m.active {
			t = m.res
		}
		name := t.task.Plugin
		if _, rest, ok := strings.Cut(name, "."); ok {
			name = rest
		}
		if name == "" {
			name = "…"
		}
		w := ansi.StringWidth(fmt.Sprintf("%d %s", i+1, render.Safe(name)))
		if m.running && t.gen == m.generation {
			w++
		}
		if x < w {
			return i
		}
		x -= w + 1
	}
	return -1
}

// openTask shows a persisted task's evidence without running it again.
func (m *model) openTask(t evidence.Task) tea.Cmd {
	m.picker.open = false
	m.showCommand = false
	m.caps.selectName(t.Plugin)
	m.openTab()
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
	case openedMsg:
		m.launcher.opening, m.launcher.cancel = false, nil
		if x.eng == nil {
			m.engine = nil
			m.showLauncher()
		} else {
			m.setEngine(x.eng)
		}
		if x.err != nil {
			m.showLauncher()
			m.launcher.err = "Cannot open " + m.launcher.target + ": " + x.err.Error()
			switch {
			case x.restored:
				m.launcher.err += " · the previous image is open again"
			case x.restoreErr != nil:
				m.launcher.err += " · reopening the previous image failed: " + x.restoreErr.Error()
			}
			return m, nil
		}
		m.say(levelSuccess, fmt.Sprintf("Opened %s · %s · %s", filepath.Base(x.eng.Config.Image), x.eng.Format, x.eng.Env.OS))
		return m, m.loadHistory()
	case spinner.TickMsg:
		if !m.running && !m.commandRunning && !m.launcher.opening {
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
		tab := m.tabFor(x.generation)
		if x.generation != m.generation || !m.running || tab == nil {
			return m, m.waitEvent()
		}
		tab.task = x.task
		if tab != &m.res {
			return m, m.waitEvent()
		}
		return m, tea.Batch(m.query(), m.waitEvent())
	case progressMsg:
		if m.running && x.task == m.runningTask() {
			m.progress = x.rows
		}
		return m, nil
	case done:
		if x.generation != m.generation {
			return m, nil
		}
		m.running, m.canceling = false, false
		m.cancel = nil
		tab := m.tabFor(x.generation)
		if tab != nil {
			tab.task = x.result.Task
		}
		elapsed := time.Since(m.runStarted).Round(time.Millisecond)
		switch {
		case errors.Is(x.err, context.Canceled):
			m.say(levelWarn, fmt.Sprintf("Canceled after %s · %d rows retained", elapsed, x.result.Task.Rows))
		case x.err != nil:
			m.say(levelError, x.err.Error())
		default:
			m.say(levelSuccess, fmt.Sprintf("%s %s · %d rows · %s · cached %t", x.result.Task.Plugin, x.result.Task.State, x.result.Task.Rows, elapsed, x.result.Reused))
		}
		if tab != &m.res {
			return m, nil
		}
		return m, m.query()
	case tick:
		if m.running && m.runningTask() != "" {
			cmds := []tea.Cmd{pulse(), m.countRows()}
			if m.res.gen == m.generation && !m.res.tree.on {
				cmds = append(cmds, m.query())
			}
			return m, tea.Batch(cmds...)
		}
		return m, pulse()
	case treeMsg:
		if !m.res.tree.on || x.task != m.res.task.ID {
			return m, nil
		}
		if x.err != nil {
			m.say(levelError, x.err.Error())
			return m, nil
		}
		m.res.tree.task = x.task
		m.res.tree.truncated = x.truncated
		m.res.tree.build(x.rows)
		m.res.applyTree()
		m.refreshDetail()
		switch {
		case x.truncated:
			m.say(levelWarn, fmt.Sprintf("Tree shows the first %d rows; filter or use pages for the rest", treeLimit))
		case !m.res.tree.linked:
			m.say(levelWarn, "These rows have no parent links; the tree is flat")
		default:
			m.say(levelInfo, "Tree view · →/← expand/collapse · +/- all · T pages")
		}
		return m, nil
	case pageMsg:
		if m.res.tree.on || !m.res.accepts(x) {
			return m, nil
		}
		if x.err != nil {
			m.say(levelError, x.err.Error())
			return m, nil
		}
		m.res.last = x.last
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
		m.picker.show(x.tasks, m.engine.Hash)
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
	image := "no image"
	if m.engine != nil {
		image = render.Safe(filepath.Base(m.engine.Config.Image)) + "  /  " + m.engine.Format + "  /  " + m.engine.Env.OS + "  /  " + m.engine.Hash[:16] + "…"
	}
	header := m.st.strong.Render(" GoMem ") + m.st.muted.Render(version.Version+"  /  "+image+"  /  development preview")
	header = ansi.Truncate(header, m.width, "…")
	left, middle, right, height := m.sizes()
	var body string
	switch {
	case m.launcher.open:
		body = row(m.st.panel(m.launcher.View(m.st, m.base, m.width-4, height, m.spin.View()), m.width, height, true))
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
			center = m.res.View(m.st, m.focus == focusResults, m.activity(), m.tabBar(middle-4))
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
	switch {
	case m.launcher.open:
		hints = keys.launcherHelp(m.engine != nil)
	case m.focus == focusResults:
		hints = keys.resultHelp()
	}
	// ShortHelpView can overrun its width when the ellipsis does not fit.
	v := tea.NewView(header + "\n" + body + "\n" + footer + "\n" + ansi.Truncate(m.help.ShortHelpView(hints), m.width, "…"))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "GoMem — Memory investigation"
	return v
}
