package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
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

const pageSize = 100

type tick time.Time
type started struct {
	task       evidence.Task
	generation uint64
}
type done struct {
	result     engine.Result
	err        error
	generation uint64
}
type pageMsg struct {
	task   string
	offset int
	filter string
	desc   bool
	rows   []evidence.Row
	err    error
}
type commandMsg struct {
	text string
	err  error
}
type model struct {
	ctx            context.Context
	engine         *engine.Engine
	explorer       *explore.Session
	specs          []plugin.Spec
	selected       int
	nav            bool
	width, height  int
	grid           table.Model
	detail         viewport.Model
	input          textinput.Model
	mode           string
	filter         string
	desc           bool
	rows           []evidence.Row
	task           evidence.Task
	offset         int
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
	input := textinput.New()
	input.CharLimit = 4096
	input.Prompt = "› "
	input.SetWidth(70)
	m := model{ctx: ctx, engine: e, explorer: explore.New(e), specs: e.Registry.List(), nav: true, width: 120, height: 30, input: input, events: make(chan tea.Msg, 4), status: "Select a capability and press enter. Results are persisted and paged."}
	m.grid = table.New(table.WithFocused(false), table.WithHeight(18))
	m.detail = viewport.New()
	m.resize()
	return m
}
func (m model) Init() tea.Cmd { return tea.Batch(m.waitEvent(), pulse()) }
func pulse() tea.Cmd {
	return tea.Tick(300*time.Millisecond, func(t time.Time) tea.Msg { return tick(t) })
}
func (m model) waitEvent() tea.Cmd {
	return func() tea.Msg {
		select {
		case event := <-m.events:
			return event
		case <-m.ctx.Done():
			return tea.Quit()
		}
	}
}
func (m model) query() tea.Cmd {
	q := evidence.Query{TaskID: m.task.ID, Offset: m.offset, Limit: pageSize, Filter: m.filter, Desc: m.desc}
	return func() tea.Msg {
		rows, err := m.engine.Store.Query(m.ctx, q)
		return pageMsg{q.TaskID, q.Offset, q.Filter, q.Desc, rows, err}
	}
}
func (m *model) resize() {
	_, right, middle := m.sizes()
	cols := []table.Column{}
	spec := m.specs[m.selected]
	if m.task.ID != "" {
		if p, err := m.engine.Registry.Get(m.task.Plugin); err == nil {
			spec = p.Spec()
		}
	}
	visible := spec.Columns[:min(4, len(spec.Columns))]
	budget := middle - 2*len(visible)
	total := 0
	for _, c := range visible {
		w := 6
		if c.Kind == "address" {
			w = 10
		}
		if c.Kind == "string" {
			w = 18
		}
		cols = append(cols, table.Column{Title: c.Name, Width: w})
		total += w
	}
	for total > budget {
		largest := 0
		for i := range cols {
			if cols[i].Width > cols[largest].Width {
				largest = i
			}
		}
		if cols[largest].Width <= 3 {
			break
		}
		cols[largest].Width--
		total--
	}
	if total < budget && len(cols) > 0 {
		target := len(cols) - 1
		for i, c := range visible {
			if c.Kind == "string" {
				target = i
				break
			}
		}
		cols[target].Width += budget - total
	}
	m.grid.SetColumns(cols)
	m.grid.SetWidth(middle)
	m.grid.SetHeight(max(4, m.height-11))
	m.detail.SetWidth(right - 4)
	m.detail.SetHeight(max(4, m.height-12))
	m.input.SetWidth(max(20, m.width-8))
	m.updateDetail()
}
func (m model) sizes() (left, right, middle int) {
	left = 24
	right = min(38, max(22, m.width/3))
	middle = max(20, m.width-(left+2)-(right+2)-4)
	return
}
func (m *model) updateDetail() {
	if m.showCommand {
		lines := strings.Split(m.commandView, "\n")
		for i := range lines {
			lines[i] = render.Safe(lines[i])
		}
		m.detail.SetContent(strings.Join(lines, "\n"))
		return
	}
	idx := m.grid.Cursor()
	if idx >= 0 && idx < len(m.rows) {
		b, err := json.MarshalIndent(m.rows[idx], "", "  ")
		if err != nil {
			m.detail.SetContent(err.Error())
		} else {
			m.detail.SetContent(string(b))
		}
	} else {
		spec := m.specs[m.selected]
		b, _ := json.MarshalIndent(spec, "", "  ")
		m.detail.SetContent(string(b))
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
	m.status = "Running " + name
	m.offset = 0
	m.filter = ""
	m.generation++
	generation := m.generation
	m.task = evidence.Task{}
	m.rows = nil
	m.grid.SetRows(nil)
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
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = x.Width, x.Height
		m.resize()
		return m, nil
	case started:
		if x.generation != m.generation || !m.running {
			return m, m.waitEvent()
		}
		m.task = x.task
		m.status = "Running " + x.task.Plugin
		return m, tea.Batch(m.query(), m.waitEvent())
	case done:
		if x.generation != m.generation {
			return m, nil
		}
		m.running = false
		m.cancel = nil
		m.task = x.result.Task
		m.status = fmt.Sprintf("%s · %d rows · cached %t", m.task.State, m.task.Rows, x.result.Reused)
		if x.err != nil {
			m.status = x.err.Error()
		}
		return m, m.query()
	case tick:
		if m.running && m.task.ID != "" {
			return m, tea.Batch(pulse(), m.query())
		}
		return m, pulse()
	case pageMsg:
		if x.task != m.task.ID || x.offset != m.offset || x.filter != m.filter || x.desc != m.desc {
			return m, nil
		}
		if x.err != nil {
			m.status = x.err.Error()
			return m, nil
		}
		m.rows = x.rows
		rows := make([]table.Row, 0, len(x.rows))
		cols := m.grid.Columns()
		for _, r := range x.rows {
			cells := make(table.Row, len(cols))
			for i, c := range cols {
				v, ok := r.Cells[c.Title]
				if !ok {
					v = evidence.Missing("column_absent", nil)
				}
				cells[i] = render.Safe(v.String())
			}
			rows = append(rows, cells)
		}
		m.grid.SetRows(rows)
		if len(rows) > 0 && (m.grid.Cursor() < 0 || m.grid.Cursor() >= len(rows)) {
			m.grid.SetCursor(0)
		}
		m.updateDetail()
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
		m.updateDetail()
		return m, nil
	case tea.KeyPressMsg:
		key := x.String()
		if key == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		if m.mode != "" {
			switch key {
			case "esc":
				m.mode = ""
				m.input.Blur()
				return m, nil
			case "enter":
				line := m.input.Value()
				mode := m.mode
				m.mode = ""
				m.input.Blur()
				if mode == "filter" {
					m.filter = line
					m.offset = 0
					return m, m.query()
				}
				args, err := explore.Split(line)
				if err != nil {
					m.status = err.Error()
					return m, nil
				}
				if len(args) == 0 {
					return m, nil
				}
				if args[0] == "quit" {
					if m.cancel != nil {
						m.cancel()
					}
					return m, tea.Quit
				}
				if args[0] == "run" && len(args) > 1 {
					p := map[string]string{}
					for _, v := range args[2:] {
						k, val, ok := strings.Cut(v, "=")
						if !ok {
							m.status = "Parameters use key=value"
							return m, nil
						}
						p[k] = val
					}
					found := false
					for i, s := range m.specs {
						if s.Name == args[1] {
							m.selected = i
							found = true
							m.resize()
							break
						}
					}
					if !found {
						m.status = "Plugin is not implemented"
						return m, nil
					}
					return m, m.start(args[1], p)
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
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
		switch key {
		case "q":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "ctrl+x":
			if m.cancel != nil {
				m.cancel()
				m.status = "Canceling; partial evidence will be retained"
			}
			return m, nil
		case "ctrl+up":
			m.detail.ScrollUp(3)
			return m, nil
		case "ctrl+down":
			m.detail.ScrollDown(3)
			return m, nil
		case "ctrl+left":
			m.detail.ScrollLeft(4)
			return m, nil
		case "ctrl+right":
			m.detail.ScrollRight(4)
			return m, nil
		case "tab":
			m.nav = !m.nav
			if m.nav {
				m.grid.Blur()
			} else {
				m.grid.Focus()
			}
			return m, nil
		case "/", ":":
			if key == "/" {
				m.mode = "filter"
				m.input.Placeholder = "Filter current task"
			} else {
				m.mode = "command"
				m.input.Placeholder = "run linux.pslist · hex 0x1000 · use kernel · help"
			}
			m.input.SetValue("")
			return m, m.input.Focus()
		case "enter":
			if m.nav {
				return m, m.start(m.specs[m.selected].Name, nil)
			}
		case "up", "k":
			if m.nav {
				m.selected = max(0, m.selected-1)
				m.resize()
				return m, nil
			}
		case "down", "j":
			if m.nav {
				m.selected = min(len(m.specs)-1, m.selected+1)
				m.resize()
				return m, nil
			}
		case "n", "pgdown":
			if len(m.rows) == pageSize {
				m.offset += pageSize
				return m, m.query()
			}
			return m, nil
		case "p", "pgup":
			m.offset = max(0, m.offset-pageSize)
			return m, m.query()
		case "s":
			m.desc = !m.desc
			m.offset = 0
			return m, m.query()
		case "b":
			idx := m.grid.Cursor()
			if idx >= 0 && idx < len(m.rows) {
				if err := m.engine.Store.Bookmark(m.ctx, m.rows[idx].ID, "TUI bookmark"); err != nil {
					m.status = err.Error()
				} else {
					m.status = "Evidence bookmarked"
				}
			}
			return m, nil
		case "h":
			if m.commandRunning {
				m.status = "Wait for the exploration command to finish"
				return m, nil
			}
			idx := m.grid.Cursor()
			if idx >= 0 && idx < len(m.rows) {
				offset := m.rows[idx].Provenance.Offset
				if offset == "" {
					m.status = "Selected row has no address"
					return m, nil
				}
				layer := m.rows[idx].Provenance.Layer
				if m.engine.Env.Kernel != nil && layer == m.engine.Env.Kernel.Name() {
					m.explorer.Layer = m.engine.Env.Kernel
				} else if layer == m.engine.Env.Physical.Name() {
					m.explorer.Layer = m.engine.Env.Physical
				}
				m.mode = "command"
				m.input.SetValue("hex " + offset + " 256")
				return m, m.input.Focus()
			}
		}
		if !m.nav {
			var cmd tea.Cmd
			m.grid, cmd = m.grid.Update(msg)
			m.showCommand = false
			m.updateDetail()
			return m, cmd
		}
	}
	// Details scroll independently with mouse wheel and ctrl+up/down.
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(msg)
	return m, cmd
}

type limitedWriter struct {
	w         *strings.Builder
	remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, fmt.Errorf("TUI command output exceeds 64 KiB; use CLI for full output")
	}
	w.remaining -= len(p)
	return w.w.Write(p)
}
func (m model) View() tea.View {
	if m.width < 85 || m.height < 18 {
		v := tea.NewView("GoMem needs at least 85 columns × 18 rows. Resize the terminal, or q to quit.")
		v.AltScreen = true
		return v
	}
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color("#52D6BE"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#8C9DAE"))
	header := accent.Bold(true).Render(" GoMem ") + muted.Render(version.Version+"  /  "+m.engine.Format+"  /  "+m.engine.Hash[:16]+"…")
	var nav strings.Builder
	nav.WriteString(accent.Render("CAPABILITIES") + "\n\n")
	for i, s := range m.specs {
		prefix := "  "
		style := muted
		if i == m.selected {
			prefix = "› "
			style = accent.Bold(true)
		}
		nav.WriteString(style.Render(prefix+s.Name) + "\n")
	}
	nav.WriteString("\n" + muted.Render("enter  run\ntab    focus\n:      commands\n/      filter\nn / p  pages\ns      reverse\nb      bookmark\nh      hex jump\nctrl+x cancel\nq      quit"))
	panel := func(text string, width int, active bool) string {
		color := "#304657"
		if active {
			color = "#52D6BE"
		}
		return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(color)).Padding(0, 1).Width(width).Height(max(8, m.height-7)).MaxHeight(m.height - 5).Render(text)
	}
	leftWidth, rightWidth, middleWidth := m.sizes()
	left := panel(nav.String(), leftWidth, m.nav)
	middle := panel(accent.Render("RESULTS")+fmt.Sprintf("  %d–%d", m.offset, m.offset+len(m.rows))+"\n\n"+m.grid.View(), middleWidth, !m.nav)
	right := panel(accent.Render("DETAIL / EVIDENCE")+"\n\n"+m.detail.View(), rightWidth, false)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, middle, right)
	footer := muted.Render(ansi.Truncate(render.Safe(m.status), m.width, "…"))
	if m.mode != "" {
		footer = m.input.View()
	}
	content := header + "\n" + body + "\n" + footer + "\n" + muted.Render("Development preview · native capabilities only · detail pane scroll: mouse wheel")
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "GoMem — Memory investigation"
	return v
}
