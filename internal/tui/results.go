package tui

import (
	"context"
	"fmt"
	"strconv"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const (
	pageSize       = 100
	visibleColumns = 4
)

// results owns the paged evidence of one task and the window of columns shown.
type results struct {
	grid     table.Model
	spec     plugin.Spec
	visible  []evidence.Column
	colStart int
	rows     []evidence.Row
	task     evidence.Task
	offset   int
	filter   string
	desc     bool
	sort     string
	width    int
}

func newResults() results {
	return results{grid: table.New(table.WithFocused(false), table.WithHeight(18))}
}

// setSpec switches the column source, resetting column window and sort for a new plugin.
func (r *results) setSpec(spec plugin.Spec) {
	if spec.Name != r.spec.Name {
		r.colStart = 0
		r.sort = ""
	}
	r.spec = spec
}

// reset clears paging state before a new task is shown.
func (r *results) reset(task evidence.Task) {
	r.task = task
	r.offset = 0
	r.filter = ""
	r.rows = nil
	r.grid.SetRows(nil)
}

func (r *results) layout(width, height int) {
	r.width = width
	cols := r.spec.Columns
	r.colStart = max(0, min(r.colStart, len(cols)-visibleColumns))
	r.visible = cols[r.colStart:min(r.colStart+visibleColumns, len(cols))]
	budget := width - 2*len(r.visible)
	total := 0
	out := make([]table.Column, 0, len(r.visible))
	for _, c := range r.visible {
		w := 6
		if c.Kind == "address" {
			w = 10
		}
		if c.Kind == "string" {
			w = 18
		}
		title := c.Name
		if c.Name == r.sort {
			title += map[bool]string{false: " ▲", true: " ▼"}[r.desc]
		}
		out = append(out, table.Column{Title: render.Safe(title), Width: w})
		total += w
	}
	for total > budget {
		largest := 0
		for i := range out {
			if out[i].Width > out[largest].Width {
				largest = i
			}
		}
		if out[largest].Width <= 3 {
			break
		}
		out[largest].Width--
		total--
	}
	if total < budget && len(out) > 0 {
		target := len(out) - 1
		for i, c := range r.visible {
			if c.Kind == "string" {
				target = i
				break
			}
		}
		out[target].Width += budget - total
	}
	// Rows must match the new column count before the columns change, which
	// also clears the cursor; restore it once the rows are back.
	cursor := r.grid.Cursor()
	r.grid.SetRows(nil)
	r.grid.SetColumns(out)
	r.grid.SetWidth(width)
	r.grid.SetHeight(max(4, height))
	r.render()
	if len(r.rows) > 0 {
		r.grid.SetCursor(max(0, cursor))
	}
}

func (r *results) setRows(rows []evidence.Row) {
	r.rows = rows
	r.render()
	if len(rows) > 0 && (r.grid.Cursor() < 0 || r.grid.Cursor() >= len(rows)) {
		r.grid.SetCursor(0)
	}
}

func (r *results) render() {
	rows := make([]table.Row, 0, len(r.rows))
	for _, row := range r.rows {
		cells := make(table.Row, len(r.visible))
		for i, c := range r.visible {
			v, ok := row.Cells[c.Name]
			if !ok {
				v = evidence.Missing("column_absent", nil)
			}
			cells[i] = render.Safe(v.String())
		}
		rows = append(rows, cells)
	}
	r.grid.SetRows(rows)
}

// shift moves the column window; it reports whether anything changed.
func (r *results) shift(delta int) bool {
	start := max(0, min(r.colStart+delta, len(r.spec.Columns)-visibleColumns))
	if start == r.colStart {
		return false
	}
	r.colStart = start
	return true
}

// cycleSort walks the visible columns, then back to insertion order.
func (r *results) cycleSort() {
	next := ""
	if len(r.visible) > 0 {
		next = r.visible[0].Name
	}
	for i, c := range r.visible {
		if c.Name == r.sort {
			next = ""
			if i+1 < len(r.visible) {
				next = r.visible[i+1].Name
			}
		}
	}
	r.sort = next
	r.offset = 0
}

func (r results) current() (evidence.Row, bool) {
	i := r.grid.Cursor()
	if i >= 0 && i < len(r.rows) {
		return r.rows[i], true
	}
	return evidence.Row{}, false
}

func (r results) query(ctx context.Context, s *store.Store) tea.Cmd {
	q := evidence.Query{TaskID: r.task.ID, Offset: r.offset, Limit: pageSize, Filter: r.filter, Desc: r.desc, Sort: r.sort}
	return func() tea.Msg {
		rows, err := s.Query(ctx, q)
		return pageMsg{q.TaskID, q.Offset, q.Filter, q.Desc, q.Sort, rows, err}
	}
}

// accepts reports whether a page answers the current query.
func (r results) accepts(p pageMsg) bool {
	return p.task == r.task.ID && p.offset == r.offset && p.filter == r.filter && p.desc == r.desc && p.sort == r.sort
}

func (r results) View() string {
	head := accent.Render("RESULTS") + muted.Render(fmt.Sprintf("  %d–%d", r.offset, r.offset+len(r.rows)))
	if n := len(r.spec.Columns); n > visibleColumns {
		head += muted.Render(fmt.Sprintf(" · cols %d–%d/%d", r.colStart+1, r.colStart+len(r.visible), n))
	}
	if r.sort != "" {
		head += muted.Render(" · by " + render.Safe(r.sort))
	}
	if r.filter != "" {
		head += muted.Render(" · " + strconv.Quote(render.Safe(r.filter)))
	}
	return ansi.Truncate(head, r.width, "…") + "\n\n" + r.grid.View()
}
