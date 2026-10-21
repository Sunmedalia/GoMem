package tui

import (
	"context"
	"fmt"
	"strconv"

	tea "charm.land/bubbletea/v2"

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
	grid     grid
	spec     plugin.Spec
	visible  []evidence.Column
	colStart int
	rows     []evidence.Row
	task     evidence.Task
	offset   int
	filter   string
	desc     bool
	sort     string
	layoutAt string
}

// setSpec switches the column source, resetting column window and sort for a new plugin.
func (r *results) setSpec(spec plugin.Spec) {
	if spec.Name != r.spec.Name {
		r.colStart = 0
		r.sort = ""
		r.layoutAt = ""
	}
	r.spec = spec
}

// reset clears paging state before a new task is shown.
func (r *results) reset(task evidence.Task) {
	r.task = task
	r.offset = 0
	r.filter = ""
	r.setRows(nil)
}

// layout sizes the visible columns; it is a no-op when nothing it depends on changed.
func (r *results) layout(width, height int) {
	cols := r.spec.Columns
	r.colStart = max(0, min(r.colStart, len(cols)-visibleColumns))
	key := fmt.Sprint(r.spec.Name, r.colStart, r.sort, r.desc, width, height)
	if key == r.layoutAt {
		return
	}
	r.layoutAt = key
	r.visible = cols[r.colStart:min(r.colStart+visibleColumns, len(cols))]
	budget := width - 2*len(r.visible)
	total := 0
	out := make([]gridColumn, 0, len(r.visible))
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
		out = append(out, gridColumn{title: render.Safe(title), width: w})
		total += w
	}
	for total > budget {
		largest := 0
		for i := range out {
			if out[i].width > out[largest].width {
				largest = i
			}
		}
		if out[largest].width <= 3 {
			break
		}
		out[largest].width--
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
		out[target].width += budget - total
	}
	r.grid.setColumns(out, max(4, height))
	r.render()
}

func (r *results) setRows(rows []evidence.Row) {
	r.rows = rows
	r.render()
}

func (r *results) render() {
	rows := make([][]string, 0, len(r.rows))
	for _, row := range r.rows {
		cells := make([]string, len(r.visible))
		for i, c := range r.visible {
			v, ok := row.Cells[c.Name]
			if !ok {
				v = evidence.Missing("column_absent", nil)
			}
			cells[i] = render.Safe(v.String())
		}
		rows = append(rows, cells)
	}
	r.grid.setRows(rows)
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

// View renders the title line, a blank line, then the grid; activity is
// appended to the title while a task runs.
func (r results) View(st styles, focused bool, activity string) string {
	head := st.accent.Render("RESULTS") + st.muted.Render(fmt.Sprintf("  %d–%d", r.offset, r.offset+len(r.rows)))
	if n := len(r.spec.Columns); n > visibleColumns {
		head += st.muted.Render(fmt.Sprintf(" · cols %d–%d/%d", r.colStart+1, r.colStart+len(r.visible), n))
	}
	if r.sort != "" {
		head += st.muted.Render(" · by " + render.Safe(r.sort))
	}
	if r.filter != "" {
		head += st.muted.Render(" · " + strconv.Quote(render.Safe(r.filter)))
	}
	if activity != "" {
		head += "  " + activity
	}
	return head + "\n\n" + r.grid.View(st, focused)
}
