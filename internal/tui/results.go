package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/Sunmedalia/GoMem/internal/explore"
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
	// cursors holds the position each insertion-order page starts after;
	// the last entry is the current page.
	cursors []int64
	last    int64
	// gen is the run that fills this tab, so run events reach it after
	// another tab is selected.
	gen uint64
	// tree, when on, replaces pages with the whole task arranged by parent;
	// prefix holds each visible row's guides.
	tree   tree
	prefix []string
}

// applyTree shows the tree's visible nodes, keeping the selected row.
func (r *results) applyTree() {
	keep := ""
	if row, ok := r.current(); ok {
		keep = row.ID
	}
	r.tree.flatten(matcher(r.filter, r.spec.Columns), r.filter != "")
	rows := make([]evidence.Row, len(r.tree.lines))
	r.prefix = make([]string, len(r.tree.lines))
	cursor := 0
	for i, l := range r.tree.lines {
		rows[i], r.prefix[i] = r.tree.all[l.row], l.prefix
		if rows[i].ID == keep {
			cursor = i
		}
	}
	r.setRows(rows)
	r.grid.setCursor(cursor)
}

// parseFilter splits filter text into free text and column terms. A term
// is COLUMN:TEXT (substring) or COLUMN=VALUE (exact) where COLUMN names one
// of the plugin's columns, ignoring case; quote names that contain spaces.
// Anything else is free text.
func parseFilter(text string, cols []evidence.Column) (string, []evidence.ColumnFilter) {
	tokens, err := explore.Split(text)
	if err != nil {
		return text, nil
	}
	var plain []string
	var terms []evidence.ColumnFilter
next:
	for _, tok := range tokens {
		if i := strings.IndexAny(tok, ":="); i > 0 {
			for _, c := range cols {
				if strings.EqualFold(c.Name, tok[:i]) {
					terms = append(terms, evidence.ColumnFilter{Column: c.Name, Value: tok[i+1:], Exact: tok[i] == '='})
					continue next
				}
			}
		}
		plain = append(plain, tok)
	}
	return strings.Join(plain, " "), terms
}

// resetPaging returns to the first page.
func (r *results) resetPaging() {
	r.offset = 0
	r.cursors = nil
}

// nextPage advances past the current page; it reports false on the last page.
func (r *results) nextPage() bool {
	if r.tree.on || len(r.rows) < pageSize {
		return false
	}
	r.offset += pageSize
	if r.sort == "" {
		r.cursors = append(r.cursors, r.last)
	}
	return true
}

func (r *results) prevPage() {
	r.offset = max(0, r.offset-pageSize)
	if len(r.cursors) > 0 {
		r.cursors = r.cursors[:len(r.cursors)-1]
	}
}

func (r results) after() int64 {
	if r.sort != "" || len(r.cursors) == 0 {
		return 0
	}
	return r.cursors[len(r.cursors)-1]
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
	r.resetPaging()
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
	// Tree guides go before the first text column, which also gets the
	// spare width, rather than squeezing an address column.
	guide := 0
	for i, c := range r.visible {
		if c.Kind == "string" {
			guide = i
			break
		}
	}
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
		if n := len(rows); n < len(r.prefix) && len(cells) > 0 {
			cells[guide] = r.prefix[n] + cells[guide]
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
	r.resetPaging()
}

func (r results) current() (evidence.Row, bool) {
	i := r.grid.Cursor()
	if i >= 0 && i < len(r.rows) {
		return r.rows[i], true
	}
	return evidence.Row{}, false
}

func (r results) query(ctx context.Context, s *store.Store) tea.Cmd {
	if r.tree.on {
		return loadTree(ctx, s, r.task.ID)
	}
	plain, cols := parseFilter(r.filter, r.spec.Columns)
	q := evidence.Query{TaskID: r.task.ID, Offset: r.offset, Limit: pageSize, Filter: plain, Columns: cols, Desc: r.desc, Sort: r.sort, After: r.after()}
	if q.After > 0 {
		q.Offset = 0
	}
	filter := r.filter
	return func() tea.Msg {
		page, err := s.QueryPage(ctx, q)
		return pageMsg{task: q.TaskID, offset: r.offset, filter: filter, desc: q.Desc, sort: q.Sort, rows: page.Rows, last: page.Last, err: err}
	}
}

// accepts reports whether a page answers the current query.
func (r results) accepts(p pageMsg) bool {
	return p.task == r.task.ID && p.offset == r.offset && p.filter == r.filter && p.desc == r.desc && p.sort == r.sort
}

// View renders the title line, a blank line, then the grid; activity is
// appended to the title while a task runs.
func (r results) View(st styles, focused bool, activity, tabs string) string {
	head := st.accent.Render("RESULTS") + st.muted.Render(fmt.Sprintf("  %d–%d", r.offset, r.offset+len(r.rows)))
	if r.tree.on {
		head = st.accent.Render("TREE") + st.muted.Render(fmt.Sprintf("  %d of %d rows", len(r.rows), len(r.tree.all)))
		if r.tree.truncated {
			head += st.warn.Render(fmt.Sprintf(" · first %d only", treeLimit))
		}
	}
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
	// The tab bar takes the line between the title and the column header.
	return head + "\n" + tabs + "\n" + r.grid.View(st, focused)
}
