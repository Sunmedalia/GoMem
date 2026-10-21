package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// treeLimit bounds how many rows a tree view loads; a tree needs the whole
// task, not a page.
const treeLimit = 20000

type treeMsg struct {
	task      string
	rows      []evidence.Row
	truncated bool
	err       error
}

// treeLine is one visible node: its row and the guides drawn before it.
type treeLine struct {
	row    int
	prefix string
}

// tree arranges a task's rows by ParentID. Rows whose parent is absent are
// roots, so partial or flat evidence still shows every row.
type tree struct {
	on        bool
	task      string
	all       []evidence.Row
	truncated bool
	children  map[string][]int
	roots     []int
	collapsed map[string]bool
	lines     []treeLine
	linked    bool
}

func loadTree(ctx context.Context, s *store.Store, task string) tea.Cmd {
	return func() tea.Msg {
		var rows []evidence.Row
		var after int64
		for {
			want := min(1000, treeLimit-len(rows))
			if want == 0 {
				// One more row tells whether the limit cut the task short.
				page, err := s.QueryPage(ctx, evidence.Query{TaskID: task, Limit: 1, After: after})
				return treeMsg{task: task, rows: rows, truncated: err == nil && len(page.Rows) > 0, err: err}
			}
			page, err := s.QueryPage(ctx, evidence.Query{TaskID: task, Limit: want, After: after})
			if err != nil {
				return treeMsg{task: task, err: err}
			}
			rows = append(rows, page.Rows...)
			if len(page.Rows) < want {
				return treeMsg{task: task, rows: rows}
			}
			after = page.Last
		}
	}
}

// build indexes rows by parent. The first row with an ID owns it; a row
// that names itself or an unknown parent is a root.
func (t *tree) build(rows []evidence.Row) {
	t.all, t.children, t.roots, t.linked = rows, map[string][]int{}, nil, false
	if t.collapsed == nil {
		t.collapsed = map[string]bool{}
	}
	ids := make(map[string]bool, len(rows))
	for _, r := range rows {
		ids[r.ID] = true
	}
	for i, r := range rows {
		if r.ParentID == "" || r.ParentID == r.ID || !ids[r.ParentID] {
			t.roots = append(t.roots, i)
			continue
		}
		t.linked = true
		t.children[r.ParentID] = append(t.children[r.ParentID], i)
	}
}

// matcher reports whether a row satisfies filter text, parsed as for pages.
func matcher(filter string, cols []evidence.Column) func(evidence.Row) bool {
	plain, terms := parseFilter(filter, cols)
	plain = strings.ToLower(plain)
	return func(r evidence.Row) bool {
		for _, c := range terms {
			v, ok := r.Cells[c.Column]
			if !ok {
				return false
			}
			s := v.String()
			if c.Exact && s != c.Value || !c.Exact && !strings.Contains(strings.ToLower(s), strings.ToLower(c.Value)) {
				return false
			}
		}
		if plain == "" {
			return true
		}
		for _, v := range r.Cells {
			if strings.Contains(strings.ToLower(v.String()), plain) {
				return true
			}
		}
		return false
	}
}

// flatten lists visible nodes depth first. With a filter, only matching
// rows and their ancestors remain, and collapsed state is ignored so every
// match shows.
func (t *tree) flatten(match func(evidence.Row) bool, filtering bool) {
	keep := make([]bool, len(t.all))
	visited := make([]bool, len(t.all))
	var mark func(i int) bool
	mark = func(i int) bool {
		if visited[i] {
			return keep[i]
		}
		visited[i] = true
		k := match(t.all[i])
		for _, c := range t.children[t.all[i].ID] {
			if mark(c) {
				k = true
			}
		}
		keep[i] = k
		return k
	}
	for i := range t.all {
		mark(i)
	}
	t.lines = t.lines[:0]
	drawn := make([]bool, len(t.all))
	var walk func(i int, guide string, last, root bool)
	walk = func(i int, guide string, last, root bool) {
		if drawn[i] || !keep[i] {
			return
		}
		drawn[i] = true
		id := t.all[i].ID
		// Children already drawn (a parent cycle) or filtered out are not
		// this node's to show.
		var shown []int
		for _, c := range t.children[id] {
			if keep[c] && !drawn[c] {
				shown = append(shown, c)
			}
		}
		branch, next := "", ""
		if !root {
			branch, next = "├─", "│ "
			if last {
				branch, next = "└─", "  "
			}
		}
		open := !t.collapsed[id] || filtering
		marker := "  "
		switch {
		case len(shown) > 0 && open:
			marker = "▾ "
		case len(shown) > 0:
			marker = "▸ "
		}
		t.lines = append(t.lines, treeLine{row: i, prefix: guide + branch + marker})
		if !open {
			return
		}
		for n, c := range shown {
			walk(c, guide+next, n == len(shown)-1, false)
		}
	}
	for _, r := range t.roots {
		walk(r, "", true, true)
	}
	// Rows in a parent cycle are unreachable from any root; show them anyway.
	for i := range t.all {
		walk(i, "", true, true)
	}
}

func (t tree) hasChildren(row int) bool { return len(t.children[t.all[row].ID]) > 0 }

// parentLine is the visible line of a row's parent, or -1.
func (t tree) parentLine(line int) int {
	parent := t.all[t.lines[line].row].ParentID
	for i := line - 1; i >= 0; i-- {
		if t.all[t.lines[i].row].ID == parent {
			return i
		}
	}
	return -1
}

// setAll collapses or expands every node with children.
func (t *tree) setAll(collapsed bool) {
	clear(t.collapsed)
	if collapsed {
		for id := range t.children {
			t.collapsed[id] = true
		}
	}
}
