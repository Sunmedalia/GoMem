package tui

import "strings"

type gridColumn struct {
	title string
	width int
}

// grid is a fixed-height table. Rows are rendered once when set and only the
// visible window is styled per frame; top is exposed so clicks map to rows.
type grid struct {
	cols   []gridColumn
	header string
	lines  []string
	cursor int
	top    int
	height int
}

func (g *grid) setColumns(cols []gridColumn, height int) {
	g.cols = cols
	g.height = max(2, height)
	titles := make([]string, len(cols))
	for i, c := range cols {
		titles[i] = c.title
	}
	g.header = g.line(titles)
	g.scroll()
}

func (g *grid) setRows(rows [][]string) {
	g.lines = g.lines[:0]
	for _, r := range rows {
		g.lines = append(g.lines, g.line(r))
	}
	g.cursor = max(0, min(g.cursor, len(g.lines)-1))
	g.scroll()
}

// line lays out cells with one space of padding on each side.
func (g grid) line(cells []string) string {
	var b strings.Builder
	for i, c := range g.cols {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		b.WriteByte(' ')
		b.WriteString(fit(cell, c.width))
		b.WriteByte(' ')
	}
	return b.String()
}

func (g grid) Cursor() int { return g.cursor }

func (g *grid) setCursor(i int) {
	g.cursor = max(0, min(i, len(g.lines)-1))
	g.scroll()
}

func (g *grid) move(delta int) { g.setCursor(g.cursor + delta) }

// rows is the number of data rows below the header.
func (g grid) rows() int { return g.height - 1 }

func (g *grid) scroll() {
	if g.cursor < g.top {
		g.top = g.cursor
	}
	if g.cursor >= g.top+g.rows() {
		g.top = g.cursor - g.rows() + 1
	}
	g.top = max(0, min(g.top, len(g.lines)-g.rows()))
}

func (g grid) View(st styles, focused bool) string {
	var b strings.Builder
	b.WriteString(st.heading.Render(g.header))
	for i := g.top; i < min(len(g.lines), g.top+g.rows()); i++ {
		b.WriteByte('\n')
		switch {
		case i == g.cursor && focused:
			b.WriteString(st.selected.Render(g.lines[i]))
		case i == g.cursor:
			b.WriteString(st.selectedDim.Render(g.lines[i]))
		default:
			b.WriteString(g.lines[i])
		}
	}
	return b.String()
}
