package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// capItem is one capability list line: a group heading when spec < 0.
type capItem struct {
	group string
	spec  int
}

// capabilities is the scrolling, grouped and searchable plugin list.
type capabilities struct {
	specs    []plugin.Spec
	query    string
	items    []capItem
	selected int
	top      int
	height   int
}

func newCapabilities(specs []plugin.Spec) capabilities {
	c := capabilities{specs: specs, height: 10}
	c.rebuild()
	return c
}

func group(s plugin.Spec) string {
	if s.Platform != "" {
		return s.Platform
	}
	if g, _, ok := strings.Cut(s.Name, "."); ok {
		return g
	}
	return "general"
}

// rebuild regroups the specs matching the query, keeping group order stable.
func (c *capabilities) rebuild() {
	var groups []string
	members := map[string][]int{}
	q := strings.ToLower(c.query)
	for i, s := range c.specs {
		if q != "" && !strings.Contains(strings.ToLower(s.Name), q) {
			continue
		}
		g := group(s)
		if _, ok := members[g]; !ok {
			groups = append(groups, g)
		}
		members[g] = append(members[g], i)
	}
	c.items = c.items[:0]
	for _, g := range groups {
		c.items = append(c.items, capItem{group: g, spec: -1})
		for _, i := range members[g] {
			c.items = append(c.items, capItem{group: g, spec: i})
		}
	}
	if c.position() < 0 {
		for _, it := range c.items {
			if it.spec >= 0 {
				c.selected = it.spec
				break
			}
		}
	}
	c.top = 0
	c.scroll()
}

// position is the item index of the selected spec, or -1 when filtered out.
func (c capabilities) position() int {
	for i, it := range c.items {
		if it.spec == c.selected {
			return i
		}
	}
	return -1
}

func (c capabilities) matches() int {
	n := 0
	for _, it := range c.items {
		if it.spec >= 0 {
			n++
		}
	}
	return n
}

func (c *capabilities) setQuery(q string) {
	c.query = q
	c.rebuild()
}

func (c *capabilities) setHeight(h int) {
	c.height = max(1, h)
	c.scroll()
}

// move selects the delta-th visible spec from the current one, skipping headings.
func (c *capabilities) move(delta int) {
	pos := c.position()
	if pos < 0 {
		return
	}
	step := 1
	if delta < 0 {
		step, delta = -1, -delta
	}
	for i := pos + step; delta > 0 && i >= 0 && i < len(c.items); i += step {
		if c.items[i].spec >= 0 {
			c.selected = c.items[i].spec
			delta--
		}
	}
	c.scroll()
}

// selectName selects a spec by name, clearing a search that hides it.
func (c *capabilities) selectName(name string) bool {
	for i, s := range c.specs {
		if s.Name == name {
			c.selected = i
			if c.position() < 0 {
				c.query = ""
				c.rebuild()
			}
			c.scroll()
			return true
		}
	}
	return false
}

// clickLine selects the spec drawn on list line i (0 is the first item line).
func (c *capabilities) clickLine(i int) bool {
	i += c.top
	if i < 0 || i >= len(c.items) || c.items[i].spec < 0 {
		return false
	}
	c.selected = c.items[i].spec
	c.scroll()
	return true
}

func (c capabilities) spec() plugin.Spec { return c.specs[c.selected] }

// scroll keeps the selection and, at the top, its group heading visible.
func (c *capabilities) scroll() {
	pos := max(0, c.position())
	if pos > 0 && c.items[pos-1].spec < 0 {
		pos--
	}
	if pos < c.top {
		c.top = pos
	}
	if p := max(0, c.position()); p >= c.top+c.height {
		c.top = p - c.height + 1
	}
	c.top = max(0, min(c.top, len(c.items)-c.height))
}

func (c capabilities) View(st styles, width int) string {
	var b strings.Builder
	b.WriteString(st.accent.Render("CAPABILITIES") + st.muted.Render(fmt.Sprintf("  %d", c.matches())) + "\n")
	if c.query != "" {
		b.WriteString(st.muted.Render(ansi.Truncate("search: "+c.query, width, "…")))
	}
	b.WriteString("\n")
	end := min(len(c.items), c.top+c.height)
	for i := c.top; i < end; i++ {
		it := c.items[i]
		switch {
		case it.spec < 0:
			b.WriteString(st.heading.Render(ansi.Truncate(strings.ToUpper(it.group), width, "…")))
		case it.spec == c.selected:
			b.WriteString(st.strong.Render(ansi.Truncate("› "+c.specs[it.spec].Name, width, "…")))
		default:
			b.WriteString(st.muted.Render(ansi.Truncate("  "+c.specs[it.spec].Name, width, "…")))
		}
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	if len(c.items) == 0 {
		b.WriteString(st.muted.Render("no match"))
	}
	return b.String()
}
