package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	Up, Down, Home, End, HalfUp, HalfDown                key.Binding
	Run, Edit, Focus, Command, Filter, Help, Tasks, Raw  key.Binding
	Next, Prev, Reverse, Sort, ColLeft, ColRight, Expand key.Binding
	Bookmark, Hex, CopyID, CopyAddr, Cancel, Quit, Back  key.Binding
	ScrollUp, ScrollDown, ScrollLeft, ScrollRight        key.Binding
	ForceQuit, NextField, PrevField, Submit, Toggle      key.Binding
	Import, AllTasks, TabLeft, TabRight, Parent, Hidden  key.Binding
	NextSection, PrevSection, TabSelect, CloseTab        key.Binding
	TreeToggle, Expand1, Collapse1, ExpandAll, Fold      key.Binding
}

var keys = keyMap{
	Up:          key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:        key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Home:        key.NewBinding(key.WithKeys("home", "g"), key.WithHelp("g", "first row")),
	End:         key.NewBinding(key.WithKeys("end", "G"), key.WithHelp("G", "last row")),
	HalfUp:      key.NewBinding(key.WithKeys("ctrl+u"), key.WithHelp("ctrl+u/d", "half page")),
	HalfDown:    key.NewBinding(key.WithKeys("ctrl+d")),
	Run:         key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "run")),
	Edit:        key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "parameters")),
	Focus:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "focus")),
	Command:     key.NewBinding(key.WithKeys(":"), key.WithHelp(":", "command")),
	Filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Tasks:       key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "tasks")),
	Raw:         key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "raw JSON")),
	Next:        key.NewBinding(key.WithKeys("n", "pgdown"), key.WithHelp("n", "next page")),
	Prev:        key.NewBinding(key.WithKeys("p", "pgup"), key.WithHelp("p", "prev page")),
	Reverse:     key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "reverse")),
	Sort:        key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "sort column")),
	ColLeft:     key.NewBinding(key.WithKeys("["), key.WithHelp("[", "columns left")),
	ColRight:    key.NewBinding(key.WithKeys("]"), key.WithHelp("]", "columns right")),
	Expand:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "expand detail")),
	Bookmark:    key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "bookmark")),
	Hex:         key.NewBinding(key.WithKeys("h"), key.WithHelp("h", "hex jump")),
	CopyID:      key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "copy ID")),
	CopyAddr:    key.NewBinding(key.WithKeys("Y"), key.WithHelp("Y", "copy address")),
	Cancel:      key.NewBinding(key.WithKeys("ctrl+x"), key.WithHelp("ctrl+x", "cancel task")),
	Quit:        key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
	ForceQuit:   key.NewBinding(key.WithKeys("ctrl+c")),
	Back:        key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	ScrollUp:    key.NewBinding(key.WithKeys("ctrl+up"), key.WithHelp("ctrl+↑↓←→", "scroll detail")),
	ScrollDown:  key.NewBinding(key.WithKeys("ctrl+down")),
	ScrollLeft:  key.NewBinding(key.WithKeys("ctrl+left")),
	ScrollRight: key.NewBinding(key.WithKeys("ctrl+right")),
	NextField:   key.NewBinding(key.WithKeys("tab", "down")),
	PrevField:   key.NewBinding(key.WithKeys("shift+tab", "up")),
	Submit:      key.NewBinding(key.WithKeys("ctrl+s")),
	Toggle:      key.NewBinding(key.WithKeys("space")),
	Import:      key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "import image")),
	AllTasks:    key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "all images")),
	TabLeft:     key.NewBinding(key.WithKeys("left"), key.WithHelp("←/→", "platform")),
	TabRight:    key.NewBinding(key.WithKeys("right")),
	Parent:      key.NewBinding(key.WithKeys("backspace", "left"), key.WithHelp("⌫", "parent dir")),
	Hidden:      key.NewBinding(key.WithKeys("."), key.WithHelp(".", "hidden files")),
	NextSection: key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "complete / next section")),
	PrevSection: key.NewBinding(key.WithKeys("shift+tab")),
	TabSelect:   key.NewBinding(key.WithKeys("1", "2", "3", "4", "5", "6", "7", "8", "9"), key.WithHelp("1-9", "result tab")),
	CloseTab:    key.NewBinding(key.WithKeys("w"), key.WithHelp("w", "close tab")),
	TreeToggle:  key.NewBinding(key.WithKeys("T"), key.WithHelp("T", "tree view")),
	Expand1:     key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/←", "expand/collapse")),
	Collapse1:   key.NewBinding(key.WithKeys("left")),
	ExpandAll:   key.NewBinding(key.WithKeys("+"), key.WithHelp("+/-", "expand/collapse all")),
	Fold:        key.NewBinding(key.WithKeys("-")),
}

// navHelp and resultHelp are the footer hints for each focus.
func (k keyMap) navHelp() []key.Binding {
	return []key.Binding{k.Run, k.Edit, k.TabLeft, k.Filter, k.Focus, k.Command, k.Tasks, k.Import, k.Help, k.Quit}
}
func (k keyMap) launcherHelp(back bool) []key.Binding {
	enter := key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open"))
	out := []key.Binding{enter, k.NextSection, k.Up, k.Parent, k.Hidden}
	if back {
		out = append(out, key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")))
	}
	return append(out, key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")))
}
func (k keyMap) resultHelp() []key.Binding {
	return []key.Binding{k.Filter, k.Sort, k.Reverse, k.ColLeft, k.ColRight, k.Next, k.Prev, k.TabSelect, k.TreeToggle, k.Expand, k.Raw, k.Help}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Run, k.Edit, k.TabLeft, k.Focus, k.Filter, k.Command, k.Tasks, k.AllTasks, k.Import},
		{k.Next, k.Prev, k.Home, k.End, k.HalfUp, k.Reverse, k.Sort, k.ColLeft, k.ColRight, k.TabSelect, k.CloseTab},
		{k.TreeToggle, k.Expand1, k.ExpandAll},
		{k.Expand, k.Raw, k.Bookmark, k.Hex, k.CopyID, k.CopyAddr, k.ScrollUp, k.Cancel, k.Back, k.Quit},
	}
}
