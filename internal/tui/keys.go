package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	Up, Down, Run, Focus, Command, Filter, Help, Tasks       key.Binding
	Next, Prev, Reverse, Sort, ColLeft, ColRight, Expand     key.Binding
	Bookmark, Hex, CopyID, CopyAddr, Cancel, Quit, Back      key.Binding
	ScrollUp, ScrollDown, ScrollLeft, ScrollRight, ForceQuit key.Binding
}

var keys = keyMap{
	Up:          key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:        key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Run:         key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "run")),
	Focus:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "focus")),
	Command:     key.NewBinding(key.WithKeys(":"), key.WithHelp(":", "command")),
	Filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Tasks:       key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "tasks")),
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
}

// navHelp and resultHelp are the footer hints for each focus.
func (k keyMap) navHelp() []key.Binding {
	return []key.Binding{k.Run, k.Filter, k.Focus, k.Command, k.Tasks, k.Help, k.Quit}
}
func (k keyMap) resultHelp() []key.Binding {
	return []key.Binding{k.Filter, k.Sort, k.Reverse, k.ColLeft, k.ColRight, k.Next, k.Prev, k.Expand, k.Help}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Run, k.Focus, k.Filter, k.Command, k.Tasks},
		{k.Next, k.Prev, k.Reverse, k.Sort, k.ColLeft, k.ColRight, k.Expand},
		{k.Bookmark, k.Hex, k.CopyID, k.CopyAddr, k.ScrollUp, k.Cancel, k.Back, k.Quit},
	}
}
