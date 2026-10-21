package tui

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

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
	sort   string
	rows   []evidence.Row
	err    error
}
type commandMsg struct {
	text string
	err  error
}
type tasksMsg struct {
	tasks []evidence.Task
	err   error
}
type historyMsg []string

// openedMsg reports an image switch. eng is the image now open: the new one,
// the previous one reopened after err, or nil when neither could be opened.
type openedMsg struct {
	eng        *engine.Engine
	err        error
	restored   bool
	restoreErr error
}
type progressMsg struct {
	task string
	rows int64
}

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
