package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// taskPicker lists persisted tasks so their evidence can be reopened without rerunning.
type taskPicker struct {
	open   bool
	tasks  []evidence.Task
	cursor int
	top    int
}

func (t *taskPicker) show(tasks []evidence.Task) {
	t.open, t.tasks, t.cursor, t.top = true, tasks, 0, 0
}

func (t *taskPicker) move(delta, height int) {
	t.cursor = max(0, min(len(t.tasks)-1, t.cursor+delta))
	if t.cursor < t.top {
		t.top = t.cursor
	}
	if t.cursor >= t.top+height {
		t.top = t.cursor - height + 1
	}
}

func (t taskPicker) selected() (evidence.Task, bool) {
	if t.cursor >= 0 && t.cursor < len(t.tasks) {
		return t.tasks[t.cursor], true
	}
	return evidence.Task{}, false
}

func (t taskPicker) View(width, height int) string {
	var b strings.Builder
	b.WriteString(accent.Render("TASKS") + muted.Render(fmt.Sprintf("  %d · enter open · esc close", len(t.tasks))) + "\n\n")
	if len(t.tasks) == 0 {
		b.WriteString(muted.Render("No persisted tasks in this case."))
	}
	for i := t.top; i < min(len(t.tasks), t.top+height); i++ {
		task := t.tasks[i]
		line := fmt.Sprintf("%-28s %-10s %7d  %s", task.Plugin, task.State, task.Rows, task.Started.Local().Format("01-02 15:04:05"))
		line = ansi.Truncate(render.Safe(line), width-2, "…")
		if i == t.cursor {
			b.WriteString(strong.Render("› " + line))
		} else {
			b.WriteString(muted.Render("  " + line))
		}
		b.WriteString("\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}
