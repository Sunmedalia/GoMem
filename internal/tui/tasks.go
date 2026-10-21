package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// taskPicker lists persisted tasks so their evidence can be reopened without
// rerunning. A case can hold several images; by default only the open
// image's tasks are listed.
type taskPicker struct {
	open   bool
	all    []evidence.Task
	tasks  []evidence.Task
	image  string
	every  bool
	cursor int
	top    int
}

func (t *taskPicker) show(tasks []evidence.Task, image string) {
	t.open, t.all, t.image, t.every = true, tasks, image, false
	t.filter()
}

// toggleEvery switches between this image's tasks and every task in the case.
func (t *taskPicker) toggleEvery() {
	t.every = !t.every
	t.filter()
}

func (t *taskPicker) filter() {
	t.tasks, t.cursor, t.top = t.tasks[:0], 0, 0
	for _, task := range t.all {
		if t.every || task.Provenance.ImageSHA256 == t.image {
			t.tasks = append(t.tasks, task)
		}
	}
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

// clickLine moves the cursor to the task drawn on list line i.
func (t *taskPicker) clickLine(i int) bool {
	i += t.top
	if i < 0 || i >= len(t.tasks) {
		return false
	}
	t.cursor = i
	return true
}

func (t taskPicker) selected() (evidence.Task, bool) {
	if t.cursor >= 0 && t.cursor < len(t.tasks) {
		return t.tasks[t.cursor], true
	}
	return evidence.Task{}, false
}

func (t taskPicker) View(st styles, width, height int) string {
	var b strings.Builder
	scope := "this image · a all images"
	if t.every {
		scope = "all images · a this image"
	}
	b.WriteString(st.accent.Render("TASKS") + st.muted.Render(fmt.Sprintf("  %d of %d · %s · enter open · esc close", len(t.tasks), len(t.all), scope)) + "\n\n")
	if len(t.tasks) == 0 {
		b.WriteString(st.muted.Render("No persisted tasks for this scope."))
	}
	for i := t.top; i < min(len(t.tasks), t.top+height); i++ {
		task := t.tasks[i]
		line := fmt.Sprintf("%-28s %-10s %7d  %s", task.Plugin, task.State, task.Rows, task.Started.Local().Format("01-02 15:04:05"))
		line = ansi.Truncate(render.Safe(line), width-2, "…")
		if i == t.cursor {
			b.WriteString(st.strong.Render("› " + line))
		} else {
			b.WriteString(st.muted.Render("  " + line))
		}
		b.WriteString("\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}
