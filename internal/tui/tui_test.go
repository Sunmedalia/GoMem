package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func fixtureModel(t testing.TB) model {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, CaseDir: t.TempDir(), Symbols: f.Symbols, OS: "linux", Arch: "x64", DTB: f.DTB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return New(context.Background(), e).(model)
}
func TestLayoutPagingFilterAndStaleMessages(t *testing.T) {
	m := fixtureModel(t)
	for _, width := range []int{85, 100, 120, 160} {
		m.width = width
		m.resize()
		v := m.View()
		if got := lipgloss.Width(v.Content); got > width {
			t.Fatalf("width %d rendered %d", width, got)
		}
		if got := lipgloss.Height(v.Content); got > m.height {
			t.Fatalf("height %d rendered %d", m.height, got)
		}
	}
	m.width = 120
	m.resize()
	if err := os.WriteFile(filepath.Join(t.TempDir(), "tui.txt"), []byte(m.View().Content), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := m.engine.Run(m.ctx, "linux.pslist", nil, engine.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m.task = res.Task
	m.resize()
	page := m.query()()
	updated, _ := m.Update(page)
	m = updated.(model)
	if len(m.rows) != 2 {
		t.Fatal(len(m.rows))
	}
	stale := pageMsg{task: "other", rows: []evidence.Row{{ID: "wrong"}}}
	updated, _ = m.Update(stale)
	m = updated.(model)
	if len(m.rows) != 2 {
		t.Fatal("stale query overwrote current task")
	}
	m.mode = "filter"
	m.input.SetValue("worker")
	updated, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(model)
	updated, _ = m.Update(cmd())
	m = updated.(model)
	if len(m.rows) != 1 || m.rows[0].Cells["Name"].String() != "worker" {
		t.Fatal(m.rows)
	}
	updated, _ = m.Update(tea.KeyPressMsg{Code: 'b', Text: "b"})
	m = updated.(model)
	notes, err := m.engine.Store.Investigation(m.ctx)
	if err != nil || len(notes["bookmarks"].([]map[string]string)) != 1 {
		t.Fatal(notes, err)
	}
	m.generation = 2
	m.running = false
	updated, _ = m.Update(started{task: evidence.Task{ID: "late"}, generation: 1})
	m = updated.(model)
	if m.task.ID == "late" {
		t.Fatal("late start overwrote completed task")
	}
}
func BenchmarkLocalNavigation(b *testing.B) {
	m := fixtureModel(b)
	rows := make([]evidence.Row, 100)
	for i := range rows {
		rows[i] = evidence.Row{ID: fmt.Sprint(i), Cells: map[string]evidence.Value{"Name": evidence.Text(strings.Repeat("X", 32))}}
	}
	m.rows = rows
	m.nav = false
	m.grid.Focus()
	b.ResetTimer()
	for b.Loop() {
		updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		m = updated.(model)
		_ = m.View()
	}
}

func TestStartedTaskSelectsFirstEvidence(t *testing.T) {
	m := fixtureModel(t)
	for i, spec := range m.specs {
		if spec.Name == "linux.pslist" {
			m.selected = i
			break
		}
	}
	run := m.start("linux.pslist", nil)
	updated, query := m.Update(run())
	m = updated.(model)
	updated, _ = m.Update(query())
	m = updated.(model)
	if m.grid.Cursor() != 0 || !strings.Contains(m.detail.GetContent(), "image_sha256") {
		t.Fatal("first result was not selected", m.grid.Cursor(), m.detail.GetContent())
	}
}
