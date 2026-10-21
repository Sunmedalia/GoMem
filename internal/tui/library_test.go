package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/library"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/charmbracelet/x/ansi"
)

func workspaceKey(w *Workspace, value string) tea.Cmd {
	msg := tea.KeyPressMsg{Code: []rune(value)[0], Text: value}
	switch value {
	case "enter":
		msg = tea.KeyPressMsg{Code: tea.KeyEnter}
	case "tab":
		msg = tea.KeyPressMsg{Code: tea.KeyTab}
	case "esc":
		msg = tea.KeyPressMsg{Code: tea.KeyEscape}
	}
	_, cmd := w.Update(msg)
	return cmd
}

// applyLibrary runs a command and delivers its messages, expanding batches
// such as a task with its spinner. Commands returned by Update are not run,
// so an analysis session's blocking event loop never starts here.
func applyLibrary(w *Workspace, cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			applyLibrary(w, c)
		}
		return
	}
	w.Update(msg)
}
func TestWorkspaceProbeLocalSelectionAnalysisAndDeletion(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	l := library.Library{Root: t.TempDir()}
	if _, err = l.Import(ctx, library.Images, f.Image); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Import(ctx, library.Symbols, f.Symbols); err != nil {
		t.Fatal(err)
	}
	w := NewWorkspace(ctx, engine.Config{DTB: f.DTB, CaseDir: t.TempDir()}, l)
	defer w.Close()
	applyLibrary(w, w.Init())
	if !strings.Contains(w.View().Content, "linux.raw") {
		t.Fatal(w.View().Content)
	}
	applyLibrary(w, workspaceKey(w, "enter"))
	if w.probe.OS != "linux" || w.image == "" {
		t.Fatal(w.probe, w.status)
	}
	// Exact local matching works without a network request or explicit --symbols.
	applyLibrary(w, workspaceKey(w, "o"))
	if w.engine == nil || !w.inAnalysis || w.engine.Config.Symbols == "" {
		t.Fatal(w.status)
	}
	// The command that opens an engine must not cancel its lifetime on return.
	if _, err = w.engine.Run(ctx, "generic.info", nil, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	applyLibrary(w, workspaceKey(w, "L"))
	workspaceKey(w, "x")
	workspaceKey(w, "y")
	if _, err = os.Stat(w.image); err != nil {
		t.Fatal("active image removed", err)
	}
	workspaceKey(w, "c")
	// Replies from a closed analysis cannot update or quit a later session.
	if _, cmd := w.Update(childMsg{seq: w.childSeq - 1, msg: tea.Quit()}); cmd != nil {
		t.Fatal("stale quit escaped session")
	}
	workspaceKey(w, "x")
	workspaceKey(w, "n")
	if _, err = os.Stat(w.image); err != nil {
		t.Fatal("declined delete removed file", err)
	}
	workspaceKey(w, "x")
	applyLibrary(w, workspaceKey(w, "y"))
	if len(w.files) != 0 || w.image != "" {
		t.Fatal(w.files, w.image)
	}
	if _, err = os.Stat(f.Image); err != nil {
		t.Fatal("original evidence removed", err)
	}
}

func TestWorkspaceDownloadRequiresConfirmationAndOfflineFails(t *testing.T) {
	w := NewWorkspace(context.Background(), engine.Config{Offline: true}, library.Library{Root: t.TempDir()})
	defer w.Close()
	w.matches = []library.Candidate{{URL: "https://example.test/kernel.json", Name: "kernel.json", Identity: library.Identity{OS: "linux", Banner: "Linux version 6.1-test"}}}
	if cmd := workspaceKey(w, "d"); cmd != nil || w.pending != "download" {
		t.Fatal("download started before confirmation")
	}
	if cmd := workspaceKey(w, "n"); cmd != nil || w.pending != "" {
		t.Fatal("declined download started")
	}
	workspaceKey(w, "d")
	applyLibrary(w, workspaceKey(w, "y"))
	if !strings.Contains(w.status, "offline") {
		t.Fatal(w.status)
	}
	if _, err := os.Stat(w.library.Directory(library.Symbols)); !os.IsNotExist(err) {
		t.Fatal("offline download wrote files", err)
	}
}

func TestWorkspaceConfirmationKeepsTheNamedFileAfterRefresh(t *testing.T) {
	l := library.Library{Root: t.TempDir()}
	w := NewWorkspace(context.Background(), engine.Config{}, l)
	defer w.Close()
	for _, name := range []string{"first.raw", "second.raw"} {
		if _, err := l.List(library.Images); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.Path(library.Images, name), []byte("evidence"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	applyLibrary(w, w.Init())
	workspaceKey(w, "x")
	// An already queued refresh can change list order while confirmation is open.
	w.Update(libraryFilesMsg{files: []library.File{{Name: "second.raw"}, {Name: "first.raw"}}})
	applyLibrary(w, workspaceKey(w, "y"))
	if _, err := os.Stat(l.Path(library.Images, "first.raw")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.Path(library.Images, "second.raw")); err != nil {
		t.Fatal("deleted a different file", err)
	}
}

func TestWorkspaceTracksImporterEngineAndLifetime(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	second, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	w := NewWorkspace(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, CaseDir: t.TempDir()}, library.Library{Root: t.TempDir()})
	defer w.Close()
	applyLibrary(w, w.openAnalysis())
	if w.engine == nil {
		t.Fatal(w.status)
	}
	firstEngine := w.engine
	current := w.child.(model)
	cmd := current.openImage(second.Image)
	w.child = current
	batch, ok := w.childCommand(cmd)().(tea.BatchMsg)
	if !ok || len(batch) == 0 {
		t.Fatal("import did not start")
	}
	// The first batch command opens the image; the other drives its spinner.
	w.Update(batch[0]())
	if w.engine == nil || w.engine == firstEngine || w.image != second.Image {
		t.Fatal("library retained the old engine", w.image)
	}
	if _, err := w.engine.Run(ctx, "generic.info", nil, engine.RunOptions{}); err != nil {
		t.Fatal("importer canceled engine lifetime", err)
	}
	if current := w.child.(model); platformTabs[current.caps.tab] != "linux" {
		t.Fatal("platform filter lost", current.caps.tab)
	}
}

func TestWorkspaceImportRenameAndView(t *testing.T) {
	w := NewWorkspace(context.Background(), engine.Config{}, library.Library{Root: t.TempDir()})
	defer w.Close()
	applyLibrary(w, w.Init())
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	workspaceKey(w, "i")
	w.input.SetValue(f.Image)
	applyLibrary(w, workspaceKey(w, "enter"))
	applyLibrary(w, w.load())
	workspaceKey(w, "r")
	w.input.SetValue("renamed.raw")
	applyLibrary(w, workspaceKey(w, "enter"))
	if len(w.files) != 1 || w.files[0].Name != "renamed.raw" {
		t.Fatal(w.files, w.status)
	}
	applyLibrary(w, workspaceKey(w, "enter"))
	w.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	view := ansi.Strip(w.View().Content)
	// Details sit inside the right panel; each JSON field keeps its own line.
	kept := false
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "│   \"os\": \"linux\"") && !strings.Contains(line, "\"format\"") {
			kept = true
		}
	}
	if !kept {
		t.Fatal("details lost newlines", view)
	}
	for _, text := range []string{"LOCAL LIBRARY", "renamed.raw", "linux", "candidate", "m match"} {
		if !strings.Contains(view, text) {
			t.Fatal("missing", text, view)
		}
	}
	if path := os.Getenv("GOMEM_LIBRARY_VIEW"); path != "" {
		// Optional review artifact: actual model output, with temporary root removed.
		preview := *w
		preview.library.Root = "."
		preview.image = "./images/renamed.raw"
		view = ansi.Strip(preview.View().Content)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte(view), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
