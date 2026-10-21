package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/library"
	"github.com/Sunmedalia/GoMem/internal/render"
)

// The library screen: a file panel on the left and the selection, download
// candidates and details on the right, framed like the analysis screen.
const (
	libraryFileTop   = 3 // header row, border, kind tabs
	librarySelection = 6 // image, symbols, scan, local match, diagnostics and analysis lines
	libraryMaxCands  = 4
)

func (w *Workspace) say(l level, text string) { w.status, w.level = text, l }

// sizes returns the panel widths and their shared height.
func (w *Workspace) sizes() (left, right, height int) {
	left = min(48, max(30, w.width*2/5))
	return left, w.width - left, max(6, w.height-3)
}

// candidateRows is how many download candidates the right panel lists.
func (w *Workspace) candidateRows() int { return min(libraryMaxCands, len(w.matches)) }

// layout sizes the detail viewport to the space left in the right panel.
func (w *Workspace) layout() {
	_, right, height := w.sizes()
	used := librarySelection + 1 + 1 // selection, blank, detail heading
	if n := w.candidateRows(); n > 0 {
		used += 1 + n + 1 // heading, rows, blank
	}
	w.detail.SetWidth(max(10, right-4))
	w.detail.SetHeight(max(1, height-2-used))
	w.input.SetWidth(max(20, w.width-12))
	w.help.SetWidth(w.width)
}

// candidateTop is the screen row of the first candidate line.
func (w *Workspace) candidateTop() int { return 2 + librarySelection + 1 + 1 }

func (w *Workspace) fileRows() int {
	_, _, height := w.sizes()
	return max(1, height-3)
}

// fileWindow returns the first visible file so the cursor stays on screen.
func (w *Workspace) fileWindow() int {
	return max(0, w.cursor-w.fileRows()+1)
}

// marker flags a file selected for analysis or held by the open analysis.
func (w *Workspace) marker(kind, name string) string {
	path := w.library.Path(kind, name)
	switch {
	case w.activeFile(kind, name):
		return w.st.warn.Render("● ")
	case path == w.image || path == w.config.Symbols:
		return w.st.accent.Render("◆ ")
	}
	return "  "
}

func (w *Workspace) filePanel(width, height int) []string {
	var b strings.Builder
	tab := func(kind, label string) string {
		if w.kind == kind {
			return w.st.strong.Underline(true).Render(label)
		}
		return w.st.muted.Render(label)
	}
	b.WriteString(tab(library.Images, "images") + " " + tab(library.Symbols, "symbols") + w.st.muted.Render(fmt.Sprintf("  %d · tab", len(w.files))) + "\n")
	inner := width - 4
	if len(w.files) == 0 {
		b.WriteString(w.st.muted.Render("No local files. Press i to import a copy."))
	}
	top := w.fileWindow()
	for i := top; i < min(len(w.files), top+w.fileRows()); i++ {
		f := w.files[i]
		size := sizeText(uint64(f.Size))
		line := fit(render.Safe(f.Name), max(4, inner-2-len(size)-1)) + " " + size
		switch {
		case i == w.cursor && !w.inputActive():
			line = w.st.selected.Render(line)
		case i == w.cursor:
			line = w.st.selectedDim.Render(line)
		}
		b.WriteString(w.marker(w.kind, f.Name) + line + "\n")
	}
	return w.st.panel(strings.TrimSuffix(b.String(), "\n"), width, height, true)
}

func (w *Workspace) selectionPanel(width, height int) []string {
	inner := width - 4
	var b strings.Builder
	field := func(label, value string) {
		b.WriteString(w.st.muted.Render(fit(label, 9)) + fitTail(value, max(4, inner-9)) + "\n")
	}
	none := w.st.muted.Render("none")
	image, symbols := none, none
	if w.image != "" {
		image = render.Safe(filepath.Base(w.image))
	}
	if w.config.Symbols != "" {
		symbols = render.Safe(filepath.Base(w.config.Symbols))
	}
	field("image", image)
	field("symbols", symbols)
	scan := w.st.muted.Render("not scanned · enter scans the selected image")
	if w.probe.Status != "" {
		scan = render.Safe(fmt.Sprintf("%s · %s · %s · %d identit%s", w.probe.Format, w.probe.OS, w.probe.Status, len(w.probe.Identities), map[bool]string{true: "y", false: "ies"}[len(w.probe.Identities) == 1]))
	}
	field("scan", scan)
	local := w.st.muted.Render("none · l local · m local first · M remote")
	if len(w.local.Matches) > 0 {
		local = render.Safe(fmt.Sprintf("%d/%d · %s · </> select · s use", w.localCursor+1, len(w.local.Matches), filepath.Base(w.local.Matches[w.localCursor].Table.Location)))
	}
	field("local", local)
	field("matching", render.Safe(fmt.Sprintf("%d local diagnostic(s) · %s", len(w.local.Diagnostics), w.remoteStatus)))
	analysis := w.st.muted.Render("closed · o opens")
	if w.engine != nil {
		analysis = w.st.success.Render("open") + w.st.muted.Render(" · "+render.Safe(filepath.Base(w.engine.Config.Image))+" · a resume · c close")
	}
	field("analysis", analysis)
	b.WriteString("\n")
	if n := w.candidateRows(); n > 0 {
		b.WriteString(w.st.accent.Render("CANDIDATES") + w.st.muted.Render(fmt.Sprintf("  %d/%d · [ ] select · d download", w.matchCursor+1, len(w.matches))) + "\n")
		top := max(0, min(w.matchCursor-n+1, len(w.matches)-n))
		for i := top; i < top+n; i++ {
			c := w.matches[i]
			line := fit(render.Safe(c.Name), max(4, inner/3)) + " " + w.st.muted.Render(render.Safe(c.URL))
			if i == w.matchCursor {
				line = w.st.strong.Render("› ") + line
			} else {
				line = "  " + line
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(w.st.accent.Render("DETAIL") + w.st.muted.Render("  ctrl+arrows scroll") + "\n")
	b.WriteString(w.detail.View())
	return w.st.panel(b.String(), width, height, false)
}

func (w *Workspace) inputActive() bool { return w.edit != "" }

func (w *Workspace) statusLine() string {
	text := render.Safe(w.status)
	switch w.level {
	case levelSuccess:
		text = w.st.success.Render(text)
	case levelWarn:
		text = w.st.warn.Render(text)
	case levelError:
		text = w.st.err.Render(text)
	default:
		text = w.st.muted.Render(text)
	}
	if w.busy {
		text = w.spin.View() + " " + text
	}
	if w.pending != "" {
		text = w.st.warn.Render("confirm ") + text
	}
	return ansi.Truncate(text, w.width, "…")
}

func (w *Workspace) hints() []key.Binding {
	b := func(k, d string) key.Binding { return key.NewBinding(key.WithKeys(k), key.WithHelp(k, d)) }
	switch {
	case w.edit != "":
		return []key.Binding{b("enter", w.edit), b("esc", "cancel")}
	case w.pending != "":
		return []key.Binding{b("y", "confirm"), b("any", "cancel")}
	case w.busy:
		return []key.Binding{b("ctrl+x", "cancel")}
	}
	out := []key.Binding{b("enter", "scan/select"), b("l", "local"), b("m", "local first"), b("M", "remote"), b("</>", "local table"), b("s", "select"), b("[/]", "candidate"), b("d", "download"), b("o", "analysis"), b("tab", "images/symbols"), b("i", "import"), b("r", "rename"), b("x", "delete"), b("R", "refresh")}
	if w.engine != nil {
		out = append(out, b("a", "resume"), b("c", "close"))
	}
	return append(out, b("q", "quit"))
}

func (w *Workspace) View() tea.View {
	if w.inAnalysis && w.child != nil {
		return w.child.View()
	}
	if w.width < minWidth || w.height < minHeight {
		v := tea.NewView(fmt.Sprintf("GoMem needs at least %d columns × %d rows. Resize the terminal, or q to quit.", minWidth, minHeight))
		v.AltScreen = true
		return v
	}
	left, right, height := w.sizes()
	header := w.st.strong.Render(" GoMem ") + w.st.muted.Render("/  LOCAL LIBRARY  /  "+render.Safe(w.library.Directory(w.kind))+string(os.PathSeparator))
	footer := w.statusLine()
	if w.edit != "" {
		footer = w.st.strong.Render(w.edit+" ") + w.input.View()
	}
	content := ansi.Truncate(header, w.width, "…") + "\n" +
		row(w.filePanel(left, height), w.selectionPanel(right, height)) + "\n" +
		footer + "\n" + ansi.Truncate(w.help.ShortHelpView(w.hints()), w.width, "…")
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "GoMem — Images and symbols"
	return v
}

// click selects a file or candidate; clicking the selected file again scans
// or selects it, as enter does.
func (w *Workspace) click(m tea.Mouse) tea.Cmd {
	if m.Button != tea.MouseLeft || w.busy || w.edit != "" || w.pending != "" {
		return nil
	}
	left, _, _ := w.sizes()
	if m.Y == 2 && m.X < left {
		switch x := m.X - 2; {
		case x >= 0 && x < len("images") && w.kind != library.Images:
			return w.switchKind(library.Images)
		case x > len("images") && x <= len("images symbols") && w.kind != library.Symbols:
			return w.switchKind(library.Symbols)
		}
		return nil
	}
	if m.X < left {
		i := w.fileWindow() + m.Y - libraryFileTop
		if m.Y < libraryFileTop || i >= len(w.files) {
			return nil
		}
		if i != w.cursor {
			w.cursor = i
			return nil
		}
		return w.inspect()
	}
	if i := m.Y - w.candidateTop(); i >= 0 && i < w.candidateRows() {
		n := w.candidateRows()
		w.matchCursor = max(0, min(w.matchCursor-n+1, len(w.matches)-n)) + i
	}
	return nil
}

func (w *Workspace) wheel(m tea.Mouse) {
	left, _, _ := w.sizes()
	delta := map[tea.MouseButton]int{tea.MouseWheelUp: -1, tea.MouseWheelDown: 1}[m.Button]
	if m.X < left {
		w.cursor = max(0, min(len(w.files)-1, w.cursor+delta))
	} else if delta < 0 {
		w.detail.ScrollUp(3)
	} else if delta > 0 {
		w.detail.ScrollDown(3)
	}
}

func (w *Workspace) switchKind(kind string) tea.Cmd {
	w.kind = kind
	w.cursor = 0
	return w.load()
}
