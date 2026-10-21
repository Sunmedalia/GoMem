package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/internal/store"
)

// launcherSection is one focusable part of the importer. Image and symbol
// management can join as further sections without changing the routing.
type launcherSection int

const (
	sectionPath launcherSection = iota
	sectionBrowse
	sectionRecent
	sectionCount
)

type fileEntry struct {
	name string
	dir  bool
	size int64
}

// launcher picks an image to open: a typed path with completion, a directory
// browser, or an image this case opened before.
type launcher struct {
	open    bool
	section launcherSection
	path    textinput.Model
	dir     string
	entries []fileEntry
	hidden  bool
	cursor  int
	top     int
	recent  []store.ImageRecord
	rcursor int
	rtop    int
	err     string
	opening bool
	target  string
	started time.Time
	cancel  context.CancelFunc
}

func newLauncher(image string) launcher {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 4096
	in.Placeholder = "path to a memory image (raw, LiME, AVML, ELF core, Windows crash dump)"
	in.SetValue(image)
	l := launcher{path: in}
	dir := filepath.Dir(image)
	if image == "" {
		dir, _ = os.Getwd()
	}
	l.chdir(dir)
	return l
}

// expandHome resolves a leading ~ to the user's home directory.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// chdir lists dir into the browser, directories first, with a parent entry.
func (l *launcher) chdir(dir string) {
	abs, err := filepath.Abs(expandHome(dir))
	if err != nil {
		l.err = err.Error()
		return
	}
	list, err := os.ReadDir(abs)
	if err != nil {
		l.err = err.Error()
		return
	}
	l.dir, l.err = abs, ""
	l.entries = l.entries[:0]
	if parent := filepath.Dir(abs); parent != abs {
		l.entries = append(l.entries, fileEntry{name: "..", dir: true})
	}
	var files []fileEntry
	for _, d := range list {
		if !l.hidden && strings.HasPrefix(d.Name(), ".") {
			continue
		}
		e := fileEntry{name: d.Name(), dir: d.IsDir()}
		if info, err := d.Info(); err == nil {
			// Follow links so a linked directory browses like one.
			if info.Mode()&os.ModeSymlink != 0 {
				if target, err := os.Stat(filepath.Join(abs, d.Name())); err == nil {
					info, e.dir = target, target.IsDir()
				}
			}
			e.size = info.Size()
		}
		if e.dir {
			l.entries = append(l.entries, e)
		} else {
			files = append(files, e)
		}
	}
	l.entries = append(l.entries, files...)
	l.cursor, l.top = 0, 0
}

func (l launcher) selectedEntry() (fileEntry, bool) {
	if l.cursor >= 0 && l.cursor < len(l.entries) {
		return l.entries[l.cursor], true
	}
	return fileEntry{}, false
}

// activate enters the selected directory, or returns the selected file's path.
func (l *launcher) activate() (string, bool) {
	e, ok := l.selectedEntry()
	if !ok {
		return "", false
	}
	if e.name == ".." {
		l.up()
		return "", false
	}
	full := filepath.Join(l.dir, e.name)
	if e.dir {
		l.chdir(full)
		return "", false
	}
	l.path.SetValue(full)
	l.path.CursorEnd()
	return full, true
}

func (l *launcher) up() {
	from := filepath.Base(l.dir)
	l.chdir(filepath.Dir(l.dir))
	for i, e := range l.entries {
		if e.name == from {
			l.cursor = i
		}
	}
}

// complete extends the typed path to the longest unambiguous name in its
// directory; it reports whether the text changed.
func (l *launcher) complete() bool {
	typed := l.path.Value()
	dirPart, prefix := filepath.Split(typed)
	dir := expandHome(dirPart)
	if dir == "" {
		dir = "."
	}
	list, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	var matches []os.DirEntry
	for _, d := range list {
		if strings.HasPrefix(d.Name(), prefix) && (strings.HasPrefix(prefix, ".") || !strings.HasPrefix(d.Name(), ".")) {
			matches = append(matches, d)
		}
	}
	if len(matches) == 0 {
		return false
	}
	common := matches[0].Name()
	for _, d := range matches[1:] {
		for !strings.HasPrefix(d.Name(), common) {
			_, n := utf8.DecodeLastRuneInString(common)
			common = common[:len(common)-n]
		}
	}
	next := dirPart + common
	if len(matches) == 1 {
		if info, err := os.Stat(filepath.Join(dir, common)); err == nil && info.IsDir() {
			next += string(os.PathSeparator)
			l.chdir(filepath.Join(dir, common))
		}
	}
	if next == typed {
		return false
	}
	l.path.SetValue(next)
	l.path.CursorEnd()
	return true
}

func (l *launcher) setRecent(recs []store.ImageRecord, err error) {
	l.recent, l.rcursor, l.rtop = recs, 0, 0
	if err != nil {
		l.err = "recent images: " + err.Error()
	}
}

// recentImages reads the case's image history. Without an open engine the
// case is opened only for the read, so the lock is free again for Open.
func recentImages(ctx context.Context, eng *engine.Engine, caseDir string) ([]store.ImageRecord, error) {
	if eng != nil {
		return eng.Store.Images(ctx)
	}
	if caseDir == "" {
		return nil, nil
	}
	s, err := store.Open(caseDir)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Images(ctx)
}

// focusSection moves focus to section s, wrapping; only the path takes typing.
func (l *launcher) focusSection(s launcherSection) tea.Cmd {
	l.section = (s%sectionCount + sectionCount) % sectionCount
	if l.section == sectionPath {
		return l.path.Focus()
	}
	l.path.Blur()
	return nil
}

// choose activates the focused list's entry and returns an image path to
// open, if the entry is one.
func (l *launcher) choose() (string, bool) {
	switch l.section {
	case sectionBrowse:
		return l.activate()
	case sectionRecent:
		if l.rcursor < len(l.recent) {
			p := l.recent[l.rcursor].Path
			l.path.SetValue(p)
			return p, true
		}
	}
	return "", false
}

// move steps the list of the focused section.
func (l *launcher) move(delta, rows int) {
	switch l.section {
	case sectionBrowse:
		l.cursor, l.top = step(l.cursor, l.top, delta, len(l.entries), rows)
	case sectionRecent:
		l.rcursor, l.rtop = step(l.rcursor, l.rtop, delta, len(l.recent), rows)
	}
}

func step(cursor, top, delta, n, rows int) (int, int) {
	cursor = max(0, min(n-1, cursor+delta))
	if cursor < top {
		top = cursor
	}
	if cursor >= top+rows {
		top = cursor - rows + 1
	}
	return max(0, cursor), max(0, top)
}

// rows is how many list entries fit: the panel's inner height less the
// title, path, message and column header lines and the configuration line.
func launcherRows(height int) int { return max(1, height-2-5) }

func (l launcher) View(st styles, cfg engine.Config, width, height int, spin string) string {
	var b strings.Builder
	title := st.accent.Render("IMPORT IMAGE")
	if l.opening {
		title += "  " + spin + " " + st.muted.Render(fmt.Sprintf("opening %s · hashing and detecting · %s · esc cancels", render.Safe(filepath.Base(l.target)), time.Since(l.started).Round(time.Second)))
	}
	b.WriteString(title + "\n")
	label := st.muted
	if l.section == sectionPath {
		label = st.strong
	}
	b.WriteString(label.Render("path  ") + l.path.View() + "\n")
	if l.err != "" {
		b.WriteString(st.err.Render(render.Safe(l.err)))
	}
	b.WriteString("\n")

	half := (width - 2) / 2
	rows := launcherRows(height)
	head := func(s launcherSection, text string) string {
		if l.section == s {
			return st.strong.Render(text)
		}
		return st.heading.Render(text)
	}
	left := []string{head(sectionBrowse, "BROWSE ") + st.muted.Render(fitTail(render.Safe(l.dir), max(4, half-7)))}
	for i := l.top; i < min(len(l.entries), l.top+rows); i++ {
		e := l.entries[i]
		name, size := render.Safe(e.name), ""
		if e.dir {
			name += string(os.PathSeparator)
		} else {
			size = sizeText(uint64(e.size))
		}
		line := fit(name, max(4, half-12)) + " " + fmt.Sprintf("%10s", size)
		left = append(left, l.item(st, line, i == l.cursor, l.section == sectionBrowse))
	}
	right := []string{head(sectionRecent, "RECENT IN THIS CASE")}
	if len(l.recent) == 0 {
		right = append(right, st.muted.Render("none yet"))
	}
	for i := l.rtop; i < min(len(l.recent), l.rtop+rows); i++ {
		r := l.recent[i]
		note := fmt.Sprintf("%s %s %s", r.Format, sizeText(r.Size), short(r.SHA256))
		if _, err := os.Stat(r.Path); err != nil {
			note = "missing · " + note
		}
		line := fitTail(render.Safe(r.Path), max(4, half-ansi.StringWidth(note)-1)) + " " + note
		right = append(right, l.item(st, line, i == l.rcursor, l.section == sectionRecent))
	}
	for i := 0; i <= rows; i++ {
		var lt, rt string
		if i < len(left) {
			lt = left[i]
		}
		if i < len(right) {
			rt = right[i]
		}
		b.WriteString(fit(lt, half) + "  " + rt + "\n")
	}
	b.WriteString(st.muted.Render(ansi.Truncate(configSummary(cfg), width, "…")))
	return b.String()
}

func (l launcher) item(st styles, line string, selected, focused bool) string {
	switch {
	case selected && focused:
		return st.selected.Render(line)
	case selected:
		return st.selectedDim.Render(line)
	}
	return line
}

// configSummary shows the settings an import reuses from the command line.
// Symbols say where automatic matching will plug in once it exists.
func configSummary(c engine.Config) string {
	or := func(v, d string) string {
		if v == "" {
			return d
		}
		return render.Safe(v)
	}
	parts := []string{
		"os " + or(c.OS, "auto"),
		"arch " + or(c.Arch, "auto"),
		"symbols " + or(c.Symbols, "none (automatic matching planned)"),
		"dtb " + or(c.DTB, "auto"),
		"case " + or(c.CaseDir, "in memory"),
	}
	if c.Offline {
		parts = append(parts, "offline")
	}
	return strings.Join(parts, " · ")
}

// sizeText formats a byte count with binary units.
func sizeText(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
