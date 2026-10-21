package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"image/color"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/library"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Workspace owns the engine lifetime and permits library use without an image.
type Workspace struct {
	local         library.LocalResult
	localCursor   int
	remoteStatus  string
	ctx           context.Context
	config        engine.Config
	library       library.Library
	engine        *engine.Engine
	child         tea.Model
	inAnalysis    bool
	kind          string
	files         []library.File
	cursor        int
	width, height int
	busy          bool
	cancel        context.CancelFunc
	engineCancel  context.CancelFunc
	childCancel   context.CancelFunc
	childSeq      uint64
	status        string
	detail        viewport.Model
	input         textinput.Model
	edit          string
	pending       string
	pendingName   string
	editName      string
	probe         library.Probe
	image         string
	matches       []library.Candidate
	matchCursor   int
	level         level
	st            styles
	spin          spinner.Model
	help          help.Model
	// background is the terminal's reported color, replayed to each new
	// analysis session so it starts in the right palette.
	background color.Color
}
type childMsg struct {
	seq uint64
	msg tea.Msg
}

type libraryFilesMsg struct {
	files []library.File
	err   error
}

type libraryMsg struct {
	local        *library.LocalResult
	remoteStatus string
	cancel       context.CancelFunc
	probe        *library.Probe
	matches      []library.Candidate
	text         string
	path         string
	eng          *engine.Engine
	err          error
}

func NewWorkspace(ctx context.Context, config engine.Config, l library.Library) *Workspace {
	w := &Workspace{ctx: ctx, config: config, library: l, kind: library.Images, width: 120, height: 30, input: textinput.New(), detail: viewport.New(), image: config.Image}
	w.st = newStyles(true)
	w.spin = spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(w.st.accent))
	w.help = help.New()
	w.help.Styles = w.st.help
	w.layout()
	w.say(levelInfo, "i import · enter inspect/select · m match symbols · o open analysis · tab images/symbols")
	return w
}
func (w *Workspace) Close() {
	if w.childCancel != nil {
		w.childCancel()
	}
	if w.cancel != nil {
		w.cancel()
	}
	if w.engine != nil {
		w.engine.Close()
	}
	if w.engineCancel != nil {
		w.engineCancel()
	}
}
func (w *Workspace) Init() tea.Cmd {
	if w.image != "" {
		path := w.image
		return tea.Batch(w.load(), tea.RequestBackgroundColor, w.task(func(ctx context.Context) libraryMsg {
			return probeLocalImage(ctx, w.library, path)
		}))
	}
	return tea.Batch(w.load(), tea.RequestBackgroundColor)
}
func (w *Workspace) load() tea.Cmd {
	l, kind := w.library, w.kind
	return func() tea.Msg {
		files, err := l.List(kind)
		sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
		return libraryFilesMsg{files: files, err: err}
	}
}
func (w *Workspace) selected() (string, bool) {
	if w.cursor < 0 || w.cursor >= len(w.files) {
		return "", false
	}
	return w.files[w.cursor].Name, true
}
func (w *Workspace) task(fn func(context.Context) libraryMsg) tea.Cmd {
	ctx, cancel := context.WithCancel(w.ctx)
	w.cancel = cancel
	w.busy = true
	run := func() tea.Msg {
		result := fn(ctx)
		if result.eng == nil {
			cancel()
		} else {
			result.cancel = cancel
		}
		return result
	}
	return tea.Batch(run, w.spin.Tick)
}
func (w *Workspace) inspect() tea.Cmd {
	name, ok := w.selected()
	if !ok {
		return nil
	}
	path, kind := w.library.Path(w.kind, name), w.kind
	if kind == library.Images {
		w.image = path
		w.probe = library.Probe{}
		w.matches = nil
		w.local = library.LocalResult{}
		w.remoteStatus = ""
		w.config.Symbols = ""
		w.status = "Scanning image for resident kernel identities… ctrl+x cancels"
		return w.task(func(ctx context.Context) libraryMsg {
			return probeLocalImage(ctx, w.library, path)
		})
	}
	if library.IsSourceRecord(path) {
		w.status = "This .source.json file is provenance only; import the full ISF or vmlinux symbol file"
		return nil
	}
	// The scan result is copied: the command runs off the update loop.
	probe := w.probe
	return w.task(func(ctx context.Context) libraryMsg {
		t, err := symbols.LoadContext(ctx, path)
		if err != nil {
			return libraryMsg{err: err}
		}
		if len(probe.Identities) > 0 {
			matched := false
			for _, id := range probe.Identities {
				if id.Matches(t) {
					matched = true
				}
			}
			if !matched {
				return libraryMsg{err: fmt.Errorf("symbols do not match any detected image identity")}
			}
		}
		b, _ := json.MarshalIndent(map[string]any{"metadata": t.Metadata(), "architecture": t.Architecture(), "symbols": len(t.Symbols), "sha256": t.Digest()}, "", "  ")
		return libraryMsg{path: path, text: string(b)}
	})
}
func (w *Workspace) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case childMsg:
		if x.seq != w.childSeq || w.child == nil {
			if opened, ok := x.msg.(openedMsg); ok && opened.eng != nil {
				opened.eng.Close()
			}
			return w, nil
		}
		if _, ok := x.msg.(tea.QuitMsg); ok {
			return w, tea.Quit
		}
		var cmd tea.Cmd
		w.child, cmd = w.child.Update(x.msg)
		w.syncChildEngine()
		return w, w.childCommand(cmd)
	case spinner.TickMsg:
		if x.ID == w.spin.ID() {
			if !w.busy {
				return w, nil
			}
			var cmd tea.Cmd
			w.spin, cmd = w.spin.Update(x)
			return w, cmd
		}
	case tea.BackgroundColorMsg:
		w.background = x.Color
		w.st = newStyles(x.IsDark())
		w.spin.Style = w.st.accent
		w.help.Styles = w.st.help
	case tea.MouseClickMsg:
		if !w.inAnalysis {
			return w, w.click(x.Mouse())
		}
	case tea.MouseWheelMsg:
		if !w.inAnalysis {
			w.wheel(x.Mouse())
			return w, nil
		}
	case libraryFilesMsg:
		if x.err != nil {
			w.say(levelError, x.err.Error())
		} else {
			w.files = x.files
			w.cursor = min(w.cursor, max(0, len(w.files)-1))
		}
		return w, nil
	case libraryMsg:
		w.busy = false
		w.cancel = nil
		if x.err != nil {
			w.say(levelError, x.err.Error())
			return w, nil
		}
		if x.probe != nil {
			w.probe = *x.probe
		}
		if x.local != nil {
			w.local = *x.local
			w.localCursor = 0
		}
		if x.matches != nil {
			w.matches = x.matches
			w.matchCursor = 0
		}
		if x.remoteStatus != "" {
			w.remoteStatus = x.remoteStatus
		}
		if x.probe != nil || x.local != nil || x.matches != nil {
			if w.config.Symbols == "" {
				if path, err := w.local.Unique(); err == nil {
					w.config.Symbols = path
				}
			}
			w.showMatches()
			w.level = levelSuccess
			w.status = fmt.Sprintf("%d local table(s), %d local diagnostic(s), %d remote URL(s). s selects local; d confirms download.", len(w.local.Matches), len(w.local.Diagnostics), len(w.matches))
			if len(w.local.Matches) == 0 && len(w.local.Diagnostics) > 0 {
				w.level = levelWarn
				w.status += " " + w.local.Diagnostics[0].Status + ": " + w.local.Diagnostics[0].Message
			}
			if w.remoteStatus != "" {
				w.status += " " + w.remoteStatus
			}
		}
		if x.text != "" {
			w.detail.SetContent(commandText(x.text))
			w.detail.GotoTop()
		}
		if x.path != "" {
			w.config.Symbols = x.path
			w.say(levelSuccess, "Selected symbols: "+x.path)
		}
		if x.eng != nil {
			if w.engine != nil {
				w.engine.Close()
			}
			if w.engineCancel != nil {
				w.engineCancel()
			}
			w.engineCancel = x.cancel
			w.engine = x.eng
			w.childSeq++
			childCtx, childCancel := context.WithCancel(w.ctx)
			w.childCancel = childCancel
			w.child = New(childCtx, Options{Config: x.eng.Config, Engine: x.eng, Open: func(ctx context.Context, c engine.Config) (*engine.Engine, error) {
				// The importer uses a temporary request context; an opened engine
				// must instead live until this analysis session is closed.
				c.Offline = true
				life, cancel := context.WithCancel(childCtx)
				stop := context.AfterFunc(ctx, cancel)
				e, err := engine.Open(life, c)
				stop()
				if err != nil {
					cancel()
				} else if ctx.Err() != nil {
					e.Close()
					cancel()
					return nil, ctx.Err()
				}
				return e, err
			}})
			w.inAnalysis = true
			w.child, _ = w.child.Update(tea.WindowSizeMsg{Width: w.width, Height: w.height})
			if w.background != nil {
				w.child, _ = w.child.Update(tea.BackgroundColorMsg{Color: w.background})
			}
			return w, w.childCommand(w.child.Init())
		}
		if x.path != "" || strings.HasPrefix(x.text, "Imported: ") {
			return w, w.load()
		}
		return w, nil
	case tea.WindowSizeMsg:
		w.width, w.height = x.Width, x.Height
		w.layout()
	case tea.KeyPressMsg:
		if x.String() == "ctrl+c" {
			w.Close()
			return w, tea.Quit
		}
		if w.inAnalysis {
			if current, ok := w.child.(model); x.String() == "L" && ok && !current.prompt.active() && !current.form.open && !current.launcher.open {
				w.inAnalysis = false
				return w, w.load()
			}
			break
		}
		if w.busy {
			if x.String() == "ctrl+x" && w.cancel != nil {
				w.cancel()
				w.say(levelWarn, "Canceling…")
			}
			return w, nil
		}
		if w.pending != "" {
			action := w.pending
			w.pending = ""
			if x.String() != "y" {
				w.say(levelWarn, "Canceled")
				return w, nil
			}
			if action == "delete" {
				name := w.pendingName
				if w.activeFile(w.kind, name) {
					w.status = "Close the analysis session before deleting its image or symbols"
					return w, nil
				}
				err := w.library.Remove(w.kind, name)
				if err != nil {
					w.status = err.Error()
				} else {
					w.status = "Removed " + name
					if sameLibraryPath(w.library.Path(w.kind, name), w.image) {
						w.image = ""
						w.probe = library.Probe{}
						w.local = library.LocalResult{}
						w.matches = nil
					}
					if sameLibraryPath(w.library.Path(w.kind, name), w.config.Symbols) {
						w.config.Symbols = ""
					}
				}
				return w, w.load()
			}
			c := w.matches[w.matchCursor]
			l, remote := w.library, library.Remote{Offline: w.config.Offline}
			w.status = "Downloading and validating kernel identity… ctrl+x cancels"
			return w, w.task(func(ctx context.Context) libraryMsg {
				path, err := remote.Download(ctx, l, c)
				return libraryMsg{path: path, err: err}
			})
		}
		if w.edit != "" {
			if x.String() == "esc" {
				w.edit = ""
				w.input.Blur()
				return w, nil
			}
			if x.String() == "enter" {
				value, action := w.input.Value(), w.edit
				w.edit = ""
				w.input.Blur()
				if action == "rename" {
					name := w.editName
					if w.activeFile(w.kind, name) {
						w.status = "Close the analysis session before renaming its image or symbols"
						return w, nil
					}
					err := w.library.Rename(w.kind, name, value)
					if err != nil {
						w.status = err.Error()
					} else {
						old, path := w.library.Path(w.kind, name), w.library.Path(w.kind, value)
						if sameLibraryPath(w.image, old) {
							w.image = path
						}
						if sameLibraryPath(w.config.Symbols, old) {
							w.config.Symbols = path
						}
						w.status = "Renamed " + name
					}
					return w, w.load()
				}
				l, kind := w.library, w.kind
				return w, w.task(func(ctx context.Context) libraryMsg {
					path, err := l.Import(ctx, kind, value)
					return libraryMsg{text: "Imported: " + path, err: err}
				})
			}
			var cmd tea.Cmd
			w.input, cmd = w.input.Update(x)
			return w, cmd
		}
		switch x.String() {
		case "q":
			return w, tea.Quit
		case "tab":
			if w.kind == library.Images {
				return w, w.switchKind(library.Symbols)
			}
			return w, w.switchKind(library.Images)
		case "up", "k":
			w.cursor = max(0, w.cursor-1)
		case "down", "j":
			w.cursor = min(max(0, len(w.files)-1), w.cursor+1)
		case "ctrl+up":
			w.detail.ScrollUp(3)
		case "ctrl+down":
			w.detail.ScrollDown(3)
		case "ctrl+left":
			w.detail.ScrollLeft(8)
		case "ctrl+right":
			w.detail.ScrollRight(8)
		case "[":
			w.matchCursor = max(0, w.matchCursor-1)
		case "]":
			w.matchCursor = min(max(0, len(w.matches)-1), w.matchCursor+1)
		case "R":
			return w, w.load()
		case "i", "r":
			w.edit = "import"
			w.input.SetValue("")
			w.input.Placeholder = "Path to local file (copied; original preserved)"
			if x.String() == "r" {
				name, ok := w.selected()
				if !ok {
					w.edit = ""
					return w, nil
				}
				w.edit = "rename"
				w.editName = name
				w.input.SetValue(name)
			}
			return w, w.input.Focus()
		case "x":
			if name, ok := w.selected(); ok {
				w.pending = "delete"
				w.pendingName = name
				w.status = "Delete local copy " + name + "? y confirms; any other key cancels"
			}
		case "enter":
			return w, w.inspect()
		case "m", "l", "M":
			return w, w.matchSymbols(x.String() == "l", x.String() == "M")
		case "<":
			w.localCursor = max(0, w.localCursor-1)
		case ">":
			w.localCursor = min(max(0, len(w.local.Matches)-1), w.localCursor+1)
		case "s":
			if len(w.local.Matches) == 0 {
				w.status = "No matching local table; press l to scan sysmbols/"
				return w, nil
			}
			entry := w.local.Matches[w.localCursor].Table
			return w, w.task(func(ctx context.Context) libraryMsg {
				_, err := symbols.LoadEntry(ctx, entry)
				return libraryMsg{path: entry.Location, err: err}
			})
		case "d":
			if len(w.matches) > 0 {
				w.pending = "download"
				w.status = "Download " + w.matches[w.matchCursor].URL + "? y confirms; any other key cancels"
			}
		case "c":
			w.childSeq++
			if w.childCancel != nil {
				w.childCancel()
				w.childCancel = nil
			}
			if w.engine != nil {
				w.engine.Close()
				w.engine = nil
				w.child = nil
			}
			if w.engineCancel != nil {
				w.engineCancel()
				w.engineCancel = nil
			}
			w.status = "Analysis closed"
		case "a":
			if w.child != nil {
				w.inAnalysis = true
			}
		case "o":
			return w, w.openAnalysis()
		}
		return w, nil
	}
	if w.child != nil {
		var cmd tea.Cmd
		w.child, cmd = w.child.Update(msg)
		return w, w.childCommand(cmd)
	}
	return w, nil
}

func (w *Workspace) openAnalysis() tea.Cmd {
	if w.image == "" {
		w.status = "Select an image and press enter first"
		return nil
	}
	c, l, p := w.config, w.library, w.probe
	c.Image = w.image
	// The manager performs all downloads through its explicit confirmation flow.
	c.Offline = true
	if c.OS == "" && p.OS != "unknown" {
		c.OS = p.OS
	}
	if w.child != nil {
		w.status = "Press c to close the current analysis before opening another image"
		return nil
	}
	w.status = "Opening analysis with local symbols…"
	return w.task(func(ctx context.Context) libraryMsg {
		if c.Symbols == "" && len(p.Identities) > 0 {
			local, err := l.MatchLocal(ctx, p)
			if err != nil {
				return libraryMsg{err: err}
			}
			path, err := local.Unique()
			if err != nil {
				return libraryMsg{err: err}
			}
			c.Symbols = path
		}
		e, err := engine.Open(ctx, c)
		return libraryMsg{eng: e, err: err}
	})
}

func (w *Workspace) activeFile(kind, name string) bool {
	if w.engine == nil {
		return false
	}
	info, err := os.Stat(w.library.Path(kind, name))
	if err != nil {
		return false
	}
	for _, path := range []string{w.engine.Config.Image, w.engine.Config.Symbols} {
		other, err := os.Stat(path)
		if err == nil && os.SameFile(info, other) {
			return true
		}
	}
	return false
}

func (w *Workspace) childCommand(cmd tea.Cmd) tea.Cmd { return wrapChildCommand(w.childSeq, cmd) }
func wrapChildCommand(seq uint64, cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg {
		msg := cmd()
		switch x := msg.(type) {
		case tea.BatchMsg:
			cmds := make([]tea.Cmd, len(x))
			for i, c := range x {
				cmds[i] = wrapChildCommand(seq, c)
			}
			return tea.Batch(cmds...)()
		case tick, started, done, pageMsg, treeMsg, commandMsg, tasksMsg, historyMsg, progressMsg, openedMsg, spinner.TickMsg, tea.QuitMsg:
			return childMsg{seq, msg}
		}
		return msg
	}
}

// The existing image importer can replace the analysis engine independently
// of the library. Keep ownership and active-file protection on the new image.
func (w *Workspace) syncChildEngine() {
	current, ok := w.child.(model)
	if !ok || current.engine == w.engine {
		return
	}
	if w.engineCancel != nil {
		w.engineCancel()
		w.engineCancel = nil
	}
	w.engine = current.engine
	w.probe = library.Probe{}
	w.matches = nil
	w.local = library.LocalResult{}
	w.remoteStatus = ""
	if current.engine != nil {
		offline := w.config.Offline
		w.config = current.engine.Config
		w.config.Offline = offline
		w.image = current.engine.Config.Image
	} else {
		w.image = ""
	}
}

func probeLocalImage(ctx context.Context, l library.Library, path string) libraryMsg {
	p, err := library.ProbeFile(ctx, path)
	if err != nil {
		return libraryMsg{err: err}
	}
	local, err := l.MatchLocal(ctx, p)
	return libraryMsg{probe: &p, local: &local, err: err}
}
func (w *Workspace) showMatches() {
	// Keep the OS and observed identities at the top of the detail viewport.
	probe, _ := json.MarshalIndent(w.probe, "", "  ")
	matching, _ := json.MarshalIndent(struct {
		Local        library.LocalResult `json:"local"`
		Remote       []library.Candidate `json:"remote"`
		RemoteStatus string              `json:"remote_status"`
	}{w.local, w.matches, w.remoteStatus}, "", "  ")
	w.detail.SetContent(commandText(string(probe) + "\n\n" + string(matching)))
	w.detail.GotoTop()
	w.layout()
}
func (w *Workspace) matchSymbols(localOnly, forceRemote bool) tea.Cmd {
	if len(w.probe.Identities) == 0 {
		w.status = "Inspect an image with enter first; no kernel identity available"
		return nil
	}
	p, l, offline := w.probe, w.library, w.config.Offline
	w.status = "Matching local kernel identities… ctrl+x cancels"
	return w.task(func(ctx context.Context) libraryMsg {
		local, err := l.MatchLocal(ctx, p)
		if err != nil {
			return libraryMsg{err: err}
		}
		msg := libraryMsg{local: &local, matches: []library.Candidate{}, remoteStatus: "Remote not queried: matching local tables available"}
		if localOnly || offline {
			msg.remoteStatus = "Local matching only"
			return msg
		}
		if len(local.Matches) > 0 && !forceRemote {
			return msg
		}
		matches, err := (library.Remote{}).Lookup(ctx, p)
		if ctx.Err() != nil {
			return libraryMsg{err: ctx.Err()}
		}
		if err != nil {
			msg.remoteStatus = "Remote lookup failed: " + err.Error()
			return msg
		}
		msg.matches = matches
		msg.remoteStatus = "Remote lookup complete"
		return msg
	})
}

func sameLibraryPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	left, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	right, err := filepath.Abs(b)
	return err == nil && left == right
}
