package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type promptMode int

const (
	promptNone promptMode = iota
	promptFilter
	promptCommand
	promptSearch
)

const historyLimit = 200

// prompt is the bottom input line with per-session command history.
type prompt struct {
	input   textinput.Model
	mode    promptMode
	history []string
	pos     int
	draft   string
}

func newPrompt() prompt {
	input := textinput.New()
	input.CharLimit = 4096
	input.Prompt = "› "
	input.SetWidth(70)
	return prompt{input: input}
}

func (p *prompt) open(mode promptMode, placeholder, value string) tea.Cmd {
	p.mode = mode
	p.input.Placeholder = placeholder
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.pos = len(p.history)
	p.draft = ""
	return p.input.Focus()
}

func (p *prompt) close() {
	p.mode = promptNone
	p.input.Blur()
}

func (p prompt) active() bool { return p.mode != promptNone }

// record appends a command, collapsing an immediate repeat.
func (p *prompt) record(line string) {
	if line == "" || (len(p.history) > 0 && p.history[len(p.history)-1] == line) {
		return
	}
	p.history = append(p.history, line)
	if len(p.history) > historyLimit {
		p.history = p.history[len(p.history)-historyLimit:]
	}
}

// recall steps through history; past the newest entry it restores the draft.
func (p *prompt) recall(delta int) {
	if len(p.history) == 0 {
		return
	}
	if p.pos == len(p.history) {
		p.draft = p.input.Value()
	}
	p.pos = max(0, min(len(p.history), p.pos+delta))
	if p.pos == len(p.history) {
		p.input.SetValue(p.draft)
	} else {
		p.input.SetValue(p.history[p.pos])
	}
	p.input.CursorEnd()
}

// runArgs parses "run NAME key=value…" arguments after the verb.
func runArgs(args []string) (string, map[string]string, error) {
	params := map[string]string{}
	for _, v := range args[1:] {
		k, val, ok := strings.Cut(v, "=")
		if !ok {
			return "", nil, fmt.Errorf("Parameters use key=value")
		}
		params[k] = val
	}
	return args[0], params, nil
}
