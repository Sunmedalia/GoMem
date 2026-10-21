package tui

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// paramForm edits a capability's parameters before it runs.
type paramForm struct {
	open   bool
	spec   plugin.Spec
	inputs []textinput.Model
	focus  int
	err    string
}

func newForm(spec plugin.Spec, width int) paramForm {
	f := paramForm{open: true, spec: spec}
	for _, p := range spec.Parameters {
		in := textinput.New()
		in.Prompt = ""
		in.CharLimit = 4096
		in.SetValue(p.Default)
		in.SetWidth(max(10, width-maxLabel-6))
		f.inputs = append(f.inputs, in)
	}
	return f
}

// focusField moves to field i, wrapping, and focuses its input.
func (f *paramForm) focusField(i int) tea.Cmd {
	if len(f.inputs) == 0 {
		return nil
	}
	f.inputs[f.focus].Blur()
	f.focus = (i%len(f.inputs) + len(f.inputs)) % len(f.inputs)
	return f.inputs[f.focus].Focus()
}

func (f paramForm) last() bool { return f.focus >= len(f.inputs)-1 }

// toggle flips a boolean field; it reports whether the field was boolean.
func (f *paramForm) toggle() bool {
	if len(f.inputs) == 0 || f.spec.Parameters[f.focus].Kind != "bool" {
		return false
	}
	v, _ := strconv.ParseBool(f.inputs[f.focus].Value())
	f.inputs[f.focus].SetValue(strconv.FormatBool(!v))
	return true
}

func (f *paramForm) update(msg tea.Msg) tea.Cmd {
	if len(f.inputs) == 0 {
		return nil
	}
	var cmd tea.Cmd
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	f.err = ""
	return cmd
}

func (f paramForm) values() map[string]string {
	out := make(map[string]string, len(f.inputs))
	for i, p := range f.spec.Parameters {
		out[p.Name] = f.inputs[i].Value()
	}
	return out
}

// commandLine is the equivalent ":run" line, listing only changed parameters.
func (f paramForm) commandLine() string {
	parts := []string{"run", f.spec.Name}
	for i, p := range f.spec.Parameters {
		if v := f.inputs[i].Value(); v != p.Default {
			arg := p.Name + "=" + v
			if strings.ContainsAny(arg, " \t'\"") {
				arg = strconv.Quote(arg)
			}
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " ")
}

func (f paramForm) View(st styles, width, height int) string {
	var b strings.Builder
	b.WriteString(st.accent.Render("PARAMETERS") + st.muted.Render("  "+render.Safe(f.spec.Name)) + "\n\n")
	if len(f.inputs) == 0 {
		b.WriteString(st.muted.Render("No parameters. enter to run · esc to cancel"))
		return b.String()
	}
	// Two header lines, then fields, then hint, error and description; the
	// description goes last so a short panel clips only its tail.
	rows := max(1, height-8)
	top := max(0, min(f.focus-rows+1, len(f.inputs)-rows))
	label := min(maxLabel, width/3)
	for i := top; i < min(len(f.inputs), top+rows); i++ {
		p := f.spec.Parameters[i]
		name := fit(render.Safe(p.Name), label)
		if i == f.focus {
			b.WriteString(st.strong.Render("› "+name) + " " + f.inputs[i].View() + "\n")
		} else {
			b.WriteString(st.muted.Render("  "+name) + " " + render.Safe(f.inputs[i].Value()) + "\n")
		}
	}
	p := f.spec.Parameters[f.focus]
	hint := "↑/↓ field · enter next/run · ctrl+s run · esc cancel"
	if p.Kind == "bool" {
		hint = "space toggle · " + hint
	}
	b.WriteString("\n" + st.muted.Render(hint))
	if f.err != "" {
		b.WriteString("\n" + st.err.Render(render.Safe(f.err)))
	}
	about := fmt.Sprintf("%s (%s, default %s) %s", p.Name, p.Kind, p.Default, p.Description)
	b.WriteString("\n" + st.muted.Render(ansi.Wordwrap(render.Safe(about), max(20, width), "")))
	return b.String()
}
