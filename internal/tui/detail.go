package tui

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const maxLabel = 22

// detailText renders evidence, a plugin spec or anything JSON-shaped verbatim.
func detailText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return commandText(string(b))
}

// commandText sanitizes multi-line output line by line.
func commandText(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = render.Safe(lines[i])
	}
	return strings.Join(lines, "\n")
}

// fields lays out label/value pairs; continuation lines of a value are
// indented under the value column.
type fields struct {
	st    styles
	b     strings.Builder
	label int
}

// newFields sizes the label column to the longest label, capped at maxLabel
// and a third of the panel so values keep most of a narrow panel.
func newFields(st styles, labels []string, width int) *fields {
	w := 0
	for _, l := range labels {
		w = max(w, ansi.StringWidth(l))
	}
	return &fields{st: st, label: max(4, min(maxLabel, width/3, w))}
}

func (f *fields) section(title string) {
	if f.b.Len() > 0 {
		f.b.WriteString("\n")
	}
	f.b.WriteString(f.st.accent.Render(title) + "\n")
}

func (f *fields) add(label, value string) {
	f.addStyled(label, render.Safe(value), false)
}

func (f *fields) addStyled(label, value string, styled bool) {
	pad := strings.Repeat(" ", f.label+2)
	for i, line := range strings.Split(value, "\n") {
		if !styled {
			line = render.Safe(line)
		}
		if i == 0 {
			f.b.WriteString(f.st.muted.Render(fit(render.Safe(label), f.label)) + "  " + line + "\n")
		} else {
			f.b.WriteString(pad + line + "\n")
		}
	}
}

func (f *fields) text() string { return strings.TrimSuffix(f.b.String(), "\n") }

// valueText renders one cell for reading; structures are indented JSON.
func valueText(st styles, v evidence.Value) (string, bool) {
	switch d := v.Data.(type) {
	case nil:
		if v.Kind == "missing" {
			return st.warn.Render(render.Safe(v.String())), true
		}
		return st.muted.Render("—"), true
	case []byte:
		const limit = 64
		s := hex.EncodeToString(d[:min(len(d), limit)])
		if len(d) > limit {
			s += "…"
		}
		return s + st.muted.Render(fmt.Sprintf("  (%d bytes)", len(d))), true
	case string, bool, json.Number, fmt.Stringer:
		if v.Kind == "bytes" {
			return render.Safe(fmt.Sprint(d)) + st.muted.Render("  (base64)"), true
		}
		return render.Safe(fmt.Sprint(d)), true
	default:
		b, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return render.Safe(fmt.Sprint(d)), false
		}
		return commandText(string(b)), false
	}
}

func short(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "…"
	}
	return hash
}

// rowView shows a row's cells in plugin column order, then any extra cells,
// then where the evidence came from.
func rowView(st styles, row evidence.Row, spec plugin.Spec, width int) string {
	var names []string
	seen := map[string]bool{}
	for _, c := range spec.Columns {
		if _, ok := row.Cells[c.Name]; ok {
			names = append(names, c.Name)
			seen[c.Name] = true
		}
	}
	var extra []string
	for n := range row.Cells {
		if !seen[n] {
			extra = append(extra, n)
		}
	}
	slices.Sort(extra)
	names = append(names, extra...)
	p := row.Provenance
	f := newFields(st, append(names, "parameters", "symbols"), width)
	f.section("EVIDENCE")
	f.add("id", short(row.ID))
	if row.ParentID != "" {
		f.add("parent", short(row.ParentID))
	}
	for _, n := range names {
		text, styled := valueText(st, row.Cells[n])
		f.addStyled(n, text, styled)
	}
	f.section("PROVENANCE")
	f.add("plugin", p.Plugin)
	f.add("layer", p.Layer)
	if p.Offset != "" {
		f.add("offset", p.Offset)
	}
	keys := make([]string, 0, len(p.Parameters))
	for k := range p.Parameters {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	params := make([]string, len(keys))
	for i, k := range keys {
		params[i] = k + "=" + p.Parameters[k]
	}
	if len(params) > 0 {
		f.add("parameters", strings.Join(params, "\n"))
	}
	f.add("image", short(p.ImageSHA256))
	if p.SymbolsSHA256 != "" {
		f.add("symbols", short(p.SymbolsSHA256))
	}
	f.add("engine", p.Engine+" "+p.EngineBuild)
	return f.text()
}

// specView describes a capability: what it does, how to run it, what it returns.
func specView(st styles, spec plugin.Spec, width int) string {
	var b strings.Builder
	b.WriteString(st.strong.Render(render.Safe(spec.Name)) + "\n")
	if spec.Description != "" {
		b.WriteString(ansi.Wordwrap(render.Safe(spec.Description), max(20, width), "") + "\n")
	}
	f := newFields(st, []string{"needs kernel"}, width)
	f.section("ABOUT")
	if spec.Platform != "" {
		f.add("platform", spec.Platform)
	}
	if spec.Upstream != "" {
		f.add("upstream", spec.Upstream)
	}
	f.add("needs kernel", fmt.Sprint(spec.NeedsKernel))
	if len(spec.Dependencies) > 0 {
		f.add("depends on", strings.Join(spec.Dependencies, "\n"))
	}
	if len(spec.Parameters) > 0 {
		f.section(fmt.Sprintf("PARAMETERS  %d · e to edit", len(spec.Parameters)))
		for _, p := range spec.Parameters {
			f.b.WriteString(st.accent.Render(render.Safe(p.Name)) + st.muted.Render(" "+p.Kind+" = "+render.Safe(p.Default)) + "\n")
			if p.Description != "" {
				f.b.WriteString(st.muted.Render(ansi.Wordwrap("  "+render.Safe(p.Description), max(20, width), "")) + "\n")
			}
		}
	}
	f.section(fmt.Sprintf("COLUMNS  %d", len(spec.Columns)))
	for _, c := range spec.Columns {
		f.b.WriteString(render.Safe(c.Name) + st.muted.Render("  "+c.Kind) + "\n")
	}
	return b.String() + "\n" + f.text()
}

type limitedWriter struct {
	w         *strings.Builder
	remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, fmt.Errorf("TUI command output exceeds 64 KiB; use CLI for full output")
	}
	w.remaining -= len(p)
	return w.w.Write(p)
}
