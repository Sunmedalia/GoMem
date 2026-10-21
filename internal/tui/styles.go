package tui

import (
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// styles is the palette for one terminal background.
type styles struct {
	dark                  bool
	accent, muted, strong lipgloss.Style
	heading               lipgloss.Style
	selected, selectedDim lipgloss.Style
	success, warn, err    lipgloss.Style
	border, borderActive  lipgloss.Style
	help                  help.Styles
}

func newStyles(dark bool) styles {
	c := lipgloss.LightDark(dark)
	accent := c(lipgloss.Color("#0E7C69"), lipgloss.Color("#52D6BE"))
	muted := c(lipgloss.Color("#5B6B7A"), lipgloss.Color("#8C9DAE"))
	s := styles{
		dark:         dark,
		accent:       lipgloss.NewStyle().Foreground(accent),
		muted:        lipgloss.NewStyle().Foreground(muted),
		strong:       lipgloss.NewStyle().Foreground(accent).Bold(true),
		heading:      lipgloss.NewStyle().Foreground(muted).Bold(true),
		selected:     lipgloss.NewStyle().Foreground(c(lipgloss.Color("#FFFFFF"), lipgloss.Color("#0B1A24"))).Background(accent).Bold(true),
		selectedDim:  lipgloss.NewStyle().Foreground(accent).Bold(true),
		success:      lipgloss.NewStyle().Foreground(c(lipgloss.Color("#18794E"), lipgloss.Color("#7BD88F"))),
		warn:         lipgloss.NewStyle().Foreground(c(lipgloss.Color("#9A5B00"), lipgloss.Color("#E5B567"))),
		err:          lipgloss.NewStyle().Foreground(c(lipgloss.Color("#B42318"), lipgloss.Color("#F07167"))).Bold(true),
		border:       lipgloss.NewStyle().Foreground(c(lipgloss.Color("#B8C4CE"), lipgloss.Color("#304657"))),
		borderActive: lipgloss.NewStyle().Foreground(accent),
		help:         help.DefaultStyles(dark),
	}
	return s
}

// fit truncates or pads one line to exactly width cells.
func fit(line string, width int) string {
	line = ansi.Truncate(line, width, "…")
	if pad := width - ansi.StringWidth(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	return line
}

// fitTail is fit for paths: it keeps the end, where the file name is.
func fitTail(line string, width int) string {
	if w := ansi.StringWidth(line); w > width {
		line = ansi.TruncateLeft(line, w-width+1, "…")
	}
	return fit(line, width)
}

// panel draws a rounded box of exactly width × height cells around content.
// Lines are truncated rather than wrapped, so the size never depends on content.
func (s styles) panel(content string, width, height int, active bool) []string {
	b := s.border
	if active {
		b = s.borderActive
	}
	inner := width - 4
	rule := strings.Repeat("─", width-2)
	side := b.Render("│")
	lines := strings.Split(content, "\n")
	out := make([]string, 0, height)
	out = append(out, b.Render("╭"+rule+"╮"))
	for i := 0; i < height-2; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		out = append(out, side+" "+fit(line, inner)+" "+side)
	}
	return append(out, b.Render("╰"+rule+"╯"))
}

// row places equally tall panels side by side.
func row(panels ...[]string) string {
	var b strings.Builder
	for i := range panels[0] {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, p := range panels {
			b.WriteString(p[i])
		}
	}
	return b.String()
}
