package tui

import "charm.land/lipgloss/v2"

var (
	accentColor = lipgloss.Color("#52D6BE")
	mutedColor  = lipgloss.Color("#8C9DAE")
	borderColor = lipgloss.Color("#304657")

	accent = lipgloss.NewStyle().Foreground(accentColor)
	muted  = lipgloss.NewStyle().Foreground(mutedColor)
	strong = accent.Bold(true)
)

// panel draws a bordered block whose total size is width × height.
func panel(text string, width, height int, active bool) string {
	color := borderColor
	if active {
		color = accentColor
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(color).Padding(0, 1).Width(width).Height(height).MaxHeight(height).Render(text)
}
