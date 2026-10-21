package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/internal/render"
)

// detailText renders evidence, a plugin spec or anything JSON-shaped.
func detailText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// commandText sanitizes exploration output line by line.
func commandText(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = render.Safe(lines[i])
	}
	return strings.Join(lines, "\n")
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
