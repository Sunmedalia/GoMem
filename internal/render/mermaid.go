package render

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func mermaidLabel(text string) string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return ' '
		}
		return r
	}, text)
	return strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;", "`", "&#96;", "\\", "&#92;", "\n", "<br>", "\t", " ").Replace(text)
}

func (r *Writer) mermaidRow(row evidence.Row) error {
	parent := ""
	if row.ParentID != "" {
		var ok bool
		parent, ok = r.nodes[row.ParentID]
		if !ok {
			return fmt.Errorf("Mermaid parent evidence has not been rendered")
		}
	}
	r.sequence++
	node := fmt.Sprintf("n%d", r.sequence)
	cells := make([]string, len(r.cols))
	for i, col := range r.cols {
		value, ok := row.Cells[col.Name]
		if !ok {
			value = evidence.Missing("column_absent", nil)
		}
		cells[i] = mermaidLabel(col.Name) + ":" + mermaidLabel(value.String())
	}
	prefix := "\t"
	if parent != "" {
		prefix += parent + " --> "
	}
	_, err := fmt.Fprintf(r.w, "%s%s[\"%s\"]\n", prefix, node, strings.Join(cells, "<br>"))
	if err == nil && row.ID != "" {
		// Repeated identical evidence still gets distinct graph nodes. A parent
		// identity resolves to its first occurrence, never a guessed PID column.
		if _, exists := r.nodes[row.ID]; !exists {
			r.nodes[row.ID] = node
		}
	}
	return err
}
