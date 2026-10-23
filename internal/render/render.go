package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func Safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

type Writer struct {
	w        io.Writer
	format   string
	cols     []evidence.Column
	csv      *csv.Writer
	first    bool
	nodes    map[string]string
	sequence uint64
}

func New(w io.Writer, format string, cols []evidence.Column) (*Writer, error) {
	r := &Writer{w: w, format: format, cols: cols, first: true}
	var err error
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	switch format {
	case "mermaid":
		r.nodes = make(map[string]string)
		_, err = io.WriteString(w, "graph TD\n")
	case "jsonl":
	case "json":
		_, err = io.WriteString(w, "[\n")
	case "csv":
		r.csv = csv.NewWriter(w)
		err = r.csv.Write(names)
		r.csv.Flush()
		err = join(err, r.csv.Error())
	case "table":
		_, err = fmt.Fprintln(w, strings.Join(names, "\t"))
	default:
		return nil, fmt.Errorf("unsupported output format %q (jsonl, json, csv, table, mermaid)", format)
	}
	return r, err
}
func join(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
func (r *Writer) Row(row evidence.Row) error {
	switch r.format {
	case "mermaid":
		return r.mermaidRow(row)
	case "jsonl":
		return json.NewEncoder(r.w).Encode(row)
	case "json":
		if !r.first {
			if _, e := io.WriteString(r.w, ",\n"); e != nil {
				return e
			}
		}
		r.first = false
		b, e := json.Marshal(row)
		if e != nil {
			return e
		}
		_, e = r.w.Write(b)
		return e
	case "csv", "table":
		cells := make([]string, len(r.cols))
		for i, c := range r.cols {
			v, ok := row.Cells[c.Name]
			if !ok {
				v = evidence.Missing("column_absent", nil)
			}
			cells[i] = v.String()
			if r.format == "table" {
				cells[i] = Safe(cells[i])
			}
		}
		if r.csv != nil {
			if e := r.csv.Write(cells); e != nil {
				return e
			}
			r.csv.Flush()
			return r.csv.Error()
		}
		_, e := fmt.Fprintln(r.w, strings.Join(cells, "\t"))
		return e
	}
	return nil
}
func (r *Writer) Close() error {
	if r.format == "json" {
		_, e := io.WriteString(r.w, "\n]\n")
		return e
	}
	return nil
}
