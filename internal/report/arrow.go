package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func eachArrowTask(ctx context.Context, s *store.Store, task evidence.Task, emit func(evidence.Row) error) error {
	var count int64
	for after := int64(0); ; {
		page, err := s.QueryPage(ctx, evidence.Query{TaskID: task.ID, After: after, Limit: 32})
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := row.Verify(); err != nil {
				return err
			}
			if err := emit(row); err != nil {
				return err
			}
			count++
		}
		if len(page.Rows) < 32 {
			break
		}
		if page.Last <= after {
			return fmt.Errorf("Arrow result cursor did not advance")
		}
		after = page.Last
	}
	if count != task.Rows {
		return fmt.Errorf("Arrow task row count differs from sealed task metadata")
	}
	return nil
}
func arrowKind(kind string) string {
	switch kind {
	case "string", "timestamp", "address", "uint64", "int64", "bool", "bytes", "structure", "artifact", "missing":
		return kind
	default:
		return "value"
	}
}
func arrowReport(ctx context.Context, s *store.Store, w io.Writer, m Manifest) (err error) {
	// Infer only the union of column names/kinds in a bounded first pass. All
	// evidence stays in SQLite; conflicting kinds use canonical Value JSON.
	kinds := map[string]string{}
	for _, task := range m.Tasks {
		if err := eachArrowTask(ctx, s, task, func(row evidence.Row) error {
			for name, value := range row.Cells {
				next := arrowKind(value.Kind)
				previous, exists := kinds[name]
				if !exists || previous == "missing" {
					kinds[name] = next
				} else if next != "missing" && next != previous {
					kinds[name] = "value"
				}
			}
			if len(kinds) > 4096 {
				return fmt.Errorf("Arrow column budget exceeded")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(kinds))
	for name := range kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	columns := make([]evidence.Column, len(names))
	for i, name := range names {
		columns[i] = evidence.Column{Name: name, Kind: kinds[name]}
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	output, err := render.NewArrow(w, columns, map[string]string{"gomem.manifest": string(manifest)})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	for _, task := range m.Tasks {
		if err := eachArrowTask(ctx, s, task, func(row evidence.Row) error { return output.RowForTask(task.ID, row) }); err != nil {
			return err
		}
	}
	return nil
}
