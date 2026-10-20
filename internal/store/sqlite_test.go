package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestResumeLockPagingAndNotes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("case lock not enforced")
	}
	task, err := s.Begin(ctx, "resume-key", "test", evidence.Provenance{ImageSHA256: "image"})
	if err != nil {
		t.Fatal(err)
	}
	var all []evidence.Row
	for i := 0; i < 255; i++ {
		r := evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text(fmt.Sprintf("item-%03d", i))}}
		r.Seal()
		all = append(all, r)
	}
	if err = s.Append(ctx, task.ID, all); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Query(ctx, evidence.Query{TaskID: task.ID, Offset: 200, Limit: 100})
	if err != nil || len(rows) != 55 {
		t.Fatal(len(rows), err)
	}
	rows, err = s.Query(ctx, evidence.Query{TaskID: task.ID, Filter: "item-123", Limit: 100})
	if err != nil || len(rows) != 1 {
		t.Fatal(len(rows), err)
	}
	if err = s.Bookmark(ctx, all[0].ID, "known process"); err != nil {
		t.Fatal(err)
	}
	if err = s.Allow(ctx, "literal-ioc", all[0].ID, "approved test artifact"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tasks, err := s.Tasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].State != "failed" || tasks[0].Rows != 255 {
		t.Fatal(tasks, err)
	}
	if _, ok, err := s.Cached(ctx, "resume-key"); err != nil || ok {
		t.Fatal("interrupted task reused", err)
	}
	allowed, err := s.Allowed(ctx, "literal-ioc", all[0].ID)
	if err != nil || !allowed {
		t.Fatal(allowed, err)
	}
	notes, err := s.Investigation(ctx)
	if err != nil || len(notes["bookmarks"].([]map[string]string)) != 1 {
		t.Fatal(notes, err)
	}
}
func BenchmarkPageQuery(b *testing.B) {
	ctx := context.Background()
	s, err := Open("")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	task, _ := s.Begin(ctx, "bench", "bench", evidence.Provenance{})
	for start := 0; start < 10000; start += 500 {
		var rows []evidence.Row
		for j := 0; j < 500; j++ {
			row := evidence.Row{ID: fmt.Sprint(start + j), Cells: map[string]evidence.Value{"PID": evidence.Number(uint64(start + j)), "Name": evidence.Text("benchmark")}}
			rows = append(rows, row)
		}
		if err = s.Append(ctx, task.ID, rows); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err = s.Query(ctx, evidence.Query{TaskID: task.ID, Offset: 9000, Limit: 100}); err != nil {
			b.Fatal(err)
		}
	}
}
