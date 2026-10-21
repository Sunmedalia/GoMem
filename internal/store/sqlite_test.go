package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestEvidenceNullCaptureAndLargeMetadataSurviveReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.Begin(ctx, "serialization", "test", evidence.Provenance{ImageSHA256: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	r := evidence.Row{Cells: map[string]evidence.Value{
		"Raw": evidence.Bytes(nil), "AbsentValue": {Kind: "bytes"}, "EmptyBase64": {Kind: "bytes", Data: ""},
		"Error":   evidence.Missing("no_readable_prefix", fmt.Errorf("missing page")),
		"Details": {Kind: "structure", Data: map[string]any{"Unsigned": uint64(18446744073709551615), "Signed": int64(-9223372036854775808), "Decimal": json.Number("1.2300")}},
	}}
	r.Seal()
	want, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Append(ctx, task.ID, []evidence.Row{r}); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, task.ID, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Query(ctx, evidence.Query{TaskID: task.ID, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	found, err := s.Find(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []evidence.Row{rows[0], found} {
		if err = row.Verify(); err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(row)
		if err != nil || string(got) != string(want) {
			t.Fatal(string(got), string(want), err)
		}
	}
}

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

func TestSortedQueryAndCommandHistory(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	task, err := s.Begin(ctx, "sort-key", "test", evidence.Provenance{ImageSHA256: "image"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	for _, v := range []struct {
		name string
		pid  uint64
		off  int64
	}{{"b", 18446744073709551615, -2}, {"c", 9, 10}, {"a", 10, -30}} {
		r := evidence.Row{Cells: map[string]evidence.Value{"Process Name": evidence.Text(v.name), "PID": evidence.Number(v.pid), "Delta": evidence.Integer(v.off)}}
		r.Seal()
		rows = append(rows, r)
	}
	if err = s.Append(ctx, task.ID, rows); err != nil {
		t.Fatal(err)
	}
	order := func(q evidence.Query) string {
		t.Helper()
		q.TaskID, q.Limit = task.ID, 10
		got, err := s.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var names string
		for _, r := range got {
			names += r.Cells["Process Name"].String()
		}
		return names
	}
	for _, c := range []struct {
		q    evidence.Query
		want string
	}{
		{evidence.Query{}, "bca"},
		{evidence.Query{Sort: "Process Name"}, "abc"},
		{evidence.Query{Sort: "Process Name", Desc: true}, "cba"},
		{evidence.Query{Sort: "PID"}, "cab"},
		{evidence.Query{Sort: "Delta"}, "abc"},
		{evidence.Query{Sort: "Delta", Filter: "-30"}, "a"},
	} {
		if got := order(c.q); got != c.want {
			t.Fatalf("%+v: got %q want %q", c.q, got, c.want)
		}
	}
	if _, err = s.Query(ctx, evidence.Query{TaskID: task.ID, Limit: 10, Sort: `x"y`}); err == nil {
		t.Fatal("quoted sort column accepted")
	}
	for _, c := range []string{"use kernel", "hex 0x10", "help"} {
		if err = s.History(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Commands(ctx, 2)
	if err != nil || len(got) != 2 || got[0] != "hex 0x10" || got[1] != "help" {
		t.Fatal(got, err)
	}
}
