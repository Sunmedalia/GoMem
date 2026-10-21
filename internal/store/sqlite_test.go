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

// benchStore holds 100k rows in one task; every 1000th row is named "needle".
func benchStore(b *testing.B) (*Store, evidence.Task) {
	ctx := context.Background()
	s, err := Open("")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	task, _ := s.Begin(ctx, "bench", "bench", evidence.Provenance{})
	for start := 0; start < 100000; start += 1000 {
		rows := make([]evidence.Row, 0, 1000)
		for j := start; j < start+1000; j++ {
			name := "benchmark"
			if j%1000 == 0 {
				name = "needle"
			}
			rows = append(rows, evidence.Row{ID: fmt.Sprint(j), Cells: map[string]evidence.Value{"PID": evidence.Number(uint64(j)), "Name": evidence.Text(name)}})
		}
		if err = s.Append(ctx, task.ID, rows); err != nil {
			b.Fatal(err)
		}
	}
	return s, task
}

func BenchmarkPageQuery(b *testing.B) {
	s, task := benchStore(b)
	ctx := context.Background()
	last, err := s.QueryPage(ctx, evidence.Query{TaskID: task.ID, Offset: 89900, Limit: 100})
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range []struct {
		name string
		q    evidence.Query
	}{
		{"offset-90000", evidence.Query{TaskID: task.ID, Offset: 90000, Limit: 100}},
		{"cursor-90000", evidence.Query{TaskID: task.ID, After: last.Last, Limit: 100}},
		{"filter-indexed", evidence.Query{TaskID: task.ID, Filter: "needle", Limit: 100}},
		{"filter-scan", evidence.Query{TaskID: task.ID, Filter: "ne", Limit: 100}},
	} {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := s.Query(ctx, c.q); err != nil {
					b.Fatal(err)
				}
			}
		})
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

func TestImagesNewestFirst(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.RecordImage(ctx, "aa", "/old.raw", "raw", 10); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordImage(ctx, "bb", "/new.lime", "lime-v1", 20); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordImage(ctx, "aa", "/moved.raw", "raw", 10); err != nil {
		t.Fatal(err)
	}
	got, err := s.Images(ctx)
	if err != nil || len(got) != 2 || got[0].SHA256 != "bb" || got[0].Size != 20 || got[1].Path != "/moved.raw" || got[1].Format != "raw" {
		t.Fatal(got, err)
	}
}

func TestSearchIndexCursorPagingAndColumnFilters(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.Begin(ctx, "search-key", "test", evidence.Provenance{ImageSHA256: "image"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	for i := 0; i < 250; i++ {
		name := fmt.Sprintf("proc-%03d", i)
		if i%50 == 0 {
			name = fmt.Sprintf(`Worker "%d"`, i)
		}
		r := evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text(name), "PID": evidence.Number(uint64(i))}}
		r.Seal()
		rows = append(rows, r)
	}
	if err = s.Append(ctx, task.ID, rows[:200]); err != nil {
		t.Fatal(err)
	}
	// A case written before the index existed is indexed when reopened.
	if _, err = s.db.Exec("DROP TRIGGER results_fts_insert; DROP TABLE results_fts"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Append(ctx, task.ID, rows[200:]); err != nil {
		t.Fatal(err)
	}
	count := func(q evidence.Query) int {
		t.Helper()
		q.TaskID, q.Limit = task.ID, 1000
		got, err := s.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	for _, c := range []struct {
		q    evidence.Query
		want int
	}{
		{evidence.Query{Filter: "worker"}, 5},       // indexed, case-insensitive
		{evidence.Query{Filter: `Worker \"200`}, 1}, // quotes escape into the phrase; row from after reopening
		{evidence.Query{Filter: "c-1"}, 98},         // indexed substring: proc-1xx less two workers
		{evidence.Query{Filter: "W"}, 5},            // too short for trigrams; scanned
		{evidence.Query{Columns: []evidence.ColumnFilter{{Column: "Name", Value: "PROC-00"}}}, 9},
		{evidence.Query{Columns: []evidence.ColumnFilter{{Column: "PID", Value: "7", Exact: true}}}, 1},
		{evidence.Query{Filter: "proc", Columns: []evidence.ColumnFilter{{Column: "PID", Value: "24"}}}, 13}, // 24, 124, 224, 240-249
	} {
		if got := count(c.q); got != c.want {
			t.Fatalf("%+v: got %d want %d", c.q, got, c.want)
		}
	}
	if _, err = s.Query(ctx, evidence.Query{TaskID: task.ID, Limit: 1, Columns: []evidence.ColumnFilter{{Column: `a"b`}}}); err == nil {
		t.Fatal("quoted column accepted")
	}
	// Cursor pages match offset pages in both directions.
	for _, desc := range []bool{false, true} {
		var after int64
		for offset := 0; offset < 250; offset += 64 {
			page, err := s.QueryPage(ctx, evidence.Query{TaskID: task.ID, Limit: 64, Desc: desc, After: after})
			if err != nil {
				t.Fatal(err)
			}
			want, err := s.Query(ctx, evidence.Query{TaskID: task.ID, Limit: 64, Desc: desc, Offset: offset})
			if err != nil || len(page.Rows) != len(want) || page.Rows[0].ID != want[0].ID || page.Rows[len(want)-1].ID != want[len(want)-1].ID {
				t.Fatalf("desc=%t offset=%d: cursor page differs", desc, offset)
			}
			after = page.Last
		}
	}
}
