package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/triage"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestLinuxMalfindTriageRetainsPartialFindingsAndWhitelist(t *testing.T) {
	for _, fault := range []string{"", "scan-hole", "data-hole"} {
		name := fault
		if name == "" {
			name = "normal"
		}
		t.Run(name, func(t *testing.T) {
			e := malfindEngine(t, "x64", "list", fault)
			ctx := context.Background()
			summary, err := triage.Run(ctx, e, nil)
			if !errors.Is(err, triage.ErrIncomplete) {
				t.Fatal(err)
			}
			checks := map[string]triage.Check{}
			for _, c := range summary.Checks {
				checks[c.Rule] = c
			}
			rx, dirty := checks["anonymous-executable-region"], checks["executable-dirty-page"]
			want := 4
			if fault == "scan-hole" {
				want = 2
			}
			state := "completed"
			if fault != "" {
				state = "incomplete"
			}
			if rx.Findings != 2 || dirty.Findings != want || rx.State != state || dirty.State != state || rx.Coverage["invalid_records"] != "0" {
				t.Fatal(rx, dirty)
			}
			findings, err := e.Store.Query(ctx, evidence.Query{TaskID: summary.FindingTask, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			entities := map[string]bool{}
			for _, r := range findings {
				if r.Cells["Rule"].String() != "anonymous-executable-region" && r.Cells["Rule"].String() != "executable-dirty-page" {
					continue
				}
				if r.Verify() != nil || r.Cells["SourceTask"].Kind != "structure" || r.Cells["FieldEvidence"].Kind != "structure" {
					t.Fatal(r)
				}
				refs := r.Cells["EvidenceIDs"].Data.([]any)
				source, err := e.Store.Find(ctx, refs[0].(string))
				if err != nil || source.Cells["ProcessIdentity"].String() != r.Cells["Entity"].String() {
					t.Fatal(source, err)
				}
				entities[r.Cells["Entity"].String()] = true
			}
			if len(entities) != 2 {
				t.Fatal("distinct process object identities merged", entities)
			}
			for entity := range entities {
				if err := e.Store.Allow(ctx, "anonymous-executable-region", entity, "known runtime"); err != nil {
					t.Fatal(err)
				}
			}
			again, err := triage.Run(ctx, e, nil)
			if !errors.Is(err, triage.ErrIncomplete) {
				t.Fatal(err)
			}
			for _, c := range again.Checks {
				if c.Rule == "anonymous-executable-region" && c.Findings != 0 {
					t.Fatal(c)
				}
			}
			for _, task := range again.Tasks {
				if task.Task.Plugin == "linux.malfind" {
					if (task.Task.State == "completed") != task.Reused {
						t.Fatal(task)
					}
				}
			}
		})
	}
}
