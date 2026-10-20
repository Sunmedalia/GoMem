package triage

import (
	"context"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func row(address uint64, name string) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(address), "Name": evidence.Text(name), "Identity": evidence.Text(name), "ProcessIdentity": evidence.Text(name)}, Provenance: evidence.Provenance{ImageSHA256: "same-image", Layer: "kernel", Offset: evidence.Address(address).String(), Plugin: "fixture"}}
	r.Seal()
	return r
}
func TestEveryRulePositiveAndControl(t *testing.T) {
	for _, rule := range Rules {
		t.Run(rule.ID, func(t *testing.T) {
			known := row(0x1000, "known")
			other := row(0x2000, "other")
			inputs := map[string][]evidence.Row{}
			switch rule.Kind {
			case "difference":
				inputs[rule.Inputs[0]] = []evidence.Row{known}
				inputs[rule.Inputs[1]] = []evidence.Row{known, other}
			case "ioc":
				inputs["ioc"] = []evidence.Row{other}
			case "rwx":
				known.Cells["Protection"] = evidence.Text("r-x")
				other.Cells["Protection"] = evidence.Text("rwx")
				inputs["maps"] = []evidence.Row{known, other}
			case "deleted":
				known.Cells["Executable"] = evidence.Text("false")
				known.Cells["Path"] = evidence.Text("/tmp/ordinary (deleted)")
				other.Cells["Executable"] = evidence.Text("true")
				other.Cells["Path"] = evidence.Text("memfd:payload (deleted)")
				inputs["maps"] = []evidence.Row{known, other}
			case "persistence":
				other.Cells["ProcessIdentity"] = evidence.Text("known")
				inputs["persistence"] = []evidence.Row{other}
				inputs["pslist"] = []evidence.Row{known}
			}
			var findings []evidence.Row
			for key := range inputs {
				for i := range inputs[key] {
					inputs[key][i].Seal()
				}
			}
			err := Evaluate(context.Background(), rule, inputs, func(r evidence.Row) error { findings = append(findings, r); return nil })
			if err != nil || len(findings) != 1 {
				t.Fatalf("%d %v", len(findings), err)
			}
			if findings[0].Cells["FalsePositive"].String() == "" || findings[0].Provenance.ImageSHA256 != "same-image" {
				t.Fatal("missing rule context")
			}
			for k := range inputs {
				inputs[k] = nil
			}
			if err = Evaluate(context.Background(), rule, inputs, func(r evidence.Row) error { t.Fatal("empty control produced a finding"); return nil }); err != nil {
				t.Fatal(err)
			}
			if err = Evaluate(context.Background(), rule, map[string][]evidence.Row{}, func(r evidence.Row) error { return nil }); err == nil {
				t.Fatal("missing prerequisites treated as a clean result")
			}
		})
	}
}
func TestTriageCoverageAndWhitelist(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(ctx, engine.Config{Image: f.Image, CaseDir: t.TempDir(), Symbols: f.Symbols, DTB: f.DTB, Arch: "x64", OS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s, err := Run(ctx, e, []string{"gomem-test-ioc"})
	if !errors.Is(err, ErrIncomplete) || s.Findings != 1 || len(s.Checks) != len(Rules) {
		t.Fatal(s, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: s.FindingTask, Limit: 100})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if err = e.Store.Allow(ctx, "literal-ioc", rows[0].Cells["Entity"].String(), "known test literal"); err != nil {
		t.Fatal(err)
	}
	s, err = Run(ctx, e, []string{"gomem-test-ioc"})
	if !errors.Is(err, ErrIncomplete) || s.Findings != 0 {
		t.Fatal(s, err)
	}
	tasks, err := e.Store.Tasks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		if task.Plugin == "triage" && task.State != "failed" {
			t.Fatal("incomplete triage stored as success", task)
		}
	}
}
