package triage

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func row(address uint64, name string) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(address), "Name": evidence.Text(name), "Identity": evidence.Text(name), "ProcessIdentity": evidence.Text(name)}, Provenance: evidence.Provenance{ImageSHA256: "same-image", Layer: "kernel", Offset: evidence.Address(address).String(), Plugin: "fixture"}}
	r.Seal()
	return r
}

func TestWindowsVADPipelineFindingsControlAndWhitelist(t *testing.T) {
	for _, scenario := range []string{"rwx", "normal", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f, err := testfixture.Write(t.TempDir(), "windows")
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "rwx" {
				data, err := os.ReadFile(f.Image)
				if err != nil {
					t.Fatal(err)
				}
				protection := uint32(0x20)
				if scenario == "unknown" {
					protection = 0x80000000
				}
				binary.LittleEndian.PutUint32(data[0x6200+6*4:], protection)
				if err = os.WriteFile(f.Image, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			summary, err := Run(ctx, e, nil)
			if err == nil || summary.State == "completed" {
				t.Fatal("remaining unsupported rules declared success", summary, err)
			}
			var check Check
			for _, c := range summary.Checks {
				if c.Rule == "executable-writable-region" {
					check = c
				}
			}
			if scenario == "unknown" {
				if check.State != "failed" || check.Reason == "" {
					t.Fatal("unknown protection became a clean check", check)
				}
				return
			}
			want := 0
			if scenario == "rwx" {
				want = 1
			}
			if !errors.Is(err, ErrIncomplete) || check.State != "completed" || check.Findings != want {
				t.Fatal(summary, err)
			}
			if scenario == "normal" {
				return
			}
			findings, err := e.Store.Query(ctx, evidence.Query{TaskID: summary.FindingTask, Limit: 100})
			if err != nil || len(findings) != 1 || findings[0].Provenance.Offset != "0x16000" {
				t.Fatal(findings, err)
			}
			refs := findings[0].Cells["EvidenceIDs"].Data.([]any)
			source, err := e.Store.Find(ctx, refs[0].(string))
			if err != nil || source.Provenance.Plugin != "windows.vadinfo" || source.Cells["ProcessIdentity"].String() != findings[0].Cells["Entity"].String() {
				t.Fatal(source, err)
			}
			if err = e.Store.Allow(ctx, check.Rule, findings[0].Cells["Entity"].String(), "known JIT fixture"); err != nil {
				t.Fatal(err)
			}
			second, err := Run(ctx, e, nil)
			if !errors.Is(err, ErrIncomplete) || second.Findings != 0 {
				t.Fatal(second, err)
			}
			for _, task := range second.Tasks {
				if !task.Reused {
					t.Fatal("completed VAD/process/module steps were not reused", task)
				}
			}
		})
	}
}

func TestWritableExecutableProtectionModifiersAndCopyOnWriteControl(t *testing.T) {
	rule := Rules[1]
	for _, tc := range []struct {
		protection string
		value      uint64
		hit        bool
	}{{"PAGE_EXECUTE_READWRITE|PAGE_GUARD", 0x140, true}, {"PAGE_EXECUTE_WRITECOPY", 0x80, false}, {"PAGE_EXECUTE_READ", 0x20, false}, {"", 0, false}} {
		r := row(0x1000, "mapping")
		r.Cells["Protection"], r.Cells["ProtectionValue"] = evidence.Text(tc.protection), evidence.Number(tc.value)
		r.Seal()
		count := 0
		err := Evaluate(context.Background(), rule, map[string][]evidence.Row{"maps": {r}}, func(evidence.Row) error { count++; return nil })
		if err != nil || (count == 1) != tc.hit {
			t.Fatal(tc, count, err)
		}
	}
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
	if !errors.Is(err, ErrIncomplete) || s.Findings != 5 || len(s.Checks) != len(Rules) {
		t.Fatal(s, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: s.FindingTask, Limit: 100})
	if err != nil || len(rows) != 5 {
		t.Fatal(rows, err)
	}
	for _, row := range rows {
		if row.Cells["Rule"].String() == "literal-ioc" {
			if err = e.Store.Allow(ctx, "literal-ioc", row.Cells["Entity"].String(), "known test literal"); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err = Run(ctx, e, []string{"gomem-test-ioc"})
	if !errors.Is(err, ErrIncomplete) || s.Findings != 4 {
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

func TestLinuxNativeMappingRulesControlsAndSourceReferences(t *testing.T) {
	for _, scenario := range []string{"positive", "normal", "unknown-deletion"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f, err := testfixture.Write(t.TempDir(), "linux")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "normal" {
				data, err := os.ReadFile(f.Image)
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint64(data[0x10028:], 1)
				binary.LittleEndian.PutUint64(data[0x11028:], 5)
				if err = os.WriteFile(f.Image, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "unknown-deletion" {
				table, err := symbols.Load(f.Symbols)
				if err != nil {
					t.Fatal(err)
				}
				inode := table.Types["inode"]
				delete(inode.Fields, "i_nlink")
				table.Types["inode"] = inode
				encoded, err := table.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(f.Image)
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint64(data[0x10038:], 0x13100)
				if err = os.WriteFile(f.Image, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			s, err := Run(ctx, e, nil)
			if err == nil || s.State == "completed" {
				t.Fatal("incomplete coverage became success", s, err)
			}
			checks := map[string]Check{}
			for _, check := range s.Checks {
				checks[check.Rule] = check
			}
			if scenario == "unknown-deletion" {
				if checks["deleted-or-memfd-execution"].State != "failed" {
					t.Fatal("unknown deletion became normal", s)
				}
				return
			}
			count := 2
			if scenario == "normal" {
				count = 0
			}
			for _, id := range []string{"executable-writable-region", "deleted-or-memfd-execution"} {
				c := checks[id]
				if c.State != "completed" || c.Findings != count {
					t.Fatal(s, err)
				}
			}
			if !errors.Is(err, ErrIncomplete) || s.Findings != count*2 {
				t.Fatal(s, err)
			}
			if scenario == "normal" {
				return
			}
			findings, err := e.Store.Query(ctx, evidence.Query{TaskID: s.FindingTask, Limit: 100})
			if err != nil || len(findings) != 4 {
				t.Fatal(findings, err)
			}
			for _, finding := range findings {
				refs := finding.Cells["EvidenceIDs"].Data.([]any)
				source, err := e.Store.Find(ctx, refs[0].(string))
				if err != nil || source.Provenance.Plugin != "linux.maps" || source.Cells["ProcessIdentity"].String() != finding.Cells["Entity"].String() {
					t.Fatal(source, err)
				}
			}
		})
	}
}
