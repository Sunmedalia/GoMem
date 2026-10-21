package triage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func nativeRules() []Rule {
	var result []Rule
	for _, rule := range Rules {
		if rule.Kind == "native-check" {
			result = append(result, rule)
		}
	}
	return result
}

func nativeCheckRows(t *testing.T, rule Rule, positive bool, diagnostics int) []evidence.Row {
	t.Helper()
	var result []evidence.Row
	eval := nativeCheckEvaluator{rule: rule}
	name, _, err := eval.inputPlugin()
	if err != nil {
		t.Fatal(err)
	}
	base := row(0x2000, "native-process")
	base.Provenance.Plugin = name
	base.Provenance.SymbolsSHA256 = "fixture-symbols"
	base.Cells["ProcessIdentity"] = evidence.Text("image-layer-object-pid-created")
	base.Cells["ProcessOffset"] = evidence.Address(0x2000)
	base.Cells["ThreadOffset"] = evidence.Address(0x2000)
	base.Cells["ThreadIdentity"] = evidence.Text("image-layer-thread-tid-created")
	base.Cells["PID"] = evidence.Number(104)
	base.Cells["Process"] = evidence.Text("main.exe")
	base.Cells["Rule"] = evidence.Text("dll_protection")
	base.Cells["Notes"] = evidence.Text("Unexpected protection for loader DLL")
	if name == "windows.suspicious_threads" {
		base.Cells["Rule"] = evidence.Text("unexpected_protection")
		base.Cells["Note"] = evidence.Text("Unexpected protection for thread entry VAD")
	}
	base.Cells["RecordType"] = evidence.Text("finding")
	base.Seal()
	for i := 0; i < diagnostics; i++ {
		diagnostic := row(uint64(0x3000+i), "diagnostic")
		diagnostic.Provenance.Plugin = name
		diagnostic.Cells["RecordType"] = evidence.Text("diagnostic")
		diagnostic.Cells["Error"] = evidence.Missing("unmapped", fmt.Errorf("missing page %d", i))
		diagnostic.Seal()
		result = append(result, diagnostic)
	}
	findings := "0"
	if positive {
		result = append(result, base)
		findings = "1"
	}
	coverage := map[string]any{"processes": "1", "findings": findings, "short_vad_sets": "0"}
	if name == "windows.suspicious_threads" {
		for key, value := range map[string]string{"threads": "1", "exited": "0", "gather_skipped": strconv.Itoa(diagnostics), "unique_addresses": "2", "duplicates": "0", "outside_vad": "1", "path_read_errors": "0"} {
			coverage[key] = value
		}
	} else {
		coverage["checked"], coverage["short_dll_sets"], coverage["diagnostics"] = "1", "0", strconv.Itoa(diagnostics)
	}
	summary := row(0, "summary")
	summary.Provenance.Plugin = name
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: coverage}
	summary.Seal()
	return append(result, summary)
}

type triageFixturePlugin struct {
	name string
	rows []evidence.Row
}

func (p triageFixturePlugin) Spec() plugin.Spec { return plugin.Spec{Name: p.name} }
func (p triageFixturePlugin) Run(ctx context.Context, _ plugin.Environment, _ map[string]string, emit plugin.Emit) error {
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return nil
}

// Exercise the production task/cache/store/evaluator path using deterministic
// plugin output. Native memory decoding has separate complete plugin fixtures.
func TestNativeTriageCasePagingWhitelistAndResume(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Registry = plugin.NewRegistry()
	for _, name := range []string{"windows.pslist", "windows.modules", "windows.vadinfo"} {
		if err = e.Registry.Register(triageFixturePlugin{name: name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range nativeRules() {
		diagnostics := 0
		if rule.Inputs[0] == "hollowprocesses" {
			diagnostics = 1001
		}
		rows := nativeCheckRows(t, rule, true, diagnostics)
		if err = e.Registry.Register(triageFixturePlugin{name: "windows." + rule.Inputs[0], rows: rows}); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || summary.Findings != 2 {
		t.Fatal(summary, err)
	}
	for _, check := range summary.Checks {
		switch check.Rule {
		case "suspicious-thread-start":
			if check.State != "completed" || check.Findings != 1 || check.Coverage["findings"] != "1" {
				t.Fatal(check)
			}
		case "hollow-process-mapping":
			if check.State != "incomplete" || check.Findings != 1 || check.Coverage["diagnostics"] != "1001" {
				t.Fatal(check)
			}
		}
	}
	findings, err := e.Store.Query(ctx, evidence.Query{TaskID: summary.FindingTask, Limit: 100})
	if err != nil || len(findings) != 2 {
		t.Fatal(findings, err)
	}
	for _, finding := range findings {
		if err := finding.Verify(); err != nil {
			t.Fatal(err)
		}
		refs := finding.Cells["EvidenceIDs"].Data.([]any)
		source, err := e.Store.Find(ctx, refs[0].(string))
		if err != nil || source.Verify() != nil || source.Provenance.ImageSHA256 != e.Hash || source.Provenance.SymbolsSHA256 != e.Env.Symbols.Digest() || source.Provenance.Offset != finding.Provenance.Offset || source.Cells["ProcessIdentity"].String() != finding.Cells["Entity"].String() {
			t.Fatal(source, err)
		}
		if err = e.Store.Allow(ctx, finding.Cells["Rule"].String(), finding.Cells["Entity"].String(), "authorized test control"); err != nil {
			t.Fatal(err)
		}
	}
	second, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || second.Findings != 0 {
		t.Fatal(second, err)
	}
	for _, task := range second.Tasks {
		if !task.Reused {
			t.Fatal("completed input was not reused", task)
		}
	}
	for _, task := range summary.Tasks {
		if task.Task.Plugin == "windows.hollowprocesses" {
			raw, err := e.Store.Query(ctx, evidence.Query{TaskID: task.Task.ID, Offset: 1000, Limit: 500})
			if err != nil || len(raw) != 3 || raw[1].Cells["RecordType"].String() != "finding" {
				t.Fatal("whitelist changed raw evidence", len(raw), err)
			}
		}
	}
}

func TestNativeTriageDiagnosticsDoNotHideLaterPages(t *testing.T) {
	for _, rule := range nativeRules() {
		t.Run(rule.ID, func(t *testing.T) {
			rows := nativeCheckRows(t, rule, true, 1001)
			evaluator := nativeCheckEvaluator{rule: rule}
			var findings []evidence.Row
			for off := 0; off < len(rows); off += 500 {
				end := min(len(rows), off+500)
				if err := evaluator.consume(context.Background(), rows[off:end], func(row evidence.Row) error { findings = append(findings, row); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			coverage, err := evaluator.finish()
			if !errors.Is(err, ErrIncomplete) || len(findings) != 1 || coverage["findings"] != "1" {
				t.Fatal(findings, coverage, err)
			}
			finding := findings[0]
			if err := finding.Verify(); err != nil {
				t.Fatal(err)
			}
			if finding.Cells["Entity"].String() != rows[1001].Cells["ProcessIdentity"].String() || finding.Provenance.SymbolsSHA256 != rows[1001].Provenance.SymbolsSHA256 || finding.Cells["NativeRule"].String() != rows[1001].Cells["Rule"].String() {
				t.Fatal(finding)
			}
			refs := finding.Cells["EvidenceIDs"].Data.([]string)
			if len(refs) != 1 || refs[0] != rows[1001].ID {
				t.Fatal(refs)
			}
		})
	}
}

func TestNativeTriageRejectsIncompleteOrInvalidEvidence(t *testing.T) {
	for _, rule := range nativeRules() {
		for _, scenario := range []string{"no-summary", "bad-count", "missing-count", "numeric-count", "diagnostic-no-cause", "wrong-plugin", "mixed-image", "unknown-rule", "wrong-offset", "missing-identity", "after-summary", "tamper", "output-failure", "cancel"} {
			t.Run(rule.ID+"/"+scenario, func(t *testing.T) {
				rows := nativeCheckRows(t, rule, true, 0)
				coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
				switch scenario {
				case "no-summary":
					rows = rows[:1]
				case "bad-count":
					coverage["findings"] = "2"
				case "missing-count":
					delete(coverage, "processes")
				case "numeric-count":
					coverage["processes"] = float64(1)
				case "diagnostic-no-cause":
					rows[0].Cells["RecordType"] = evidence.Text("diagnostic")
				case "wrong-plugin":
					rows[0].Provenance.Plugin = "windows.pslist"
				case "mixed-image":
					rows[1].Provenance.ImageSHA256 = "other-image"
				case "unknown-rule":
					rows[0].Cells["Rule"] = evidence.Text("unknown")
				case "wrong-offset":
					rows[0].Provenance.Offset = "0xdead"
				case "missing-identity":
					delete(rows[0].Cells, "ProcessIdentity")
				case "after-summary":
					rows = append(rows, rows[0])
				}
				for i := range rows {
					rows[i].Seal()
				}
				if scenario == "tamper" {
					rows[0].Cells["PID"] = evidence.Number(999)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if scenario == "cancel" {
					cancel()
				}
				failure := errors.New("write failed")
				err := Evaluate(ctx, rule, map[string][]evidence.Row{rule.Inputs[0]: rows}, func(evidence.Row) error {
					if scenario == "output-failure" {
						return failure
					}
					return nil
				})
				if err == nil {
					t.Fatal("accepted invalid/incomplete native input")
				}
				if scenario == "cancel" && !errors.Is(err, context.Canceled) || scenario == "output-failure" && !errors.Is(err, failure) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestNativeTriageUnreadablePathRemainsLimitedEvidence(t *testing.T) {
	for _, rule := range nativeRules() {
		t.Run(rule.ID, func(t *testing.T) {
			rows := nativeCheckRows(t, rule, true, 0)
			rows[0].Cells["PathError"] = evidence.Missing("file_path_unreadable", errors.New("missing page"))
			if rule.Inputs[0] == "suspicious_threads" {
				rows[1].Cells["Coverage"].Data.(map[string]any)["path_read_errors"] = "1"
			}
			for i := range rows {
				rows[i].Seal()
			}
			count := 0
			err := Evaluate(context.Background(), rule, map[string][]evidence.Row{rule.Inputs[0]: rows}, func(row evidence.Row) error {
				count++
				if row.Cells["Severity"].String() != "info" || row.Cells["Confidence"].String() != "limited_by_path_read_error" || row.Cells["PathError"].Error == "" {
					t.Fatal(row)
				}
				return nil
			})
			if !errors.Is(err, ErrIncomplete) || count != 1 {
				t.Fatal(count, err)
			}
		})
	}
}
