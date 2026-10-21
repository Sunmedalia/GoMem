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

func ghostingRule() Rule {
	for _, rule := range Rules {
		if rule.ID == "deleted-or-memfd-execution" {
			return ruleForPlatform(rule, "windows")
		}
	}
	panic("missing deletion rule")
}
func ghostingRows(diagnostics int, positive bool) []evidence.Row {
	var rows []evidence.Row
	for i := 0; i < diagnostics; i++ {
		r := row(uint64(0x4000+i), "diagnostic")
		r.Provenance.Plugin = "windows.processghosting"
		r.Cells["RecordType"] = evidence.Text("diagnostic")
		r.Cells["Error"] = evidence.Missing("page", errors.New("missing page"))
		r.Seal()
		rows = append(rows, r)
	}
	count := "0"
	if positive {
		count = "3"
		for _, rule := range []string{"image_file_state", "vad_delete_on_close", "vad_delete_pending"} {
			r := row(0x2000, "main.exe")
			r.Provenance.Plugin = "windows.processghosting"
			r.Provenance.SymbolsSHA256 = "fixture-symbols"
			r.Cells["RecordType"] = evidence.Text("finding")
			r.Cells["ProcessIdentity"] = evidence.Text("image-layer-object-pid-created")
			r.Cells["ProcessOffset"] = evidence.Address(0x2000)
			r.Cells["PID"] = evidence.Number(104)
			r.Cells["Process"] = evidence.Text("main.exe")
			r.Cells["Base"] = evidence.Address(0x100000)
			r.Cells["FILE_OBJECT"] = evidence.Address(0x8000)
			r.Cells["Rule"] = evidence.Text(rule)
			r.Cells["Path"] = evidence.Text(`C:\main.exe`)
			r.Cells["DeletePending"], r.Cells["DeleteOnClose"] = evidence.Missing("not_applicable", nil), evidence.Missing("not_applicable", nil)
			r.Cells["DeletePendingRaw"], r.Cells["DeleteOnCloseRaw"] = evidence.Number(1), evidence.Number(1)
			if rule == "vad_delete_on_close" {
				r.Cells["DeleteOnClose"] = evidence.Number(1)
			} else {
				r.Cells["DeletePending"] = evidence.Number(1)
			}
			if rule == "image_file_state" {
				r.Cells["ImageFilePointerOffset"] = evidence.Address(0x2488)
				r.Cells["ImageFileRaw"] = evidence.Address(0x8000)
			} else {
				r.Cells["VADOffset"] = evidence.Address(0x6000)
				r.Cells["ControlArea"] = evidence.Address(0x7000)
			}
			r.Seal()
			rows = append(rows, r)
		}
	}
	r := row(0, "summary")
	r.Provenance.Plugin = "windows.processghosting"
	r.Cells["RecordType"] = evidence.Text("summary")
	r.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{"processes": "1", "active": "1", "filtered": "0", "vads": "5", "mapped_files": "3", "private_skipped": "0", "findings": count, "diagnostics": strconv.Itoa(diagnostics), "image_file_member": "1", "handle_count_member": "0"}}
	r.Seal()
	return append(rows, r)
}

func TestGhostingTriageControlsAndLateFindings(t *testing.T) {
	for _, positive := range []bool{false, true} {
		for _, diagnostics := range []int{0, 1001} {
			t.Run(fmt.Sprint(positive, diagnostics), func(t *testing.T) {
				rows := ghostingRows(diagnostics, positive)
				eval := nativeCheckEvaluator{rule: ghostingRule()}
				var findings []evidence.Row
				for off := 0; off < len(rows); off += 500 {
					if err := eval.consume(context.Background(), rows[off:min(off+500, len(rows))], func(r evidence.Row) error { findings = append(findings, r); return nil }); err != nil {
						t.Fatal(err)
					}
				}
				coverage, err := eval.finish()
				want := 0
				if positive {
					want = 3
				}
				if diagnostics == 0 && err != nil || diagnostics > 0 && !errors.Is(err, ErrIncomplete) || len(findings) != want || coverage["diagnostics"] != strconv.Itoa(diagnostics) {
					t.Fatal(findings, coverage, err)
				}
				for i, f := range findings {
					source := rows[diagnostics+i]
					if f.Verify() != nil || f.Cells["NativeRule"].String() != source.Cells["Rule"].String() || f.Cells["Severity"].String() != "high" || f.Cells["EvidenceIDs"].Data.([]string)[0] != source.ID || f.Cells["Entity"].String() != source.Cells["ProcessIdentity"].String() || f.Provenance.SymbolsSHA256 != source.Provenance.SymbolsSHA256 || f.Cells["FILE_OBJECT"].String() != source.Cells["FILE_OBJECT"].String() {
						t.Fatal(f)
					}
				}
			})
		}
	}
}

func TestGhostingTriageRejectsInvalidEvidence(t *testing.T) {
	for _, scenario := range []string{"missing-summary", "bad-count", "missing-count", "numeric-count", "bad-diagnostics", "bad-active", "bad-filtered", "bad-mapped", "bad-private", "bad-image-member", "unknown-rule", "wrong-plugin", "mixed-image", "wrong-offset", "missing-identity", "missing-file", "missing-vad", "missing-control", "bad-pending", "bad-raw-pending", "bad-close", "bad-raw-close", "bad-close-path", "string-pending", "missing-image-field", "image-field-before-object", "bad-null-pending", "wrong-missing-path", "unexpected-flag", "bad-path-type", "after-summary", "tamper", "output-failure", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			rows := ghostingRows(0, true)
			coverage := rows[3].Cells["Coverage"].Data.(map[string]any)
			switch scenario {
			case "missing-summary":
				rows = rows[:3]
			case "bad-count":
				coverage["findings"] = "4"
			case "missing-count":
				delete(coverage, "vads")
			case "numeric-count":
				coverage["processes"] = float64(1)
			case "bad-diagnostics":
				coverage["diagnostics"] = "1"
			case "bad-active":
				coverage["active"] = "2"
			case "bad-filtered":
				coverage["filtered"] = "1"
			case "bad-mapped":
				coverage["mapped_files"] = "6"
			case "bad-private":
				coverage["private_skipped"] = "4"
			case "bad-image-member":
				coverage["image_file_member"] = "0"
			case "unknown-rule":
				rows[0].Cells["Rule"] = evidence.Text("unknown")
			case "wrong-plugin":
				rows[0].Provenance.Plugin = "windows.vadinfo"
			case "mixed-image":
				rows[1].Provenance.ImageSHA256 = "other"
			case "wrong-offset":
				rows[0].Provenance.Offset = "0xbeef"
			case "missing-identity":
				delete(rows[0].Cells, "ProcessIdentity")
			case "missing-file":
				delete(rows[0].Cells, "FILE_OBJECT")
			case "missing-vad":
				delete(rows[1].Cells, "VADOffset")
			case "missing-control":
				delete(rows[1].Cells, "ControlArea")
			case "bad-pending":
				rows[0].Cells["DeletePending"] = evidence.Number(2)
			case "bad-raw-pending":
				rows[0].Cells["DeletePendingRaw"] = evidence.Number(0)
			case "bad-close":
				rows[1].Cells["DeleteOnClose"] = evidence.Number(0)
			case "bad-raw-close":
				rows[1].Cells["DeleteOnCloseRaw"] = evidence.Number(2)
			case "bad-close-path":
				rows[1].Cells["Path"] = evidence.Text("a.exe ")
			case "string-pending":
				rows[0].Cells["DeletePending"] = evidence.Text("1")
			case "missing-image-field":
				delete(rows[0].Cells, "ImageFilePointerOffset")
			case "image-field-before-object":
				rows[0].Cells["ImageFilePointerOffset"] = evidence.Address(0x1000)
			case "bad-null-pending":
				rows[0].Cells["FILE_OBJECT"] = evidence.Address(0)
				rows[0].Cells["DeletePending"] = evidence.Number(2)
			case "wrong-missing-path":
				rows[0].Cells["Path"] = evidence.Missing("unreadable", errors.New("page"))
			case "unexpected-flag":
				rows[0].Cells["DeleteOnClose"] = evidence.Number(1)
			case "bad-path-type":
				rows[1].Cells["Path"] = evidence.Value{Kind: "string", Data: 1}
			case "after-summary":
				rows = append(rows, rows[0])
			}
			for i := range rows {
				rows[i].Seal()
			}
			if scenario == "tamper" {
				rows[0].Cells["PID"] = evidence.Number(3)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			failure := errors.New("output failed")
			err := Evaluate(ctx, ghostingRule(), map[string][]evidence.Row{"processghosting": rows}, func(evidence.Row) error {
				if scenario == "output-failure" {
					return failure
				}
				return nil
			})
			if err == nil {
				t.Fatal("accepted invalid evidence")
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) || scenario == "output-failure" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
		})
	}
}

func TestGhostingTriageNullAndUnreadableFilesAreInformational(t *testing.T) {
	for _, readError := range []bool{false, true} {
		t.Run(fmt.Sprint(readError), func(t *testing.T) {
			diagnostics := 0
			if readError {
				diagnostics = 1
			}
			rows := ghostingRows(diagnostics, true)
			r := &rows[diagnostics]
			r.Cells["FILE_OBJECT"] = evidence.Address(0)
			r.Cells["DeletePending"] = evidence.Missing("not_applicable", nil)
			r.Cells["Path"] = evidence.Missing("not_available", nil)
			if readError {
				r.Cells["Error"] = evidence.Missing("image_file_unreadable", errors.New("missing page"))
			}
			r.Seal()
			var findings []evidence.Row
			err := Evaluate(context.Background(), ghostingRule(), map[string][]evidence.Row{"processghosting": rows}, func(r evidence.Row) error { findings = append(findings, r); return nil })
			if !readError && err != nil || readError && !errors.Is(err, ErrIncomplete) || len(findings) != 3 {
				t.Fatal(findings, err)
			}
			if findings[0].Cells["Severity"].String() != "info" || findings[0].Cells["Confidence"].String() != "limited_by_null_or_unreadable_file_object" || readError && findings[0].Cells["Error"].Error == "" {
				t.Fatal(findings[0])
			}
		})
	}
}

func TestGhostingTriageCasePagingWhitelistResumeAndEvidence(t *testing.T) {
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
	if err = e.Registry.Register(triageFixturePlugin{name: "windows.processghosting", rows: ghostingRows(1001, true)}); err != nil {
		t.Fatal(err)
	}
	first, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || first.Findings != 3 {
		t.Fatal(first, err)
	}
	for _, check := range first.Checks {
		if check.Rule == ghostingRule().ID && (check.State != "incomplete" || check.Findings != 3 || check.Coverage["diagnostics"] != "1001") {
			t.Fatal(check)
		}
	}
	findings, err := e.Store.Query(ctx, evidence.Query{TaskID: first.FindingTask, Limit: 100})
	if err != nil || len(findings) != 3 {
		t.Fatal(findings, err)
	}
	for _, finding := range findings {
		refs := finding.Cells["EvidenceIDs"].Data.([]any)
		source, err := e.Store.Find(ctx, refs[0].(string))
		if err != nil || source.Verify() != nil || finding.Verify() != nil || source.Provenance.Plugin != "windows.processghosting" || source.Provenance.Offset != finding.Provenance.Offset || source.Provenance.SymbolsSHA256 != e.Env.Symbols.Digest() || source.Cells["ProcessIdentity"].String() != finding.Cells["Entity"].String() {
			t.Fatal(finding, source, err)
		}
	}
	if err = e.Store.Allow(ctx, ghostingRule().ID, findings[0].Cells["Entity"].String(), "test process control"); err != nil {
		t.Fatal(err)
	}
	again, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || again.Findings != 0 {
		t.Fatal(again, err)
	}
	for _, task := range again.Tasks {
		if !task.Reused {
			t.Fatal(task)
		}
		if task.Task.Plugin == "windows.processghosting" {
			raw, err := e.Store.Query(ctx, evidence.Query{TaskID: task.Task.ID, Offset: 1000, Limit: 500})
			if err != nil || len(raw) != 5 || raw[1].Cells["RecordType"].String() != "finding" {
				t.Fatal("whitelist removed raw data", len(raw), err)
			}
		}
	}
}

func TestGhostingTriageKeepsSamePIDDifferentObjects(t *testing.T) {
	rows := ghostingRows(0, true)
	reused := rows[0]
	reused.Cells = map[string]evidence.Value{}
	for key, value := range rows[0].Cells {
		reused.Cells[key] = value
	}
	reused.Provenance.Offset = "0x3000"
	reused.Cells["ProcessOffset"] = evidence.Address(0x3000)
	reused.Cells["ProcessIdentity"] = evidence.Text("same-pid-other-object")
	reused.Cells["ImageFilePointerOffset"] = evidence.Address(0x3488)
	reused.Seal()
	summary := rows[3]
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	coverage["findings"], coverage["processes"], coverage["active"] = "4", "2", "2"
	summary.Seal()
	rows = append(rows[:3], reused, summary)
	var findings []evidence.Row
	err := Evaluate(context.Background(), ghostingRule(), map[string][]evidence.Row{"processghosting": rows}, func(r evidence.Row) error { findings = append(findings, r); return nil })
	if err != nil || len(findings) != 4 || findings[0].Cells["PID"].String() != findings[3].Cells["PID"].String() || findings[0].Cells["Entity"].String() == findings[3].Cells["Entity"].String() {
		t.Fatal(findings, err)
	}
	for _, rule := range Rules {
		if rule.ID == ghostingRule().ID {
			linux := ruleForPlatform(rule, "linux")
			if linux.Kind != "deleted" || len(linux.Inputs) != 1 || linux.Inputs[0] != "maps" {
				t.Fatal(linux)
			}
		}
	}
}
