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

func pebTriageRule() Rule {
	for _, r := range Rules {
		if r.ID == "peb-string-length" {
			return r
		}
	}
	panic("missing PEB length rule")
}
func pebTriageRows(controls, diagnostics, positives int) []evidence.Row {
	var rows []evidence.Row
	for i := 0; i < controls+diagnostics+positives; i++ {
		offset := uint64(0x2000 + i*0x100)
		r := row(offset, "proc.exe")
		r.Provenance.Plugin = "windows.pebmasquerade"
		r.Provenance.SymbolsSHA256 = "fixture-symbols"
		r.Cells["RecordType"] = evidence.Text("process")
		r.Cells["ProcessIdentity"] = evidence.Text(fmt.Sprintf("process-object-%x", offset))
		r.Cells["ProcessOffset"] = evidence.Address(offset)
		r.Cells["ProcessLayer"] = evidence.Text("process:" + r.Cells["ProcessIdentity"].String())
		r.Cells["PEB"], r.Cells["Parameters"] = evidence.Address(0x4000), evidence.Address(0x5000)
		r.Cells["PID"] = evidence.Number(104) // Same PID is deliberately not the join key.
		r.Cells["EPROCESS_ImageFileName"], r.Cells["EPROCESS_SeAudit_ImageFileName"] = evidence.Text("proc.exe"), evidence.Text(`\Device\disk\proc.exe`)
		r.Cells["Error"] = evidence.Missing("not_applicable", nil)
		diagnostic := i >= controls && i < controls+diagnostics
		positive := i >= controls+diagnostics
		for j, f := range []struct{ text, detail, check, compatibility string }{
			{"PEB_ImageFilePath", "ImagePathEvidence", "ImagePathLengthMismatch", "PEB_CommandLine_Spoofed"},
			{"PEB_CommandLine", "CommandLineEvidence", "CommandLineLengthMismatch", "PEB_ImageFilePath_Spoofed"},
		} {
			r.Cells[f.compatibility] = evidence.Bool(positive)
			if diagnostic {
				r.Cells[f.text] = evidence.Missing("not_available", nil)
				r.Cells[f.detail] = evidence.Missing("not_applicable", nil)
				r.Cells[f.check] = evidence.Missing("not_checked", nil)
				r.Cells["Error"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"peb_unreadable": evidence.Missing("peb_unreadable", errors.New("missing page"))}}
				continue
			}
			raw := []byte{'A', 0}
			maximum := uint64(4)
			if positive {
				raw = append(raw, 0, 0)
				maximum = 6
			}
			r.Cells[f.text] = evidence.Text("A")
			r.Cells[f.check] = evidence.Bool(positive)
			r.Cells[f.detail] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{
				"Descriptor": evidence.Address(0x5000 + uint64(j*16)), "Buffer": evidence.Address(0x6000 + uint64(j*0x100)),
				"Length": evidence.Number(uint64(len(raw))), "MaximumLength": evidence.Number(maximum),
				"Raw": evidence.Bytes(raw), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(true), "Decoded": evidence.Text("A"), "Codepoints": evidence.Number(1), "Layer": r.Cells["ProcessLayer"],
			}}
		}
		r.Seal()
		rows = append(rows, r)
	}
	r := row(0, "summary")
	r.Provenance.Plugin = "windows.pebmasquerade"
	r.Cells["RecordType"] = evidence.Text("summary")
	r.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{"processes": strconv.Itoa(controls + diagnostics + positives), "image_path_checked": strconv.Itoa(controls + positives), "command_line_checked": strconv.Itoa(controls + positives), "image_path_mismatches": strconv.Itoa(positives), "command_line_mismatches": strconv.Itoa(positives), "diagnostics": strconv.Itoa(diagnostics)}}
	r.Seal()
	return append(rows, r)
}
func TestPebTriageControlsAndLateFindings(t *testing.T) {
	for _, diagnostics := range []int{0, 1001} {
		for _, positives := range []int{0, 2} {
			rows := pebTriageRows(501, diagnostics, positives)
			eval := nativeCheckEvaluator{rule: pebTriageRule()}
			var findings []evidence.Row
			for off := 0; off < len(rows); off += 500 {
				if err := eval.consume(context.Background(), rows[off:min(off+500, len(rows))], func(r evidence.Row) error { findings = append(findings, r); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			coverage, err := eval.finish()
			if diagnostics == 0 && err != nil || diagnostics > 0 && !errors.Is(err, ErrIncomplete) || len(findings) != positives || coverage["diagnostics"] != strconv.Itoa(diagnostics) {
				t.Fatal(coverage, len(findings), err)
			}
			for i, f := range findings {
				source := rows[501+diagnostics+i]
				if f.Verify() != nil || f.Cells["Severity"].String() != "info" || f.Cells["Confidence"].String() != "length_indicator_only" || f.Cells["EvidenceIDs"].Data.([]string)[0] != source.ID || f.Cells["Entity"].String() != source.Cells["ProcessIdentity"].String() || f.Provenance.Offset != source.Provenance.Offset || f.Provenance.SymbolsSHA256 != source.Provenance.SymbolsSHA256 || f.Cells["ImagePathEvidence"].Kind != "structure" || f.Cells["FalsePositive"].String() == "" {
					t.Fatal(f)
				}
			}
			if positives == 2 && findings[0].Cells["Entity"].String() == findings[1].Cells["Entity"].String() {
				t.Fatal("same PID merged")
			}
		}
	}
}
func TestPebTriageInvalidEvidence(t *testing.T) {
	for _, scenario := range []string{"summary-missing", "summary-count", "missing-checked", "diagnostics-count", "after-summary", "source", "image", "offset", "identity", "pid", "peb", "parameters", "descriptor", "layer", "text", "empty-text", "bool-type", "swapped-flag", "missing-check", "invalid-missing", "length", "capacity", "raw", "raw-text", "captured", "complete", "points", "decoded", "detail-error", "error-state", "error-cause", "diagnostic-record", "finding-record", "unsealed", "cancel", "output"} {
		t.Run(scenario, func(t *testing.T) {
			rows := pebTriageRows(0, 0, 1)
			r := &rows[0]
			summary := rows[1].Cells["Coverage"].Data.(map[string]any)
			detail := r.Cells["ImagePathEvidence"].Data.(map[string]evidence.Value)
			switch scenario {
			case "summary-missing":
				rows = rows[:1]
			case "summary-count":
				summary["processes"] = "2"
			case "missing-checked":
				delete(summary, "image_path_checked")
			case "diagnostics-count":
				summary["diagnostics"] = "1"
			case "after-summary":
				rows = append(rows, rows[0])
			case "source":
				r.Provenance.Plugin = "windows.cmdline"
			case "image":
				r.Provenance.ImageSHA256 = ""
			case "offset":
				r.Provenance.Offset = "0x9000"
			case "identity":
				delete(r.Cells, "ProcessIdentity")
			case "pid":
				r.Cells["PID"] = evidence.Text("104")
			case "peb":
				delete(r.Cells, "PEB")
			case "parameters":
				r.Cells["Parameters"] = evidence.Address(0x6000)
			case "descriptor":
				detail["Descriptor"] = evidence.Number(0x5000)
			case "layer":
				detail["Layer"] = evidence.Text("wrong")
			case "text":
				r.Cells["PEB_ImageFilePath"] = evidence.Missing("not_available", nil)
			case "empty-text":
				r.Cells["PEB_ImageFilePath"] = evidence.Text("")
			case "bool-type":
				r.Cells["ImagePathLengthMismatch"] = evidence.Text("true")
			case "swapped-flag":
				r.Cells["PEB_CommandLine_Spoofed"] = evidence.Bool(false)
			case "missing-check":
				delete(r.Cells, "ImagePathLengthMismatch")
			case "invalid-missing":
				r.Cells["ImagePathLengthMismatch"] = evidence.Missing("not_applicable", nil)
			case "length":
				detail["Length"] = evidence.Number(65536)
			case "capacity":
				detail["MaximumLength"] = evidence.Number(65536)
			case "raw":
				detail["Raw"] = evidence.Bytes([]byte{'A'})
			case "raw-text":
				detail["Raw"] = evidence.Bytes([]byte{'B', 0, 0, 0})
			case "captured":
				detail["CapturedBytes"] = evidence.Number(2)
			case "complete":
				detail["ReadComplete"] = evidence.Bool(false)
			case "points":
				detail["Codepoints"] = evidence.Number(3)
			case "decoded":
				detail["Decoded"] = evidence.Text("different")
			case "detail-error":
				detail["Error"] = evidence.Missing("bad", errors.New("partial"))
			case "error-state":
				delete(r.Cells, "Error")
			case "error-cause":
				r.Cells["Error"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"bad": evidence.Missing("bad", nil)}}
			case "diagnostic-record":
				r.Cells["RecordType"] = evidence.Text("diagnostic")
			case "finding-record":
				r.Cells["RecordType"] = evidence.Text("finding")
			}
			for i := range rows {
				rows[i].Seal()
			}
			if scenario == "unsealed" {
				rows[0].Cells["PID"] = evidence.Number(123)
			}
			ctx := context.Background()
			if scenario == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := Evaluate(ctx, pebTriageRule(), map[string][]evidence.Row{"pebmasquerade": rows}, func(evidence.Row) error {
				if scenario == "output" {
					return errors.New("output failed")
				}
				return nil
			})
			if err == nil {
				t.Fatal("invalid evidence treated as valid")
			}
		})
	}
}

func TestPebTriageCasePagingWhitelistAndResume(t *testing.T) {
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
	if err = e.Registry.Register(triageFixturePlugin{name: "windows.pebmasquerade", rows: pebTriageRows(501, 1001, 2)}); err != nil {
		t.Fatal(err)
	}
	first, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || first.Findings != 2 {
		t.Fatal(first, err)
	}
	findings, err := e.Store.Query(ctx, evidence.Query{TaskID: first.FindingTask, Limit: 100})
	if err != nil || len(findings) != 2 {
		t.Fatal(findings, err)
	}
	for _, finding := range findings {
		refs := finding.Cells["EvidenceIDs"].Data.([]any)
		source, err := e.Store.Find(ctx, refs[0].(string))
		if err != nil || source.Verify() != nil || finding.Verify() != nil || finding.Provenance.Offset != source.Provenance.Offset || finding.Cells["Entity"].String() != source.Cells["ProcessIdentity"].String() {
			t.Fatal(finding, source, err)
		}
	}
	if err = e.Store.Allow(ctx, pebTriageRule().ID, findings[0].Cells["Entity"].String(), "one object is an authorized control"); err != nil {
		t.Fatal(err)
	}
	again, err := Run(ctx, e, nil)
	if !errors.Is(err, ErrIncomplete) || again.Findings != 1 {
		t.Fatal(again, err)
	}
	seen := false
	for _, check := range again.Checks {
		if check.Rule == pebTriageRule().ID {
			seen = true
			if check.State != "incomplete" || check.Coverage["diagnostics"] != "1001" || check.Findings != 1 {
				t.Fatal(check)
			}
		}
	}
	if !seen {
		t.Fatal("PEB rule missing")
	}
	for _, task := range again.Tasks {
		if !task.Reused {
			t.Fatal(task)
		}
		if task.Task.Plugin == "windows.pebmasquerade" {
			raw, err := e.Store.Query(ctx, evidence.Query{TaskID: task.Task.ID, Offset: 1500, Limit: 500})
			if err != nil || len(raw) != 5 || raw[2].Cells["ImagePathLengthMismatch"].Data != true {
				t.Fatal("whitelist changed original evidence", raw, err)
			}
		}
	}
}

func TestPebTriageIndependentChecksAndSkippedApplicability(t *testing.T) {
	for _, mode := range []string{"maximum-fault", "empty-string", "null-parameters"} {
		t.Run(mode, func(t *testing.T) {
			rows := pebTriageRows(0, 0, 1)
			r := &rows[0]
			r.Cells["ImagePathLengthMismatch"] = evidence.Missing("not_checked", nil)
			r.Cells["PEB_CommandLine_Spoofed"] = evidence.Bool(false)
			coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
			coverage["image_path_checked"], coverage["image_path_mismatches"] = "0", "0"
			want := 1
			if mode == "maximum-fault" {
				detail := r.Cells["ImagePathEvidence"].Data.(map[string]evidence.Value)
				delete(detail, "MaximumLength")
				detail["Error"] = evidence.Missing("maximum_length_unreadable", errors.New("capacity page missing"))
				// The diagnostic stage stored on the row includes its field name.
				r.Cells["Error"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"ImagePathName_maximum_length_unreadable": evidence.Missing("ImagePathName_maximum_length_unreadable", errors.New("capacity page missing"))}}
				coverage["diagnostics"] = "1"
			} else {
				r.Cells["PEB_ImageFilePath"] = evidence.Missing("not_available", nil)
				if mode == "null-parameters" {
					r.Cells["PEB_CommandLine"] = evidence.Missing("not_available", nil)
					r.Cells["CommandLineLengthMismatch"] = evidence.Missing("not_checked", nil)
					r.Cells["PEB_ImageFilePath_Spoofed"] = evidence.Bool(false)
					r.Cells["Parameters"] = evidence.Address(0)
					coverage["command_line_checked"], coverage["command_line_mismatches"] = "0", "0"
					want = 0
				}
			}
			for i := range rows {
				rows[i].Seal()
			}
			findings := 0
			err := Evaluate(context.Background(), pebTriageRule(), map[string][]evidence.Row{"pebmasquerade": rows}, func(evidence.Row) error { findings++; return nil })
			if !errors.Is(err, ErrIncomplete) || findings != want {
				t.Fatal(findings, err)
			}
		})
	}
}
