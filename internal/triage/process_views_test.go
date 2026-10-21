package triage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func processViewRule() Rule {
	for _, r := range Rules {
		if r.ID == "hidden-process" {
			return ruleForPlatform(r, "windows")
		}
	}
	panic("missing hidden-process rule")
}

// Use the same PID for active and absent objects to detect PID-only correlation.
func processViewRows(diagnostics, controls int) []evidence.Row {
	var rows []evidence.Row
	counts := [4]int{}
	for i := 0; i < diagnostics; i++ {
		r := row(uint64(0x1000+i), "diagnostic")
		r.Provenance.Plugin = "windows.psxview"
		r.Cells["RecordType"] = evidence.Text("diagnostic")
		r.Cells["Error"] = evidence.Missing("read_failure", errors.New("missing page"))
		r.Seal()
		rows = append(rows, r)
	}
	for i := 0; i < controls+2; i++ {
		addr := uint64(0x10000 + i*0x1000)
		r := row(addr, "process.exe")
		r.Provenance.Plugin = "windows.psxview"
		r.Provenance.SymbolsSHA256 = "fixture-symbols"
		r.Cells["RecordType"] = evidence.Text("process")
		r.Cells["PID"] = evidence.Number(104)
		r.Cells["Identity"] = evidence.Text(evidence.ProcessID(r.Provenance.ImageSHA256, r.Provenance.Layer, addr, 104, ""))
		r.Cells["ObjectOffset"] = evidence.Address(addr)
		r.Cells["ObjectLayer"] = evidence.Text(r.Provenance.Layer)
		r.Cells["OffsetSpace"] = evidence.Text("kernel_virtual")
		r.Cells["ExitTime"] = evidence.Text("")
		if i == controls+1 {
			r.Cells["ExitTime"] = evidence.Text("2025-03-01 12:00:00+00:00")
		}
		origins := map[string]any{}
		for j, source := range processViewNames {
			flag := i < controls || j == 1 || j == 2
			r.Cells[source] = evidence.Bool(flag)
			if flag {
				origins[source] = map[string]any{"offset": evidence.Address(addr).String(), "layer": r.Provenance.Layer, "display_space": "kernel_virtual"}
				counts[j]++
			}
		}
		r.Cells["Sources"] = evidence.Value{Kind: "structure", Data: origins}
		r.Seal()
		rows = append(rows, r)
	}
	coverage := map[string]any{"active_candidates": strconv.Itoa(controls), "csrss_processes": "1", "csrss_handles": "1", "csrss_unreadable_object_tables": "0", "csrss_unreadable_handle_tables": "0", "csrss_handle_cycles": "0", "pool_read_failures": "0", "pool_type_map_entries": "8"}
	for i, source := range processViewNames {
		coverage[source] = strconv.Itoa(counts[i])
		coverage[source+"_rejected"], coverage[source+"_duplicates"] = "0", "0"
	}
	summary := row(0, "summary")
	summary.Provenance.Plugin = "windows.psxview"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: coverage}
	summary.Seal()
	return append(rows, summary)
}

func TestProcessViewTriagePagedIdentityAndExitControls(t *testing.T) {
	for _, diagnostics := range []int{0, 1001} {
		t.Run(fmt.Sprint(diagnostics), func(t *testing.T) {
			rows := processViewRows(diagnostics, 501)
			eval := nativeCheckEvaluator{rule: processViewRule()}
			var findings []evidence.Row
			for off := 0; off < len(rows); off += 500 {
				if err := eval.consume(context.Background(), rows[off:min(off+500, len(rows))], func(r evidence.Row) error { findings = append(findings, r); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			coverage, err := eval.finish()
			if (diagnostics == 0 && err != nil) || (diagnostics > 0 && !errors.Is(err, ErrIncomplete)) || len(findings) != 2 || coverage["psscan"] != "503" {
				t.Fatal(len(findings), coverage, err)
			}
			for i, f := range findings {
				source := rows[diagnostics+501+i]
				severity := "high"
				if i == 1 {
					severity = "info"
				}
				if f.Verify() != nil || f.Cells["Severity"].String() != severity || f.Cells["Entity"].String() != source.Cells["Identity"].String() || f.Cells["ObjectOffset"].String() != source.Provenance.Offset || f.Cells["NativeRule"].String() != "absent_active_view" || f.Cells["SourcePlugin"].String() != "windows.psxview" || f.Provenance.SymbolsSHA256 != source.Provenance.SymbolsSHA256 || f.Cells["EvidenceIDs"].Data.([]string)[0] != source.ID {
					t.Fatal(f)
				}
			}
			if findings[0].Cells["Entity"].String() == findings[1].Cells["Entity"].String() {
				t.Fatal("PID reuse merged objects")
			}
		})
	}
}

func TestProcessViewTriageRejectsInvalidEvidence(t *testing.T) {
	for _, scenario := range []string{"no-summary", "bad-count", "missing-count", "numeric-count", "wrong-plugin", "mixed-image", "wrong-offset", "missing-identity", "missing-layer", "string-flag", "source-mismatch", "invalid-origin", "invalid-origin-offset", "wrong-representative", "invalid-space", "bad-exit", "unreadable-exit", "no-view", "after-summary", "tamper", "output-failure", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			rows := processViewRows(0, 0)
			coverage := rows[2].Cells["Coverage"].Data.(map[string]any)
			origins := rows[0].Cells["Sources"].Data.(map[string]any)
			switch scenario {
			case "no-summary":
				rows = rows[:2]
			case "bad-count":
				coverage["psscan"] = "3"
			case "missing-count":
				delete(coverage, "pool_type_map_entries")
			case "numeric-count":
				coverage["psscan"] = float64(2)
			case "wrong-plugin":
				rows[0].Provenance.Plugin = "windows.psscan"
			case "mixed-image":
				rows[1].Provenance.ImageSHA256 = "other-image"
			case "wrong-offset":
				rows[0].Provenance.Offset = "0xbeef"
			case "missing-identity":
				delete(rows[0].Cells, "Identity")
			case "missing-layer":
				delete(rows[0].Cells, "ObjectLayer")
			case "string-flag":
				rows[0].Cells["psscan"] = evidence.Text("true")
			case "source-mismatch":
				delete(origins, "psscan")
			case "invalid-origin":
				origins["psscan"] = "kernel"
			case "invalid-origin-offset":
				origins["psscan"].(map[string]any)["offset"] = "bad"
			case "wrong-representative":
				origins["psscan"].(map[string]any)["offset"] = "0xbeef"
			case "invalid-space":
				rows[0].Cells["OffsetSpace"] = evidence.Text("unknown")
			case "bad-exit":
				rows[0].Cells["ExitTime"] = evidence.Text("2025-03-01")
			case "unreadable-exit":
				rows[0].Cells["ExitTime"] = evidence.Missing("missing_page", errors.New("page"))
			case "no-view":
				for _, name := range processViewNames {
					rows[0].Cells[name] = evidence.Bool(false)
					delete(origins, name)
				}
			case "after-summary":
				rows = append(rows, rows[0])
			}
			for i := range rows {
				rows[i].Seal()
			}
			if scenario == "tamper" {
				rows[0].Cells["PID"] = evidence.Number(1)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			failure := errors.New("write failed")
			err := Evaluate(ctx, processViewRule(), map[string][]evidence.Row{"psxview": rows}, func(evidence.Row) error {
				if scenario == "output-failure" {
					return failure
				}
				return nil
			})
			if err == nil {
				t.Fatal("accepted invalid input")
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) || scenario == "output-failure" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
		})
	}
}

func TestProcessViewTriageIncompleteCoverage(t *testing.T) {
	for _, field := range []string{"csrss_processes", "pool_type_map_entries", "pool_read_failures", "csrss_unreadable_object_tables", "csrss_unreadable_handle_tables", "csrss_handle_cycles"} {
		t.Run(field, func(t *testing.T) {
			rows := processViewRows(0, 0)
			value := "1"
			if field == "csrss_processes" || field == "pool_type_map_entries" {
				value = "0"
			}
			rows[2].Cells["Coverage"].Data.(map[string]any)[field] = value
			rows[2].Seal()
			count := 0
			err := Evaluate(context.Background(), processViewRule(), map[string][]evidence.Row{"psxview": rows}, func(evidence.Row) error { count++; return nil })
			if !errors.Is(err, ErrIncomplete) || count != 2 {
				t.Fatal(count, err)
			}
		})
	}
}

func TestHiddenProcessPlatformRules(t *testing.T) {
	r := processViewRule()
	if r.Kind != "native-check" || r.Inputs[0] != "psxview" {
		t.Fatal(r)
	}
	for _, rule := range Rules {
		if rule.ID == r.ID {
			linux := ruleForPlatform(rule, "linux")
			if linux.Kind != "difference" || len(linux.Inputs) != 2 {
				t.Fatal(linux)
			}
		}
	}
}
