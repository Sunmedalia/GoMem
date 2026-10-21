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
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func moduleViewRule() Rule {
	for _, r := range Rules {
		if r.ID == "module-enumeration-difference" {
			return ruleForPlatform(r, "windows")
		}
	}
	panic("missing module rule")
}
func moduleViewRows(controls int, scanning bool, layer string) []evidence.Row {
	var rows []evidence.Row
	count := controls
	if scanning {
		count++
	}
	for i := 0; i < count; i++ {
		// All rows intentionally share name/base; only their object addresses differ.
		r := row(uint64(0x8000+i*64), "same.sys")
		r.Provenance.Layer = layer
		r.Provenance.Plugin = "windows.modules"
		if scanning {
			r.Provenance.Plugin = "windows.modscan"
			r.Cells["RecordType"] = evidence.Text("module")
		}
		r.Cells["Base"] = evidence.Address(0x4000)
		r.Cells["Size"] = evidence.Number(4096)
		r.Cells["Path"] = evidence.Text("\\SystemRoot\\same.sys")
		r.Seal()
		rows = append(rows, r)
	}
	if !scanning {
		return rows
	}
	summary := row(0, "summary")
	summary.Provenance.Layer = layer
	summary.Provenance.Plugin = "windows.modscan"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{"layer": layer, "modules": strconv.Itoa(count), "ranges": "1", "scanned_bytes": "131072", "skipped_invalid": "0", "skipped_type": "0", "skipped_name": "0", "read_failures": "0", "windows10": "true"}}
	summary.Seal()
	return append(rows, summary)
}

func TestModuleViewsPagedCoordinatesNotNameOrBase(t *testing.T) {
	active, scanned := moduleViewRows(1001, false, "kernel"), moduleViewRows(1001, true, "kernel")
	// Duplicate pool allocations cannot manufacture repeated findings.
	scanned = append(scanned[:len(scanned)-1], scanned[len(scanned)-2], scanned[len(scanned)-1])
	summary := &scanned[len(scanned)-1]
	summary.Cells["Coverage"].Data.(map[string]any)["modules"] = "1003"
	summary.Seal()
	eval := moduleViewEvaluator{rule: moduleViewRule()}
	var findings []evidence.Row
	for phase, rows := range [][]evidence.Row{active, scanned} {
		for off := 0; off < len(rows); off += 500 {
			if err := eval.consume(context.Background(), rows[off:min(off+500, len(rows))], phase == 1, func(r evidence.Row) error { findings = append(findings, r); return nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
	coverage, err := eval.finish()
	if err != nil || len(findings) != 1 || coverage["matched"] != "1001" || coverage["scanned_modules"] != "1003" || coverage["mismatches"] != "1" {
		t.Fatal(coverage, len(findings), err)
	}
	f := findings[0]
	source := scanned[1001]
	if f.Verify() != nil || f.Cells["EvidenceIDs"].Data.([]string)[0] != source.ID || f.Cells["ComparisonOffset"].String() != source.Cells["Offset"].String() || f.Provenance.Offset != source.Provenance.Offset || f.Cells["Name"].String() != "same.sys" || f.Cells["Severity"].String() != "medium" {
		t.Fatal(f)
	}
}

func TestModuleViewsRejectInvalidEvidence(t *testing.T) {
	for _, scenario := range []string{"wrong-plugin", "mixed-image", "wrong-offset", "missing-offset", "mixed-space", "summary-layer", "missing-summary", "bad-count", "missing-count", "numeric-count", "bad-coverage-type", "after-summary", "unknown-type", "bad-record-kind", "diagnostic-no-cause", "tamper", "cancel", "output-failure"} {
		t.Run(scenario, func(t *testing.T) {
			active, scanned := moduleViewRows(1, false, "kernel"), moduleViewRows(1, true, "kernel")
			coverage := scanned[2].Cells["Coverage"].Data.(map[string]any)
			switch scenario {
			case "wrong-plugin":
				scanned[0].Provenance.Plugin = "windows.psscan"
			case "mixed-image":
				scanned[0].Provenance.ImageSHA256 = "other"
			case "wrong-offset":
				scanned[0].Provenance.Offset = "0x123"
			case "missing-offset":
				delete(scanned[0].Cells, "Offset")
			case "mixed-space":
				scanned[0].Provenance.Layer = "physical"
			case "summary-layer":
				coverage["layer"] = "other"
			case "missing-summary":
				scanned = scanned[:2]
			case "bad-count":
				coverage["modules"] = "3"
			case "missing-count":
				delete(coverage, "skipped_name")
			case "numeric-count":
				coverage["modules"] = float64(2)
			case "bad-coverage-type":
				value := scanned[2].Cells["Coverage"]
				value.Kind = "string"
				scanned[2].Cells["Coverage"] = value
			case "after-summary":
				scanned = append(scanned, scanned[0])
			case "bad-record-kind":
				value := scanned[0].Cells["RecordType"]
				value.Kind = "address"
				scanned[0].Cells["RecordType"] = value
			case "unknown-type":
				scanned[0].Cells["RecordType"] = evidence.Text("process")
			case "diagnostic-no-cause":
				scanned[0].Cells["RecordType"] = evidence.Text("diagnostic")
			}
			for i := range scanned {
				scanned[i].Seal()
			}
			if scenario == "tamper" {
				scanned[0].Cells["Name"] = evidence.Text("changed")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			failure := errors.New("output failed")
			err := Evaluate(ctx, moduleViewRule(), map[string][]evidence.Row{"modules": active, "modscan": scanned}, func(evidence.Row) error {
				if scenario == "output-failure" {
					return failure
				}
				return nil
			})
			if err == nil {
				t.Fatal("accepted invalid module evidence")
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) || scenario == "output-failure" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
		})
	}
}

func TestModuleViewsIncompleteCoverageAndUnreadableNames(t *testing.T) {
	for _, scenario := range []string{"read_failures", "skipped_invalid", "skipped_type", "skipped_name", "ranges", "scanned_bytes", "no-active", "diagnostic", "name-error"} {
		t.Run(scenario, func(t *testing.T) {
			active, scanned := moduleViewRows(1, false, "kernel"), moduleViewRows(1, true, "kernel")
			coverage := scanned[2].Cells["Coverage"].Data.(map[string]any)
			switch scenario {
			case "no-active":
				active = nil
			case "diagnostic":
				d := row(0, "diagnostic")
				d.Provenance.Plugin = "windows.modscan"
				d.Cells["RecordType"] = evidence.Text("diagnostic")
				d.Cells["Error"] = evidence.Missing("read_failed", errors.New("page"))
				d.Seal()
				scanned = append([]evidence.Row{d}, scanned...)
			case "name-error":
				scanned[1].Cells["Name"] = evidence.Missing("unreadable", nil)
				scanned[1].Cells["NameError"] = evidence.Missing("unreadable", errors.New("page"))
			default:
				value := "1"
				if scenario == "ranges" || scenario == "scanned_bytes" {
					value = "0"
				}
				coverage[scenario] = value
			}
			for i := range scanned {
				scanned[i].Seal()
			}
			var findings []evidence.Row
			err := Evaluate(context.Background(), moduleViewRule(), map[string][]evidence.Row{"modules": active, "modscan": scanned}, func(r evidence.Row) error { findings = append(findings, r); return nil })
			if scenario == "name-error" {
				if err != nil || len(findings) != 1 || findings[0].Cells["NameError"].Error == "" || findings[0].Cells["Severity"].String() != "info" || findings[0].Cells["Confidence"].String() != "limited_by_module_metadata" {
					t.Fatal(findings, err)
				}
			} else if !errors.Is(err, ErrIncomplete) {
				t.Fatal(err)
			}
		})
	}
}

type moduleFixturePlugin struct {
	scanning bool
	controls int
	legacy   bool
}

func (p moduleFixturePlugin) Spec() plugin.Spec {
	name := "windows.modules"
	if p.scanning {
		name = "windows.modscan"
	}
	return plugin.Spec{Name: name}
}
func (p moduleFixturePlugin) Run(ctx context.Context, e plugin.Environment, _ map[string]string, emit plugin.Emit) error {
	layer := e.Kernel.Name()
	if p.scanning && p.legacy {
		layer = e.Physical.Name()
	}
	for _, r := range moduleViewRows(p.controls, p.scanning, layer) {
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func TestModuleViewsCasePhysicalLegacyPagingWhitelistAndResume(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
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
			for _, p := range []moduleFixturePlugin{{controls: 501}, {scanning: true, controls: 501, legacy: legacy}} {
				if err = e.Registry.Register(p); err != nil {
					t.Fatal(err)
				}
			}
			first, err := Run(ctx, e, nil)
			if !errors.Is(err, ErrIncomplete) || first.Findings != 1 {
				t.Fatal(first, err)
			}
			for _, check := range first.Checks {
				if check.Rule == "module-enumeration-difference" && (check.State != "completed" || check.Coverage["matched"] != "501") {
					t.Fatal(check)
				}
			}
			findings, err := e.Store.Query(ctx, evidence.Query{TaskID: first.FindingTask, Limit: 100})
			if err != nil || len(findings) != 1 {
				t.Fatal(findings, err)
			}
			finding := findings[0]
			refs := finding.Cells["EvidenceIDs"].Data.([]any)
			source, err := e.Store.Find(ctx, refs[0].(string))
			if err != nil || source.Verify() != nil || finding.Verify() != nil || finding.Cells["ComparisonSpace"].String() != "physical" || finding.Cells["ComparisonLayer"].String() != e.Env.Physical.Name() || source.Provenance.Plugin != "windows.modscan" || source.Provenance.Offset != finding.Provenance.Offset {
				t.Fatal(finding, source, err)
			}
			if err = e.Store.Allow(ctx, "module-enumeration-difference", finding.Cells["Entity"].String(), "test control"); err != nil {
				t.Fatal(err)
			}
			second, err := Run(ctx, e, nil)
			if !errors.Is(err, ErrIncomplete) || second.Findings != 0 {
				t.Fatal(second, err)
			}
			for _, task := range second.Tasks {
				if !task.Reused {
					t.Fatal(task)
				}
				if task.Task.Plugin == "windows.modscan" {
					raw, err := e.Store.Query(ctx, evidence.Query{TaskID: task.Task.ID, Offset: 500, Limit: 500})
					if err != nil || len(raw) != 3 {
						t.Fatal("raw module evidence removed", len(raw), err)
					}
				}
			}
		})
	}
}

// Resolve real virtual aliases through a deterministic page-table translator.
type moduleTestTranslator struct{ fail map[uint64]bool }

func (t moduleTestTranslator) Translate(ctx context.Context, a uint64) (memory.Translation, error) {
	if err := ctx.Err(); err != nil {
		return memory.Translation{}, err
	}
	if t.fail[a] {
		return memory.Translation{}, errors.New("page unavailable")
	}
	return memory.Translation{Physical: a & 0xffff}, nil
}
func TestModuleViewsTranslationCoverageAndAliases(t *testing.T) {
	for _, fault := range []string{"none", "active", "scanned"} {
		t.Run(fault, func(t *testing.T) {
			physical := &memory.Virtual{ID: "physical-test"}
			fail := map[uint64]bool{}
			if fault == "active" {
				fail[0xffff800000008000] = true
			}
			if fault == "scanned" {
				fail[0x8040] = true
			}
			env := plugin.Environment{Physical: physical, Kernel: &memory.Virtual{ID: "kernel-test", Translator: moduleTestTranslator{fail: fail}}}
			active, scanned := moduleViewRows(1, false, "kernel-test"), moduleViewRows(1, true, "physical-test")
			active[0].Cells["Offset"] = evidence.Address(0xffff800000008000)
			active[0].Provenance.Offset = "0xffff800000008000"
			active[0].Seal()
			if fault == "scanned" {
				scanned = moduleViewRows(1, true, "kernel-test")
			}
			eval := moduleViewEvaluator{rule: moduleViewRule(), resolve: physicalModuleResolver(env)}
			count := 0
			emit := func(evidence.Row) error { count++; return nil }
			if err := eval.consume(context.Background(), active, false, emit); err != nil {
				t.Fatal(err)
			}
			if err := eval.consume(context.Background(), scanned, true, emit); err != nil {
				t.Fatal(err)
			}
			coverage, err := eval.finish()
			if fault == "none" {
				if err != nil || count != 1 || coverage["matched"] != "1" {
					t.Fatal(count, coverage, err)
				}
			} else if !errors.Is(err, ErrIncomplete) || count != 0 {
				t.Fatal(count, coverage, err)
			}
		})
	}
}
