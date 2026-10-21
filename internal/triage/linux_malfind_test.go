package triage

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func malfindTestCapture(at uint64, raw []byte) evidence.Value {
	return evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(raw), "RequestedBytes": evidence.Number(uint64(len(raw))), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(true)}}
}
func malfindTestRow(reason string) evidence.Row {
	r := row(0x10000, "mapping")
	r.Provenance.Plugin = "linux.malfind"
	r.Provenance.SymbolsSHA256 = "symbols"
	r.Cells["RecordType"] = evidence.Text("malfind_region")
	r.Cells["PID"] = evidence.Number(7)
	r.Cells["ProcessOffset"] = evidence.Address(0x8000)
	r.Cells["Created"] = evidence.Missing("not_available", nil)
	r.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID("same-image", "kernel", 0x8000, 7, ""))
	r.Cells["Start"] = evidence.Address(0x400000)
	r.Cells["End"] = evidence.Address(0x401000)
	r.Cells["RegionStart"] = r.Cells["Start"]
	r.Cells["RegionSize"] = evidence.Number(4096)
	r.Cells["Reason"] = evidence.Text(reason)
	flags, file := uint64(5), uint64(0)
	if reason == "X_DIRTY" {
		file = 0x60000
	}
	if reason == "RWX" {
		flags = 7
	}
	raw := make([]byte, 64)
	binary.LittleEndian.PutUint64(raw[40:], flags)
	binary.LittleEndian.PutUint64(raw[56:], file)
	scalar := func(at, n uint64) evidence.Value {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, n)
		return malfindTestCapture(at, b)
	}
	fields := map[string]evidence.Value{"VMA": malfindTestCapture(0x10000, raw), "Flags": malfindTestCapture(0x10028, raw[40:48]), "File": malfindTestCapture(0x10038, raw[56:]), "Process": {Kind: "structure", Data: map[string]evidence.Value{"MM": scalar(0x8010, 0x9000), "PGD": scalar(0x9000, 0xa000)}}}
	if reason == "X_DIRTY" {
		fields["DirtyLeaf"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Virtual": r.Cells["Start"], "PageSize": evidence.Number(4096), "Entry": evidence.Address(0x24043), "Capture": scalar(0x20000, 0x24043), "Layer": evidence.Text("physical"), "Dirty": evidence.Bool(true)}}
	}
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	protection := "r-x"
	if reason == "RWX" {
		protection = "rwx"
	}
	r.Cells["Protection"] = evidence.Text(protection)
	r.Seal()
	return r
}
func TestMalfindRulesProofControlsAndTaskCoverage(t *testing.T) {
	for _, rule := range Rules {
		if rule.Kind != "linux-malfind" {
			continue
		}
		t.Run(rule.ID, func(t *testing.T) {
			rows := []evidence.Row{malfindTestRow("RX"), malfindTestRow("X_DIRTY"), malfindTestRow("RWX")}
			task := evidence.Task{Plugin: "linux.malfind", State: "completed", Rows: 3, Provenance: rows[0].Provenance}
			task.Provenance.Offset = ""
			m := malfindEvaluator{rule: rule, source: &task}
			var findings []evidence.Row
			if err := m.consume(context.Background(), rows, func(r evidence.Row) error { findings = append(findings, r); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := m.finish(); err != nil || len(findings) != 1 {
				t.Fatal(err, findings, m)
			}
			if findings[0].Cells["FieldEvidence"].Kind != "structure" || findings[0].Verify() != nil {
				t.Fatal(findings)
			}
			task.State = "failed"
			if _, err := m.finish(); !errors.Is(err, ErrIncomplete) {
				t.Fatal("failed producer declared clean", err)
			}
			if err := Evaluate(context.Background(), rule, map[string][]evidence.Row{"malfind": rows}, func(evidence.Row) error { return nil }); !errors.Is(err, ErrIncomplete) {
				t.Fatal("standalone rows cannot establish complete source coverage", err)
			}
		})
	}
}
func TestMalfindRejectsResealedSemanticTampering(t *testing.T) {
	mutations := map[string]func(*evidence.Row){
		"protection": func(r *evidence.Row) { r.Cells["Protection"] = evidence.Text("rwx") },
		"identity":   func(r *evidence.Row) { r.Cells["ProcessOffset"] = evidence.Address(0x9999) },
		"extent":     func(r *evidence.Row) { r.Cells["RegionSize"] = evidence.Number(8192) },
		"leaf": func(r *evidence.Row) {
			f := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			l := f["DirtyLeaf"].Data.(map[string]evidence.Value)
			l["Entry"] = evidence.Address(0x24003)
		},
		"flags": func(r *evidence.Row) {
			f := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			c := f["Flags"].Data.(map[string]evidence.Value)
			c["Raw"] = evidence.Bytes(make([]byte, 8))
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := malfindTestRow("X_DIRTY")
			mutate(&r)
			r.Seal()
			m := malfindEvaluator{rule: Rules[len(Rules)-1]}
			if err := m.consume(context.Background(), []evidence.Row{r}, func(evidence.Row) error { t.Fatal("tampered evidence emitted"); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := m.finish(); !errors.Is(err, ErrIncomplete) || m.invalid != 1 {
				t.Fatal(err, m)
			}
		})
	}
}
func TestMalfindLateFindingAfterDiagnosticPages(t *testing.T) {
	m := malfindEvaluator{rule: Rules[len(Rules)-1]}
	diagnostic := malfindTestRow("RX")
	diagnostic.Cells["RecordType"] = evidence.Text("malfind_error")
	diagnostic.Seal()
	first := make([]evidence.Row, 500)
	for i := range first {
		first[i] = diagnostic
	}
	count := 0
	emit := func(evidence.Row) error { count++; return nil }
	if err := m.consume(context.Background(), first, emit); err != nil {
		t.Fatal(err)
	}
	if err := m.consume(context.Background(), []evidence.Row{malfindTestRow("X_DIRTY")}, emit); err != nil {
		t.Fatal(err)
	}
	if _, err := m.finish(); !errors.Is(err, ErrIncomplete) || count != 1 || m.diagnostics != 500 {
		t.Fatal(err, count, m)
	}
}

func TestMalfindProcessIdentitySeparatesReusedPID(t *testing.T) {
	first := malfindTestRow("RX")
	second := malfindTestRow("RX")
	second.Cells["ProcessOffset"] = evidence.Address(0x8800)
	second.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID("same-image", "kernel", 0x8800, 7, ""))
	second.Seal()
	m := malfindEvaluator{rule: Rules[len(Rules)-2]}
	entities := map[string]bool{}
	if err := m.consume(context.Background(), []evidence.Row{first, second}, func(r evidence.Row) error { entities[r.Cells["Entity"].String()] = true; return nil }); err != nil || len(entities) != 2 {
		t.Fatal(err, entities)
	}
}

func TestMalfindProvenanceCancellationAndEmitErrors(t *testing.T) {
	row := malfindTestRow("RX")
	m := malfindEvaluator{rule: Rules[len(Rules)-2]}
	sentinel := errors.New("output failed")
	if err := m.consume(context.Background(), []evidence.Row{row}, func(evidence.Row) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.consume(ctx, []evidence.Row{row}, func(evidence.Row) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	row.Provenance.ImageSHA256 = "another-image"
	row.Seal()
	if err := m.consume(context.Background(), []evidence.Row{row}, func(evidence.Row) error { return nil }); err == nil {
		t.Fatal("mixed image accepted")
	}
}
