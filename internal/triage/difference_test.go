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
)

func TestDifferenceUsesPhysicalCoordinatesAndRejectsMixedDomains(t *testing.T) {
	active := row(0xffff800000001000, "active")
	active.Cells["PhysicalOffset"] = evidence.Address(0x5000)
	active.Cells["PhysicalLayer"] = evidence.Text("physical:raw")
	active.Cells["RecordType"] = evidence.Text("task")
	active.Seal()
	scanned := row(0x5000, "same-object")
	scanned.Provenance.Layer = "physical:raw"
	scanned.Cells["PhysicalOffset"] = evidence.Address(0x5000)
	scanned.Cells["PhysicalLayer"] = evidence.Text("physical:raw")
	scanned.Cells["RecordType"] = evidence.Text("task")
	scanned.Cells["ExitState"] = evidence.Text("TASK_RUNNING")
	scanned.Seal()
	count := 0
	if err := Evaluate(context.Background(), Rules[0], map[string][]evidence.Row{"pslist": {active}, "psscan": {scanned}}, func(evidence.Row) error { count++; return nil }); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	for _, fault := range []string{"image", "layer", "space", "unreadable-physical", "missing-coordinate", "diagnostic", "incomplete-summary", "summary-read-errors"} {
		t.Run(fault, func(t *testing.T) {
			bad := scanned
			bad.Cells = map[string]evidence.Value{}
			for k, v := range scanned.Cells {
				bad.Cells[k] = v
			}
			switch fault {
			case "image":
				bad.Provenance.ImageSHA256 = "other-image"
			case "layer":
				bad.Cells["PhysicalLayer"] = evidence.Text("other-physical")
			case "space":
				delete(bad.Cells, "PhysicalOffset")
				delete(bad.Cells, "PhysicalLayer")
			case "unreadable-physical":
				bad.Cells["PhysicalOffset"] = evidence.Missing("translation_failed", errors.New("missing page"))
			case "missing-coordinate":
				delete(bad.Cells, "PhysicalOffset")
			case "diagnostic":
				bad.Cells["RecordType"] = evidence.Text("diagnostic")
			case "incomplete-summary":
				bad.Cells["RecordType"] = evidence.Text("scan_summary")
				bad.Cells["Scan"] = evidence.Value{Kind: "structure", Data: map[string]any{"complete": false, "candidate_read_failures": "0"}}
			case "summary-read-errors":
				bad.Cells["RecordType"] = evidence.Text("scan_summary")
				bad.Cells["Scan"] = evidence.Value{Kind: "structure", Data: map[string]any{"complete": true, "candidate_read_failures": "1"}}
			}
			bad.Seal()
			if err := Evaluate(context.Background(), Rules[0], map[string][]evidence.Row{"pslist": {active}, "psscan": {bad}}, func(evidence.Row) error { t.Fatal("invalid comparison emitted finding"); return nil }); err == nil {
				t.Fatal("invalid task coordinates became comparable")
			}
		})
	}
}

func TestLinuxHiddenTaskPipelineControlsResidualsPIDReuseAndWhitelist(t *testing.T) {
	for _, scenario := range []string{"hidden-running", "zombie", "visible-thread", "pid-reuse"} {
		t.Run(scenario, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), "linux")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[0x1e000:0x1e090], data[0xa000:0xa090])
			put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
			binary.LittleEndian.PutUint32(data[0x1e010:], 222)
			binary.LittleEndian.PutUint32(data[0x1e014:], 222)
			put(0x1e028, 0xa000)
			put(0x1e030, 3000000000)
			put(0x1e038, 0)
			put(0x1e070, 3000000000)
			if scenario == "zombie" {
				binary.LittleEndian.PutUint32(data[0x1e088:], 32)
			}
			if scenario == "pid-reuse" {
				binary.LittleEndian.PutUint32(data[0x1e010:], 100)
				binary.LittleEndian.PutUint32(data[0x1e014:], 100)
			}
			if scenario == "visible-thread" {
				binary.LittleEndian.PutUint32(data[0x1e014:], 100)
				put(0x1e058, 0xa000)
				put(0xa060, 0x1e060)
				put(0xa068, 0x1e060)
				put(0x1e060, 0xa060)
				put(0x1e068, 0xa060)
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			summary, err := Run(ctx, e, nil)
			if !errors.Is(err, ErrIncomplete) {
				t.Fatal(summary, err)
			}
			var check Check
			for _, c := range summary.Checks {
				if c.Rule == "hidden-process" {
					check = c
				}
			}
			want := 1
			if scenario == "visible-thread" {
				want = 0
			}
			if check.State != "completed" || check.Findings != want {
				t.Fatal(check, summary)
			}
			if want == 0 {
				return
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: summary.FindingTask, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			var finding evidence.Row
			for _, r := range rows {
				if r.Cells["Rule"].String() == "hidden-process" {
					finding = r
				}
			}
			severity := "high"
			if scenario == "zombie" {
				severity = "info"
			}
			if finding.Cells["Severity"].String() != severity || finding.Cells["Assessment"].String() == "" || finding.Cells["Entity"].String() != finding.Cells["TaskIdentity"].String() {
				t.Fatal(finding)
			}
			if finding.Cells["Comparison"].Kind != "structure" {
				t.Fatal("difference lost the completed task comparison provenance", finding)
			}
			if err := finding.Verify(); err != nil {
				t.Fatal("stored comparison evidence did not retain its seal", err)
			}
			refs := finding.Cells["EvidenceIDs"].Data.([]any)
			source, err := e.Store.Find(ctx, refs[0].(string))
			if err != nil || source.Provenance.Plugin != "linux.psscan" {
				t.Fatal(source, err)
			}
			if err = e.Store.Allow(ctx, "hidden-process", finding.Cells["Entity"].String(), "authorized synthetic fixture"); err != nil {
				t.Fatal(err)
			}
			again, err := Run(ctx, e, nil)
			if !errors.Is(err, ErrIncomplete) {
				t.Fatal(again, err)
			}
			for _, c := range again.Checks {
				if c.Rule == "hidden-process" && c.Findings != 0 {
					t.Fatal("physical task whitelist not honored", c)
				}
			}
			for _, task := range again.Tasks {
				if !task.Reused {
					t.Fatal("completed producer not reused", task)
				}
			}
		})
	}
}
