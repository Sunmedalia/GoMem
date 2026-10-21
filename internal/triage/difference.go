package triage

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func emitFinding(ctx context.Context, rule Rule, row evidence.Row, entity string, refs []string, emit plugin.Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if row.ID == "" || row.Provenance.ImageSHA256 == "" {
		return fmt.Errorf("rule input lacks sealed evidence provenance")
	}
	cells := map[string]evidence.Value{"Rule": evidence.Text(rule.ID), "Severity": evidence.Text(rule.Severity), "Basis": evidence.Text(rule.Basis), "FalsePositive": evidence.Text(rule.FalsePositive), "Entity": evidence.Text(entity), "EvidenceIDs": {Kind: "references", Data: refs}}
	if rule.Kind == "module-difference" {
		cells["SourcePlugin"] = evidence.Text(row.Provenance.Plugin)
		cells["Assessment"] = evidence.Text("Pool-scanned loader object absent from the loaded-module list; stale or unloaded allocations may explain this mismatch")
		for _, key := range []string{"Offset", "Base", "Size", "Name", "NameError", "Path", "PathError"} {
			if value, ok := row.Cells[key]; ok {
				cells[key] = value
			}
		}
		if row.Cells["Name"].Kind == "missing" || row.Cells["Path"].Kind == "missing" || row.Cells["NameError"].Error != "" || row.Cells["PathError"].Error != "" {
			cells["Severity"] = evidence.Text("info")
			cells["Confidence"] = evidence.Text("limited_by_module_metadata")
			cells["Assessment"] = evidence.Text("Pool candidate absent from the loaded-module list with unreadable metadata; a false pool match, stale allocation or acquisition smear may explain it")
		}
	}
	if rule.Kind == "native-check" && row.Provenance.Plugin == "windows.psxview" {
		cells["SourcePlugin"] = evidence.Text("windows.psxview")
		cells["NativeRule"] = evidence.Text("absent_active_view")
		for _, key := range []string{"Identity", "ObjectOffset", "ObjectLayer", "Offset", "OffsetSpace", "TranslationError", "Sources", "pslist", "psscan", "thrdscan", "csrss", "ExitTime", "ExitTimeRaw", "Created", "CreatedRaw"} {
			if value, ok := row.Cells[key]; ok {
				cells[key] = value
			}
		}
		cells["Assessment"] = evidence.Text("Process object collected outside the active process list; investigate view coverage and the original object before assessing hiding")
		if row.Cells["ExitTime"].String() != "" {
			cells["Severity"] = evidence.Text("info")
			cells["Assessment"] = evidence.Text("Exited process object absent from the active list; residual allocations can explain this view mismatch")
		}
	} else if rule.Kind == "native-check" {
		cells["SourcePlugin"] = evidence.Text(row.Provenance.Plugin)
		cells["NativeRule"] = row.Cells["Rule"]
		cells["Assessment"] = row.Cells["Notes"]
		if row.Provenance.Plugin == "windows.suspicious_threads" {
			cells["Assessment"] = row.Cells["Note"]
		}
		for _, key := range []string{"PID", "Process", "ProcessIdentity", "ProcessOffset", "ThreadIdentity", "ThreadOffset", "TID", "Context", "Address", "RawAddress", "Base", "ImageBase", "SectionBase", "VADOffset", "VADBase", "VADPath", "Protection", "Path", "PathError", "LoaderOffset", "LoaderLayer"} {
			if value, ok := row.Cells[key]; ok {
				cells[key] = value
			}
		}
		if row.Cells["PathError"].Error != "" {
			cells["Severity"] = evidence.Text("info")
			cells["Confidence"] = evidence.Text("limited_by_path_read_error")
		}
	}
	if rule.ID == "hidden-process" {
		if state, ok := row.Cells["ExitState"]; ok {
			if state.Kind != "string" {
				return fmt.Errorf("unreadable scanned task exit state")
			}
			cells["ExitState"] = state
			switch state.String() {
			case "TASK_RUNNING":
				cells["Assessment"] = evidence.Text("Task candidate with exit_state=0 absent from the active task/thread list; this is not a CPU scheduling state, and hiding is not proven")
			case "EXIT_DEAD", "EXIT_ZOMBIE", "EXIT_TRACE":
				cells["Severity"] = evidence.Text("info")
				cells["Assessment"] = evidence.Text("Residual or exiting task candidate; absence from the active list alone is not evidence of hiding")
			default:
				return fmt.Errorf("unknown scanned task exit state")
			}
		}
		for _, key := range []string{"PID", "TID", "Name", "PhysicalOffset", "PhysicalLayer", "TaskIdentity"} {
			if v, ok := row.Cells[key]; ok {
				cells[key] = v
			}
		}
	}
	proof := row.Provenance
	proof.Plugin = "triage." + rule.ID
	result := evidence.Row{Cells: cells, Provenance: proof}
	result.Seal()
	return emit(result)
}

func differenceKey(rule Rule, row evidence.Row, scanning bool) (string, bool, error) {
	if rule.ID == "hidden-process" {
		if kind, ok := row.Cells["RecordType"]; ok {
			switch kind.String() {
			case "task", "thread":
			case "scan_summary":
				if !scanning {
					return "", false, fmt.Errorf("scan summary cannot stand in for active task evidence")
				}
				meta, ok := row.Cells["Scan"].Data.(map[string]any)
				if !ok || meta["complete"] != true || meta["candidate_read_failures"] != "0" {
					return "", false, fmt.Errorf("task scan coverage is incomplete")
				}
				return "", false, nil
			default:
				return "", false, fmt.Errorf("non-entity or unreadable task evidence cannot participate in task comparison")
			}
		}
	}
	key, err := objectKey(row)
	return key, err == nil, err
}

func evaluateDifferenceRows(ctx context.Context, rule Rule, known *differenceIndex, rows []evidence.Row, emit plugin.Emit) error {
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := row.Verify(); err != nil {
			return err
		}
		key, entity, err := differenceKey(rule, row, true)
		if err != nil {
			return err
		}
		if !entity {
			continue
		}
		if err := known.observeDomain(row); err != nil {
			return err
		}
		if known.objects[key] {
			continue
		}
		identity := key
		if rule.ID == "hidden-process" {
			if value, ok := row.Cells["TaskIdentity"]; ok {
				if value.Kind != "string" || value.String() == "" {
					return fmt.Errorf("unreadable physical task identity")
				}
				identity = value.String()
			}
		}
		if err = emitFinding(ctx, rule, row, identity, []string{row.ID}, emit); err != nil {
			return err
		}
	}
	return nil
}

type differenceIndex struct {
	objects map[string]bool
	domain  string
}

func (d *differenceIndex) observeDomain(row evidence.Row) error {
	space, layer := "virtual", row.Provenance.Layer
	if _, ok := row.Cells["PhysicalOffset"]; ok {
		space, layer = "physical", row.Cells["PhysicalLayer"].String()
	}
	domain := row.Provenance.ImageSHA256 + "\x00" + space + "\x00" + layer
	if d.domain != "" && d.domain != domain {
		return fmt.Errorf("task/object comparison cannot mix images or address spaces")
	}
	d.domain = domain
	return nil
}

func (d *differenceIndex) add(rule Rule, row evidence.Row) error {
	if err := row.Verify(); err != nil {
		return err
	}
	key, entity, err := differenceKey(rule, row, false)
	if err != nil {
		return err
	}
	if !entity {
		return nil
	}
	if err = d.observeDomain(row); err != nil {
		return err
	}
	d.objects[key] = true
	if len(d.objects) > 1000000 {
		return fmt.Errorf("difference index exceeds 1000000 objects")
	}
	return nil
}
