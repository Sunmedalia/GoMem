package triage

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// State is bounded independently of the result count and spans SQLite pages.
// Diagnostics do not stop later findings from being evaluated. finish checks
// the final coverage record after all evidence has been consumed.
type nativeCheckEvaluator struct {
	rule        Rule
	coverage    map[string]string
	findings    uint64
	diagnostics uint64
	pathErrors  uint64
	image       string
}

func (n *nativeCheckEvaluator) inputPlugin() (string, map[string]bool, error) {
	if n.rule.Kind != "native-check" || len(n.rule.Inputs) != 1 {
		return "", nil, fmt.Errorf("invalid native triage rule")
	}
	switch n.rule.Inputs[0] {
	case "suspicious_threads":
		return "windows.suspicious_threads", map[string]bool{"non_file_backed": true, "unexpected_protection": true, "other_executable": true}, nil
	case "hollowprocesses":
		return "windows.hollowprocesses", map[string]bool{"image_base_mismatch": true, "executable_vad_missing": true, "executable_protection": true, "dll_protection": true}, nil
	default:
		return "", nil, fmt.Errorf("unknown native triage input %s", n.rule.Inputs[0])
	}
}

func (n *nativeCheckEvaluator) consume(ctx context.Context, rows []evidence.Row, emit plugin.Emit) error {
	name, rules, err := n.inputPlugin()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := row.Verify(); err != nil {
			return err
		}
		if row.Provenance.Plugin != name {
			return fmt.Errorf("rule %s received evidence from %s instead of %s", n.rule.ID, row.Provenance.Plugin, name)
		}
		if row.Provenance.ImageSHA256 == "" || n.image != "" && n.image != row.Provenance.ImageSHA256 {
			return fmt.Errorf("native triage input has missing or mixed image identities")
		}
		n.image = row.Provenance.ImageSHA256
		if n.coverage != nil {
			return fmt.Errorf("native triage input has rows after its summary")
		}
		kind, err := required(row, "RecordType")
		if err != nil || kind.Kind != "string" {
			return fmt.Errorf("native triage input has no record type")
		}
		switch kind.String() {
		case "summary":
			if row.Cells["Coverage"].Kind != "structure" {
				return fmt.Errorf("native triage input has no structured coverage")
			}
			values, ok := row.Cells["Coverage"].Data.(map[string]any)
			if !ok {
				return fmt.Errorf("native triage input coverage is not a map")
			}
			n.coverage = make(map[string]string, len(values))
			for key, value := range values {
				text, ok := value.(string)
				if !ok {
					return fmt.Errorf("native triage coverage %s is not a decimal string", key)
				}
				if _, err := strconv.ParseUint(text, 10, 64); err != nil {
					return fmt.Errorf("invalid native triage coverage %s: %w", key, err)
				}
				n.coverage[key] = text
			}
		case "diagnostic":
			value, ok := row.Cells["Error"]
			if !ok || value.Error == "" && (value.Kind != "string" || value.String() == "") {
				return fmt.Errorf("native diagnostic has no readable cause")
			}
			n.diagnostics++
		case "finding":
			identity, err := required(row, "ProcessIdentity")
			if err != nil || identity.Kind != "string" {
				return fmt.Errorf("native finding has no process identity")
			}
			rule, err := required(row, "Rule")
			if err != nil || rule.Kind != "string" || !rules[rule.String()] {
				return fmt.Errorf("native finding has unknown rule %s", rule.String())
			}
			note, coordinate := "Notes", "ProcessOffset"
			if name == "windows.suspicious_threads" {
				note, coordinate = "Note", "ThreadOffset"
				if value, err := required(row, "ThreadIdentity"); err != nil || value.Kind != "string" {
					return fmt.Errorf("native thread finding has no thread identity")
				}
			}
			if value, err := required(row, "ProcessOffset"); err != nil || value.Kind != "address" {
				return fmt.Errorf("native finding has no process offset")
			}
			if value, err := required(row, note); err != nil || value.Kind != "string" {
				return fmt.Errorf("native finding has no readable assessment")
			}
			location, err := required(row, coordinate)
			if err != nil || location.Kind != "address" || row.Provenance.Layer == "" {
				return fmt.Errorf("native finding has no object coordinates")
			}
			address, err := location.Uint()
			proof, proofErr := strconv.ParseUint(row.Provenance.Offset, 0, 64)
			if err != nil || proofErr != nil || address != proof {
				return fmt.Errorf("native finding object coordinates differ from provenance")
			}
			n.findings++
			if row.Cells["PathError"].Error != "" {
				n.pathErrors++
			}
			if err = emitFinding(ctx, n.rule, row, identity.String(), []string{row.ID}, emit); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected native triage record type %s", kind.String())
		}
	}
	return nil
}

func (n *nativeCheckEvaluator) finish() (map[string]string, error) {
	if _, _, err := n.inputPlugin(); err != nil {
		return nil, err
	}
	if n.coverage == nil {
		return nil, fmt.Errorf("%w: native input lacks a final coverage summary", ErrIncomplete)
	}
	keys := []string{"processes", "findings"}
	if n.rule.Inputs[0] == "suspicious_threads" {
		keys = append(keys, "short_vad_sets", "threads", "exited", "gather_skipped", "unique_addresses", "duplicates", "outside_vad", "path_read_errors")
	} else {
		keys = append(keys, "short_dll_sets", "short_vad_sets", "checked", "diagnostics")
	}
	counts := map[string]uint64{}
	for _, key := range keys {
		text, ok := n.coverage[key]
		if !ok {
			return n.coverage, fmt.Errorf("native input coverage lacks %s", key)
		}
		count, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return n.coverage, err
		}
		counts[key] = count
	}
	if counts["findings"] != n.findings {
		return n.coverage, fmt.Errorf("native finding count differs from its summary")
	}
	if n.rule.Inputs[0] == "suspicious_threads" {
		if counts["path_read_errors"] != n.pathErrors || counts["gather_skipped"] < n.diagnostics {
			return n.coverage, fmt.Errorf("native thread error counts differ from its summary")
		}
		if counts["gather_skipped"] > 0 || counts["path_read_errors"] > 0 {
			return n.coverage, fmt.Errorf("%w: %d thread gathers skipped and %d findings with unreadable VAD paths", ErrIncomplete, counts["gather_skipped"], counts["path_read_errors"])
		}
	} else if counts["diagnostics"] != n.diagnostics {
		return n.coverage, fmt.Errorf("native diagnostic count differs from its summary")
	}
	if n.pathErrors > 0 {
		return n.coverage, fmt.Errorf("%w: %d findings with unreadable paths; original evidence is retained", ErrIncomplete, n.pathErrors)
	}
	if n.diagnostics > 0 {
		return n.coverage, fmt.Errorf("%w: %d native read/coverage diagnostics; original evidence is retained", ErrIncomplete, n.diagnostics)
	}
	return n.coverage, nil
}
