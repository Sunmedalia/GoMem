package triage

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func ghostAddress(row evidence.Row, key string) (uint64, error) {
	value, err := required(row, key)
	if err != nil || value.Kind != "address" {
		return 0, fmt.Errorf("ghosting evidence lacks address %s", key)
	}
	return value.Uint()
}
func ghostFlag(row evidence.Row, key string) (uint64, error) {
	value, err := required(row, key)
	if err != nil || value.Kind != "uint64" {
		return 0, fmt.Errorf("ghosting evidence lacks numeric %s", key)
	}
	return value.Uint()
}
func (n *nativeCheckEvaluator) consumeGhosting(ctx context.Context, row evidence.Row, emit plugin.Emit) error {
	identity, err := required(row, "ProcessIdentity")
	if err != nil || identity.Kind != "string" {
		return fmt.Errorf("ghosting evidence lacks process identity")
	}
	address, err := ghostAddress(row, "ProcessOffset")
	if err != nil {
		return err
	}
	proof, err := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || address != proof || row.Provenance.Layer == "" {
		return fmt.Errorf("ghosting process coordinates differ from provenance")
	}
	for _, key := range []string{"Base", "FILE_OBJECT"} {
		if _, err = ghostAddress(row, key); err != nil {
			return err
		}
	}
	file, _ := ghostAddress(row, "FILE_OBJECT")
	if _, err = ghostFlag(row, "PID"); err != nil {
		return err
	}
	if value, err := required(row, "Process"); err != nil || value.Kind != "string" {
		return fmt.Errorf("ghosting evidence lacks process name")
	}
	rule, err := required(row, "Rule")
	if err != nil || rule.Kind != "string" {
		return fmt.Errorf("ghosting evidence lacks native rule")
	}
	pending := func() error {
		value, err := ghostFlag(row, "DeletePending")
		raw, rawErr := ghostFlag(row, "DeletePendingRaw")
		if err != nil || rawErr != nil || value != 1 || raw != 1 {
			return fmt.Errorf("ghosting pending evidence lacks matching DeletePending=1")
		}
		return nil
	}
	absent := func(key string) bool {
		value, ok := row.Cells[key]
		return ok && value.Kind == "missing" && value.Reason == "not_applicable" && value.Error == ""
	}
	switch rule.String() {
	case "image_file_state":
		if file != 0 || !absent("DeletePending") {
			if err = pending(); err != nil {
				return err
			}
		}
		if !absent("DeleteOnClose") {
			return fmt.Errorf("image file state includes an unexpected DeleteOnClose")
		}
		slot, err := ghostAddress(row, "ImageFilePointerOffset")
		if err != nil || slot < address {
			return fmt.Errorf("ghosting image field has inconsistent coordinates")
		}
		path, ok := row.Cells["Path"]
		if !ok || path.Kind != "string" && (path.Kind != "missing" || path.Reason != "not_available" || path.Error != "") {
			return fmt.Errorf("ghosting image path has an invalid state")
		}
		if path.Kind == "string" {
			if _, ok := path.Data.(string); !ok {
				return fmt.Errorf("ghosting image path is not a string")
			}
		}
		if row.Cells["Error"].Error != "" {
			n.pathErrors++
		}
		n.ghostImages++
	case "vad_delete_on_close", "vad_delete_pending":
		for _, key := range []string{"VADOffset", "ControlArea"} {
			if _, err = ghostAddress(row, key); err != nil {
				return err
			}
		}
		path, ok := row.Cells["Path"]
		if !ok || path.Kind != "string" {
			return fmt.Errorf("ghosting VAD has no named mapping")
		}
		if _, ok = path.Data.(string); !ok {
			return fmt.Errorf("ghosting VAD path is not a string")
		}
		if rule.String() == "vad_delete_on_close" {
			value, err := ghostFlag(row, "DeleteOnClose")
			raw, rawErr := ghostFlag(row, "DeleteOnCloseRaw")
			name := strings.ToLower(path.String())
			if err != nil || rawErr != nil || value == 0 || value != raw || !strings.HasSuffix(name, ".exe") && !strings.HasSuffix(name, ".dll") || !absent("DeletePending") {
				return fmt.Errorf("ghosting close evidence has inconsistent flags or path")
			}
		} else {
			if err = pending(); err != nil {
				return err
			}
			if !absent("DeleteOnClose") {
				return fmt.Errorf("VAD pending evidence includes an unexpected DeleteOnClose")
			}
		}
	default:
		return fmt.Errorf("unknown ghosting rule %s", rule.String())
	}
	n.findings++
	return emitFinding(ctx, n.rule, row, identity.String(), []string{row.ID}, emit)
}

func (n *nativeCheckEvaluator) finishGhosting() (map[string]string, error) {
	counts := map[string]uint64{}
	for _, key := range []string{"processes", "active", "filtered", "vads", "mapped_files", "private_skipped", "findings", "diagnostics", "image_file_member", "handle_count_member"} {
		value, ok := n.coverage[key]
		if !ok {
			return n.coverage, fmt.Errorf("ghosting coverage lacks %s", key)
		}
		count, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return n.coverage, err
		}
		counts[key] = count
	}
	if counts["findings"] != n.findings || counts["diagnostics"] != n.diagnostics || n.pathErrors > n.diagnostics {
		return n.coverage, fmt.Errorf("ghosting finding or diagnostic counts differ from original records")
	}
	if counts["active"] > counts["processes"] || counts["filtered"] != counts["processes"]-counts["active"] {
		return n.coverage, fmt.Errorf("ghosting process filter counts are inconsistent")
	}
	if counts["mapped_files"] > counts["vads"] || counts["private_skipped"] > counts["mapped_files"] {
		return n.coverage, fmt.Errorf("ghosting mapped VAD counts are inconsistent")
	}
	if counts["image_file_member"] > 1 || counts["handle_count_member"] > 1 || counts["image_file_member"] == 0 && n.ghostImages > 0 {
		return n.coverage, fmt.Errorf("ghosting findings contradict field applicability")
	}
	if n.ghostImages > counts["active"] || (n.findings-n.ghostImages+1)/2 > counts["mapped_files"]-counts["private_skipped"] || counts["active"] == 0 && n.findings > 0 {
		return n.coverage, fmt.Errorf("ghosting findings exceed eligible process or VAD counts")
	}
	if n.diagnostics > 0 {
		return n.coverage, fmt.Errorf("%w: %d ghosting read diagnostics; findings and original evidence are retained", ErrIncomplete, n.diagnostics)
	}
	return n.coverage, nil
}
