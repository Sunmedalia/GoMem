package triage

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var processViewNames = [...]string{"pslist", "psscan", "thrdscan", "csrss"}

func (n *nativeCheckEvaluator) consumeProcessView(ctx context.Context, row evidence.Row, emit plugin.Emit) error {
	var flags [4]bool
	var selected map[string]any
	origins, ok := row.Cells["Sources"].Data.(map[string]any)
	if row.Cells["Sources"].Kind != "structure" || !ok {
		return fmt.Errorf("process-view evidence has no source coordinates")
	}
	for i, name := range processViewNames {
		value := row.Cells[name]
		flag, ok := value.Data.(bool)
		if value.Kind != "bool" || !ok {
			return fmt.Errorf("process-view evidence has no boolean %s", name)
		}
		flags[i] = flag
		_, exists := origins[name]
		if exists != flag {
			return fmt.Errorf("process-view %s differs from its source coordinates", name)
		}
		if flag {
			origin, ok := origins[name].(map[string]any)
			if !ok {
				return fmt.Errorf("process-view %s has invalid source coordinates", name)
			}
			offset, offsetOK := origin["offset"].(string)
			layer, layerOK := origin["layer"].(string)
			space, spaceOK := origin["display_space"].(string)
			if _, err := strconv.ParseUint(offset, 0, 64); !offsetOK || err != nil || !layerOK || layer == "" || !spaceOK || space != "kernel_virtual" && space != "physical_pool" && space != "physical" {
				return fmt.Errorf("process-view %s has invalid source coordinates", name)
			}
			if selected == nil {
				selected = origin
			}
			n.viewCounts[i]++
		}
	}
	if !flags[0] && !flags[1] && !flags[2] && !flags[3] {
		return fmt.Errorf("process-view evidence has no originating view")
	}
	identity, err := required(row, "Identity")
	if err != nil || identity.Kind != "string" {
		return fmt.Errorf("process-view evidence has no object-based identity")
	}
	location, err := required(row, "ObjectOffset")
	if err != nil || location.Kind != "address" {
		return fmt.Errorf("process-view evidence has no object address")
	}
	layer, err := required(row, "ObjectLayer")
	if err != nil || layer.Kind != "string" || layer.String() != row.Provenance.Layer {
		return fmt.Errorf("process-view evidence has no consistent object layer")
	}
	address, err := location.Uint()
	proof, proofErr := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || proofErr != nil || address != proof {
		return fmt.Errorf("process-view object address differs from provenance")
	}
	selectedAddress, _ := strconv.ParseUint(selected["offset"].(string), 0, 64)
	if selectedAddress != address || selected["layer"] != layer.String() || row.Cells["OffsetSpace"].Kind != "string" || selected["display_space"] != row.Cells["OffsetSpace"].String() {
		return fmt.Errorf("process-view representative differs from its source coordinates")
	}
	exit := row.Cells["ExitTime"]
	text, ok := exit.Data.(string)
	if exit.Kind != "string" || !ok {
		return fmt.Errorf("process-view evidence has unreadable exit time")
	}
	if text != "" {
		if _, err = time.Parse("2006-01-02 15:04:05Z07:00", text); err != nil {
			return fmt.Errorf("invalid process-view exit datetime: %w", err)
		}
	}
	if flags[0] {
		return nil
	}
	n.findings++
	return emitFinding(ctx, n.rule, row, identity.String(), []string{row.ID}, emit)
}

func (n *nativeCheckEvaluator) finishProcessViews() (map[string]string, error) {
	keys := []string{"active_candidates", "csrss_processes", "csrss_handles", "csrss_unreadable_object_tables", "csrss_unreadable_handle_tables", "csrss_handle_cycles", "pool_read_failures", "pool_type_map_entries"}
	for _, source := range processViewNames {
		keys = append(keys, source, source+"_rejected", source+"_duplicates")
	}
	counts := map[string]uint64{}
	for _, key := range keys {
		text, ok := n.coverage[key]
		if !ok {
			return n.coverage, fmt.Errorf("process-view coverage lacks %s", key)
		}
		count, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return n.coverage, err
		}
		counts[key] = count
	}
	for i, source := range processViewNames {
		if counts[source] != n.viewCounts[i] {
			return n.coverage, fmt.Errorf("process-view %s count differs from its summary", source)
		}
	}
	if counts["csrss_processes"] == 0 || counts["pool_type_map_entries"] == 0 {
		return n.coverage, fmt.Errorf("%w: csrss handle view requires an active csrss.exe and an object type map", ErrIncomplete)
	}
	if n.diagnostics > 0 || counts["pool_read_failures"] > 0 || counts["csrss_unreadable_object_tables"] > 0 || counts["csrss_unreadable_handle_tables"] > 0 || counts["csrss_handle_cycles"] > 0 {
		return n.coverage, fmt.Errorf("%w: process-view read/handle coverage is incomplete; raw mismatches are retained", ErrIncomplete)
	}
	return n.coverage, nil
}
