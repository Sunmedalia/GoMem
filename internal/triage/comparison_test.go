package triage

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestComparisonTaskSurvivesJSONStoreRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 2, 3, 123456789, time.UTC)
	task := evidence.Task{ID: "task", CacheKey: "cache", Plugin: "windows.modules", State: "completed", Started: now, Finished: &now, Rows: 1<<54 + 1, Provenance: evidence.Provenance{ImageSHA256: "image", Layer: "kernel", Parameters: map[string]string{"z": "last", "a": "first"}}}
	original := evidence.Row{Cells: map[string]evidence.Value{"Comparison": {Kind: "structure", Data: map[string]any{"active_task": comparisonTask(task)}}}}
	original.Seal()
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded evidence.Row
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Verify(); err != nil {
		t.Fatal(err)
	}
	comparison := decoded.Cells["Comparison"].Data.(map[string]any)
	source := comparison["active_task"].(map[string]any)
	if source["rows"] != "18014398509481985" || source["started"] != "2026-10-21T01:02:03.123456789Z" || source["finished"] != source["started"] {
		t.Fatal(source)
	}
}
