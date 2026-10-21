package triage

import (
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// Structure cells must contain JSON primitives: nested Go structs marshal in
// field order, but SQLite decodes them as maps with sorted keys. Sealing structs
// directly would therefore produce evidence IDs that fail after a store read.
func comparisonTask(task evidence.Task) map[string]any {
	proof := task.Provenance
	result := map[string]any{
		"id": task.ID, "cache_key": task.CacheKey, "plugin": task.Plugin, "state": task.State,
		"rows": strconv.FormatInt(task.Rows, 10), "error": task.Error,
		"started": task.Started.Format(time.RFC3339Nano),
		"provenance": map[string]any{
			"image_sha256": proof.ImageSHA256, "engine": proof.Engine, "engine_build": proof.EngineBuild,
			"symbols_sha256": proof.SymbolsSHA256, "plugin": proof.Plugin, "parameters": proof.Parameters,
			"layer": proof.Layer, "offset": proof.Offset,
		},
	}
	if task.Finished != nil {
		result["finished"] = task.Finished.Format(time.RFC3339Nano)
	}
	return result
}
