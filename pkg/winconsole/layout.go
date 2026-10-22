package winconsole

import (
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ParseHistoryLayout projects only the four command/history types. Some upstream
// screen types contain negative synthetic field offsets, which the general ISF
// reader intentionally rejects. Those unrelated types are not exposed by this
// adapter. The returned table digest identifies the projection; callers must
// separately retain the original file digest for provenance and cache keys.
func ParseHistoryLayout(data []byte) (*symbols.ISF, error) {
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, fmt.Errorf("invalid console layout size")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	var types map[string]json.RawMessage
	if err := json.Unmarshal(document["user_types"], &types); err != nil {
		return nil, err
	}
	selected := map[string]json.RawMessage{}
	for _, name := range []string{"_COMMAND", "_COMMAND_HISTORY", "_VECTOR", "_CONSOLE_PROCESS_HANDLE"} {
		value, ok := types[name]
		if !ok {
			return nil, fmt.Errorf("console layout missing %s", name)
		}
		selected[name] = value
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	document["user_types"] = raw
	projected, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	table, err := symbols.Parse(projected)
	if err != nil {
		return nil, err
	}
	if table.PointerSize() != 8 {
		return nil, fmt.Errorf("console history layouts require x64")
	}
	return table, nil
}
