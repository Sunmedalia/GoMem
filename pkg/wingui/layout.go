package wingui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Layout struct {
	Types  *symbols.ISF
	SHA256 string
}

// ParseLayout projects the station/desktop/thread-owner fields. Kernel list and
// process references stay explicitly external; callers resolve those through
// their matching kernel table rather than guessing kernel offsets from GUI ISF.
func ParseLayout(raw []byte) (*Layout, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("invalid GUI layout size")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var types map[string]struct {
		Kind   string
		Size   uint64
		Fields map[string]symbols.Field
	}
	if err := json.Unmarshal(doc["user_types"], &types); err != nil {
		return nil, err
	}
	required := map[string][]string{
		"tagWINDOWSTATION": {"dwSessionId", "rpwinstaNext", "rpdeskList"},
		"tagDESKTOP":       {"rpwinstaParent", "PtiList"},
		"tagTHREADINFO":    {"ppi", "PtiLink"},
		"tagPROCESSINFO":   {"Process"},
	}
	projected := map[string]symbols.Type{}
	for name, fields := range required {
		source, ok := types[name]
		if !ok || source.Kind != "struct" || source.Size < 8 || source.Size > 1<<20 {
			return nil, fmt.Errorf("invalid GUI type %s", name)
		}
		typ := symbols.Type{Kind: "struct", Size: source.Size, Fields: map[string]symbols.Field{}}
		for _, name := range fields {
			f, ok := source.Fields[name]
			if !ok || f.Offset > source.Size {
				return nil, fmt.Errorf("invalid GUI field %s", name)
			}
			typ.Fields[name] = f
		}
		projected[name] = typ
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	doc["user_types"] = encoded
	// Unused enums can contain references unrelated to these projected types.
	doc["enums"] = json.RawMessage(`{}`)
	doc["symbols"] = json.RawMessage(`{}`)
	encoded, err = json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	table, err := symbols.Parse(encoded)
	if err != nil {
		return nil, err
	}
	if table.PointerSize() != 8 {
		return nil, fmt.Errorf("GUI layouts require x64 pointers")
	}
	expected := map[string]string{"tagWINDOWSTATION.rpwinstaNext": "tagWINDOWSTATION", "tagWINDOWSTATION.rpdeskList": "tagDESKTOP", "tagDESKTOP.rpwinstaParent": "tagWINDOWSTATION", "tagTHREADINFO.ppi": "tagPROCESSINFO", "tagPROCESSINFO.Process": "nt_symbols!_EPROCESS"}
	for name, target := range expected {
		var typ, member string
		for i := range name {
			if name[i] == '.' {
				typ, member = name[:i], name[i+1:]
				break
			}
		}
		f := table.Types[typ].Fields[member]
		if f.Type.Kind != "pointer" || f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" || f.Type.Subtype.Name != target || f.Offset > table.Types[typ].Size-8 {
			return nil, fmt.Errorf("invalid GUI pointer %s", name)
		}
	}
	for _, name := range []string{"tagDESKTOP", "tagTHREADINFO"} {
		member := "PtiList"
		if name == "tagTHREADINFO" {
			member = "PtiLink"
		}
		f := table.Types[name].Fields[member]
		if f.Type.Kind != "struct" || f.Type.Name != "nt_symbols!_LIST_ENTRY" || table.Types[name].Size < 16 || f.Offset > table.Types[name].Size-16 {
			return nil, fmt.Errorf("invalid external GUI list %s.%s", name, member)
		}
	}
	session := table.Types["tagWINDOWSTATION"].Fields["dwSessionId"]
	b, ok := table.Bases[session.Type.Name]
	if session.Type.Kind != "base" || !ok || b.Size != 4 || b.Signed || b.Endian != "little" || session.Offset > table.Types["tagWINDOWSTATION"].Size-4 {
		return nil, fmt.Errorf("invalid GUI session id")
	}
	digest := sha256.Sum256(raw)
	return &Layout{Types: table, SHA256: hex.EncodeToString(digest[:])}, nil
}
