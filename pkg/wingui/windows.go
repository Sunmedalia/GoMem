package wingui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ParseWindowLayout adds only the fields needed for window inspection. Keeping
// this separate allows station-only callers to use their smaller schema.
func ParseWindowLayout(raw []byte) (*Layout, error) {
	l, err := ParseLayout(raw)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	required := map[string][]string{
		"tagDESKTOP":            {"pDeskInfo"},
		"tagDESKTOPINFO":        {"spwnd"},
		"tagWND":                {"head", "spwndNext", "spwndChild", "strName", "lpfnWndProc"},
		"_THRDESKHEAD":          {"rpdesk", "pti"},
		"_LARGE_UNICODE_STRING": {"Length", "Buffer"},
	}
	wnd, ok := doc.Types["tagWND"]
	if !ok {
		return nil, fmt.Errorf("missing GUI window type")
	}
	if _, ok := wnd.Fields["subPointer"]; ok {
		required["tagWND"] = append(required["tagWND"], "subPointer")
		required["subTagWNDType"] = []string{"lpfnWndProc"}
	}
	if _, ok := wnd.Fields["directName"]; ok {
		required["tagWND"] = append(required["tagWND"], "directName")
	}
	for name, fields := range required {
		src, ok := doc.Types[name]
		if !ok || src.Kind != "struct" || src.Size < 8 || src.Size > 1<<20 {
			return nil, fmt.Errorf("invalid GUI window type %s", name)
		}
		dst, ok := l.Types.Types[name]
		if !ok {
			dst = symbols.Type{Kind: src.Kind, Size: src.Size, Fields: map[string]symbols.Field{}}
		}
		for _, member := range fields {
			f, ok := src.Fields[member]
			if !ok {
				return nil, fmt.Errorf("missing GUI window field %s.%s", name, member)
			}
			dst.Fields[member] = f
		}
		l.Types.Types[name] = dst
	}
	o := &object.Reader{Symbols: l.Types}
	for name, fields := range required {
		for _, member := range fields {
			f, err := o.Field(name, member)
			if err != nil {
				return nil, err
			}
			switch member {
			case "head", "strName":
				target := "_THRDESKHEAD"
				if member == "strName" {
					target = "_LARGE_UNICODE_STRING"
				}
				if f.Type.Kind != "struct" || f.Type.Name != target {
					return nil, fmt.Errorf("invalid GUI embedded field %s.%s", name, member)
				}
			case "Length":
				b, ok := l.Types.Bases[f.Type.Name]
				if f.Type.Kind != "base" || !ok || b.Size != 4 || b.Signed || b.Endian != "little" {
					return nil, fmt.Errorf("invalid GUI window name length")
				}
			default:
				if f.Type.Kind != "pointer" || f.Type.Subtype == nil {
					return nil, fmt.Errorf("invalid GUI window pointer %s.%s", name, member)
				}
				targets := map[string]string{"pDeskInfo": "tagDESKTOPINFO", "spwnd": "tagWND", "spwndNext": "tagWND", "spwndChild": "tagWND", "rpdesk": "tagDESKTOP", "pti": "tagTHREADINFO", "subPointer": "subTagWNDType"}
				if target := targets[member]; target != "" && (f.Type.Subtype.Kind != "struct" || f.Type.Subtype.Name != target) {
					return nil, fmt.Errorf("invalid GUI window pointer target %s.%s", name, member)
				}
			}
		}
	}
	return l, nil
}

// DesktopWindow reads the top window through the supplied session address space.
func (r Reader) DesktopWindow(ctx context.Context, desktop uint64) (uint64, error) {
	o, err := r.objects()
	if err != nil {
		return 0, err
	}
	info, err := o.Uint(ctx, desktop, "tagDESKTOP", "pDeskInfo")
	if err != nil {
		return 0, err
	}
	return o.Uint(ctx, info, "tagDESKTOPINFO", "spwnd")
}

func (r Reader) WindowDesktop(ctx context.Context, window uint64) (uint64, error) {
	o, err := r.objects()
	if err != nil {
		return 0, err
	}
	return o.Uint(ctx, window, "tagWND", "head.rpdesk")
}

func (r Reader) WindowSession(ctx context.Context, window uint64) (*uint64, error) {
	desktop, err := r.WindowDesktop(ctx, window)
	if err != nil {
		return nil, err
	}
	return r.DesktopSession(ctx, desktop)
}

// WindowProcedure preserves zero as a readable value and returns faults rather
// than substituting an unavailable procedure with a zero address.
func (r Reader) WindowProcedure(ctx context.Context, window uint64) (uint64, error) {
	o, err := r.objects()
	if err != nil {
		return 0, err
	}
	if _, ok := r.Layout.Types.Types["tagWND"].Fields["subPointer"]; ok {
		sub, err := o.Uint(ctx, window, "tagWND", "subPointer")
		if err != nil {
			return 0, err
		}
		return o.Uint(ctx, sub, "subTagWNDType", "lpfnWndProc")
	}
	return o.Uint(ctx, window, "tagWND", "lpfnWndProc")
}
