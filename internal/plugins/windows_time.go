package plugins

import (
	"context"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsRawTime(ctx context.Context, e plugin.Environment, address uint64, typ, field string) (uint64, error) {
	f, err := e.Objects.Field(typ, field)
	if err != nil {
		return 0, err
	}
	if f.Type.Kind == "struct" || f.Type.Kind == "union" {
		field += ".QuadPart"
	}
	return e.Objects.Uint(ctx, address, typ, field)
}
func windowsFiletime(stamp uint64) evidence.Value {
	if stamp < 10000000 {
		return evidence.Missing("not_set", nil)
	}
	seconds := stamp / 10000000
	if seconds > 265046774399 {
		return evidence.Missing("invalid_filetime", nil)
	}
	return evidence.Text(time.Unix(int64(seconds)-11644473600, int64(stamp%10000000)*100).UTC().Format(time.RFC3339Nano))
}
func windowsTime(ctx context.Context, e plugin.Environment, address uint64, typ, field string) (evidence.Value, evidence.Value) {
	raw, err := windowsRawTime(ctx, e, address, typ, field)
	if err != nil {
		v := evidence.Missing("unreadable_or_unavailable", err)
		return v, v
	}
	return windowsFiletime(raw), evidence.Number(raw)
}
