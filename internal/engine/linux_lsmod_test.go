package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestLinuxLsmodDisplayEvidenceAndCache(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"get", "ops"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := moduleParamsEngine(t, arch, layout, false, true)
				var fresh, cached bytes.Buffer
				captures := 0
				check := func(r evidence.Row) {
					if r.Cells["RecordType"].String() != "module" || r.Cells["Name"].String() != "sys-only" || r.Cells["Module Name"].String() != "sys-only" || r.Cells["Load Arguments"].String() != "signed=-123, toggle=Y, label=hello, mystery=None, items=7,N" {
						t.Fatal(r)
					}
					size, err := r.Cells["Code Size"].Uint()
					if err != nil || size != 4096 || r.Cells["Taints"].String() == "" || r.Cells["File Output"].Reason != "not_requested" {
						t.Fatal(r, err)
					}
					captures += verifyModuleParameterWireCaptures(t, e, r.Cells["FieldEvidence"])
				}
				result, err := e.Run(context.Background(), "linux.lsmod", nil, engine.RunOptions{Emit: func(r evidence.Row) error { check(r); return json.NewEncoder(&fresh).Encode(r) }})
				if err != nil || result.Task.State != "completed" || result.Task.Rows != 1 || captures < 20 {
					t.Fatal(result, err, captures)
				}
				captures = 0
				replay, err := e.Run(context.Background(), "linux.lsmod", nil, engine.RunOptions{Emit: func(r evidence.Row) error { check(r); return json.NewEncoder(&cached).Encode(r) }})
				if err != nil || !replay.Reused || captures < 20 || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(replay, err, captures)
				}
				var plain string
				_, err = e.Run(context.Background(), "linux.lsmod", map[string]string{"plain-taints": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { plain = r.Cells["Taints"].String(); return nil }})
				if err != nil || plain != "C" {
					t.Fatal(plain, err)
				}
			})
		}
	}
}

func TestLinuxLsmodPartialReadAndEmitFailure(t *testing.T) {
	e := moduleParamsEngine(t, "x64", "ops", true, true)
	for i := 0; i < 2; i++ {
		var rows []evidence.Row
		result, err := e.Run(context.Background(), "linux.lsmod", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
		if err == nil || result.Reused || result.Task.State != "failed" || len(rows) != 1 || rows[0].Cells["Load Arguments"].Reason != "module_arguments_unreadable" || rows[0].Cells["Name"].String() != "sys-only" {
			t.Fatal(result, err, rows)
		}
	}
	stop := errors.New("stop output")
	_, err := e.Run(context.Background(), "linux.lsmod", nil, engine.RunOptions{Emit: func(evidence.Row) error { return stop }})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = e.Run(ctx, "linux.lsmod", nil, engine.RunOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
