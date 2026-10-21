package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func withDwarf2JSON(t *testing.T, f testfixture.Fixture, version string) {
	t.Helper()
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	if table.Meta == nil {
		table.Meta = map[string]json.RawMessage{}
	}
	table.Meta["producer"] = json.RawMessage(fmt.Sprintf(`{"name":"dwarf2json","version":%q}`, version))
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxHiddenModulesSynthetic(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"legacy", "layout", "mem"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				f := modxFixture(t, arch, layout, "")
				withDwarf2JSON(t, f, "0.9.0")
				e := openModx(t, f, arch)
				ctx := context.Background()
				var fresh, replay bytes.Buffer
				check := func(rows []evidence.Row) {
					if len(rows) != 3 || rows[0].Cells["Module Name"].String() != "sys-only" || rows[1].Cells["Module Name"].String() != "scan-only" || rows[2].Cells["RecordType"].String() != "hidden_scan_summary" {
						t.Fatal(rows)
					}
					for _, row := range rows[:2] {
						if err := row.Verify(); err != nil || row.Cells["RecordType"].String() != "hidden_module" || row.Cells["Status"].String() != "hidden" || row.Cells["Source"].String() != "Scanner" {
							t.Fatal(row, err)
						}
					}
					fields := bashProofFields(t, rows[2].Cells["Coverage"])
					hidden, _ := fields["hidden"].Uint()
					excluded, _ := fields["excluded"].Uint()
					rejected, _ := fields["rejected"].Uint()
					selfMatches, _ := fields["self_matches"].Uint()
					step, _ := fields["step"].Uint()
					wantStep := uint64(8)
					if arch != "x64" {
						wantStep = 4
					}
					if hidden != 2 || excluded != 1 || rejected != 1 || selfMatches != 3 || step != wantStep {
						t.Fatal(fields)
					}
				}
				var rows []evidence.Row
				result, err := e.Run(ctx, "linux.hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					rows = append(rows, row)
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || result.Task.Rows != 3 {
					t.Fatal(result, err)
				}
				check(rows)
				rows = nil
				cached, err := e.Run(ctx, "linux.hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					rows = append(rows, row)
					return json.NewEncoder(&replay).Encode(row)
				}})
				if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
					t.Fatal(cached, err)
				}
				check(rows)
			})
		}
	}
}

func TestLinuxHiddenModulesRejectsOldSymbols(t *testing.T) {
	f := modxFixture(t, "x64", "legacy", "")
	e := openModx(t, f, "x64")
	var rows int
	result, err := e.Run(context.Background(), "linux.hidden_modules", nil, engine.RunOptions{Emit: func(evidence.Row) error { rows++; return nil }})
	if err == nil || rows != 0 || result.Reused || result.Task.State == "completed" {
		t.Fatal(result, err, rows)
	}
	withDwarf2JSON(t, f, "0.7.9")
	old := openModx(t, f, "x64")
	rows = 0
	result, err = old.Run(context.Background(), "linux.hidden_modules", nil, engine.RunOptions{Emit: func(evidence.Row) error { rows++; return nil }})
	if err == nil || rows != 0 || result.Reused {
		t.Fatal(result, err, rows)
	}
}

func TestLinuxHiddenModulesStop(t *testing.T) {
	f := modxFixture(t, "x64", "legacy", "")
	withDwarf2JSON(t, f, "0.8.0")
	e := openModx(t, f, "x64")
	sentinel := errors.New("stop output")
	calls := 0
	_, err := e.Run(context.Background(), "linux.hidden_modules", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return sentinel }})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	_, err = e.Run(cancelled, "linux.hidden_modules", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return nil }})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err, calls)
	}
}
