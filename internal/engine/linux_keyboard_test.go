package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func keyboardFixture(t *testing.T, arch, variant string) testfixture.Fixture {
	t.Helper()
	f := kthreadFixture(t, arch, "worker-private")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	width := table.PointerSize()
	ptr := symbols.TypeRef{Kind: "pointer"}
	field := func(off uint64) symbols.Field { return symbols.Field{Offset: off, Type: ptr} }
	table.Types["notifier_block"] = symbols.Type{Kind: "struct", Size: uint64(width * 3), Fields: map[string]symbols.Field{"notifier_call": field(0), "next": field(uint64(width))}}
	table.Types["atomic_notifier_head"] = symbols.Type{Kind: "struct", Size: uint64(width), Fields: map[string]symbols.Field{"head": field(0)}}
	ref := symbols.TypeRef{Kind: "struct", Name: "atomic_notifier_head"}
	table.Symbols["keyboard_notifier_list"] = symbols.Symbol{Address: 0x18000, Type: &ref}
	write := func(at, v uint64) {
		if width == 8 {
			binary.LittleEndian.PutUint64(data[at:], v)
		} else {
			binary.LittleEndian.PutUint32(data[at:], uint32(v))
		}
	}
	clear(data[0x18000:0x19300])
	write(0x19000, 0x8500)
	write(0x19000+uint64(width), 0)
	write(0x19100, 0x10100)
	write(0x19100+uint64(width), 0x19000)
	switch variant {
	case "empty":
	case "kernel":
		write(0x18000, 0x19000)
	case "module":
		write(0x18000, 0x19100)
	case "unknown":
		write(0x19000, 0x16400)
		write(0x18000, 0x19000)
	case "repeat":
		write(0x19000+uint64(width), 0x19100)
		write(0x18000, 0x19100)
	case "unreadable-head":
		write(0x18000, 0x300000)
	case "missing-symbol":
		delete(table.Symbols, "keyboard_notifier_list")
	case "qualified":
		delete(table.Symbols, "a_entry")
		delete(table.Symbols, "z_entry")
		table.Symbols["owner!entry!tail"] = symbols.Symbol{Address: 0x8500}
		write(0x18000, 0x19000)
	default:
		t.Fatal(variant)
	}
	encoded, err := table.Encode()
	if err != nil || os.WriteFile(f.Symbols, encoded, 0600) != nil || os.WriteFile(f.Image, data, 0600) != nil {
		t.Fatal(err)
	}
	return f
}

func TestLinuxKeyboardPinnedChains(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-keyboard-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name  string
			Error any
			Rows  []struct {
				Address             uint64
				Module, Symbol      *string
				SelectedOwnerSymbol *string `json:"selected_owner_symbol"`
			}
		}
		Bound struct{ Visited, Last int }
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 8 || oracle.Bound.Visited != 4097 {
		t.Fatal(err, oracle.Bound)
	}
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, variant := range []string{"empty", "kernel", "module", "unknown", "qualified", "repeat", "unreadable-head", "missing-symbol"} {
			t.Run(arch+"/"+variant, func(t *testing.T) {
				e := openModx(t, keyboardFixture(t, arch, variant), arch)
				if variant == "empty" {
					base := e.Env.Kernel
					e.Env.Kernel = keyboardZeroHole{base}
					e.Env.Objects = &object.Reader{Layer: e.Env.Kernel, Symbols: e.Env.Symbols}
				}
				var selected []evidence.Row
				captures := 0
				result, err := e.Run(context.Background(), "linux.keyboard_notifiers", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
						for _, proof := range fields {
							if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" && c["ReadComplete"].Data == true {
								captures++
								at, err := c["Address"].Uint()
								raw := c["Raw"].Data.([]byte)
								actual, readErr := memory.Read(context.Background(), e.Env.Kernel, at, len(raw))
								if err != nil || readErr != nil || !bytes.Equal(raw, actual) {
									t.Fatal(err, readErr)
								}
							}
						}
					}
					if r.Cells["RecordType"].String() == "notifier" {
						selected = append(selected, r)
					}
					return nil
				}})
				if variant == "missing-symbol" || variant == "unreadable-head" || variant == "empty" {
					if err == nil || result.Task.State != "failed" {
						t.Fatal(variant, result, err)
					}
					return
				}
				if err != nil || result.Task.State != "completed" {
					t.Fatal(result, err, len(selected))
				}
				var wantRows []struct {
					Address             uint64
					Module, Symbol      *string
					SelectedOwnerSymbol *string
				}
				for _, c := range oracle.Cases {
					if c.Name == variant {
						for _, row := range c.Rows {
							wantRows = append(wantRows, struct {
								Address             uint64
								Module, Symbol      *string
								SelectedOwnerSymbol *string
							}{row.Address, row.Module, row.Symbol, row.SelectedOwnerSymbol})
						}
					}
				}
				if len(wantRows) != len(selected) {
					t.Fatalf("%s native=%d oracle=%d first=%v", variant, len(selected), len(wantRows), func() any {
						if len(selected) == 0 {
							return nil
						}
						return selected[0].Cells["Address"]
					}())
				}
				for i, want := range wantRows {
					r := selected[i]
					at, _ := r.Cells["Address"].Uint()
					if at != want.Address {
						t.Fatal(want, at)
					}
					check := func(key string, value *string) {
						if value == nil {
							if r.Cells[key].Reason != "not_available" {
								t.Fatal(key, r.Cells[key])
							}
						} else if r.Cells[key].String() != *value {
							t.Fatal(key, value, r.Cells[key])
						}
					}
					check("Module", want.Module)
					check("Symbol", want.SelectedOwnerSymbol)
				}
				if captures == 0 {
					t.Fatal("no raw captures")
				}
				cached, err := e.Run(context.Background(), "linux.keyboard_notifiers", nil, engine.RunOptions{})
				if err != nil || !cached.Reused {
					t.Fatal(cached, err)
				}
				t.Logf("callbacks=%d raw_captures_reread=%d", len(selected), captures)
			})
		}
	}
}

func TestLinuxKeyboardCancellation(t *testing.T) {
	e := openModx(t, keyboardFixture(t, "control", "kernel"), "control")
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	sentinel := errors.New("stop")
	_, err := e.Run(ctx, "linux.keyboard_notifiers", nil, engine.RunOptions{Emit: func(evidence.Row) error {
		stop()
		return sentinel
	}})
	if !errors.Is(err, sentinel) && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type keyboardZeroHole struct{ memory.MemoryLayer }

func (h keyboardZeroHole) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at < 0x1000 {
		return 0, fmt.Errorf("synthetic null page is absent")
	}
	return h.MemoryLayer.ReadAt(ctx, p, at)
}
