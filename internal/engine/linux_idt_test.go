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

const idtFixtureBase = uint64(0x19000)

func idtFixture(t *testing.T, arch, variant string) testfixture.Fixture {
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
	table.Bases["u16"] = symbols.Type{Kind: "int", Size: 2, Endian: "little"}
	field := func(off uint64, name string) symbols.Field {
		return symbols.Field{Offset: off, Type: symbols.TypeRef{Kind: "base", Name: name}}
	}
	packed := variant == "packed" || variant == "mixed"
	stride := uint64(16)
	if variant == "packed" || variant == "split-low" {
		stride = 8
	}
	fields := map[string]symbols.Field{}
	if packed {
		fields["a"], fields["b"] = field(0, "u32"), field(4, "u32")
	}
	if variant != "packed" {
		low, middle, high := uint64(0), uint64(6), uint64(8)
		if variant == "mixed" {
			low, middle, high = 8, 10, 12
		}
		fields["offset_low"], fields["offset_middle"] = field(low, "u16"), field(middle, "u16")
		if variant != "split-low" {
			fields["offset_high"] = field(high, "u32")
		}
	}
	typ := "gate_struct64"
	if table.PointerSize() == 4 {
		typ = "gate_struct"
	}
	table.Types[typ] = symbols.Type{Kind: "struct", Size: stride, Fields: fields}
	table.Symbols["idt_table"] = symbols.Symbol{Address: idtFixtureBase}
	clear(data[idtFixtureBase : idtFixtureBase+4096])
	targets := []uint64{0, 0x8500, 0x8501, 0x10100, 0x12100, 0x16400}
	for i := uint64(0); i < 256; i++ {
		target := uint64(0x8500)
		if i < uint64(len(targets)) {
			target = targets[i]
		}
		if i == 19 {
			target = 0x11000
		}
		if i > 19 && i != 128 {
			target = 0xdeadbeef
		}
		at := idtFixtureBase + i*stride
		if packed {
			binary.LittleEndian.PutUint32(data[at:], uint32(target&0xffff)|0xcafe0000)
			binary.LittleEndian.PutUint32(data[at+4:], uint32(target&0xffff0000)|0xbeef)
		}
		if variant != "packed" {
			low, middle, high := uint64(0), uint64(6), uint64(8)
			if variant == "mixed" {
				low, middle, high = 8, 10, 12
			}
			v := uint16(target)
			if variant == "mixed" {
				v = 0xdead
			}
			binary.LittleEndian.PutUint16(data[at+low:], v)
			binary.LittleEndian.PutUint16(data[at+middle:], uint16(target>>16))
			if variant != "split-low" {
				v := uint32(0xffff0000)
				if table.PointerSize() == 4 {
					v = 0xdeadbeef
				}
				binary.LittleEndian.PutUint32(data[at+high:], v)
			}
		}
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

type idtFaultLayer struct {
	memory.MemoryLayer
	start, end uint64
}

func (l idtFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at < l.end && at+uint64(len(p)) > l.start {
		n := 0
		if at < l.start {
			var err error
			n, err = l.MemoryLayer.ReadAt(ctx, p[:l.start-at], at)
			if err != nil {
				return n, err
			}
		}
		return n, fmt.Errorf("injected missing IDT bytes")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func idtFault(e *engine.Engine, start, end uint64) {
	layer := idtFaultLayer{e.Env.Kernel, start, end}
	e.Env.Kernel = layer
	e.Env.Objects = &object.Reader{Layer: layer, Symbols: e.Env.Symbols}
}

func TestLinuxIDTLayoutsAndAttribution(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-idt-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Generators []struct {
			Width int
			Name  string
			Rows  []struct {
				Index, Address      uint64
				Module, Symbol      *string
				SelectedOwnerSymbol *string `json:"selected_owner_symbol"`
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Generators) != 10 {
		t.Fatal(err)
	}
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, variant := range []string{"packed", "split-low", "split-high", "mixed", "probe-hole"} {
			t.Run(arch+"/"+variant, func(t *testing.T) {
				e := openModx(t, idtFixture(t, arch, variant), arch)
				if variant == "probe-hole" {
					idtFault(e, idtFixtureBase+7*16, idtFixtureBase+8*16)
				}
				var selected []evidence.Row
				captures, records := 0, 0
				result, err := e.Run(context.Background(), "linux.check_idt", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					records++
					if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
						for key, proof := range fields {
							if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" && c["ReadComplete"].Data == true {
								captures++
								at, err := c["Address"].Uint()
								raw := c["Raw"].Data.([]byte)
								actual, readErr := memory.Read(context.Background(), e.Env.Kernel, at, len(raw))
								if err != nil || readErr != nil || !bytes.Equal(raw, actual) {
									t.Fatal(key, err, readErr)
								}
							}
						}
					}
					if r.Cells["RecordType"].String() == "idt_entry" {
						selected = append(selected, r)
					}
					return nil
				}})
				if variant == "probe-hole" {
					if err == nil || result.Task.State != "failed" {
						t.Fatal(result, err)
					}
				} else if err != nil || result.Task.State != "completed" {
					t.Fatal(result, err)
				}
				found := false
				for _, profile := range oracle.Generators {
					if profile.Width != e.Env.Symbols.PointerSize() || profile.Name != variant {
						continue
					}
					found = true
					if len(profile.Rows) != len(selected) {
						t.Fatal(len(selected), profile)
					}
					for i, want := range profile.Rows {
						r := selected[i]
						idx, _ := r.Cells["Index"].Uint()
						at, _ := r.Cells["Address"].Uint()
						if idx != want.Index || at != want.Address {
							t.Fatal(want, idx, at)
						}
						for _, v := range []struct {
							key  string
							want *string
						}{{"Module", want.Module}, {"Symbol", want.SelectedOwnerSymbol}} {
							if v.want == nil {
								if r.Cells[v.key].Reason != "not_available" {
									t.Fatal(want, r.Cells[v.key])
								}
							} else if r.Cells[v.key].String() != *v.want {
								t.Fatal(want, r.Cells[v.key])
							}
						}
					}
				}
				if !found {
					t.Fatal("missing oracle")
				}
				wantCaptures := 131
				if variant == "split-high" {
					wantCaptures = 152
				}
				if variant == "probe-hole" {
					wantCaptures = 148
				}
				if captures != wantCaptures {
					t.Fatal("raw capture coverage drift", captures, wantCaptures)
				}
				stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
				if err != nil || len(stored) != records {
					t.Fatal(err, len(stored), records)
				}
				for _, r := range stored {
					if err = r.Verify(); err != nil {
						t.Fatal(err)
					}
				}
				// Restore the deterministic fault for a second run; failed tasks cannot be reused.
				cached, err := e.Run(context.Background(), "linux.check_idt", nil, engine.RunOptions{})
				if variant == "probe-hole" {
					if err == nil || cached.Reused || cached.Task.ID == result.Task.ID {
						t.Fatal(cached, err)
					}
				} else if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
					t.Fatal(cached, err)
				}
				t.Logf("records=%d entries=%d complete_raw_captures_reread=%d; pinned index/address/module/order and selected-owner symbols verified; sealed rows verified; cache state checked", records, len(selected), captures)
			})
		}
	}
}

func TestLinuxIDTFailuresAndCancellation(t *testing.T) {
	for _, fault := range []string{"missing-type", "zero-size", "oversized-type", "missing-table", "bad-table", "partial-field", "missing-offset", "missing-module-source", "missing-kernel-bounds", "bad-module-symbol"} {
		t.Run(fault, func(t *testing.T) {
			f := idtFixture(t, "control", "split-high")
			table, err := symbols.Load(f.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			typ := table.Types["gate_struct64"]
			switch fault {
			case "missing-type":
				delete(table.Types, "gate_struct64")
			case "zero-size":
				typ.Size = 0
				typ.Fields = nil
				table.Types["gate_struct64"] = typ
			case "oversized-type":
				typ.Size = 4097
				table.Types["gate_struct64"] = typ
			case "missing-table":
				delete(table.Symbols, "idt_table")
			case "bad-table":
				table.Symbols["idt_table"] = symbols.Symbol{Address: 0x300000}
			case "missing-offset":
				delete(typ.Fields, "offset_middle")
			case "missing-module-source":
				delete(table.Symbols, "module_kset")
			case "missing-kernel-bounds":
				delete(table.Symbols, "_text")
			}
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			e := openModx(t, f, "control")
			if fault == "partial-field" {
				idtFault(e, idtFixtureBase+16+10, idtFixtureBase+16+12)
			}
			if fault == "bad-module-symbol" {
				idtFault(e, 0x1e000, 0x1e040)
			}
			count, partial, partialBytes := 0, false, false
			result, err := e.Run(context.Background(), "linux.check_idt", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				count++
				if r.Cells["RecordType"].String() == "entry_observation" {
					partial = true
				}
				if fault == "partial-field" && r.Cells["Status"].String() == "descriptor_unreadable" {
					fields := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
					for _, proof := range fields {
						if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" && c["ReadComplete"].Data == false && len(c["Raw"].Data.([]byte)) == 2 {
							partialBytes = true
						}
					}
				}
				return nil
			}})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err, count)
			}
			if (fault == "partial-field" || fault == "bad-table") && !partial {
				t.Fatal("missing failure observations")
			}
			if fault == "partial-field" && !partialBytes {
				t.Fatal("partial descriptor bytes lost")
			}
		})
	}
	for _, params := range []map[string]string{{"max-nodes": "0"}, {"max-nodes": "1"}, {"max-scan-bytes": "0"}, {"max-scan-bytes": "8589934593"}} {
		e := openModx(t, idtFixture(t, "control", "split-high"), "control")
		r, err := e.Run(context.Background(), "linux.check_idt", params, engine.RunOptions{})
		if err == nil || r.Task.State != "failed" {
			t.Fatal(params, r, err)
		}
	}
	for _, phase := range []string{"source", "entry"} {
		for _, cancel := range []bool{true, false} {
			e := openModx(t, idtFixture(t, "control", "split-high"), "control")
			ctx, stop := context.WithCancel(context.Background())
			sentinel := errors.New("output failure")
			emittedAfterTarget, targeted := 0, false
			_, err := e.Run(ctx, "linux.check_idt", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				if targeted {
					emittedAfterTarget++
					return nil
				}
				if phase == "entry" && r.Cells["RecordType"].String() != "idt_entry" {
					return nil
				}
				targeted = true
				if cancel {
					stop()
					return nil
				}
				return sentinel
			}})
			stop()
			want := sentinel
			if cancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) || !targeted || emittedAfterTarget != 0 {
				t.Fatal(phase, err, targeted, emittedAfterTarget)
			}
		}
	}
}
