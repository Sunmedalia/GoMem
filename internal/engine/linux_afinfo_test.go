package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func afinfoFixture(t *testing.T, arch, variant string) testfixture.Fixture {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	structure := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(at uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: at, Type: ref} }
	put := func(at, v uint64) {
		if table.PointerSize() == 8 {
			binary.LittleEndian.PutUint64(data[at:], v)
		} else {
			binary.LittleEndian.PutUint32(data[at:], uint32(v))
		}
	}
	table.Symbols["known_handler"] = symbols.Symbol{Address: 0x8500}
	table.Symbols["alias_handler"] = symbols.Symbol{Address: 0x8500}
	table.Types["file_operations"] = symbols.Type{Kind: "struct", Size: 32, FieldOrder: []string{"write", "owner", "__UNIQUE_ID_rh_kabi_hide_one", "next"}, Fields: map[string]symbols.Field{"write": field(0, ptr), "owner": field(8, ptr), "__UNIQUE_ID_rh_kabi_hide_one": field(16, ptr), "next": field(24, ptr)}}
	table.Types["seq_operations"] = symbols.Type{Kind: "struct", Size: 32, FieldOrder: []string{"stop", "show", "start", "next"}, Fields: map[string]symbols.Field{"start": field(0, ptr), "stop": field(8, ptr), "next": field(16, ptr), "show": field(24, ptr)}}
	legacy := variant != "modern" && variant != "global-pointer" && variant != "null-global" && variant != "untyped-global" && variant != "partial-members" && variant != "all-absent"
	table.Types["tcp_seq_afinfo"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{}}
	if legacy {
		table.Types["tcp_seq_afinfo"].Fields["seq_fops"] = field(0, symbols.TypeRef{Kind: "pointer", Subtype: refPointer(structure("file_operations"))})
	}
	for i, at := range []uint64{0x18000, 0x18200} {
		clear(data[at : at+64])
		global := []string{"raw_seq_ops", "udp_seq_ops"}[i]
		typ := "seq_operations"
		seq := at
		if legacy {
			global = []string{"tcp4_seq_afinfo", "udp4_seq_afinfo"}[i]
			typ = "tcp_seq_afinfo"
			table.Types["tcp_seq_afinfo"].Fields["seq_ops"] = field(8, structure("seq_operations"))
			fops := uint64(0x18800 + i*0x100)
			put(at, fops)
			seq = at + 8
			for j, v := range []uint64{0x8501, 0, 0xdeadbeef, 0x8500} {
				put(fops+uint64(j*8), v)
			}
		}
		ref := structure(typ)
		table.Symbols[global] = symbols.Symbol{Address: at, Type: &ref}
		for j, v := range []uint64{0, 0x8600, 0x8500, 0x8500} {
			put(seq+uint64(j*8), v)
		}
	}
	switch variant {
	case "seq-show", "seq-show-zero", "seq-show-slide", "seq-show-relative-known":
		delete(table.Types["tcp_seq_afinfo"].Fields, "seq_ops")
		table.Types["tcp_seq_afinfo"].Fields["seq_show"] = field(8, ptr)
		v := uint64(0x8600)
		if variant == "seq-show-zero" {
			v = 0
		}
		if variant == "seq-show-slide" {
			v = 0x8500
		}
		if variant == "seq-show-relative-known" {
			v = 0x7500
		}
		put(0x18008, v)
		put(0x18208, v)
	case "seq-show-and-ops":
		typ := table.Types["tcp_seq_afinfo"]
		typ.Size = 48
		typ.Fields["seq_show"] = field(40, ptr)
		table.Types["tcp_seq_afinfo"] = typ
		put(0x18028, 0xdeadbeef)
		put(0x18228, 0xdeadbeef)
	case "fops-only":
		delete(table.Types["tcp_seq_afinfo"].Fields, "seq_ops")
	case "null-fops":
		put(0x18000, 0)
	case "bad-fops":
		put(0x18000, 0x300000)
	case "embedded-fops":
		typ := table.Types["tcp_seq_afinfo"]
		typ.Size = 72
		typ.Fields["seq_fops"] = field(40, structure("file_operations"))
		table.Types["tcp_seq_afinfo"] = typ
		for _, at := range []uint64{0x18000, 0x18200} {
			for j, v := range []uint64{0x8501, 0, 0xdeadbeef, 0x8500} {
				put(at+40+uint64(j*8), v)
			}
		}
	case "global-pointer", "null-global":
		ref := structure("seq_operations")
		pointer := symbols.TypeRef{Kind: "pointer", Subtype: &ref}
		table.Symbols["raw_seq_ops"] = symbols.Symbol{Address: 0x17000, Type: &pointer}
		value := uint64(0x18000)
		if variant == "null-global" {
			value = 0
		}
		put(0x17000, value)
	case "untyped-global":
		v := table.Symbols["raw_seq_ops"]
		v.Type = nil
		table.Symbols["raw_seq_ops"] = v
	case "partial-members":
		ref := structure("seq_operations")
		table.Symbols["raw_seq_ops"] = symbols.Symbol{Address: 0x1fff0, Type: &ref}
	case "all-absent":
		delete(table.Symbols, "raw_seq_ops")
		delete(table.Symbols, "udp_seq_ops")
	}
	if strings.HasSuffix(variant, "-slide") || variant == "seq-show-relative-known" {
		for name, symbol := range table.Symbols {
			symbol.Address -= 0x1000
			table.Symbols[name] = symbol
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
func refPointer(ref symbols.TypeRef) *symbols.TypeRef { return &ref }

func TestLinuxAFInfoLayoutsAndPinnedPolicies(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-afinfo-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name     string
			Handlers []struct {
				Global  string `json:"global_name"`
				Member  string
				Address uint64
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, variant := range []string{"legacy", "modern", "seq-show", "seq-show-zero", "seq-show-and-ops", "embedded-fops", "global-pointer", "all-absent", "legacy-slide", "seq-show-slide", "seq-show-relative-known"} {
			t.Run(arch+"/"+variant, func(t *testing.T) {
				f := afinfoFixture(t, arch, variant)
				var e *engine.Engine
				if strings.HasSuffix(variant, "-slide") || variant == "seq-show-relative-known" {
					nativeArch := arch
					if arch == "control" {
						nativeArch = "x64"
					}
					var openErr error
					e, openErr = engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: nativeArch, OS: "linux", CaseDir: t.TempDir(), Offline: true, KernelSlide: 0x1000})
					if openErr != nil {
						t.Fatal(openErr)
					}
					defer e.Close()
				} else {
					e = openModx(t, f, arch)
				}
				var handlers []evidence.Row
				captures := 0
				result, err := e.Run(context.Background(), "linux.check_afinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					if r.Cells["RecordType"].String() == "handler" {
						handlers = append(handlers, r)
					}
					if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
						for key, proof := range fields {
							if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" {
								at, err := c["Address"].Uint()
								raw := c["Raw"].Data.([]byte)
								actual, readErr := memory.Read(context.Background(), e.Env.Kernel, at, len(raw))
								if err != nil || readErr != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
									t.Fatal(key, err, readErr)
								}
								captures++
							}
						}
					}
					return nil
				}})
				if err != nil || result.Task.State != "completed" {
					t.Fatal(result, err)
				}
				found := false
				for _, tc := range oracle.Cases {
					if tc.Name == variant {
						found = true
						if len(tc.Handlers) != len(handlers) {
							t.Fatal(tc, len(handlers))
						}
						for i, want := range tc.Handlers {
							row := handlers[i]
							addr, _ := row.Cells["Handler Address"].Uint()
							if row.Cells["Symbol Name"].String() != want.Global || row.Cells["Member"].String() != want.Member || addr != want.Address {
								t.Fatal(want, row.Cells["Symbol Name"], row.Cells["Member"], addr)
							}
						}
					}
				}
				if !found {
					t.Fatal("missing oracle profile", variant)
				}
				stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range stored {
					if err := r.Verify(); err != nil {
						t.Fatal(err)
					}
				}
				cached, err := e.Run(context.Background(), "linux.check_afinfo", nil, engine.RunOptions{})
				if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
					t.Fatal(cached, err)
				}
				t.Logf("records=%d handlers=%d raw_captures_reread=%d; all three fields and order match pinned generator; sealed rows and cache verified", len(stored), len(handlers), captures)
			})
		}
	}
}
func TestLinuxAFInfoFailuresAndCancellation(t *testing.T) {
	for _, variant := range []string{"fops-only", "null-fops", "bad-fops", "untyped-global", "null-global", "partial-members"} {
		t.Run(variant, func(t *testing.T) {
			e := openModx(t, afinfoFixture(t, "control", variant), "control")
			result, err := e.Run(context.Background(), "linux.check_afinfo", nil, engine.RunOptions{})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil || len(rows) == 0 {
				t.Fatal(err)
			}
			for _, r := range rows {
				if err := r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, value := range []string{"0", "1000001", "1"} {
		e := openModx(t, afinfoFixture(t, "control", "legacy"), "control")
		if _, err := e.Run(context.Background(), "linux.check_afinfo", map[string]string{"max-members": value}, engine.RunOptions{}); err == nil {
			t.Fatal(value)
		}
	}
	for _, cancelled := range []bool{false, true} {
		e := openModx(t, afinfoFixture(t, "control", "legacy"), "control")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sentinel := errors.New("output closed")
		count := 0
		_, err := e.Run(ctx, "linux.check_afinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
			count++
			if cancelled {
				cancel()
				return nil
			}
			return sentinel
		}})
		want := sentinel
		if cancelled {
			want = context.Canceled
		}
		if !errors.Is(err, want) || count != 1 {
			t.Fatal(err, count)
		}
	}
}
