package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/Sunmedalia/GoMem/internal/report"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func kthreadFixture(t *testing.T, arch, variant string) testfixture.Fixture {
	t.Helper()
	f := modxFixture(t, arch, "legacy", "")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: ref}
	}
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	word := func(at, v uint64) { binary.LittleEndian.PutUint32(data[at:], uint32(v)) }
	pointer := put
	if table.PointerSize() == 4 {
		pointer = word
	}
	list := func(at, next, prev uint64) { pointer(at, next); pointer(at+uint64(table.PointerSize()), prev) }
	task := table.Types["task_struct"]
	task.Size = 160
	member := "worker_private"
	if variant == "set-child-tid" {
		member = "set_child_tid"
	}
	task.Fields[member] = field(152, ptr)
	table.Types["task_struct"] = task
	table.Types["kthread"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"threadfn": field(0, ptr)}}
	if variant == "full-name" || variant == "bad-full-name" || variant == "empty-full-name" {
		table.Types["kthread"].Fields["full_name"] = field(8, ptr)
	}
	table.Symbols["_text"] = symbols.Symbol{Address: 0x8400}
	table.Symbols["_etext"] = symbols.Symbol{Address: 0x8600}
	table.Symbols["a_entry"] = symbols.Symbol{Address: 0x8500}
	table.Symbols["z_entry"] = symbols.Symbol{Address: 0x8500}
	// One additional thread belongs to the first task-list entry.
	clear(data[0xa400:0xa4a0])
	word(0xa410, 102)
	word(0xa414, 100)
	pointer(0xa458, 0xa000)
	list(0xa460, 0xa060, 0xa060)
	list(0xa060, 0xa460, 0xa460)
	for i, a := range []uint64{0xa000, 0xa400, 0xb000} {
		list(a+96, a+96, a+96)
		if a == 0xa000 {
			list(a+96, 0xa460, 0xa460)
		}
		if a == 0xa400 {
			list(a+96, 0xa060, 0xa060)
		}
		word(a+80, 0x200000)
		pointer(a+152, uint64(0x17000+i*0x100))
		clear(data[a+24 : a+40])
		copy(data[a+24:], []string{"kernel-worker", "module-worker", "sys-worker"}[i])
		pointer(uint64(0x17000+i*0x100), []uint64{0x8500, 0x10100, 0x12100}[i])
		pointer(uint64(0x17008+i*0x100), uint64(0x18800+i*256))
		clear(data[0x18800+i*256 : 0x18800+i*256+255])
		copy(data[0x18800+i*256:], []string{"full-kernel", "full-module", "full-sys"}[i])
	}
	for i, module := range []uint64{0xc000, 0xc400} {
		table.Types["module"].Fields["symtab"] = field(200, ptr)
		table.Types["module"].Fields["strtab"] = field(208, ptr)
		table.Types["module"].Fields["num_symtab"] = field(216, u32)
		symtab, strtab := uint64(0x1e000+i*128), uint64(0x1e400+i*1024)
		pointer(module+200, symtab)
		pointer(module+208, strtab)
		word(module+216, 2)
		clear(data[symtab : symtab+64])
		clear(data[strtab : strtab+1024])
		copy(data[strtab+1:], []string{"module_entry", "sys_entry"}[i])
		if table.PointerSize() == 8 {
			word(symtab+24, 1)
			put(symtab+32, uint64(0x10100+i*0x2000))
		} else {
			word(symtab+16, 1)
			word(symtab+20, uint64(0x10100+i*0x2000))
		}
	}
	switch variant {
	case "kallsyms-pointer", "kallsyms-embedded":
		kref := symbols.TypeRef{Kind: "struct", Name: "mod_kallsyms"}
		table.Types["mod_kallsyms"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"symtab": field(0, ptr), "strtab": field(8, ptr), "num_symtab": field(16, u32)}}
		for _, m := range []uint64{0xc000, 0xc400} {
			if variant == "kallsyms-pointer" {
				ref := symbols.TypeRef{Kind: "pointer", Subtype: &kref}
				table.Types["module"].Fields["kallsyms"] = field(232, ref)
				pointer(m+232, m+200)
			} else {
				table.Types["module"].Fields["kallsyms"] = field(200, kref)
			}
		}
	case "signal-threads":
		delete(task.Fields, "thread_group")
		task.Fields["signal"] = field(96, ptr)
		task.Fields["thread_node"] = field(104, symbols.TypeRef{Kind: "struct", Name: "list_head"})
		table.Types["signal_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"thread_head": field(0, symbols.TypeRef{Kind: "struct", Name: "list_head"})}}
		pointer(0xa060, 0x1bf00)
		pointer(0xa460, 0x1bf00)
		pointer(0xb060, 0x1bf40)
		list(0x1bf00, 0xa068, 0xa468)
		list(0xa068, 0xa468, 0x1bf00)
		list(0xa468, 0x1bf00, 0xa068)
		list(0x1bf40, 0xb068, 0xb068)
		list(0xb068, 0x1bf40, 0x1bf40)
	case "user-task":
		word(0xb050, 0)
	case "null-private":
		pointer(0xb098, 0)
	case "bad-private":
		pointer(0xb098, 0x300000)
	case "null-handler":
		pointer(0x17200, 0)
	case "bad-handler":
		pointer(0x17200, 0x300000)
	case "unknown-module":
		pointer(0x17200, 0x16400)
	case "interior-symbol":
		pointer(0x17200, 0x12101)
	case "bad-full-name":
		pointer(0x17208, 0x300000)
	case "empty-full-name":
		clear(data[0x18a00:0x18aff])
	case "bad-symbols":
		pointer(0xc4d0, 0x300000)
	case "bad-thread-list":
		pointer(0xa460, 0x300000)
	case "bad-kernel-bounds":
		table.Symbols["_etext"] = symbols.Symbol{Address: 0x8300}
	case "missing-kernel-bounds":
		delete(table.Symbols, "_text")
	case "unsupported":
		delete(table.Types["kthread"].Fields, "threadfn")
	}
	table.Types["task_struct"] = task
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

func TestLinuxKthreadsLayoutsAndAttribution(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-kthreads-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Generators []struct {
			Name string
			Rows []struct {
				Tid, Handler        uint64
				Name                string
				Module, Symbol      *string
				SelectedOwnerSymbol *string `json:"selected_owner_symbol"`
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Generators) != 16 {
		t.Fatal(err)
	}

	for _, arch := range []string{"control", "x86", "pae"} {
		for _, variant := range []string{"worker-private", "set-child-tid", "kallsyms-pointer", "kallsyms-embedded", "signal-threads", "full-name", "bad-full-name", "empty-full-name", "user-task", "null-private", "null-handler", "unknown-module", "interior-symbol"} {
			t.Run(arch+"/"+variant, func(t *testing.T) {
				e := openModx(t, kthreadFixture(t, arch, variant), arch)
				var rows []evidence.Row
				captures, records := 0, 0
				result, err := e.Run(context.Background(), "linux.kthreads", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
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
					if r.Cells["RecordType"].String() == "kthread" {
						rows = append(rows, r)
					}
					return nil
				}})
				count := 3
				if variant == "user-task" || variant == "null-private" || variant == "null-handler" {
					count = 2
				}
				if err != nil || result.Task.State != "completed" || len(rows) != count {
					t.Fatal(result, err, len(rows))
				}
				found := false
				for _, profile := range oracle.Generators {
					if profile.Name != variant {
						continue
					}
					found = true
					if len(profile.Rows) != len(rows) {
						t.Fatal(profile, len(rows))
					}
					for i, want := range profile.Rows {
						r := rows[i]
						tid, _ := r.Cells["TID"].Uint()
						handler, _ := r.Cells["Handler Address"].Uint()
						if tid != want.Tid || handler != want.Handler || r.Cells["Thread Name"].String() != want.Name {
							t.Fatal(profile.Name, want, tid, handler, r.Cells["Thread Name"])
						}
						for _, v := range []struct {
							key  string
							want *string
						}{{"Module", want.Module}, {"Symbol", want.SelectedOwnerSymbol}} {
							if v.want == nil {
								if r.Cells[v.key].Reason != "not_available" {
									t.Fatal(r)
								}
							} else if r.Cells[v.key].String() != *v.want {
								t.Fatal(want, r.Cells[v.key])
							}
						}
					}
				}
				if !found {
					t.Fatal("missing pinned generator profile", variant)
				}

				for i, r := range rows {
					if err := r.Verify(); err != nil {
						t.Fatal(err)
					}
					module, symbol := []string{"__kernel__", "active", "sys-only"}[i], []string{"a_entry", "module_entry", "sys_entry"}[i]
					if i == 2 && variant == "unknown-module" {
						module, symbol = "<not_available>", "<not_available>"
					}
					if i == 2 && variant == "interior-symbol" {
						symbol = "<not_available>"
					}
					if r.Cells["Module"].String() != module || r.Cells["Symbol"].String() != symbol {
						t.Fatal(i, r.Cells["Module"], r.Cells["Symbol"])
					}
					if variant == "full-name" && r.Cells["Thread Name"].String() != []string{"full-kernel", "full-module", "full-sys"}[i] {
						t.Fatal(r)
					}
					if variant == "bad-full-name" && i == 2 && r.Cells["NameSource"].String() != "task.comm" {
						t.Fatal(r)
					}
					if variant == "empty-full-name" && i == 2 && r.Cells["Thread Name"].String() != "" {
						t.Fatal(r)
					}
				}
				cached, err := e.Run(context.Background(), "linux.kthreads", nil, engine.RunOptions{})
				if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
					t.Fatal(cached, err)
				}
				stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
				if err != nil || len(stored) != records {
					t.Fatal(err, len(stored), records)
				}
				for _, r := range stored {
					if err := r.Verify(); err != nil {
						t.Fatal(err)
					}
				}
				if arch == "control" && variant == "worker-private" {
					bundle, err := report.Export(context.Background(), e.Store, "bundle", "kthreads.zip", result.Task.ID)
					if err != nil {
						t.Fatal(err)
					}
					verified, err := exec.Command("python3", filepath.Join("..", "..", "tools", "verify_bundle.py"), bundle).CombinedOutput()
					if err != nil {
						t.Fatal(string(verified), err)
					}
					raw, err := os.ReadFile(bundle)
					if err != nil {
						t.Fatal(err)
					}
					first, err := report.Export(context.Background(), e.Store, "jsonl", "fresh.jsonl", result.Task.ID)
					if err != nil {
						t.Fatal(err)
					}
					second, err := report.Export(context.Background(), e.Store, "jsonl", "cached.jsonl", cached.Task.ID)
					if err != nil {
						t.Fatal(err)
					}
					a, err := os.ReadFile(first)
					if err != nil {
						t.Fatal(err)
					}
					b, err := os.ReadFile(second)
					if err != nil || !bytes.Equal(bytes.Join(bytes.Split(a, []byte("\n"))[1:], []byte("\n")), bytes.Join(bytes.Split(b, []byte("\n"))[1:], []byte("\n"))) {
						t.Fatal("cache export mismatch", err)
					}
					t.Logf("synthetic bundle verification=%s sha256=%x; exported fresh/cache evidence records byte-identical (manifest timestamps excluded)", bytes.TrimSpace(verified), sha256.Sum256(raw))
				}
				t.Logf("records=%d selected=%d independently_reread_captures=%d; pinned TID/name/handler/module and selected-owner symbol helper verified; sealed rows and cache reused", records, len(rows), captures)

			})
		}
	}
}

func TestLinuxKthreadsFailuresAndCancellation(t *testing.T) {
	for _, variant := range []string{"bad-private", "bad-handler", "bad-symbols", "bad-thread-list", "missing-kernel-bounds", "bad-kernel-bounds", "unsupported"} {
		t.Run(variant, func(t *testing.T) {
			e := openModx(t, kthreadFixture(t, "control", variant), "control")
			result, err := e.Run(context.Background(), "linux.kthreads", nil, engine.RunOptions{})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			if variant == "unsupported" && !strings.Contains(err.Error(), "Linux >= 5.8") {
				t.Fatal(err)
			}
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil || (variant != "unsupported" && len(rows) == 0) {
				t.Fatal(err, len(rows))
			}
			for _, r := range rows {
				if err := r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, p := range []map[string]string{{"max-tasks": "1"}, {"max-tasks": "0"}, {"max-tasks": "1000001"}, {"max-nodes": "1"}, {"max-scan-bytes": "1"}} {
		e := openModx(t, kthreadFixture(t, "control", "worker-private"), "control")
		if _, err := e.Run(context.Background(), "linux.kthreads", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	for _, cancelled := range []bool{false, true} {
		e := openModx(t, kthreadFixture(t, "control", "worker-private"), "control")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sentinel := errors.New("stop emitting")
		count := 0
		_, err := e.Run(ctx, "linux.kthreads", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
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
