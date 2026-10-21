package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type callStackRow struct {
	TID                      uint64
	Comm                     string
	Position, Address, Value uint64
	Name, Type, Module       *string
}
type callStackCase struct {
	Width             int
	Threads, Scenario string
	ISF               json.RawMessage
	Writes            [][]json.RawMessage
	Profiles          []struct {
		Unresolved bool
		PIDs       []uint64
		Rows       []callStackRow
		Error      *struct{ Class, Message string }
		Tasks      []struct {
			TID   uint64
			Rows  []callStackRow
			Error *struct{ Class, Message string }
		}
	}
}

func callStackCases(t testing.TB) []callStackCase {
	t.Helper()
	data, err := os.ReadFile("testdata/linux-pscallstack-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []callStackCase
	}
	if err = json.Unmarshal(data, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 44 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func callStackEngine(t *testing.T, c callStackCase, arch string) *engine.Engine {
	t.Helper()
	data := make([]byte, 0x80000)
	for _, w := range c.Writes {
		var at int
		var s string
		if err := json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w[1], &s); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	if arch == "pae" {
		clear(data[0x70000:0x75000])
		binary.LittleEndian.PutUint64(data[0x70000:], 0x72003)
		binary.LittleEndian.PutUint64(data[0x72000:], 0x73003)
		for page := 0; page < 0x80; page++ {
			if c.Scenario == "read-hole" && page == 0x43 {
				continue
			}
			binary.LittleEndian.PutUint64(data[0x73000+page*8:], uint64(page*4096|3))
		}
	}
	if arch == "pae" && c.Scenario == "user-space" {
		clear(data[0x74000:0x78000])
		binary.LittleEndian.PutUint64(data[0x74000:], 0x75003)
		binary.LittleEndian.PutUint64(data[0x75000:], 0x77003)
		for page := 0; page < 0x80; page++ {
			physical := page
			if page >= 0x40 && page < 0x4c {
				physical += 0x10
			}
			binary.LittleEndian.PutUint64(data[0x77000+page*8:], uint64(physical*4096|3))
		}
	}

	dir := t.TempDir()
	image, syms := filepath.Join(dir, "image.raw"), filepath.Join(dir, "kernel.json")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(syms, c.ISF, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: syms, DTB: "0x70000", Arch: arch, OS: "linux", CaseDir: filepath.Join(dir, "case"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func callStackSelected(r evidence.Row) callStackRow {
	text := func(k string) *string {
		if r.Cells[k].Kind == "missing" {
			return nil
		}
		s := r.Cells[k].String()
		return &s
	}
	v := callStackRow{Comm: r.Cells["Comm"].String(), Name: text("Name"), Type: text("Type"), Module: text("Module")}
	v.TID, _ = r.Cells["TID"].Uint()
	v.Position, _ = r.Cells["Position"].Uint()
	v.Address, _ = r.Cells["Address"].Uint()
	v.Value, _ = r.Cells["Value"].Uint()
	return v
}
func TestLinuxPsCallStackPinnedPagingEvidenceAndCache(t *testing.T) {
	for _, c := range callStackCases(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Threads, c.Scenario), func(t *testing.T) {
				e := callStackEngine(t, c, arch)
				for _, p := range c.Profiles {
					params := map[string]string{"unresolved": strconv.FormatBool(p.Unresolved)}
					if p.PIDs != nil {
						tokens := []string{}
						for _, pid := range p.PIDs {
							tokens = append(tokens, strconv.FormatUint(pid, 10))
						}
						params["pid"] = strings.Join(tokens, ",")
					}
					var got []callStackRow
					want := []callStackRow(nil)
					failure := false
					for _, task := range p.Tasks {
						want = append(want, task.Rows...)
						failure = failure || task.Error != nil || ((c.Scenario == "read-hole" || c.Scenario == "no-mm") && task.TID == 100)
					}
					// With no error, the independent per-task continuation must equal the actual generator.
					if p.Error == nil && !(len(want) == 0 && len(p.Rows) == 0) && !reflect.DeepEqual(want, p.Rows) {
						t.Fatal("generator/per-task disagreement", want, p.Rows)
					}
					var fresh, cached bytes.Buffer
					reads, summaries := 0, 0
					result, err := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{Emit: func(row evidence.Row) error {
						switch row.Cells["RecordType"].String() {
						case "stack_entry":
							got = append(got, callStackSelected(row))
						case "stack_read":
							reads++
							proof := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
							at, _ := proof["Address"].Uint()
							requested, _ := proof["RequestedBytes"].Uint()
							raw := proof["Raw"].Data.([]byte)
							controlAt := at
							if strings.HasPrefix(row.Provenance.Layer, "process:") && c.Scenario == "user-space" {
								if at < 0x40000 || at >= 0x4c000 {
									t.Fatal("unexpected process read", at)
								}
								controlAt += 0x10000
							}
							control, cause := memory.Read(context.Background(), e.Env.Kernel, controlAt, int(requested))
							if !bytes.Equal(raw, control) || (cause == nil) != (proof["ReadComplete"].Data == true) {
								t.Fatal("independent acquisition mismatch", at, cause)
							}
						case "stack_summary":
							summaries++
						case "diagnostic", "stack_error", "task_stack_summary":
						default:
							t.Fatal(row)
						}
						return json.NewEncoder(&fresh).Encode(row)
					}})
					if (err != nil) != failure || !reflect.DeepEqual(got, want) || summaries != 1 || reads == 0 {
						g, _ := json.Marshal(got)
						w, _ := json.Marshal(want)
						t.Fatalf("unresolved=%v pids=%v error=%v expectedFailure=%v state=%s reads=%d summaries=%d\ngot %s\nwant %s", p.Unresolved, p.PIDs, err, failure, result.Task.State, reads, summaries, g, w)
					}
					for offset := 0; offset < int(result.Task.Rows); {
						rows, er := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
						if er != nil || len(rows) == 0 {
							t.Fatal(er)
						}
						for _, row := range rows {
							if er := row.Verify(); er != nil {
								t.Fatal(er)
							}
						}
						offset += len(rows)
					}
					again, er := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
					if failure {
						if er == nil || again.Reused {
							t.Fatal("failed result replayed", again, er)
						}
					} else if er != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
						t.Fatal("cache mismatch", again, er)
					}
				}
			})
		}
	}
}

type callStackFaultLayer struct {
	memory.MemoryLayer
	calls, fail, cancelAt int
	cancel                context.CancelFunc
}

func (l *callStackFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.calls++
	if l.calls == l.fail {
		return 0, memory.ErrUnmapped
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if l.calls == l.cancelAt {
		l.cancel()
	}
	return n, err
}
func callStackNormal(t testing.TB) callStackCase {
	for _, c := range callStackCases(t) {
		if c.Width == 8 && c.Threads == "legacy" && c.Scenario == "normal" {
			return c
		}
	}
	t.Fatal("missing control")
	return callStackCase{}
}
func TestLinuxPsCallStackEveryAcquisitionAndOutputBoundary(t *testing.T) {
	e := callStackEngine(t, callStackNormal(t), "x64")
	if _, err := e.Run(context.Background(), "linux.pscallstack", nil, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	p, err := e.Registry.Get("linux.pscallstack")
	if err != nil {
		t.Fatal(err)
	}
	params, err := plugin.Parameters(p.Spec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	env := e.Env
	layer := &callStackFaultLayer{MemoryLayer: env.Kernel}
	env.Kernel = layer
	rows := 0
	expected := []callStackRow(nil)
	if err := p.Run(context.Background(), env, params, func(row evidence.Row) error {
		rows++
		if row.Cells["RecordType"].String() == "stack_entry" {
			expected = append(expected, callStackSelected(row))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reads := layer.calls
	for boundary := 1; boundary <= reads; boundary++ {
		for _, inside := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			layer.calls = 0
			layer.fail = 0
			layer.cancelAt = 0
			layer.cancel = cancel
			if inside {
				layer.cancelAt = boundary
			} else {
				layer.fail = boundary
			}
			err := p.Run(ctx, env, params, func(evidence.Row) error { return nil })
			cancel()
			if err == nil {
				t.Fatal("read/cancel became clean", boundary, inside)
			}
			if inside && !errors.Is(err, context.Canceled) {
				t.Fatal(boundary, err)
			}
			layer.calls = 0
			layer.fail = 0
			layer.cancelAt = 0
			got := []callStackRow(nil)
			if err := p.Run(context.Background(), env, params, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "stack_entry" {
					got = append(got, callStackSelected(row))
				}
				return nil
			}); err != nil || !reflect.DeepEqual(got, expected) {
				t.Fatal("retry", boundary, inside, err)
			}
		}
	}
	marker := errors.New("callstack consumer stopped")
	for boundary := 1; boundary <= rows; boundary++ {
		count := 0
		err := p.Run(context.Background(), env, params, func(evidence.Row) error {
			count++
			if count == boundary {
				return marker
			}
			return nil
		})
		if !errors.Is(err, marker) || count != boundary {
			t.Fatal("output failure", boundary, count, err)
		}
	}
}
func TestLinuxPsCallStackLimitsAndInvalidLayouts(t *testing.T) {
	for _, fault := range []string{"max-tasks", "max-words", "max-nodes", "max-symbols", "max-bytes", "missing-stack", "bad-files", "bad-thread", "stack-overflow", "thread-cycle", "missing-flags", "mm-root-hole"} {
		t.Run(fault, func(t *testing.T) {
			c := callStackNormal(t)
			params := map[string]string{}
			switch fault {
			case "max-tasks", "max-words", "max-nodes", "max-symbols", "max-bytes":
				params[fault] = "1"
			case "missing-stack", "bad-files", "bad-thread", "missing-flags":
				var table map[string]any
				if err := json.Unmarshal(c.ISF, &table); err != nil {
					t.Fatal(err)
				}
				types := table["user_types"].(map[string]any)
				fields := types["task_struct"].(map[string]any)["fields"].(map[string]any)
				switch fault {
				case "missing-stack":
					delete(fields, "stack")
				case "missing-flags":
					delete(fields, "flags")
				case "bad-files":
					fields["files"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "u32"}
				case "bad-thread":
					fields["thread"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "thread_struct"}}
				}
				c.ISF, _ = json.Marshal(table)
			default:
				var at, value uint64
				switch fault {
				case "stack-overflow":
					at, value = 0x30050, 0xfffffffffffffff0
				case "thread-cycle":
					at, value = 0x30440, 0x30440
				case "mm-root-hole":
					at, value = 0x30030, 0xdead000
				}
				if fault == "mm-root-hole" {
					a, _ := json.Marshal(0x30028)
					b, _ := json.Marshal("00000000")
					c.Writes = append(c.Writes, []json.RawMessage{a, b})
				}
				a, _ := json.Marshal(at)
				raw := make([]byte, 8)
				binary.LittleEndian.PutUint64(raw, value)
				b, _ := json.Marshal(hex.EncodeToString(raw))
				c.Writes = append(c.Writes, []json.RawMessage{a, b})
			}
			e := callStackEngine(t, c, "x64")
			result, err := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			next, err := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{})
			if err == nil || next.Reused {
				t.Fatal(next, err)
			}
		})
	}
}
