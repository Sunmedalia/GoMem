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
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type ebpfOracleRow struct {
	Address         uint64
	Name, Tag, Type *string
}
type ebpfOracleCase struct {
	Width            int
	Layout, Metadata string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	NativeIDs        []uint64 `json:"native_ids"`
	Selected         []ebpfOracleRow
}

func loadEBPFOracle(t *testing.T) []ebpfOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-ebpf-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []ebpfOracleCase
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 96 {
		t.Fatal(err, len(oracle.Cases))
	}
	return oracle.Cases
}
func ebpfOracleEngine(t *testing.T, c ebpfOracleCase, arch, fault string) *engine.Engine {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range fragment.Bases {
		table.Bases[k] = v
	}
	for k, v := range fragment.Types {
		table.Types[k] = v
	}
	for k, v := range fragment.Symbols {
		table.Symbols[k] = v
	}
	table.Enums = fragment.Enums
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	clear(data[0x10000:0x18000])
	for _, write := range c.Writes {
		var at int
		var text string
		if err = json.Unmarshal(write[0], &at); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(write[1], &text); err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], b)
	}
	put := func(at, value uint64) {
		if c.Width == 4 {
			binary.LittleEndian.PutUint32(data[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[at:], value)
		}
	}
	switch fault {
	case "name-hole":
		put(0x14010, 0x300000)
	case "unknown-type":
		binary.LittleEndian.PutUint32(data[0x14000:], 99)
	case "cycle":
		put(0x11000, 2)
		put(0x11010, 0x11002)
	case "missing-root":
		delete(table.Symbols, "prog_idr")
	}
	raw, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func TestLinuxEBPFPinnedObjectsPagingRawCapturesAndCache(t *testing.T) {
	for _, c := range loadEBPFOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Metadata), func(t *testing.T) {
				e := ebpfOracleEngine(t, c, arch, "")
				var fresh, cached bytes.Buffer
				got := []ebpfOracleRow{}
				ids := []uint64{}
				reads, captures, summaries := 0, 0, 0
				optional := func(v evidence.Value) *string {
					if v.Kind == "missing" {
						return nil
					}
					s := v.String()
					return &s
				}
				result, err := e.Run(context.Background(), "linux.ebpf", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("unsealed row")
					}
					switch row.Cells["RecordType"].String() {
					case "ebpf_program":
						id, _ := row.Cells["ID"].Uint()
						ids = append(ids, id)
						captures += verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						if row.Cells["Selected"].Data == true {
							address, _ := row.Cells["Address"].Uint()
							got = append(got, ebpfOracleRow{address, optional(row.Cells["Name"]), optional(row.Cells["Tag"]), optional(row.Cells["Type"])})
						}
					case "idr_read":
						reads++
						captures += verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					case "idr_summary":
						summaries++
					default:
						t.Fatal(row)
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, c.Selected) || !reflect.DeepEqual(ids, c.NativeIDs) || reads == 0 || captures == 0 || summaries != 1 {
					t.Fatal(result, err, got, c.Selected, ids, c.NativeIDs)
				}
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
				if err != nil || len(rows) != int(result.Task.Rows) {
					t.Fatal(err, len(rows), result)
				}
				for _, row := range rows {
					if err = row.Verify(); err != nil {
						t.Fatal(err)
					}
				}
				again, err := e.Run(context.Background(), "linux.ebpf", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(again, err)
				}
			})
		}
	}
}
func TestLinuxEBPFIncompleteFieldsRetryAndUnsupportedKernel(t *testing.T) {
	c := loadEBPFOracle(t)[6] // xarray, modern metadata
	if c.Layout != "xarray" || c.Metadata != "modern" {
		t.Fatal(c.Layout, c.Metadata)
	}
	for _, fault := range []string{"name-hole", "unknown-type", "cycle", "missing-root"} {
		t.Run(fault, func(t *testing.T) {
			e := ebpfOracleEngine(t, c, "x86", fault)
			var fresh, again bytes.Buffer
			programs := 0
			opts := func(b *bytes.Buffer) engine.RunOptions {
				return engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "ebpf_program" {
						programs++
					}
					return json.NewEncoder(b).Encode(row)
				}}
			}
			result, err := e.Run(context.Background(), "linux.ebpf", nil, opts(&fresh))
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			if (fault == "name-hole" || fault == "unknown-type") && programs != 2 {
				t.Fatal("field error discarded another program", programs)
			}
			firstTaskID := result.Task.ID
			result, err = e.Run(context.Background(), "linux.ebpf", nil, opts(&again))
			if err == nil || result.Reused || result.Task.ID == firstTaskID || !bytes.Equal(fresh.Bytes(), again.Bytes()) {
				t.Fatal(result, err)
			}
		})
	}
}
func TestLinuxEBPFEngineCancellationAndLimits(t *testing.T) {
	c := loadEBPFOracle(t)[6]
	e := ebpfOracleEngine(t, c, "x86", "")
	ctx := context.Background()
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-programs": "1000001"}, {"max-programs": "1"}} {
		r, err := e.Run(ctx, "linux.ebpf", p, engine.RunOptions{})
		if err == nil || r.Task.State == "completed" {
			t.Fatal(r, err)
		}
	}
	stop := fmt.Errorf("output failed")
	calls := 0
	_, err := e.Run(ctx, "linux.ebpf", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return stop }})
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(ctx)
	calls = 0
	_, err = e.Run(ctx, "linux.ebpf", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}
