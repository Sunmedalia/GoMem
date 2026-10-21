package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// A deterministic read-fault queue exercises the fixed generator's per-task
// is_readable skips, even if the next task points to the same credential.
type credentialReadFaults struct {
	memory.MemoryLayer
	reads map[uint64][]bool
}

func (l *credentialReadFaults) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	if len(p) == 16 && len(l.reads[address]) > 0 {
		readable := l.reads[address][0]
		l.reads[address] = l.reads[address][1:]
		if !readable {
			return 0, fmt.Errorf("injected unreadable credential")
		}
	}
	return l.MemoryLayer.ReadAt(ctx, p, address)
}

func TestLinuxCheckCredsPinnedGenerator(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-check-creds-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name  string
			Tasks []struct {
				PID      uint64
				Cred     string
				Readable bool
			}
			Rows []struct{ CredVAddr, PIDs string }
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 9 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), "linux")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
			slots := []uint64{0xa000, 0xb000, 0x1e000, 0x1e200}
			head := uint64(0x9000)
			chain := append([]uint64{head}, slots[:len(tc.Tasks)]...)
			for i, a := range chain {
				put(a, chain[(i+1)%len(chain)])
				put(a+8, chain[(i+len(chain)-1)%len(chain)])
			}
			reads := map[uint64][]bool{}
			diagnostics := 0
			for i, task := range tc.Tasks {
				address, err := strconv.ParseUint(task.Cred, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				put(slots[i]+72, address)
				binary.LittleEndian.PutUint32(data[slots[i]+16:], uint32(task.PID))
				put(slots[i]+48, uint64(i+1))
				reads[address] = append(reads[address], task.Readable)
				if address == 0 || !task.Readable {
					diagnostics++
				}
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e := openPsaux(t, f)
			layer := &credentialReadFaults{MemoryLayer: e.Env.Kernel, reads: reads}
			e.Env.Kernel = layer
			e.Env.Objects = &object.Reader{Layer: layer, Symbols: e.Env.Symbols}
			var rows []evidence.Row
			ctx := context.Background()
			result, err := e.Run(ctx, "linux.check_creds", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if (diagnostics > 0) != (err != nil) {
				t.Fatal(result, err)
			}
			if len(rows) != len(tc.Tasks)+len(tc.Rows)+1 {
				t.Fatal(len(rows), rows)
			}
			observations := map[uint64]string{}
			for i := range tc.Tasks {
				r := rows[i]
				address, _ := r.Cells["ProcessOffset"].Uint()
				observations[address] = r.Cells["ProcessIdentity"].String()
				if r.Cells["RecordType"].String() == "process" && len(r.Cells["CredRaw"].Data.([]byte)) != 16 {
					t.Fatal(r)
				}
				if len(r.Cells["CredPointerRaw"].Data.([]byte)) != 8 {
					t.Fatal(r)
				}
			}
			for i, want := range tc.Rows {
				r := rows[len(tc.Tasks)+i]
				address, _ := r.Cells["CredVAddr"].Uint()
				expected, _ := strconv.ParseUint(want.CredVAddr, 0, 64)
				if r.Cells["RecordType"].String() != "shared" || address != expected || r.Cells["PIDs"].String() != want.PIDs || r.Provenance.Offset != fmt.Sprintf("0x%x", address) {
					t.Fatal(r, want)
				}
				members := r.Cells["Members"].Data.([]map[string]evidence.Value)
				if len(members) < 2 {
					t.Fatal(r)
				}
				seen := map[string]bool{}
				for _, m := range members {
					task, _ := m["ProcessOffset"].Uint()
					id := m["ProcessIdentity"].String()
					if id == "" || observations[task] != id || seen[id] {
						t.Fatal(m)
					}
					seen[id] = true
				}
			}
			summary := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
			if summary["processes"] != fmt.Sprint(len(tc.Tasks)) || summary["shared_groups"] != fmt.Sprint(len(tc.Rows)) || summary["diagnostics"] != fmt.Sprint(diagnostics) {
				t.Fatal(summary)
			}
			saved, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(saved) != len(rows) {
				t.Fatal(saved, err)
			}
			for _, r := range saved {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if diagnostics == 0 {
				again, err := e.Run(ctx, "linux.check_creds", nil, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}

func TestLinuxCheckCredsLayoutsAndFailures(t *testing.T) {
	for _, scenario := range []string{"missing-cred", "bad-pointer-type", "zero-cred", "huge-cred", "partial-cred", "pid-fault", "shared-x86", "shared-pae"} {
		t.Run(scenario, func(t *testing.T) {
			mode := "x64"
			f, err := testfixture.Write(t.TempDir(), "linux")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "shared-x86" || scenario == "shared-pae" {
				if scenario == "shared-x86" {
					mode = "x86"
				} else {
					mode = "pae"
				}
				f = linuxCapabilityFixture(t, mode)
			}
			table, err := symbols.Load(f.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			task, cred := table.Types["task_struct"], table.Types["cred"]
			switch scenario {
			case "missing-cred":
				delete(task.Fields, "cred")
			case "bad-pointer-type":
				field := task.Fields["cred"]
				field.Type = symbols.TypeRef{Kind: "base", Name: "u64"}
				task.Fields["cred"] = field
			case "zero-cred":
				cred.Size = 0
				cred.Fields = map[string]symbols.Field{}
			case "huge-cred":
				cred.Size = 65537
			case "partial-cred":
				binary.LittleEndian.PutUint64(data[0xa048:], 0x1fffc)
			case "pid-fault":
				delete(task.Fields, "pid")
			case "shared-x86", "shared-pae":
				binary.LittleEndian.PutUint64(data[0xb048:], 0x1c800)
			}
			table.Types["task_struct"], table.Types["cred"] = task, cred
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
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.check_creds", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			valid := scenario == "shared-x86" || scenario == "shared-pae"
			if valid != (err == nil) {
				t.Fatal(result, err)
			}
			if valid && (len(rows) != 4 || rows[2].Cells["PIDs"].String() != "100, 101") {
				t.Fatal(rows)
			}
			if scenario == "partial-cred" && (len(rows) != 3 || rows[0].Cells["RecordType"].String() != "diagnostic" || len(rows[0].Cells["CredRaw"].Data.([]byte)) != 4) {
				t.Fatal(rows)
			}
		})
	}
	e := openPsaux(t, linuxCapabilityFixture(t, "control"))
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-nodes": "1"}, {"pid": "100"}} {
		if _, err := e.Run(context.Background(), "linux.check_creds", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("output stopped")
	if _, err := e.Run(context.Background(), "linux.check_creds", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, "linux.check_creds", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
