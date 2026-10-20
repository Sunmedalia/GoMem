package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxTaskFieldsAndThreads(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected legacy Linux task fields/threads; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("image drift", e.Hash)
	}
	for _, threads := range []bool{false, true} {
		name := "reference-linux-pslist.json"
		want := 133
		if threads {
			name = "reference-linux-pslist-threads.json"
			want = 316
		}
		file, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(file)
		decoder.UseNumber()
		var reference []map[string]any
		err = decoder.Decode(&reference)
		file.Close()
		if err != nil || len(reference) != want {
			t.Fatal("reference drift", len(reference), err)
		}
		groups := map[uint64]map[string]any{}
		for _, row := range reference {
			a, err := strconv.ParseUint(row["OFFSET (V)"].(json.Number).String(), 10, 64)
			if err != nil || groups[a] != nil {
				t.Fatal("duplicate or invalid reference address", err)
			}
			groups[a] = row
		}
		identities := map[string]string{}
		taskIDs := map[string]bool{}
		processes, userThreads, kernel := 0, 0, 0
		result, err := e.Run(ctx, "linux.pslist", map[string]string{"threads": strconv.FormatBool(threads), "decorate-comm": strconv.FormatBool(threads)}, engine.RunOptions{Emit: func(row evidence.Row) error {
			c := row.Cells
			a, err := c["Offset"].Uint()
			if err != nil {
				return err
			}
			ref := groups[a&0xffffffffffff]
			if ref == nil {
				return fmt.Errorf("unexpected task address")
			}
			delete(groups, a&0xffffffffffff)
			for _, pair := range [][2]string{{"PID", "PID"}, {"TID", "TID"}, {"PPID", "PPID"}, {"Name", "COMM"}, {"UID", "UID"}, {"GID", "GID"}, {"EUID", "EUID"}, {"EGID", "EGID"}} {
				if c[pair[0]].String() != fmt.Sprint(ref[pair[1]]) {
					return fmt.Errorf("task %s differs", pair[0])
				}
			}
			if c["RecordType"].String() == "task" {
				processes++
				identities[c["PID"].String()] = c["Identity"].String()
			} else if c["RecordType"].String() == "thread" {
				userThreads++
				if identities[c["PID"].String()] != c["Identity"].String() {
					return fmt.Errorf("thread process identity differs")
				}
			} else {
				return fmt.Errorf("unexpected diagnostic")
			}
			if taskIDs[c["TaskIdentity"].String()] || c["TaskIdentity"].String() == c["Identity"].String() {
				return fmt.Errorf("task identity reused or collapsed into process identity")
			}
			taskIDs[c["TaskIdentity"].String()] = true
			if c["IsKernelThread"].Data == true {
				kernel++
			}
			created, err := time.Parse(time.RFC3339Nano, c["Created"].String())
			if err != nil {
				return err
			}
			referenceTime, err := time.Parse(time.RFC3339Nano, ref["CREATION TIME"].(string))
			if err != nil {
				return err
			}
			// Explicit microsecond round-to-even comparison, never integer-second
			// truncation. The original nanosecond string remains unchanged.
			second, micro := created.Truncate(time.Second), created.Nanosecond()/1000
			remainder := created.Nanosecond() % 1000
			if remainder > 500 || remainder == 500 && micro%2 == 1 {
				micro++
			}
			if !second.Add(time.Duration(micro) * time.Microsecond).Equal(referenceTime) {
				return fmt.Errorf("creation time differs after declared precision rounding")
			}
			counter, err := c["CreationCounterNS"].Uint()
			if err != nil {
				return err
			}
			if c["CreationCounterField"].String() != "real_start_time" {
				return fmt.Errorf("wrong counter field selected")
			}
			boot, err := time.Parse(time.RFC3339Nano, c["BootTime"].String())
			if err != nil {
				return err
			}
			exact, err := time.Parse(time.RFC3339Nano, c["CreatedExact"].String())
			if err != nil {
				return err
			}
			asNS := func(v time.Time) *big.Int {
				n := new(big.Int).Mul(big.NewInt(v.Unix()), big.NewInt(1000000000))
				return n.Add(n, big.NewInt(int64(v.Nanosecond())))
			}
			if asNS(exact).Cmp(new(big.Int).Add(asNS(boot), new(big.Int).SetUint64(counter))) != 0 {
				return fmt.Errorf("exact clock evidence lost precision")
			}
			return row.Verify()
		}})
		wantThreads := 0
		if threads {
			wantThreads = 183
		}
		if err != nil || result.Task.Rows != int64(want) || len(groups) != 0 || processes != 133 || userThreads != wantThreads || kernel != 39 {
			t.Fatal(result, processes, userThreads, kernel, len(groups), err)
		}
	}
	for _, tc := range []struct {
		pid  string
		rows int64
	}{{"2652", 65}, {"2065", 0}, {"2652,3576", 92}} {
		r, err := e.Run(ctx, "linux.pslist", map[string]string{"threads": "true", "pid": tc.pid}, engine.RunOptions{})
		if err != nil || r.Task.Rows != tc.rows {
			t.Fatal(tc, r, err)
		}
	}
}
