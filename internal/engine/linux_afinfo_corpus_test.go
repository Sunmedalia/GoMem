package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxAFInfo(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian AFINFO negative/inspection differential; not complete acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift", e.Hash)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-afinfo-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Global           string `json:"Symbol Name"`
		Member           string
		Address          uint64 `json:"Handler Address"`
		OperationAddress uint64
		Status           string
		ExactSymbols     []string
	}
	if err = json.Unmarshal(raw, &expected); err != nil || len(expected) != 180 {
		t.Fatal(err, len(expected))
	}
	result, err := e.Run(ctx, "linux.check_afinfo", nil, engine.RunOptions{})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
	if err != nil || len(rows) != 199 {
		t.Fatal(err, len(rows))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	entities, captures, observations, aliases := 0, 0, 0, 0
	for _, r := range rows {
		if err := r.Verify(); err != nil {
			t.Fatal(err)
		}
		if err := encoder.Encode(r); err != nil {
			t.Fatal(err)
		}
		if r.Cells["Error"].Reason != "not_applicable" {
			t.Fatal(r.Cells["Error"])
		}
		switch r.Cells["RecordType"].String() {
		case "handler":
			entities++
			fallthrough
		case "member_observation":
			if observations >= len(expected) {
				t.Fatal("extra member")
			}
			want := expected[observations]
			observations++
			at, _ := r.Cells["Handler Address"].Uint()
			base, _ := r.Cells["OperationAddress"].Uint()
			if r.Cells["Symbol Name"].String() != want.Global || r.Cells["Member"].String() != want.Member || at&0xffffffffffff != want.Address || base&0xffffffffffff != want.OperationAddress || r.Cells["Status"].String() != want.Status {
				t.Fatal(want, r.Cells["Symbol Name"], r.Cells["Member"], at, base, r.Cells["Status"])
			}
			if r.Cells["LookupMode"].String() != "absolute_exact" {
				t.Fatal(r.Cells["LookupMode"])
			}
			if want.Address != 0 {
				proof := r.Cells["ExactSymbols"].Data.(map[string]any)
				var names []string
				for _, n := range proof["Names"].([]any) {
					names = append(names, n.(string))
				}
				sort.Strings(want.ExactSymbols)
				if !reflect.DeepEqual(names, want.ExactSymbols) {
					t.Fatal(names, want.ExactSymbols)
				}
				aliases++
			}
		case "summary":
			coverage := r.Cells["Coverage"].Data.(map[string]any)
			for k, v := range map[string]string{"layout": "pre_4_18", "globals_present": "6", "globals_absent": "0", "member_visits": "180", "checked_nonzero_or_seq_show": "48", "flagged_handlers": "0", "unimplemented_zero": "132", "diagnostics": "0", "read_layout_errors": "0"} {
				if coverage[k] != v {
					t.Fatal(k, coverage)
				}
			}
		case "symbol_observation", "container_observation":
		default:
			t.Fatal("unexpected record", r.Cells["RecordType"])
		}
		if r.Cells["FieldEvidence"].Kind == "structure" {
			encoded, err := json.Marshal(r.Cells["FieldEvidence"])
			if err != nil {
				t.Fatal(err)
			}
			var fields struct {
				Value map[string]struct{ Value map[string]evidence.Value }
			}
			if err = json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			for key, proof := range fields.Value {
				c := proof.Value
				if c["Raw"].Kind != "bytes" {
					continue
				}
				at, err := c["Address"].Uint()
				if err != nil {
					t.Fatal(key, err)
				}
				raw, err := base64.StdEncoding.DecodeString(c["Raw"].Data.(string))
				if err != nil {
					t.Fatal(key, err)
				}
				actual, err := memory.Read(ctx, e.Env.Kernel, at, len(raw))
				if err != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
					t.Fatal(key, err)
				}
				captures++
			}
		}
	}
	if entities != 0 || observations != 180 || captures != 192 || aliases != 48 {
		t.Fatal(entities, observations, captures, aliases)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []struct{ reference, mapping string }{{"reference-linux-afinfo.json", "linux.check_afinfo.json"}, {"reference-linux-afinfo-observations.json", "linux.afinfo-observations.json"}} {
		output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, profile.reference), "--mapping", filepath.Join("..", "..", "docs", "diff", profile.mapping)).CombinedOutput()
		if err != nil {
			t.Fatal(string(output), err)
		}
	}
	cached, err := e.Run(ctx, "linux.check_afinfo", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	t.Log("0 flagged handlers match unmodified reference; all 180 member checks, statuses, coordinates, exact symbol lists and order match delegated reference observations; 192 raw captures reread; sealed rows and cache reused")
}
