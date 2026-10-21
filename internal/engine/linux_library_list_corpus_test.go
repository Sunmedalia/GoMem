package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxLibraryListDifferentialAndRawCaptures(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_LIBRARY_LIST_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned reference prefix; skipped test is not acceptance")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline struct{ Commit string }
		Image    string `json:"image_sha256"`
		Output   string `json:"output_sha256"`
		Plugin   string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.library_list" {
		t.Fatal(manifest, err)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != manifest.Output {
		t.Fatal("reference digest mismatch")
	}
	var reference []struct {
		Name, Path       string
		Pid, LoadAddress uint64
	}
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 2673 {
		t.Fatal(err, len(reference))
	}
	key := func(name string, pid, load uint64, path string) string {
		return fmt.Sprintf("%s:%d:%x:%s", name, pid, load, path)
	}
	expected := map[string]int{}
	for _, r := range reference {
		expected[key(r.Name, r.Pid, r.LoadAddress, r.Path)]++
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	spaces := map[uint64]memory.MemoryLayer{}
	var fresh, again bytes.Buffer
	libraries, scans, nameErrors, incomplete, userCaptures, kernelCaptures := 0, 0, 0, 0, 0, 0
	result, err := e.Run(ctx, "linux.library_list", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		fields := bashProofFields(t, row.Cells["FieldEvidence"])
		switch row.Cells["RecordType"].String() {
		case "library_scan":
			scans++
			if row.Cells["Error"].Error != "" {
				incomplete++
			}
		case "library_error":
			nameErrors++
			if row.Cells["Error"].Error == "" {
				t.Fatal("diagnostic lacks error")
			}
		case "library":
			libraries++
			pid, _ := row.Cells["Pid"].Uint()
			load, _ := row.Cells["LoadAddress"].Uint()
			k := key(row.Cells["Name"].String(), pid, load, row.Cells["Path"].String())
			expected[k]--
			if expected[k] < 0 {
				t.Fatal("unexpected native library", k)
			}
			task, _ := row.Cells["ProcessOffset"].Uint()
			space := spaces[task]
			if space == nil {
				mm, err := e.Env.Objects.Uint(ctx, task, "task_struct", "mm")
				if err != nil {
					t.Fatal(err)
				}
				pgd, err := e.Env.Objects.Uint(ctx, mm, "mm_struct", "pgd")
				if err != nil {
					t.Fatal(err)
				}
				backing, err := e.Env.Kernel.(*memory.Virtual).Translator.Translate(ctx, pgd)
				if err != nil {
					t.Fatal(err)
				}
				translator, err := memory.NewIntel(e.Env.Physical, backing.Physical, "x64", 8)
				if err != nil {
					t.Fatal(err)
				}
				space = &memory.Virtual{ID: "independent-library-read", Physical: e.Env.Physical, Translator: translator}
				spaces[task] = space
			}
			for _, name := range []string{"Header", "ProgramHeader", "Dynamic", "GOT", "LinkMap", "Name"} {
				capture := bashProofFields(t, fields[name])
				at, _ := capture["Address"].Uint()
				raw := malfindBytes(t, capture["Raw"])
				original, err := memory.Read(ctx, space, at, len(raw))
				if err != nil || !bytes.Equal(raw, original) {
					t.Fatal("user capture differs", name, err)
				}
				userCaptures++
			}
			kernelCaptures += verifyModuleParameterWireCaptures(t, e, fields["Process"])
			kernelCaptures += verifyModuleParameterWireCaptures(t, e, fields["VMA"])
			created := row.Cells["Created"]
			stamp := ""
			if created.Kind != "missing" {
				stamp = created.String()
			}
			if row.Cells["ProcessIdentity"].String() != evidence.ProcessID(e.Hash, e.Env.Kernel.Name(), task, pid, stamp) {
				t.Fatal("identity lost process coordinates")
			}
		default:
			t.Fatal("unknown record", row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err == nil || result.Task.State != "failed" || libraries != 2673 || scans != 14045 || nameErrors != 29 || incomplete == 0 || userCaptures != 16038 || kernelCaptures != 8019 {
		t.Fatal(result, err, libraries, scans, nameErrors, incomplete, userCaptures, kernelCaptures)
	}
	for k, count := range expected {
		if count != 0 {
			t.Fatal("missing native library", k, count)
		}
	}
	rerun, err := e.Run(ctx, "linux.library_list", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&again).Encode(row) }})
	if err == nil || rerun.Reused || !reflect.DeepEqual(fresh.Bytes(), again.Bytes()) {
		t.Fatal("failed source was cached or changed", rerun, err)
	}
	t.Logf("%d libraries match four pinned fields; %d VMA scans (%d incomplete), %d name failures; %d process and %d kernel captures independently reread", libraries, scans, incomplete, nameErrors, userCaptures, kernelCaptures)
}
