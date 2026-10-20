package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func openFixture(t *testing.T, platform string) (*engine.Engine, testfixture.Fixture) {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), platform)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, CaseDir: t.TempDir(), Symbols: f.Symbols, OS: platform, DTB: f.DTB, Arch: "x64", KernelBase: f.KernelBase})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, f
}

func TestImageCannotAliasCaseOutputs(t *testing.T) {
	for _, name := range []string{"case.db", "case.db-wal", "case.db-shm", "case.db-journal", "case.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			image := filepath.Join(dir, name)
			before := []byte("read-only acquisition must survive")
			if err := os.WriteFile(image, before, 0600); err != nil {
				t.Fatal(err)
			}
			if e, err := engine.Open(context.Background(), engine.Config{Image: image, CaseDir: dir}); err == nil {
				e.Close()
				t.Fatal("accepted image/output alias")
			}
			after, _ := os.ReadFile(image)
			if string(after) != string(before) {
				t.Fatal("image modified")
			}
		})
	}
}
func TestChangedImageCannotReplayCache(t *testing.T) {
	e, f := openFixture(t, "linux")
	if _, err := e.Run(context.Background(), "generic.info", nil, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(f.Image, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), "generic.info", nil, engine.RunOptions{}); err == nil {
		t.Fatal("reused changed image")
	}
}

type blockingPlugin struct{ ready chan struct{} }

func (p blockingPlugin) Spec() plugin.Spec { return plugin.Spec{Name: "blocking"} }
func (p blockingPlugin) Run(ctx context.Context, _ plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := out(evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text("partial")}}); err != nil {
		return err
	}
	close(p.ready)
	<-ctx.Done()
	return ctx.Err()
}
func TestCloseWaitsForCanceledTaskCommit(t *testing.T) {
	e, _ := openFixture(t, "linux")
	ready := make(chan struct{})
	if err := e.Registry.Register(blockingPlugin{ready}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := e.Run(context.Background(), "blocking", nil, engine.RunOptions{}); done <- err }()
	<-ready
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s, err := store.Open(e.Config.CaseDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tasks, err := s.Tasks(context.Background())
	if err != nil || len(tasks) != 1 || tasks[0].State != "canceled" || tasks[0].Rows != 1 {
		t.Fatal(tasks, err)
	}
}
func TestNativeWindowsLinuxAndCache(t *testing.T) {
	for _, os := range []string{"windows", "linux"} {
		t.Run(os, func(t *testing.T) {
			e, _ := openFixture(t, os)
			var rows []evidence.Row
			result, err := e.Run(context.Background(), os+".pslist", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || result.Task.State != "completed" {
				t.Fatalf("rows=%d %+v", len(rows), result)
			}
			if rows[0].ID == "" || rows[0].Provenance.ImageSHA256 != e.Hash || rows[0].Provenance.SymbolsSHA256 == "" {
				t.Fatal("missing provenance")
			}
			pid, _ := rows[0].Cells["PID"].Uint()
			want := uint64(100)
			if os == "windows" {
				want = 4
			}
			if pid != want {
				t.Fatal(pid)
			}
			copy := rows[0]
			copy.Seal()
			if copy.ID != rows[0].ID {
				t.Fatal("non-deterministic evidence ID")
			}
			cached, err := e.Run(context.Background(), os+".pslist", nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			name := os + ".modules"
			if os == "linux" {
				name = "linux.lsmod"
			}
			mod, err := e.Run(context.Background(), name, nil, engine.RunOptions{})
			if err != nil || mod.Task.Rows != 1 {
				t.Fatal(mod, err)
			}
			filtered, err := e.Run(context.Background(), os+".pslist", map[string]string{"pid": "999"}, engine.RunOptions{})
			if err != nil || filtered.Task.Rows != 0 || filtered.Reused {
				t.Fatal(filtered, err)
			}
		})
	}
}
func TestMismatchedSymbolsRefused(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			e, f := openFixture(t, platform)
			e.Close()
			b, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			a := 0x8000
			if platform == "windows" {
				a = 0x4404
			}
			b[a] ^= 0xff
			if err = os.WriteFile(f.Image, b, 0600); err != nil {
				t.Fatal(err)
			}
			e2, err := engine.Open(context.Background(), e.Config)
			if err != nil {
				t.Fatal(err)
			}
			defer e2.Close()
			if _, err = e2.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{}); err == nil {
				t.Fatal("accepted mismatched symbols")
			}
		})
	}
}
func TestPartialFailureAndRetry(t *testing.T) {
	e, f := openFixture(t, "linux")
	e.Close()
	b, _ := os.ReadFile(f.Image)
	binary.LittleEndian.PutUint64(b[0xb000+8:], 0xdeadbeef)
	os.WriteFile(f.Image, b, 0600)
	e, err := engine.Open(context.Background(), e.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 2; i++ {
		res, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{})
		if err == nil || res.Task.State != "failed" || res.Task.Rows != 1 || res.Reused {
			t.Fatalf("%+v %v", res, err)
		}
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: res.Task.ID, Limit: 100})
		if err != nil || len(rows) != 1 {
			t.Fatal(len(rows), err)
		}
	}
}
func TestCancellationRetainsResults(t *testing.T) {
	e, _ := openFixture(t, "linux")
	ctx, cancel := context.WithCancel(context.Background())
	res, err := e.Run(ctx, "linux.pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error { cancel(); return ctx.Err() }})
	if !errors.Is(err, context.Canceled) || res.Task.State != "canceled" {
		t.Fatal(res, err)
	}
	rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: res.Task.ID, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}
func TestScanBoundariesAndSerialization(t *testing.T) {
	e, f := openFixture(t, "linux")
	e.Close()
	b := make([]byte, (1<<20)+4096)
	copy(b[(1<<20)-2:], "ABABA")
	copy(b[32:], "Linux version fixture #1")
	os.WriteFile(f.Image, b, 0600)
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var offsets []uint64
	res, err := e.Run(context.Background(), "generic.ioc", map[string]string{"needle": "ABA"}, engine.RunOptions{Emit: func(r evidence.Row) error {
		a, err := r.Cells["Offset"].Uint()
		if err != nil {
			return err
		}
		offsets = append(offsets, a)
		return nil
	}})
	if err != nil || res.Task.Rows != 2 || fmt.Sprint(offsets) != "[1048574 1048576]" {
		t.Fatal(res, offsets, err)
	}
	v := evidence.Row{Cells: map[string]evidence.Value{"Address": evidence.Address(^uint64(0)), "Count": evidence.Number(^uint64(0))}}
	encoded, _ := json.Marshal(v)
	var back evidence.Row
	json.Unmarshal(encoded, &back)
	n, err := back.Cells["Address"].Uint()
	if err != nil || n != ^uint64(0) {
		t.Fatal(string(encoded), n, err)
	}
}
