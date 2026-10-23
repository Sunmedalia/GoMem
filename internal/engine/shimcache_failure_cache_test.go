package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type shimcacheRetryPlugin struct{}

func (shimcacheRetryPlugin) Spec() plugin.Spec {
	return plugin.Spec{Name: "shimcache.failure.retry", Platform: "windows"}
}

func (shimcacheRetryPlugin) Run(_ context.Context, _ plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := out(evidence.Row{ID: "partial", Cells: map[string]evidence.Value{
		"RecordType": evidence.Text("entry"),
	}}); err != nil {
		return err
	}
	return errors.New("injected Shimcache field failure")
}

func TestShimcacheFailedTaskIsNotReused(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{
		Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, OS: "windows",
		Arch: "x64", KernelBase: f.KernelBase, Offline: true, CaseDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Registry.Register(shimcacheRetryPlugin{}); err != nil {
		t.Fatal(err)
	}
	var firstID string
	for attempt := 0; attempt < 2; attempt++ {
		result, runErr := e.Run(context.Background(), "shimcache.failure.retry", nil, engine.RunOptions{})
		if runErr == nil || result.Task.State != "failed" || result.Reused || result.Task.Rows != 1 {
			t.Fatalf("attempt %d: result=%+v err=%v", attempt, result, runErr)
		}
		if firstID != "" && result.Task.ID == firstID {
			t.Fatal("failed task was reused")
		}
		if firstID == "" {
			firstID = result.Task.ID
		}
	}
}
