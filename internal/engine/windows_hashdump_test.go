package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsHashdumpMissingSAMIsNotEmptySuccess(t *testing.T) {
	f := printKeyFixture(t, true)
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.hashdump", nil, engine.RunOptions{Emit: engineRun(t, &rows)})
	if err == nil || result.Task.State != "failed" {
		t.Fatal(result.Task.State, err, len(rows))
	}
	if !strings.Contains(err.Error(), "SAM is absent") {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Cells["RecordType"].String() != "diagnostic" || rows[0].Cells["Error"].Reason != "sam_hash_unavailable" {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "hash" {
			t.Fatal("hash row without a SAM hive")
		}
	}
}
