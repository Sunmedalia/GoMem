package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsCredentialDumpsMissingSecurityAreNotEmptySuccess(t *testing.T) {
	f := printKeyFixture(t, true)
	for _, name := range []string{"windows.lsadump", "windows.cachedump"} {
		var rows []evidence.Row
		result, err := openWindowsImage(t, f).Run(context.Background(), name, nil, engine.RunOptions{Emit: engineRun(t, &rows)})
		if err == nil || result.Task.State != "failed" {
			t.Fatal(name, result.Task.State, err, len(rows))
		}
		if !strings.Contains(err.Error(), "SECURITY is absent") {
			t.Fatal(name, err)
		}
		if len(rows) != 1 || rows[0].Cells["RecordType"].String() != "diagnostic" {
			t.Fatal(name, rows)
		}
		reason := "lsa_secret_unavailable"
		if name == "windows.cachedump" {
			reason = "cached_credential_unavailable"
		}
		if rows[0].Cells["Error"].Reason != reason {
			t.Fatal(name, rows[0].Cells["Error"])
		}
		for _, row := range rows {
			if row.Cells["RecordType"].String() == "secret" || row.Cells["RecordType"].String() == "credential" {
				t.Fatal(name, "credential row without SECURITY")
			}
		}
	}
}
