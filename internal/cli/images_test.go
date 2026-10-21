package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/library"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

func TestImageInspectAndOfflineSymbolMatch(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "", "images", "inspect", f.Image)
	if err != nil {
		t.Fatal(err)
	}
	var probe library.Probe
	if err = json.Unmarshal([]byte(out), &probe); err != nil || probe.OS != "linux" || len(probe.Identities) != 1 {
		t.Fatal(out, err)
	}
	root := filepath.Join(t.TempDir(), "library")
	out, _, err = run(t, "y\n", "symbols", "match", f.Image, "--download", "--offline", "--library-dir", root)
	if err != nil || !strings.Contains(out, "offline: local matching only") {
		t.Fatal(out, err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("local-only lookup created an absent library", err)
	}
	l := library.Library{Root: root}
	if _, err = l.Import(context.Background(), library.Symbols, f.Symbols); err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{{"--offline"}, {"--local-only"}, {}} {
		args := append([]string{"symbols", "match", f.Image, "--library-dir", root}, flags...)
		out, _, err = run(t, "", args...)
		if err != nil {
			t.Fatal(out, err)
		}
		var result struct {
			Local  library.LocalResult `json:"local"`
			Remote []library.Candidate `json:"matches"`
			Status string              `json:"remote_status"`
		}
		if err = json.Unmarshal([]byte(out), &result); err != nil || len(result.Local.Matches) != 1 || len(result.Remote) != 0 || result.Status == "queried" {
			t.Fatal(out, err)
		}
	}
	after, err := os.ReadFile(f.Image)
	if err != nil || string(before) != string(after) {
		t.Fatal("image modified", err)
	}
}
