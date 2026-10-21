package cli

import (
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
	if _, _, err = run(t, "y\n", "symbols", "match", f.Image, "--download", "--offline", "--library-dir", root); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatal(err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("offline lookup wrote files", err)
	}
	after, err := os.ReadFile(f.Image)
	if err != nil || string(before) != string(after) {
		t.Fatal("image modified", err)
	}
}
