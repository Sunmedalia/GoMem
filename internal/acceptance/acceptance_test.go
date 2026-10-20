package acceptance

import (
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/version"
)

func TestReleasePolicy(t *testing.T) {
	r, err := Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if r.PluginCount != 195 {
		t.Fatalf("locked plugin inventory drift: %d", r.PluginCount)
	}
	if !strings.Contains(version.Version, "-") && !r.Ready {
		t.Fatalf("formal version %s with incomplete acceptance: %+v", version.Version, r)
	}
}
