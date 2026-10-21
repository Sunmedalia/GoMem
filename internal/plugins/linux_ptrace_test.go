package plugins

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestLinuxPtracePinnedFlags(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-ptrace-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Flags []struct {
			Raw     string
			Display *string
			Error   bool
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Flags) != 4101 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Flags {
		value, err := strconv.ParseUint(tc.Raw, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		display, unknown, err := linuxPtraceFlags(value)
		if (err != nil) != tc.Error {
			t.Fatal(tc, display, unknown, err)
		}
		if tc.Display != nil && display != *tc.Display || tc.Error && unknown == 0 {
			t.Fatal(tc, display, unknown, err)
		}
	}
}
