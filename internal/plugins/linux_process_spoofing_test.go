package plugins

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLinuxProcessSpoofingPinnedHelpers(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-process-spoofing-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Comparisons []struct {
			Exe, Command, Comm *string
			CommandSpoofed     bool `json:"command_spoofed"`
			CommSpoofed        bool `json:"comm_spoofed"`
		}
		Paths     []struct{ Path, Basename string }
		Decoded   []struct{ Raw, Decoded, Basename string }
		Extracted []struct{ Exe, Command, Comm, Basename *string }
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Comparisons) != 1728 || len(oracle.Paths) != 20 || len(oracle.Decoded) != 11 || len(oracle.Extracted) != 36 {
		t.Fatal(err)
	}
	value := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	for i, c := range oracle.Comparisons {
		cmd, comm := linuxSpoofNames(value(c.Exe), value(c.Command), value(c.Comm))
		if cmd != c.CommandSpoofed || comm != c.CommSpoofed {
			t.Fatal(i, c, cmd, comm)
		}
	}
	for _, c := range oracle.Paths {
		if got := spoofPosixName(c.Path); got != c.Basename {
			t.Fatal(c, got)
		}
	}
	for _, c := range oracle.Decoded {
		raw, err := hex.DecodeString(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded := spoofDecoded(raw)
		if decoded != c.Decoded || spoofPosixName(decoded) != c.Basename {
			t.Fatal(c, decoded)
		}
	}
	for _, c := range oracle.Extracted {
		got := strings.TrimSuffix(spoofPosixName(value(c.Exe)), " (deleted)")
		if got != value(c.Basename) {
			t.Fatal(c, got)
		}
	}
}
