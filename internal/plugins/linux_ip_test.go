package plugins

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestLinuxIPPinnedFlagsAndEncoding(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-ip-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Flags []struct {
			Choices                    string
			Flags, Gflags, State, Oper uint64
			Result                     string
		}
		IPv6 []struct{ Raw, Text string }
		IPv4 []struct {
			Value uint32
			Text  string
		}
		Scopes6 []struct {
			Value uint64
			Text  string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Flags) != 768 || len(oracle.IPv6) != 7 {
		t.Fatal("oracle coverage drift")
	}
	bits := map[string]uint64{"__LINK_STATE_START": 0, "__LINK_STATE_NOCARRIER": 1, "__LINK_STATE_DORMANT": 2}
	for _, tc := range oracle.Flags {
		choices := map[string]uint64{}
		for k, v := range linuxIPFlagDefaults {
			choices[k] = v
		}
		if tc.Choices == "composite" {
			choices["IFF_COMPOSITE"] = 3
			choices["IFF_ZERO"] = 0
		}
		if tc.Choices == "typo" {
			choices["IFF_ALLMULTI)"] = 512
		}
		got, err := linuxIPFlags(tc.Flags, tc.Gflags, tc.State, tc.Oper, choices, bits)
		if err != nil || got != tc.Result {
			t.Fatalf("%+v: %s %v", tc, got, err)
		}
	}
	for _, tc := range oracle.IPv6 {
		raw, err := hex.DecodeString(tc.Raw)
		if err != nil {
			t.Fatal(err)
		}
		var bytes [16]byte
		copy(bytes[:], raw)
		if got := linuxIP6Text(bytes); got != tc.Text {
			t.Fatalf("%s got %s want %s", tc.Raw, got, tc.Text)
		}
	}
	for _, tc := range oracle.IPv4 {
		if got := linuxIP4Text(tc.Value); got != tc.Text {
			t.Fatal(tc, got)
		}
	}
	for _, tc := range oracle.Scopes6 {
		if got := linuxIP6Scope(tc.Value); got != tc.Text {
			t.Fatal(tc, got)
		}
	}
	if len(oracle.Scopes6) != 128 || len(oracle.IPv4) != 5 {
		t.Fatal("scope/IP coverage drift")
	}
	if _, err := linuxIPFlags(0, 0, 0, 0, linuxIPFlagDefaults, nil); err == nil {
		t.Fatal("missing state enum silently accepted")
	}
}
