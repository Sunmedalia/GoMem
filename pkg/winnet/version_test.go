package winnet

import (
	"encoding/json"
	"os"
	"testing"
)

func TestActualNetworkVersionFactory(t *testing.T) {
	raw, err := os.ReadFile("../../internal/plugins/testdata/windows-network-version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Arch                string
			Width               int
			Major, Minor, Build uint64
			TCPIPRevision       uint64 `json:"tcpip_revision"`
			Is18363             bool
			Result              struct {
				Name, Error  string
				Windows10X64 bool `json:"win10_x64_classes"`
				Constraints  []struct {
					Tag, Type         string
					Minimum, PageType uint64
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 99 {
		t.Fatal("version fixture drift")
	}
	for _, c := range fixture.Cases {
		v := Version{Width: c.Width, Major: c.Major, Minor: c.Minor, Build: c.Build, TCPIPRevision: c.TCPIPRevision, Is18363: c.Is18363}
		got, err := Select(v)
		if c.Result.Error != "" {
			if err == nil {
				t.Fatal("unsupported version selected", v, got)
			}
			continue
		}
		if err != nil || got.Name != c.Result.Name || got.Windows10X64 != c.Result.Windows10X64 {
			t.Fatal("version factory differs", c.Arch, v, got, c.Result, err)
		}
		additional := false
		for _, constraint := range c.Result.Constraints {
			if constraint.Tag == "54546362" {
				additional = true
			}
		}
		if additional != got.AdditionalTCPTag {
			t.Fatal("additional pool tag differs", v, got)
		}
		if _, exists := catalogPins[got.Name]; !exists {
			t.Fatal("selected layout not pinned", got.Name)
		}
	}
	if _, err := Select(Version{Width: 16}); err == nil {
		t.Fatal("invalid pointer width accepted")
	}
}
