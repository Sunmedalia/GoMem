package plugins

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestLinuxBootDisplayPinnedTimestamps(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-boottime-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Timestamps []struct {
			Nanos   string
			Display *string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Timestamps) != 79 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Timestamps {
		n, ok := new(big.Int).SetString(tc.Nanos, 10)
		if !ok {
			t.Fatal(tc)
		}
		before := n.String()
		got := linuxBootDisplay(n)
		if n.String() != before {
			t.Fatal("clock modified")
		}
		if tc.Display == nil {
			if got.Kind != "missing" || got.Reason != "unparsable_boot_time" {
				t.Fatal(tc, got)
			}
			continue
		}
		want, err := time.Parse(time.RFC3339Nano, *tc.Display)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := time.Parse(time.RFC3339Nano, got.String())
		if err != nil || !actual.Equal(want) {
			t.Fatal(tc, got, err)
		}
	}
}
