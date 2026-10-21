package plugins

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestVMCoreInfoPinnedParser(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-vmcoreinfo-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Raw      string
			Accepted bool
			Error    string
			Entries  []struct{ Key, Value, Integer string }
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Cases) != 268 {
		t.Fatal(len(oracle.Cases))
	}
	for _, tc := range oracle.Cases {
		data, err := hex.DecodeString(tc.Raw)
		if err != nil {
			t.Fatal(err)
		}
		entries, status, err := vmcoreParse(data)
		if (tc.Error != "") != (err != nil) {
			t.Fatalf("%q: %v expected %s", data, err, tc.Error)
		}
		if err != nil {
			continue
		}
		if (status == "parsed") != tc.Accepted || len(entries) != len(tc.Entries) {
			t.Fatalf("%q: %s %+v", data, status, entries)
		}
		for i, v := range entries {
			want := tc.Entries[i]
			if v.key != want.Key || v.value != want.Value || v.integer != want.Integer {
				t.Fatalf("%q: %+v want %+v", data, v, want)
			}
		}
	}
	if _, err := vmcoreInteger(strings.Repeat("1", 4301), 0); err == nil {
		t.Fatal("decimal bound not enforced")
	}
	if _, err := vmcoreInteger(strings.Repeat("f", 65537), 16); err == nil {
		t.Fatal("native digit bound not enforced")
	}
}

func FuzzVMCoreInfoDescriptor(f *testing.F) {
	for _, s := range []string{"OSRELEASE=test\nPAGESIZE=4096\n", "OSRELEASE=a\r\nSYMBOL(x)=-0xf_f\n", "OSRELEASE=a\n\n\x00", "OSRELEASE=a\nNUMBER(x)=00_00\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			t.Skip()
		}
		entries, status, err := vmcoreParse(raw)
		if err != nil || status != "parsed" {
			return
		}
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[e.key] || e.offset < 0 || e.length < 1 || e.offset+e.length > len(raw) {
				t.Fatal("invalid parsed entry", e)
			}
			seen[e.key] = true
			line := raw[e.offset : e.offset+e.length]
			if !strings.HasPrefix(string(line), e.key+"=") {
				t.Fatal("invalid line coordinate", e)
			}
			if e.integer != "" {
				if _, ok := new(big.Int).SetString(e.integer, 10); !ok {
					t.Fatal("invalid lossless integer", e)
				}
			}
		}
	})
}
