package plugins

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func TestPESymbolRequestPrecisionAndValidation(t *testing.T) {
	p := map[string]string{"symbols": "[]", "addresses": `["0xffffffffffffffff",18446744073709551615,"010","0X10"]`}
	r, err := peSymbolRequest(p)
	if err != nil || len(r.Addresses) != 4 || r.Addresses[0] != ^uint64(0) || r.Addresses[1] != ^uint64(0) || r.Addresses[2] != 10 || r.Addresses[3] != 16 {
		t.Fatal(r, err)
	}
	p["symbols"] = `["a,b","a,b","Alpha"]`
	r, err = peSymbolRequest(p)
	if err != nil || len(r.Names) != 3 || r.Names[0] != "a,b" || len(r.Addresses) != 0 {
		t.Fatal(r, err)
	}
	for _, raw := range []string{`[1]`, `[""]`, `[null]`, `{}`, `[`, `true`} {
		p["symbols"] = raw
		if _, err := peSymbolRequest(p); err == nil {
			t.Fatal("invalid name array", raw)
		}
	}
	p["symbols"] = "[]"
	for _, raw := range []string{`[-1]`, `[1.5]`, `[18446744073709551616]`, `["-1"]`, `["0x"]`, `[true]`, `[null]`, `{}`, `[`} {
		p["addresses"] = raw
		if _, err := peSymbolRequest(p); err == nil {
			t.Fatal("invalid address array", raw)
		}
	}
	b := windowsPESymbolPlugins()[0]
	for _, key := range []string{"max-nodes", "max-regions", "max-modules", "max-read-bytes", "max-symbols"} {
		for _, bad := range []string{"0", "-1", "no", "18446744073709551615"} {
			params, err := plugin.Parameters(b.Spec(), map[string]string{"source": "kernel", "module": "x.dll", key: bad})
			if err == nil {
				err = b.Run(context.Background(), plugin.Environment{}, params, func(evidence.Row) error { return nil })
			}
			if err == nil {
				t.Fatal(key, bad)
			}
		}
	}
}

func FuzzPESymbolRequest(f *testing.F) {
	f.Add(`['x']`, `["0xffffffffffffffff"]`)
	f.Add(`["a,b","Alpha"]`, `[0,42]`)
	f.Fuzz(func(t *testing.T, names, addresses string) {
		if len(names)+len(addresses) > 65536 {
			return
		}
		r, err := peSymbolRequest(map[string]string{"symbols": names, "addresses": addresses})
		if err != nil {
			return
		}
		if len(r.Names) > 0 && len(r.Addresses) > 0 {
			t.Fatal("command precedence")
		}
		if len(r.Names) > 0 {
			var expected []string
			if err := json.Unmarshal([]byte(names), &expected); err != nil || len(expected) != len(r.Names) {
				t.Fatal(err)
			}
			for i, name := range expected {
				if r.Names[i] != name {
					t.Fatal("name order or bytes changed")
				}
			}
		}
	})
}
