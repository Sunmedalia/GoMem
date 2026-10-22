package pe

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

type importOracleCase struct {
	Width  int
	Name   string
	Size   int
	Writes []struct {
		Offset int
		Data   string
	}
	Expected [][]json.RawMessage
	Error    *string
}

func importCases(t testing.TB) []importOracleCase {
	t.Helper()
	raw, err := os.ReadFile("../../internal/engine/testdata/windows-iat-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []importOracleCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 90 {
		t.Fatal("fixture drift")
	}
	return f.Cases
}
func importData(t testing.TB, c importOracleCase) []byte {
	t.Helper()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset+len(raw) > len(data) {
			t.Fatal("bad fixture")
		}
		copy(data[w.Offset:], raw)
	}
	return data
}
func TestImportsActualPinnedIATGenerator(t *testing.T) {
	for _, c := range importCases(t) {
		if c.Name == "no-peb" || c.Name == "no-base" || strings.HasPrefix(c.Name, "second-") || strings.HasPrefix(c.Name, "pid-") {
			continue
		}
		t.Run(fmt.Sprintf("%d/%s", c.Width, c.Name), func(t *testing.T) {
			data := importData(t, c)
			original := append([]byte(nil), data...)
			var calls, captured uint64
			limits := DefaultImportLimits()
			limits.Observe = func(r ExportRead) error {
				calls++
				captured += uint64(len(r.Raw))
				if r.Address+uint64(len(r.Raw)) > uint64(len(data)) || !bytes.Equal(r.Raw, data[r.Address:r.Address+uint64(len(r.Raw))]) {
					t.Fatal("raw capture differs")
				}
				return nil
			}
			table, err := ReadImports(context.Background(), testLayer{0, data}, 0x100000, limits)
			if table.ReadBytes != captured || calls == 0 || !bytes.Equal(original, data) {
				t.Fatal("acquisition accounting", table, captured, calls)
			}
			if len(table.Entries) != len(c.Expected) {
				t.Fatalf("rows %v expected %s err %v", table.Entries, c.Expected, err)
			}
			for i, got := range table.Entries {
				want := c.Expected[i]
				var lib string
				var bound bool
				var address uint64
				json.Unmarshal(want[2], &lib)
				json.Unmarshal(want[3], &bound)
				json.Unmarshal(want[5], &address)
				if string(got.Library) != lib || got.Bound != bound || got.Address != address || got.Address != got.Slot+0x100000 {
					t.Fatal(got, lib, bound, address)
				}
				if string(want[4]) == "null" {
					if got.Name != nil {
						t.Fatal("unexpected name", got)
					}
				} else {
					var name string
					json.Unmarshal(want[4], &name)
					if name != string(got.Name) {
						t.Fatal(got, name)
					}
				}
				if c.Name == "empty-iat" && i == 0 && (!got.ValueAvailable || got.Value != 0) {
					t.Fatal("captured null IAT value lost", got)
				}
				if got.ValueAvailable {
					slot := got.Slot
					if slot+uint64(c.Width) > uint64(len(data)) {
						t.Fatal("bad slot")
					}
					var v uint64
					for n := c.Width - 1; n >= 0; n-- {
						v = v<<8 | uint64(data[slot+uint64(n)])
					}
					if got.Value != v {
						t.Fatal("IAT pointer drift", got, v)
					}
				}
			}
			malformed := map[string]bool{"bad-ilt": true, "bad-iat": true, "bad-function-rva": true, "bad-dll-rva": true, "overlap-ilt": true, "bad-ordinal": true, "bad-mz": true, "bad-pe": true, "empty-ilt": true, "first-bad-ilt": true, "first-bad-dll": true, "long-function": true, "long-library": true, "repeated-thunks": true}
			if malformed[c.Name] && (err == nil || table.Complete) {
				t.Fatal("corruption masked as empty success", table)
			}
			if !malformed[c.Name] && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImportsLimitsFaultsAndStops(t *testing.T) {
	c := importCases(t)[0]
	data := importData(t, c)
	for _, key := range []string{"descriptors", "imports", "thunks", "bytes", "string"} {
		t.Run(key, func(t *testing.T) {
			limits := DefaultImportLimits()
			switch key {
			case "descriptors":
				limits.MaxDescriptors = 1
			case "imports":
				limits.MaxImports = 1
			case "thunks":
				limits.MaxThunks = 1
			case "bytes":
				limits.MaxBytes = 1
			case "string":
				limits.MaxString = 1
			}
			table, err := ReadImports(context.Background(), testLayer{0, data}, 0x100000, limits)
			if err == nil || table.Complete || !strings.Contains(err.Error(), "limit") {
				t.Fatal(table, err)
			}
		})
	}
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint("read/", invalid), func(t *testing.T) {
			fault := &exportFaultLayer{testLayer: testLayer{0, data}, fail: 1, invalid: invalid}
			table, err := ReadImports(context.Background(), fault, 0x100000, DefaultImportLimits())
			if err == nil || table.Complete {
				t.Fatal(table, err)
			}
		})
	}
	stop := errors.New("observer stopped")
	for _, mode := range []string{"observer", "emitter", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			limits := DefaultImportLimits()
			reads := 0
			stopped := false
			limits.Observe = func(r ExportRead) error {
				if stopped {
					t.Fatal("read after stop")
				}
				reads++
				if mode == "observer" {
					stopped = true
					return stop
				}
				if mode == "cancel" {
					stopped = true
					cancel()
				}
				return nil
			}
			limits.Emit = func(entry Import) error { stopped = true; return stop }
			table, err := ReadImports(ctx, testLayer{0, data}, 0x100000, limits)
			if err == nil || table.Complete || reads == 0 {
				t.Fatal(table, err, reads)
			}
		})
	}
}

func FuzzMappedPEImports(f *testing.F) {
	c := importCases(f)[0]
	data := importData(f, c)[0x100000:0x104000]
	f.Add(data)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		limits := DefaultImportLimits()
		limits.MaxBytes = 1 << 20
		limits.MaxThunks = 256
		limits.MaxDescriptors = 64
		limits.MaxImports = 128
		_, _ = ReadImports(context.Background(), testLayer{0, raw}, 0, limits)
	})
}
