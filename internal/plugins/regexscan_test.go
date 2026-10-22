package plugins

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func regexFixture(t testing.TB) (plugin.Environment, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		VMAs []struct {
			Name, Arch string
			Size       int
			ISF        json.RawMessage
			Writes     []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.VMAs {
		if c.Name != "literal" || c.Arch != "x64" {
			continue
		}
		data := make(flatMemory, c.Size)
		for _, w := range c.Writes {
			b, e := hex.DecodeString(w.Data)
			if e != nil {
				t.Fatal(e)
			}
			copy(data[w.Offset:], b)
		}
		table, e := symbols.Parse(c.ISF)
		if e != nil {
			t.Fatal(e)
		}
		return plugin.Environment{OS: "linux", Architecture: "x64", Symbols: table, ImageHash: "fixture"}, data
	}
	t.Fatal("missing fixture")
	return plugin.Environment{}, nil
}
func regexFixtureEnv(t testing.TB, base plugin.Environment, data flatMemory) plugin.Environment {
	t.Helper()
	intel, err := memory.NewIntelForOS(data, 0x8000, "x64", "linux", 16)
	if err != nil {
		t.Fatal(err)
	}
	base.Physical = data
	base.Kernel = &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	base.Objects = &object.Reader{Layer: base.Kernel, Symbols: base.Symbols}
	return base
}

func TestRegexLimitsStopNestedContextWalks(t *testing.T) {
	base, data := regexFixture(t)
	e := regexFixtureEnv(t, base, data)
	b := regexPlugins()[0]
	p, err := plugin.Parameters(b.spec, map[string]string{"pattern": "MATCH", "max-map-tables": "6", "maxsize": "4"})
	if err != nil {
		t.Fatal(err)
	}
	o, err := parseRegexOptions(p)
	if err != nil {
		t.Fatal(err)
	}
	// Directly inspect the shared counters, including a nested context walk
	// entered from a streaming mapping callback.
	a := &regexAnalysis{ctx: context.Background(), env: e, o: o, out: func(evidence.Row) error { return nil }}
	intel, _ := a.intel(0x8000, "page_table")
	err = a.walk(intel, []memory.Range{{Start: 0x10000, Length: 4096}}, func(memory.PageMapping) error { _, _, err := a.contextBytes(intel, 0x10002); return err })
	if err == nil || a.stats.Tables > 6 || a.stats.Tables != 6 {
		t.Fatal("shared table budget bypassed", a.stats, err)
	}
}

func FuzzRegexPluginPipeline(f *testing.F) {
	base, original := regexFixture(f)
	f.Add("MATCH", []byte("MATCH"), uint8(0), false)
	f.Add("", []byte{0xff, 0}, uint8(1), true)
	f.Fuzz(func(t *testing.T, pattern string, payload []byte, region uint8, linux bool) {
		if len(pattern) > 64 || len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x10000, 0xb080, 0x2000, 0x3000, 0x1028}[int(region)%5]
		copy(data[at:], payload)
		e := regexFixtureEnv(t, base, data)
		b := regexPlugins()[0]
		if linux {
			b = linuxVMARegexPlugins()[0]
		}
		p, err := plugin.Parameters(b.spec, map[string]string{"pattern": pattern, "maxsize": "8", "max-map-tables": "32", "max-map-entries": "8192", "max-mappings": "32", "max-chunks": "32", "max-matches": "16", "max-proof-pages": "32", "max-read-bytes": "262144", "regex-steps": "4096"})
		if err != nil {
			t.Fatal(err)
		}
		if linux {
			p["max-nodes"] = "8"
			p["max-regions"] = "8"
		}
		calls, matches := 0, 0
		stopped := false
		stop := errors.New("output bound")
		_ = b.run(context.Background(), e, p, func(r evidence.Row) error {
			if stopped {
				t.Fatal("output after stop")
			}
			calls++
			if calls > 3000 {
				stopped = true
				return stop
			}
			if r.Cells["RecordType"].String() != "regex_match" {
				return nil
			}
			matches++
			if matches > 16 {
				t.Fatal("unbounded matches")
			}
			source, ok := r.Cells["Source"].Data.(map[string]evidence.Value)
			if !ok {
				t.Fatal("missing source")
			}
			parts := source["Parts"].Data.([]map[string]evidence.Value)
			var expected []byte
			for _, part := range parts {
				physical, _ := part["Physical"].Uint()
				size, _ := part["Length"].Uint()
				if physical > uint64(len(data)) || size > uint64(len(data))-physical {
					t.Fatal("source outside original image")
				}
				expected = append(expected, data[physical:physical+size]...)
			}
			if !bytes.Equal(expected, r.Cells["MatchRaw"].Data.([]byte)) {
				t.Fatal("false byte attribution")
			}
			return nil
		})
	})
}

func TestRegexEmptyMatchesAndZeroContextStayLossless(t *testing.T) {
	base, data := regexFixture(t)
	env := regexFixtureEnv(t, base, data)
	b := linuxVMARegexPlugins()[0]
	p, err := plugin.Parameters(b.spec, map[string]string{"pattern": "", "max-matches": "3"})
	if err != nil {
		t.Fatal(err)
	}
	var found []evidence.Row
	err = b.run(context.Background(), env, p, func(r evidence.Row) error {
		if r.Cells["RecordType"].String() == "regex_match" {
			found = append(found, r)
		}
		return nil
	})
	if err == nil || len(found) != 3 {
		t.Fatal("empty pattern did not respect task bound", len(found), err)
	}
	for i, want := range []uint64{0, 0x10000, 0x10001} {
		row := found[i]
		at, _ := row.Cells["Offset"].Uint()
		source := row.Cells["Source"].Data.(map[string]evidence.Value)
		if at != want || source["EmptyMatch"].Data != true || source["CoordinatesMatchSource"].Data != false || len(row.Cells["MatchRaw"].Data.([]byte)) != 0 {
			t.Fatal("empty match invented bytes", row.Cells)
		}
	}
	b = regexPlugins()[0]
	p, err = plugin.Parameters(b.spec, map[string]string{"pattern": "MATCH", "maxsize": "0"})
	if err != nil {
		t.Fatal(err)
	}
	found = nil
	err = b.run(context.Background(), env, p, func(r evidence.Row) error {
		if r.Cells["RecordType"].String() == "regex_match" {
			found = append(found, r)
		}
		return nil
	})
	if err != nil || len(found) != 4 {
		t.Fatal(len(found), err)
	}
	for _, r := range found {
		proof := r.Cells["Context"].Data.(map[string]evidence.Value)
		n, _ := proof["Requested"].Uint()
		if n != 0 || r.Cells["Text"].String() != "" || len(r.Cells["Hex"].Data.([]byte)) != 0 || string(r.Cells["MatchRaw"].Data.([]byte)) != "MATCH" {
			t.Fatal("zero displayed context lost original match", r.Cells)
		}
	}
}
