package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestPoolScannerActualCompleteNonexecutiveGenerators(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-poolscanner-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Width    int
			Vista    bool
			PoolType uint64 `json:"pool_type"`
			Delta    int
			ISF      json.RawMessage
			Size     int
			Writes   []struct {
				Offset int
				Data   string
			}
			Rows [][]json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 36 {
		t.Fatal("fixture drift")
	}
	for _, c := range fixture.Cases {
		t.Run(fmt.Sprintf("width%d/vista%t/type%d/delta%d", c.Width, c.Vista, c.PoolType, c.Delta), func(t *testing.T) {
			data := make(flatMemory, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
					t.Fatal("invalid fixture")
				}
				copy(data[w.Offset:], b)
			}
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			arch := "x64"
			if c.Width == 4 {
				arch = "x86"
			}
			intel, err := memory.NewIntelForOS(data, 0x8000, arch, "windows", 16)
			if err != nil {
				t.Fatal(err)
			}
			kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "memory"}
			env := plugin.Environment{OS: "windows", Architecture: arch, Kernel: kernel, Physical: data, Symbols: table, Objects: &object.Reader{Layer: kernel, Symbols: table}}
			b := windowsPoolScannerPlugins()[0]
			p, err := plugin.Parameters(b.spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			var rows []evidence.Row
			err = b.run(context.Background(), env, p, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "pool_object" {
					rows = append(rows, row)
				}
				return nil
			})
			if err != nil || len(rows) != len(c.Rows) {
				t.Fatal("generator count", err, len(rows), len(c.Rows))
			}
			for i, want := range c.Rows {
				var name, layer string
				var at uint64
				json.Unmarshal(want[0], &name)
				json.Unmarshal(want[1], &at)
				json.Unmarshal(want[2], &layer)
				got := rows[i]
				offset, _ := got.Cells["Offset"].Uint()
				objectAt, _ := got.Cells["ObjectOffset"].Uint()
				if got.Cells["Type"].String() != strings.TrimPrefix(name, "kernel!") || offset != at || layer != "physical" || got.Cells["Layer"].String() != data.Name() || got.Cells["Name"].Kind != "missing" || string(want[3]) != "null" || objectAt != at+uint64(c.Width*2) {
					t.Fatal("generator row drift", got.Cells, string(want[0]))
				}
			}
		})
	}
}

func poolScannerFixture(t testing.TB) (plugin.Environment, flatMemory) {
	t.Helper()
	data := make(flatMemory, 0x1000)
	data[0x202] = 16
	data[0x203] = 2
	copy(data[0x204:], "File")
	putU64(data, 0x210, 1)
	data[0x228] = 3
	putUnicode(data, 0x298, 0x400, `\Device\fixture.txt`)
	putU64(data, 0x188, 0x600)
	putUnicode(data, 0x610, 0x700, "File")
	table := fileSymbols(true)
	return plugin.Environment{OS: "windows", Kernel: data, Physical: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}}, data
}

func FuzzPoolScannerOriginalCaptures(f *testing.F) {
	base, original := poolScannerFixture(f)
	f.Add([]byte("File"), uint8(0))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x204, 0x202, 0x228, 0x298, 0x188, 0x610}[int(region)%6]
		copy(data[at:], payload)
		env := base
		env.Kernel = data
		env.Physical = data
		env.Objects = &object.Reader{Layer: data, Symbols: base.Symbols}
		b := windowsPoolScannerPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"max-read-bytes": "65536", "max-reads": "1000", "max-rows": "1000"})
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		stopped := false
		_ = b.run(context.Background(), env, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("output after stop")
			}
			calls++
			if calls > 1000 {
				t.Fatal("evidence bound bypassed")
			}
			if calls == 50 {
				stopped = true
				return errors.New("output stopped")
			}
			if row.Cells["RecordType"].String() != "memory_read" {
				return nil
			}
			at, _ := row.Cells["Offset"].Uint()
			n, _ := row.Cells["Captured"].Uint()
			if at > uint64(len(data)) {
				if n != 0 {
					t.Fatal("capture beyond image")
				}
				return nil
			}
			if n > uint64(len(data))-at {
				t.Fatal("capture beyond image")
			}
			original := data[at : at+n]
			digest := sha256.Sum256(original)
			if row.Cells["SHA256"].String() != hex.EncodeToString(digest[:]) {
				t.Fatal("false read digest")
			}
			if raw, ok := row.Cells["Raw"]; ok && !bytes.Equal(raw.Data.([]byte), original) {
				t.Fatal("false captured bytes")
			}
			return nil
		})
	})
}

func TestPoolScannerHeaderObjectAndOriginalReads(t *testing.T) {
	env, data := poolScannerFixture(t)
	b := windowsPoolScannerPlugins()[0]
	p, err := plugin.Parameters(b.spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	objects := 0
	completed := false
	err = b.run(context.Background(), env, p, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "pool_object":
			objects++
			header, _ := row.Cells["Offset"].Uint()
			body, _ := row.Cells["ObjectOffset"].Uint()
			if header != 0x200 || body != 0x240 || row.Cells["Type"].String() != "_FILE_OBJECT" || row.Cells["Name"].String() != `\Device\fixture.txt` || !bytes.Equal(row.Cells["Tag"].Data.([]byte), []byte("File")) {
				t.Fatal(row.Cells)
			}
		case "memory_read":
			at, _ := row.Cells["Offset"].Uint()
			n, _ := row.Cells["Captured"].Uint()
			if at > uint64(len(data)) || n > uint64(len(data))-at {
				t.Fatal("read outside image")
			}
			original := data[at : at+n]
			digest := sha256.Sum256(original)
			if hex.EncodeToString(digest[:]) != row.Cells["SHA256"].String() {
				t.Fatal("false read digest")
			}
			if raw, ok := row.Cells["Raw"]; ok && !bytes.Equal(raw.Data.([]byte), original) {
				t.Fatal("false original bytes")
			}
		case "task_summary":
			coverage := row.Cells["Coverage"].Data.(map[string]evidence.Value)
			completed = coverage["Completed"].Data.(bool)
		}
		return nil
	})
	if err != nil || objects != 1 || !completed {
		t.Fatal(err, objects, completed)
	}
}

func TestPoolScannerBudgetReadAndOutputFailures(t *testing.T) {
	for _, mode := range []string{"max-reads", "max-read-bytes", "max-rows", "metadata-hole", "cancel", "output"} {
		t.Run(mode, func(t *testing.T) {
			env, data := poolScannerFixture(t)
			if mode == "metadata-hole" {
				putU64(data, 0x2a0, 0x2000)
			}
			b := windowsPoolScannerPlugins()[0]
			in := map[string]string{}
			if mode == "max-reads" || mode == "max-read-bytes" || mode == "max-rows" {
				in[mode] = "1"
			}
			p, err := plugin.Parameters(b.spec, in)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			sentinel := errors.New("output stopped")
			err = b.run(ctx, env, p, func(evidence.Row) error {
				calls++
				if mode == "cancel" {
					cancel()
				}
				if mode == "output" {
					return sentinel
				}
				return nil
			})
			if err == nil {
				t.Fatal("failure hidden", mode, calls)
			}
			if mode == "cancel" && (!errors.Is(err, context.Canceled) || calls != 1) {
				t.Fatal("continued after cancel", calls, err)
			}
			if mode == "output" && (!errors.Is(err, sentinel) || calls != 1) {
				t.Fatal("continued after output failure", calls, err)
			}
		})
	}
}
