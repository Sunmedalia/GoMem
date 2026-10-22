package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func netstatPipelineFixture(t testing.TB, arch string) (plugin.Environment, flatMemory) {
	t.Helper()
	e, original := networkPipelineFixture(t, arch, "_TCP_ENDPOINT", "normal")
	data := make(flatMemory, 0x70000)
	copy(data, original)
	raw, err := os.ReadFile("testdata/windows-netstat-index-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Layout, Mode, Scenario string
			Kernel                 json.RawMessage `json:"kernel_isf"`
			TCPIP                  json.RawMessage `json:"tcpip_isf"`
			Writes                 []networkWrite
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	name := "netscan-win7-x64"
	if e.Symbols.PointerSize() == 4 {
		name = "netscan-win7-x86"
	}
	var driver *symbols.ISF
	table := e.Symbols.(*symbols.ISF)
	for _, c := range fixture.Cases {
		if c.Layout == name && c.Mode == "direct" && c.Scenario == "normal" {
			kernel, err := symbols.Parse(c.Kernel)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range kernel.Types {
				table.Types[key] = value
			}
			for key, value := range kernel.Bases {
				table.Bases[key] = value
			}
			driver, err = symbols.Parse(c.TCPIP)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil {
					t.Fatal(err)
				}
				if len(b) == table.PointerSize() {
					var value uint64
					if len(b) == 4 {
						value = uint64(binary.LittleEndian.Uint32(b))
					} else {
						value = binary.LittleEndian.Uint64(b)
					}
					if value >= 0x1000 && value < 0x40000 {
						value += 0x30000
						if len(b) == 4 {
							binary.LittleEndian.PutUint32(b, uint32(value))
						} else {
							binary.LittleEndian.PutUint64(b, value)
						}
					}
				}
				copy(data[w.Offset+0x30000:], b)
			}
			break
		}
	}
	if driver == nil {
		t.Fatal("index fixture absent")
	}
	// Preserve all reference index routes; populate each object using independent
	// network-byte controls. The existing Next links must survive field copying.
	width := table.PointerSize()
	root := 0x12000 + width*2
	for _, group := range []struct {
		typ       string
		addresses []int
	}{{"_TCP_ENDPOINT", []int{0x50000, 0x51000}}, {"_TCP_LISTENER", []int{0x52000, 0x53000}}, {"_UDP_ENDPOINT", []int{0x54000}}} {
		_, objects := networkPipelineFixture(t, arch, group.typ, "normal")
		// Read offsets directly from the pinned schema; Next is a network member.
		schemaPath := e.SymbolCache + "/network-symbols"
		entries, err := os.ReadDir(schemaPath)
		if err != nil {
			t.Fatal(err)
		}
		schema, err := os.ReadFile(schemaPath + "/" + entries[0].Name())
		if err != nil {
			t.Fatal(err)
		}
		var layout symbols.ISF
		if err := json.Unmarshal(schema, &layout); err != nil {
			t.Fatal(err)
		}
		for _, at := range group.addresses {
			var next []byte
			if f, ok := layout.Types[group.typ].Fields["Next"]; ok {
				next = append([]byte(nil), data[at+int(f.Offset):at+int(f.Offset)+width]...)
			}
			copy(data[at:at+0x800], objects[root:root+0x800])
			if next != nil {
				f := layout.Types[group.typ].Fields["Next"]
				copy(data[at+int(f.Offset):], next)
			}
		}
	}
	// An actual native loaded-module list supplies the driver extent. Only the
	// already-verified symbol acquisition provider is injected at this boundary.
	scalar := symbols.TypeRef{Kind: "base", Name: "uptr"}
	table.Types["_NETSTAT_MODULE"] = symbols.Type{Kind: "struct", Size: 128}
	unicode := symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": {Offset: 0, Type: symbols.TypeRef{Kind: "base", Name: "u16"}}, "Buffer": {Offset: 8, Type: scalar}}}
	table.Types["_UNICODE_STRING"] = unicode
	table.Types["_KLDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 128, Fields: map[string]symbols.Field{
		"InLoadOrderLinks": {Offset: 0, Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
		"DllBase":          {Offset: 32, Type: scalar}, "SizeOfImage": {Offset: 40, Type: scalar}, "BaseDllName": {Offset: 48, Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}},
	}}
	table.Symbols["PsLoadedModuleList"] = symbols.Symbol{Address: 0x1c000}
	put := func(at int, value uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(data[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[at:], value)
		}
	}
	put(0x1c000, 0x1d000)
	put(0x1c000+width, 0x1d000)
	put(0x1d000, 0x1c000)
	put(0x1d000+width, 0x1c000)
	put(0x1d020, 0x30000)
	put(0x1d028, 0x40000)
	binary.LittleEndian.PutUint16(data[0x1d030:], 18)
	put(0x1d038, 0x1e000)
	for i, c := range "tcpip.sys" {
		binary.LittleEndian.PutUint16(data[0x1e000+i*2:], uint16(c))
	}
	intel, err := memory.NewIntelForOS(data, 0x8000, arch, "windows", 16)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	e.Physical, e.Kernel = data, kernel
	e.Objects = &object.Reader{Layer: kernel, Symbols: table}
	e.ModulePDB = func(ctx context.Context, m pesymbols.Module) (pesymbols.PDB, error) {
		if err := ctx.Err(); err != nil {
			return pesymbols.PDB{}, err
		}
		if m.Base != 0x30000 || m.Size != 0x40000 || len(m.PDBNames) != 1 || m.PDBNames[0] != "tcpip.pdb" {
			return pesymbols.PDB{}, fmt.Errorf("unexpected driver acquisition extent")
		}
		return pesymbols.PDB{Table: driver, SourceSHA256: "fixture-driver-source"}, nil
	}
	return e, data
}

func TestNetStatAcquisitionAndFailureControls(t *testing.T) {
	b := windowsNetStatPlugins()[0]
	for _, arch := range []string{"x86", "pae", "x64"} {
		t.Run(arch, func(t *testing.T) {
			e, _ := netstatPipelineFixture(t, arch)
			p, _ := plugin.Parameters(b.spec, nil)
			networks := 0
			routes := map[string]int{}
			err := b.run(context.Background(), e, p, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "network" {
					networks++
					routes[row.Cells["IndexRoute"].String()]++
					if row.Cells["Owner"].String() != "System" {
						t.Fatal(row.Cells)
					}
				}
				return nil
			})
			if err != nil || networks != 5 || routes["partition"] != 2 || routes["port_pool"] != 3 {
				t.Fatal("native index acquisition", networks, routes, err)
			}
			for name := range map[string]bool{"max-nodes": true, "max-reads": true, "max-rows": true, "max-read-bytes": true} {
				params, _ := plugin.Parameters(b.spec, map[string]string{name: "1"})
				if err := b.run(context.Background(), e, params, func(evidence.Row) error { return nil }); err == nil {
					t.Fatal("bound ignored", name)
				}
			}
			stop := errors.New("stop output")
			calls := 0
			if err := b.run(context.Background(), e, p, func(evidence.Row) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
				t.Fatal("output stop lost", calls, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := b.run(ctx, e, p, func(evidence.Row) error { t.Fatal("output after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			provider := e.ModulePDB
			partial := errors.New("driver acquisition page missing")
			e.ModulePDB = func(ctx context.Context, module pesymbols.Module) (pesymbols.PDB, error) {
				pdb, err := provider(ctx, module)
				return pdb, errors.Join(err, partial)
			}
			recovered := 0
			if err := b.run(context.Background(), e, p, func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "network" {
					recovered++
				}
				return nil
			}); !errors.Is(err, partial) || recovered != 5 {
				t.Fatal("valid symbols with partial acquisition were discarded or became success", recovered, err)
			}
			e.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
				return pesymbols.PDB{}, pesymbols.ErrUnavailable
			}
			if err := b.run(context.Background(), e, p, func(evidence.Row) error { return nil }); !errors.Is(err, pesymbols.ErrUnavailable) {
				t.Fatal("missing driver symbols became absence", err)
			}
		})
	}
}

func TestNetStatCompletePinnedGenerators(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for complete NetStat generation")
	}
	raw, err := os.ReadFile("testdata/windows-netstat-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Arch, Layout, Scenario string
			Size                   int
			KernelBase             uint64 `json:"kernel_base"`
			ModuleBase             uint64 `json:"module_base"`
			ISF                    json.RawMessage
			Driver                 json.RawMessage `json:"driver_isf"`
			Writes                 []networkWrite
			Results                []struct {
				Corrupt bool `json:"include_corrupt"`
				Rows    [][]json.RawMessage
				Error   *struct{ Type, Message string }
				Faults  []json.RawMessage `json:"read_faults"`
				Invalid []json.RawMessage `json:"unavailable_checks"`
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 48 {
		t.Fatal("complete NetStat fixture drift")
	}
	b := windowsNetStatPlugins()[0]
	fields := []string{"Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprint(i)+c.Arch+c.Scenario, func(t *testing.T) {
			data := networkBytes(t, c.Size, c.Writes)
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			driver, err := symbols.Parse(c.Driver)
			if err != nil {
				t.Fatal(err)
			}
			cache := t.TempDir()
			if err := os.MkdirAll(filepath.Join(cache, "network-symbols"), 0700); err != nil {
				t.Fatal(err)
			}
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", c.Layout+".json"))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(schema)
			if err := os.WriteFile(filepath.Join(cache, "network-symbols", c.Layout+"-"+hex.EncodeToString(digest[:])+".json"), schema, 0600); err != nil {
				t.Fatal(err)
			}
			intel, err := memory.NewIntelForOS(data, 0x8000, c.Arch, "windows", 16)
			if err != nil {
				t.Fatal(err)
			}
			kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
			e := plugin.Environment{OS: "windows", Architecture: c.Arch, KernelBase: c.KernelBase, Offline: true, SymbolCache: cache, Symbols: table, Kernel: kernel, Physical: data, Objects: &object.Reader{Layer: kernel, Symbols: table}}
			e.ModulePDB = func(_ context.Context, m pesymbols.Module) (pesymbols.PDB, error) {
				if m.Base != c.ModuleBase {
					return pesymbols.PDB{}, fmt.Errorf("driver base differs")
				}
				return pesymbols.PDB{Table: driver}, nil
			}
			for _, result := range c.Results {
				params, _ := plugin.Parameters(b.spec, map[string]string{"include-corrupt": fmt.Sprint(result.Corrupt)})
				var rows []evidence.Row
				err := b.run(context.Background(), e, params, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "network" {
						rows = append(rows, row)
					}
					return nil
				})
				bad := len(result.Faults)+len(result.Invalid) > 0
				if (err != nil) != bad {
					t.Fatal("complete NetStat source fault distinction", err, bad)
				}
				if result.Error != nil {
					// The upstream corrupt-mode debug formatter throws on unreadable AF.
					// Native preserves the candidate/typed errors and continues, rather than
					// crashing in a logging expression. This remains an explicit difference.
					if c.Scenario != "missing-family" || !result.Corrupt || result.Error.Type != "TypeError" || len(result.Rows) != 0 || len(rows) != 2 || err == nil {
						t.Fatal("unexpected generator exception difference", result.Error, len(rows), err)
					}
					continue
				}
				if len(rows) != len(result.Rows) {
					t.Fatal("complete NetStat count", result.Corrupt, len(rows), len(result.Rows), err)
				}
				for k, want := range result.Rows {
					for j, key := range fields {
						got := rows[k].Cells[key]
						if string(want[j]) == "null" {
							if got.Kind != "missing" {
								t.Fatal("absence lost", key, got)
							}
							continue
						}
						if key == "Offset" || key == "PID" || key == "LocalPort" || key == "ForeignPort" {
							var number uint64
							if err := json.Unmarshal(want[j], &number); err != nil {
								t.Fatal(err)
							}
							value, err := got.Uint()
							if err != nil || value != number {
								t.Fatal("complete NetStat numeric drift", key, got, number)
							}
						} else {
							var text string
							if err := json.Unmarshal(want[j], &text); err != nil {
								t.Fatal(err)
							}
							if key == "Created" && strings.HasSuffix(text, "+00:00") {
								text = strings.TrimSuffix(text, "+00:00") + "Z"
							}
							if got.String() != text {
								t.Fatal("complete NetStat field drift", key, got, text)
							}
						}
					}
				}
			}
		})
	}
}
