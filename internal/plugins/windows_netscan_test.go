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
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/winnet"
)

type networkWrite struct {
	Offset int
	Data   string
}

func networkBytes(t testing.TB, size int, writes []networkWrite) flatMemory {
	t.Helper()
	data := make(flatMemory, size)
	for _, w := range writes {
		b, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > size || len(b) > size-w.Offset {
			t.Fatal("invalid network fixture write")
		}
		copy(data[w.Offset:], b)
	}
	return data
}

func TestNetworkMeasuredVersionAndConstraints(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-network-version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Arch   string
			Size   int
			Writes []networkWrite
			ISF    json.RawMessage
			Result struct {
				Name, Error string
				Constraints []struct {
					Tag, Type string
					Minimum   uint64
					PageType  int `json:"page_type"`
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 99 {
		t.Fatal("version fixture drift")
	}
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%d/%s", i, c.Arch), func(t *testing.T) {
			data := networkBytes(t, c.Size, c.Writes)
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			intel, err := memory.NewIntelForOS(data, 0x8000, c.Arch, "windows", 16)
			if err != nil {
				t.Fatal(err)
			}
			kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
			e := plugin.Environment{OS: "windows", Architecture: c.Arch, Symbols: table, Physical: data, Kernel: kernel, Objects: &object.Reader{Symbols: table, Layer: kernel}}
			v, err := networkVersion(context.Background(), e)
			if err != nil {
				t.Fatal("measured input", err)
			}
			selected, err := winnet.Select(v)
			if c.Result.Error != "" {
				if err == nil {
					t.Fatal("unsupported NT accepted")
				}
				return
			}
			if err != nil || selected.Name != c.Result.Name {
				t.Fatal("measured selection differs", selected, c.Result, err)
			}
			if baseline == "" {
				return
			}
			b, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", selected.Name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			layout, err := winnet.Parse(b)
			if err != nil {
				t.Fatal(err)
			}
			constraints, err := networkConstraints(layout, selected)
			if err != nil || len(constraints) != len(c.Result.Constraints) {
				t.Fatal(constraints, err)
			}
			for j, want := range c.Result.Constraints {
				tag, _ := hex.DecodeString(want.Tag)
				got := constraints[j]
				if string(tag) != string(got.tag) || got.typeName != want.Type || got.minSize != want.Minimum || got.pageType != want.PageType {
					t.Fatal("actual constraint differs", got, want)
				}
			}
		})
	}
}

func TestNetworkNativeValidityOwnerTimeAndRows(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for all original network layouts")
	}
	raw, err := os.ReadFile("testdata/windows-network-object-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Layouts []struct {
			Name   string
			Kernel json.RawMessage `json:"kernel_isf"`
		}
		Cases []struct {
			Layout, Type, Scenario string
			Family                 int
			Size                   int
			Offset                 uint64 `json:"object_offset"`
			Writes                 []networkWrite
			Observations           map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 1200 {
		t.Fatal("object fixture drift")
	}
	layouts := map[string]*winnet.Layout{}
	kernels := map[string]*symbols.ISF{}
	for _, l := range fixture.Layouts {
		b, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", l.Name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		layouts[l.Name], err = winnet.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		kernels[l.Name], err = symbols.Parse(l.Kernel)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%s/%s/%d/%s", c.Layout, c.Type, c.Family, c.Scenario), func(t *testing.T) {
			data := networkBytes(t, c.Size, c.Writes)
			table := kernels[c.Layout]
			e := plugin.Environment{ImageHash: "original-network-fixture", Kernel: data, Physical: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}}
			o := winnet.Object{Layout: layouts[c.Layout], Layer: data, Address: c.Offset, Type: c.Type}
			valid, _ := networkObjectValid(context.Background(), e, o)
			var wantValid bool
			if err := json.Unmarshal(c.Observations["valid"], &wantValid); err != nil {
				t.Fatal(err)
			}
			if valid != wantValid {
				t.Fatal("actual network validity differs", valid, wantValid)
			}
			rows, rowErr := networkRows(context.Background(), e, o, "not_checked_include_corrupt")
			if c.Type == "_TCP_ENDPOINT" {
				if len(rows) != 1 {
					t.Fatal("endpoint row lost", rows, rowErr)
				}
			} else {
				var sockets [][]string
				if err := json.Unmarshal(c.Observations["sockets"], &sockets); err != nil {
					if !errors.Is(rowErr, winnet.ErrClassExtension) {
						t.Fatal("class error lost", rowErr)
					}
					return
				}
				if len(rows) != len(sockets) {
					t.Fatal("socket expansion differs", rows, sockets, rowErr)
				}
				for i, socket := range sockets {
					proto, remote := "TCP", socket[2]
					if c.Type == "_UDP_ENDPOINT" {
						proto, remote = "UDP", "*"
					}
					if rows[i].Cells["Proto"].String() != proto+socket[0] || rows[i].Cells["LocalAddr"].String() != socket[1] || rows[i].Cells["ForeignAddr"].String() != remote {
						t.Fatal("socket fields differ", rows[i].Cells, socket)
					}
				}
			}
			for _, row := range rows {
				for key, observation := range map[string]string{"PID": "pid", "Owner": "owner", "Created": "created", "LocalAddr": "local", "ForeignAddr": "remote", "LocalPort": "local_port", "ForeignPort": "remote_port", "State": "state"} {
					want, exists := c.Observations[observation]
					if !exists {
						continue
					}
					got := row.Cells[key]
					if string(want) == "null" || len(want) > 0 && want[0] == '{' {
						if got.Kind != "missing" {
							t.Fatal("absent field became value", key, got, string(want))
						}
						continue
					}
					var text string
					if json.Unmarshal(want, &text) == nil {
						if key == "Created" && len(text) > 6 && text[len(text)-6:] == "+00:00" {
							text = text[:len(text)-6] + "Z"
						}
						if got.String() != text {
							t.Fatal("actual field differs", key, got, text)
						}
					} else {
						var number uint64
						if err := json.Unmarshal(want, &number); err != nil {
							t.Fatal(err)
						}
						value, err := got.Uint()
						if err != nil || value != number {
							t.Fatal("actual numeric field differs", key, got, number)
						}
					}
				}
			}
		})
	}
}

func TestNetworkTimeBounds(t *testing.T) {
	for _, c := range []struct {
		Raw    uint64
		Reason string
	}{{0, "not_applicable_filetime"}, {9999999, "not_applicable_filetime"}, {1 << 63, "unparsable_filetime"}, {1<<63 - 1, "unparsable_filetime"}, {10000000, "unreadable_network_time"}} {
		if got := networkTime(c.Raw); got.Kind != "missing" || got.Reason != c.Reason {
			t.Fatal(c, got)
		}
	}
	if got := networkTime(133801632000000000); got.Kind != "timestamp" || got.String() != "2025-01-01T00:00:00Z" {
		t.Fatal(got)
	}
}

// Assemble real independently referenced version, pool and network bytes into
// one native acquisition path. This is an integration control, not a claim of
// complete upstream-generator differential coverage.
func networkPipelineFixture(t testing.TB, arch, typ, scenario string) (plugin.Environment, flatMemory) {
	t.Helper()
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for native network acquisition controls")
	}
	read := func(name string, target any) {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	var versions struct {
		Cases []struct {
			Arch   string
			Build  uint64
			Mode   string
			Size   int
			ISF    json.RawMessage
			Writes []networkWrite
		}
	}
	read("windows-network-version-oracle.json", &versions)
	var data flatMemory
	var table *symbols.ISF
	for _, c := range versions.Cases {
		if c.Arch == arch && c.Build == 7601 && c.Mode == "metadata" {
			data = networkBytes(t, c.Size, c.Writes)
			var err error
			table, err = symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if table == nil {
		t.Fatal("version fixture absent")
	}
	width := table.PointerSize()
	name := "netscan-win7-x64"
	if width == 4 {
		name = "netscan-win7-x86"
	}
	var objects struct {
		Layouts []struct {
			Name   string
			Kernel json.RawMessage `json:"kernel_isf"`
		}
		Cases []struct {
			Layout, Type, Scenario string
			Family                 int
			Writes                 []networkWrite
		}
	}
	read("windows-network-object-oracle.json", &objects)
	for _, l := range objects.Layouts {
		if l.Name == name {
			kernel, err := symbols.Parse(l.Kernel)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range kernel.Types {
				table.Types[key] = value
			}
			for key, value := range kernel.Bases {
				table.Bases[key] = value
			}
		}
	}
	var pools struct {
		Cases []struct {
			Width int
			Vista bool
			ISF   json.RawMessage
		}
	}
	read("windows-poolscanner-oracle.json", &pools)
	for _, c := range pools.Cases {
		if c.Width == width && c.Vista {
			pool, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range pool.Types {
				table.Types[key] = value
			}
			for key, value := range pool.Bases {
				table.Bases[key] = value
			}
			break
		}
	}
	table.Symbols["ObTypeIndexTable"] = symbols.Symbol{Address: 0x1a000}
	table.Symbols["KdCopyDataBlock"] = symbols.Symbol{Address: 0x1b000}
	allocation := uint64(0x12000)
	root := allocation + uint64(width*2)
	found := false
	for _, c := range objects.Cases {
		if c.Layout == name && c.Type == typ && c.Scenario == scenario && c.Family == 23 {
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil {
					t.Fatal(err)
				}
				at := w.Offset
				if at >= 0x1000 && at < 0x2000 {
					at = int(root) + at - 0x1000
				}
				copy(data[at:], b)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("network fixture absent")
	}
	raw, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := winnet.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	size, err := layout.DeclaredSize(typ)
	if err != nil {
		t.Fatal(err)
	}
	align := uint64(width * 2)
	data[allocation+2], data[allocation+3] = byte((size+align-1)/align), 2
	tag := map[string]string{"_TCP_ENDPOINT": "TcpE", "_TCP_LISTENER": "TcpL", "_UDP_ENDPOINT": "UdpA"}[typ]
	copy(data[allocation+4:], tag)
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "network-symbols"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "network-symbols", name+"-"+layout.Digest()+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// The referenced 0x20000 pointer denotes a genuine source hole. Keep the
	// KUSER page and tables but omit that physical interval.
	data = data[:0x20000]
	intel, err := memory.NewIntelForOS(data, 0x8000, arch, "windows", 16)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	return plugin.Environment{OS: "windows", Architecture: arch, ImageHash: "network-pipeline-original", Offline: true, SymbolCache: cache, Physical: data, Kernel: kernel, Symbols: table, Objects: &object.Reader{Layer: kernel, Symbols: table}}, data
}

func TestNetworkAcquisitionOriginalCapturesAndBounds(t *testing.T) {
	b := windowsNetScanPlugins()[0]
	for _, arch := range []string{"x86", "pae", "x64"} {
		for _, typ := range []string{"_TCP_ENDPOINT", "_TCP_LISTENER", "_UDP_ENDPOINT"} {
			t.Run(arch+typ, func(t *testing.T) {
				e, data := networkPipelineFixture(t, arch, typ, "normal")
				p, err := plugin.Parameters(b.spec, nil)
				if err != nil {
					t.Fatal(err)
				}
				networks, reads := 0, 0
				completed := false
				err = b.run(context.Background(), e, p, func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "network":
						networks++
						if row.Cells["Owner"].String() != "System" || row.Cells["Created"].String() != "2025-01-01T00:00:00Z" {
							t.Fatal(row.Cells)
						}
					case "task_summary":
						completed = row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data == true
					case "memory_read":
						reads++
						at, _ := row.Cells["Offset"].Uint()
						requested, _ := row.Cells["Requested"].Uint()
						var layer memory.MemoryLayer = data
						if row.Cells["Layer"].String() == e.Kernel.Name() {
							layer = e.Kernel
						}
						original, err := memory.Read(context.Background(), layer, at, int(requested))
						if err != nil {
							t.Fatal("unexpected original fault", err)
						}
						sum := sha256.Sum256(original)
						if row.Cells["SHA256"].String() != hex.EncodeToString(sum[:]) {
							t.Fatal("false read digest")
						}
						if raw, ok := row.Cells["Raw"]; ok && !bytes.Equal(raw.Data.([]byte), original) {
							t.Fatal("false original bytes")
						}
					}
					return nil
				})
				if err != nil || networks != 1 || reads == 0 || !completed {
					t.Fatal("acquisition", networks, reads, completed, err)
				}
				for name, value := range map[string]string{"max-reads": "1", "max-read-bytes": "1", "max-rows": "1"} {
					params, _ := plugin.Parameters(b.spec, map[string]string{name: value})
					if err := b.run(context.Background(), e, params, func(evidence.Row) error { return nil }); err == nil {
						t.Fatal("bound ignored", name)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := b.run(ctx, e, p, func(evidence.Row) error { t.Fatal("output after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				stop := errors.New("emitter stopped")
				calls := 0
				if err := b.run(context.Background(), e, p, func(evidence.Row) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
					t.Fatal("output stop lost", calls, err)
				}

			})
		}
	}
}

func TestNetworkCorruptAndMissingPagesRemainDistinct(t *testing.T) {
	b := windowsNetScanPlugins()[0]
	for _, scenario := range []string{"invalid-state", "missing-family", "missing-local"} {
		t.Run(scenario, func(t *testing.T) {
			e, _ := networkPipelineFixture(t, "x64", "_TCP_ENDPOINT", scenario)
			for _, corrupt := range []string{"false", "true"} {
				p, _ := plugin.Parameters(b.spec, map[string]string{"include-corrupt": corrupt})
				networks, candidates, faults := 0, 0, 0
				completed := false
				err := b.run(context.Background(), e, p, func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "network":
						networks++
						if corrupt == "true" && row.Cells["Validity"].String() != "not_checked_include_corrupt" {
							t.Fatal("corrupt bypass mislabeled")
						}
					case "network_candidate":
						candidates++
					case "memory_read":
						if row.Cells["Error"].Kind == "missing" {
							faults++
						}
					case "task_summary":
						completed = row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data == true
					}
					return nil
				})
				if scenario == "invalid-state" {
					if err != nil || faults != 0 || !completed {
						t.Fatal("semantic rejection became source failure", err, faults, completed)
					}
					if corrupt == "false" && (networks != 0 || candidates != 1) || corrupt == "true" && networks != 1 {
						t.Fatal("corrupt semantics", networks, candidates)
					}
				} else {
					if err == nil || faults == 0 || completed {
						t.Fatal("actual missing page became successful absence", err, faults, completed)
					}
					if scenario == "missing-local" && networks != 1 {
						t.Fatal("raw owner PID fallback lost", networks)
					}
				}
			}
		})
	}
}

func TestNetworkWrongOwnerSymbolsAreExplicitFailure(t *testing.T) {
	e, _ := networkPipelineFixture(t, "x64", "_TCP_ENDPOINT", "normal")
	table := e.Symbols.(*symbols.ISF)
	process := table.Types["_EPROCESS"]
	delete(process.Fields, "ImageFileName")
	table.Types["_EPROCESS"] = process
	b := windowsNetScanPlugins()[0]
	p, _ := plugin.Parameters(b.spec, nil)
	if err := b.run(context.Background(), e, p, func(evidence.Row) error { t.Fatal("wrong owner symbols produced apparent results"); return nil }); err == nil {
		t.Fatal("wrong symbols became clean empty scan")
	}
}

type networkOwnerHole struct{ memory.MemoryLayer }

func (l networkOwnerHole) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at >= 0x6000 && at < 0x6080 {
		return 0, fmt.Errorf("owner page unavailable")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

func TestNetworkOwnerReadFailureIsNotInvalidOwner(t *testing.T) {
	e, _ := networkPipelineFixture(t, "x64", "_TCP_ENDPOINT", "normal")
	schema, err := os.ReadFile(filepath.Join(os.Getenv("GOMEM_BASELINE_DIR"), "volatility3/framework/symbols/windows/netscan/netscan-win7-x64.json"))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := winnet.Parse(schema)
	if err != nil {
		t.Fatal(err)
	}
	e.Kernel = networkOwnerHole{e.Kernel}
	o := winnet.Object{Layout: layout, Layer: e.Physical, Native: e.Kernel, Address: 0x12010, Type: "_TCP_ENDPOINT"}
	row := poolScannerRow(e.Physical.Name(), 0x12010)
	if err := networkOwner(context.Background(), e, o, &row); err == nil {
		t.Fatal("owner read fault became clean invalid owner")
	}
	for _, key := range []string{"PID", "Owner", "ProcessIdentity"} {
		if row.Cells[key].Reason != "network_owner_read_failed" || row.Cells[key].Error == "" {
			t.Fatal("owner read error lost", key, row.Cells[key])
		}
	}
}

func TestNetworkCompletePinnedGenerators(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for complete network generator controls")
	}
	raw, err := os.ReadFile("testdata/windows-netscan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Arch, Layout, Type, Scenario string
			Family, Size                 int
			ISF                          json.RawMessage
			Writes                       []networkWrite
			Results                      []struct {
				Corrupt     bool `json:"include_corrupt"`
				Rows        [][]json.RawMessage
				Faults      []json.RawMessage `json:"read_faults"`
				Unavailable []json.RawMessage `json:"unavailable_checks"`
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 144 {
		t.Fatal("complete generator fixture drift")
	}
	cache := t.TempDir()
	if err := os.Mkdir(filepath.Join(cache, "network-symbols"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netscan-win7-x86", "netscan-win7-x64"} {
		data, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if err := os.WriteFile(filepath.Join(cache, "network-symbols", name+"-"+hex.EncodeToString(sum[:])+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := windowsNetScanPlugins()[0]
	fields := []string{"Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"}
	for index, c := range fixture.Cases {
		t.Run(fmt.Sprint(index)+c.Arch+c.Type+c.Scenario, func(t *testing.T) {
			data := networkBytes(t, c.Size, c.Writes)
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			intel, err := memory.NewIntelForOS(data, 0x8000, c.Arch, "windows", 16)
			if err != nil {
				t.Fatal(err)
			}
			kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
			e := plugin.Environment{OS: "windows", Architecture: c.Arch, Offline: true, SymbolCache: cache, Symbols: table, Physical: data, Kernel: kernel, Objects: &object.Reader{Layer: kernel, Symbols: table}}
			for _, result := range c.Results {
				p, _ := plugin.Parameters(b.spec, map[string]string{"include-corrupt": fmt.Sprint(result.Corrupt)})
				var rows []evidence.Row
				faults := 0
				completed := false
				err := b.run(context.Background(), e, p, func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "network":
						rows = append(rows, row)
					case "memory_read":
						if row.Cells["Error"].Kind == "missing" {
							faults++
						}
					case "task_summary":
						completed = row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data == true
					}
					return nil
				})
				if (err != nil) != (len(result.Faults)+len(result.Unavailable) > 0) || completed != (err == nil) || (faults > 0) != (len(result.Faults)+len(result.Unavailable) > 0) {
					t.Fatal("complete generator source fault distinction", result.Corrupt, err, completed, faults, len(result.Faults))
				}
				if len(rows) != len(result.Rows) {
					t.Fatal("complete generator row count", result.Corrupt, len(rows), len(result.Rows), err)
				}
				for i, want := range result.Rows {
					if len(want) != len(fields) {
						t.Fatal("reference column drift")
					}
					for j, key := range fields {
						got := rows[i].Cells[key]
						if string(want[j]) == "null" {
							if got.Kind != "missing" {
								t.Fatal("absent became value", key, got)
							}
							continue
						}
						if key == "Offset" || key == "LocalPort" || key == "ForeignPort" || key == "PID" {
							var expected uint64
							if err := json.Unmarshal(want[j], &expected); err != nil {
								t.Fatal(err)
							}
							value, err := got.Uint()
							if err != nil || value != expected {
								t.Fatal("numeric generator drift", key, got, expected)
							}
						} else {
							var expected string
							if err := json.Unmarshal(want[j], &expected); err != nil {
								t.Fatal(err)
							}
							if key == "Created" && len(expected) > 6 && expected[len(expected)-6:] == "+00:00" {
								expected = expected[:len(expected)-6] + "Z"
							}
							if got.String() != expected {
								t.Fatal("generator field drift", key, got, expected)
							}
						}
					}
				}
			}
		})
	}
}

func FuzzNetworkAcquisition(f *testing.F) {
	e, original := networkPipelineFixture(f, "x64", "_TCP_ENDPOINT", "normal")
	f.Add([]byte{}, uint16(0), false)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint16(2), true)
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, uint16(24), false)
	b := windowsNetScanPlugins()[0]
	p, err := plugin.Parameters(b.spec, map[string]string{"max-reads": "2048", "max-read-bytes": "4194304", "max-rows": "4096", "include-corrupt": "true"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, mutation []byte, offset uint16, cancelNow bool) {
		if len(mutation) > 4096 {
			mutation = mutation[:4096]
		}
		data := append(flatMemory(nil), original...)
		at := 0x12000 + int(offset)%4096
		copy(data[at:], mutation)
		intel, err := memory.NewIntelForOS(data, 0x8000, "x64", "windows", 16)
		if err != nil {
			t.Fatal(err)
		}
		kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
		env := e
		env.Physical = data
		env.Kernel = kernel
		env.Objects = &object.Reader{Layer: kernel, Symbols: e.Symbols}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cancelNow {
			cancel()
		}
		rows := 0
		runErr := b.run(ctx, env, p, func(row evidence.Row) error {
			if cancelNow {
				t.Fatal("output after cancellation")
			}
			rows++
			if rows > 4096 {
				t.Fatal("evidence bound bypassed")
			}
			if row.Cells["RecordType"].String() == "memory_read" {
				at, _ := row.Cells["Offset"].Uint()
				requested, _ := row.Cells["Requested"].Uint()
				captured, _ := row.Cells["Captured"].Uint()
				if requested > 4194304 || captured > requested {
					t.Fatal("unbounded read capture")
				}
				var layer memory.MemoryLayer = data
				if row.Cells["Layer"].String() == kernel.Name() {
					layer = kernel
				}
				buf := make([]byte, int(requested))
				n, _ := layer.ReadAt(context.Background(), buf, at)
				if uint64(n) != captured {
					t.Fatal("false capture length")
				}
				sum := sha256.Sum256(buf[:n])
				if row.Cells["SHA256"].String() != hex.EncodeToString(sum[:]) {
					t.Fatal("false source digest")
				}
				if raw, ok := row.Cells["Raw"]; ok && !bytes.Equal(raw.Data.([]byte), buf[:n]) {
					t.Fatal("false source bytes")
				}
			}
			return nil
		})
		if cancelNow && !errors.Is(runErr, context.Canceled) {
			t.Fatal("cancellation lost", runErr)
		}
	})
}
