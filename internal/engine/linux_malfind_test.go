package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func malfindEngine(t *testing.T, arch, layout, fault string, configure ...func([]byte)) *engine.Engine {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	if arch == "x64" && layout != "list" {
		f = linuxMapsFixture(t, layout, "")
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 0x40000 {
		data = append(data, make([]byte, 0x40000-len(data))...)
	}
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(data[at:], value) }
	pointer := func(at, value uint64) {
		if arch == "x64" {
			put(at, value)
		} else {
			binary.LittleEndian.PutUint32(data[at:], uint32(value))
		}
	}
	pointer(0xe000, 0x35000)
	width := uint64(8)
	switch arch {
	case "x64":
		put(0x35000, 0x36003)
		put(0x36000, 0x37003)
		put(0x37010, 0x20003)
	case "pae":
		put(0x35000, 0x36001)
		put(0x36010, 0x20003)
	case "x86":
		width = 4
		pointer(0x35004, 0x20003)
	}
	for i := uint64(0); i < 16; i++ {
		entry := uint64(0x24000) + i*4096 | 3
		if i == 9 || i == 10 {
			entry |= 64
		}
		pointer(0x20000+i*width, entry)
		copy(data[0x24000+i*4096:], []byte{0xb8, byte(i), 0, 0, 0, 0xc3, 0x90, 0x90})
	}
	mmOffset := uint64(0)
	if arch == "x64" && layout != "list" {
		mmOffset = 16
	}
	put(0xe010+mmOffset, 0x404000)
	put(0xe018+mmOffset, 0x405000)
	put(0xe020+mmOffset, 0x4ff000)
	put(0xe028+mmOffset, 0x800000)
	for i, at := range []uint64{0x10000, 0x11000, 0x12000, 0x12100} {
		start := []uint64{0x400000, 0x404000, 0x408000, 0x40c000}[i]
		size := []uint64{8192, 8192, 12288, 8192}[i]
		pointer(at, start)
		pointer(at+8, start+size)
		put(at+40, []uint64{7, 5, 5, 5}[i])
		pointer(at+56, []uint64{0, 0, 0x13100, 0x13100}[i])
	}
	switch fault {
	case "clean":
		pointer(0x20000+9*width, 0x2d003)
		pointer(0x20000+10*width, 0x2e003)
	case "data-hole":
		pointer(0x20000, 0)
	case "scan-hole":
		pointer(0x20000+9*width, 0)
	case "root":
		pointer(0xe000, 0)
	case "owner":
		pointer(0x10020, 0)
	case "vdso":
		put(0xe028+mmOffset, 0x400000)
	case "huge":
		if arch != "x64" {
			t.Fatal("huge fixture is x64")
		}
		put(0x37010, 0xc3)
		put(0x10000, 0x401000)
		put(0x10008, 0x403000)
		put(0x10010, 0)
		put(0x10028, 5)
		put(0x10038, 0x13100)
	}
	for _, change := range configure {
		change(data)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func malfindBytes(t *testing.T, value evidence.Value) []byte {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Data string `json:"value"`
	}
	if err = json.Unmarshal(wire, &v); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLinuxMalfindNativePagingAndCache(t *testing.T) {
	for _, tc := range []struct{ arch, layout string }{{"x64", "list"}, {"x64", "dense"}, {"x64", "range"}, {"x86", "list"}, {"pae", "list"}} {
		for _, all := range []bool{false, true} {
			name := tc.arch + "/" + tc.layout
			if all {
				name += "/all"
			}
			t.Run(name, func(t *testing.T) {
				e := malfindEngine(t, tc.arch, tc.layout, "")
				params := map[string]string{"pid": "100"}
				if all {
					params["show-all-dirty-pages"] = "true"
				}
				var fresh, cached bytes.Buffer
				var retained []evidence.Row
				var findings []evidence.Row
				scans := 0
				result, err := e.Run(context.Background(), "linux.malfind", params, engine.RunOptions{Emit: func(row evidence.Row) error {
					retained = append(retained, row)
					if row.Cells["RecordType"].String() == "malfind_region" {
						findings = append(findings, row)
					}
					if row.Cells["RecordType"].String() == "dirty_scan" {
						scans++
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				want := 3
				if all {
					want = 4
				}
				if err != nil || result.Task.State != "completed" || len(findings) != want || scans != 2 {
					t.Fatal(result, err, len(findings), scans)
				}
				for i, row := range findings {
					reason := []string{"RWX", "RX", "X_DIRTY", "X_DIRTY"}[i]
					if row.Cells["Reason"].String() != reason {
						t.Fatal(row)
					}
					raw := malfindBytes(t, row.Cells["Hexdump"])
					if len(raw) != 64 || raw[0] != 0xb8 {
						t.Fatal(raw)
					}
					expected := byte([]int{0, 4, 8, 10}[i])
					if all && i == 2 {
						expected = 9
					}
					if raw[1] != expected {
						t.Fatal(raw, expected)
					}
					pc, err := row.Cells["RegionStart"].Uint()
					if err != nil {
						t.Fatal(err)
					}
					wire := bashProofFields(t, row.Cells["Disassembly"])
					address, err := wire["Address"].Uint()
					if err != nil || address != pc {
						t.Fatal(wire, err)
					}
					if wire["Architecture"].String() != "intel64" && tc.arch == "x64" || wire["Architecture"].String() != "intel" && tc.arch != "x64" {
						t.Fatal(wire)
					}
					fields := bashProofFields(t, row.Cells["FieldEvidence"])
					tr, err := memory.NewIntel(e.Env.Physical, 0x35000, tc.arch, 8)
					if err != nil {
						t.Fatal(err)
					}
					space := &memory.Virtual{Physical: e.Env.Physical, Translator: tr, ID: "independent-malfind-read"}
					for key, value := range bashProofFields(t, fields["Data"]) {
						if strings.HasPrefix(key, "Page_") {
							capture := bashProofFields(t, value)
							at, _ := capture["Address"].Uint()
							raw := malfindBytes(t, capture["Raw"])
							original, err := memory.Read(context.Background(), space, at, len(raw))
							if err != nil || !bytes.Equal(raw, original) {
								t.Fatal("process display capture differs", err)
							}
						}
					}

					verifyModuleParameterWireCaptures(t, e, fields["VMA"])
					verifyModuleParameterWireCaptures(t, e, fields["Flags"])
					verifyModuleParameterWireCaptures(t, e, fields["File"])
					verifyModuleParameterWireCaptures(t, e, fields["Process"])
					if reason == "X_DIRTY" {
						leaf := bashProofFields(t, fields["DirtyLeaf"])
						capture := bashProofFields(t, leaf["Capture"])
						at, err := capture["Address"].Uint()
						if err != nil {
							t.Fatal(err)
						}
						raw := malfindBytes(t, capture["Raw"])
						actual, err := memory.Read(context.Background(), e.Env.Physical, at, len(raw))
						if err != nil || !bytes.Equal(raw, actual) {
							t.Fatal(err, raw, actual)
						}
						entry := uint64(binary.LittleEndian.Uint32(raw))
						if len(raw) == 8 {
							entry = binary.LittleEndian.Uint64(raw)
						}
						if entry&64 == 0 {
							t.Fatal("dirty bit lost", entry)
						}
					}
				}
				for _, row := range retained {
					if err = row.Verify(); err != nil {
						t.Fatal(err)
					}
				}
				replay, err := e.Run(context.Background(), "linux.malfind", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !replay.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(replay, err)
				}
			})
		}
	}
}

func TestLinuxMalfindFailureAndParameterSemantics(t *testing.T) {
	for _, tc := range []struct {
		fault    string
		params   map[string]string
		findings int
		failed   bool
	}{
		{"clean", nil, 2, false}, {"data-hole", nil, 3, true}, {"scan-hole", nil, 3, true}, {"root", nil, 0, true}, {"owner", nil, 0, true}, {"vdso", nil, 2, false}, {"huge", nil, 1, false},
		{"", map[string]string{"max-pages": "1"}, 2, true}, {"", map[string]string{"max-regions": "3"}, 0, true}, {"", map[string]string{"hexdump-size": "0"}, 3, false}, {"", map[string]string{"hexdump-size": "67108865"}, 0, true},
	} {
		t.Run(tc.fault+"/"+fmtMap(tc.params), func(t *testing.T) {
			e := malfindEngine(t, "x64", "list", tc.fault)
			p := map[string]string{"pid": "100"}
			for k, v := range tc.params {
				p[k] = v
			}
			count := 0
			result, err := e.Run(context.Background(), "linux.malfind", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "malfind_region" {
					count++
					if tc.fault == "data-hole" && count == 1 {
						if row.Cells["Error"].Reason != "display_read_incomplete" || !bytes.Equal(malfindBytes(t, row.Cells["Hexdump"]), make([]byte, 64)) {
							t.Fatal(row)
						}
					}
					if tc.fault == "huge" {
						size, err := row.Cells["RegionSize"].Uint()
						if err != nil || size != 2<<20 {
							t.Fatal(row, err)
						}
					}
				}
				return row.Verify()
			}})
			if (err != nil) != tc.failed || count != tc.findings || tc.failed && result.Task.State != "failed" {
				t.Fatal(result, err, count)
			}
		})
	}
	e := malfindEngine(t, "x64", "list", "")
	stop := errors.New("stop malfind output")
	calls := 0
	_, err := e.Run(context.Background(), "linux.malfind", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { calls++; return stop }})
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls = 0
	_, err = e.Run(ctx, "linux.malfind", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { calls++; cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}

func fmtMap(p map[string]string) string { b, _ := json.Marshal(p); return string(b) }

func TestLinuxMalfindStrictDumpLimit(t *testing.T) {
	for _, limit := range []string{"0", "4096", "4097", "8192", "8193"} {
		t.Run(limit, func(t *testing.T) {
			e := malfindEngine(t, "x64", "list", "")
			var outputs []string
			result, err := e.Run(context.Background(), "linux.malfind", map[string]string{"pid": "100", "dump-regions": "true", "dump-maxsize": limit}, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "malfind_region" {
					outputs = append(outputs, row.Cells["FileOutput"].Kind)
				}
				return nil
			}})
			want := []string{"missing", "missing", "missing"}
			if limit == "4097" || limit == "8192" {
				want[2] = "artifact"
			}
			if limit == "8193" {
				want = []string{"artifact", "artifact", "artifact"}
			}
			if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(outputs, want) {
				t.Fatal(result, err, outputs, want)
			}
			if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
				t.Fatal(err)
			}
			artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, kind := range want {
				if kind == "artifact" {
					count++
				}
			}
			if len(artifacts) != count {
				t.Fatal(artifacts)
			}
			tr, _ := memory.NewIntel(e.Env.Physical, 0x35000, "x64", 8)
			space := &memory.Virtual{Physical: e.Env.Physical, Translator: tr, ID: "independent-extraction"}
			for _, a := range artifacts {
				start, _ := strconv.ParseUint(a.Provenance.Offset, 0, 64)
				size, _ := strconv.ParseUint(a.Size, 10, 64)
				original, err := memory.Read(context.Background(), space, start, int(size))
				if err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(filepath.Join(e.Store.Dir, a.Path))
				if err != nil || !bytes.Equal(original, actual) || a.MissingBytes != "0" {
					t.Fatal(a, err)
				}
			}

		})
	}
}

type malfindOracleRow struct {
	PID                    uint64
	Process                string
	Start, End             uint64
	Path, Protection, Data string
	DataAddress            uint64 `json:"data_address"`
	RegionStart            uint64 `json:"region_start"`
	RegionSize             uint64 `json:"region_size"`
	DisasmAddress          uint64 `json:"disasm_address"`
	DisasmData             string `json:"disasm_data"`
	Architecture           string
	FileOutput             string `json:"file_output"`
}

func TestLinuxMalfindPinnedTraversal(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-malfind-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []struct {
			Bits     int
			Scenario string
			All      bool `json:"all_pages"`
			Rows     []malfindOracleRow
		}
		Flags []struct {
			Protection string
			File       uint64
			Result     []uint64
			Pages      [][]uint64 `json:"dirty_pages"`
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 24 || len(oracle.Flags) != 14 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Cases {
		arches := []string{"x64"}
		if tc.Bits == 32 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(arch+"/"+tc.Scenario+"/"+strconv.FormatBool(tc.All), func(t *testing.T) {
				e := malfindEngine(t, arch, "list", tc.Scenario)
				p := map[string]string{"pid": "100", "show-all-dirty-pages": strconv.FormatBool(tc.All)}
				if tc.Scenario == "zero-data" {
					p["hexdump-size"] = "0"
				}
				var actual []malfindOracleRow
				_, err := e.Run(context.Background(), "linux.malfind", p, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Cells["RecordType"].String() != "malfind_region" {
						return nil
					}
					get := func(key string) uint64 {
						value, err := row.Cells[key].Uint()
						if err != nil {
							t.Fatal(key, err)
						}
						return value
					}
					disasm := bashProofFields(t, row.Cells["Disassembly"])
					address, err := disasm["Address"].Uint()
					if err != nil {
						t.Fatal(err)
					}
					actual = append(actual, malfindOracleRow{get("PID"), row.Cells["Process"].String(), get("Start"), get("End"), row.Cells["Path"].String(), row.Cells["Protection"].String(), hex.EncodeToString(malfindBytes(t, row.Cells["Hexdump"])), get("DataAddress"), get("RegionStart"), get("RegionSize"), address, hex.EncodeToString(malfindBytes(t, disasm["Bytes"])), disasm["Architecture"].String(), "Disabled"})
					return row.Verify()
				}})
				failed := tc.Scenario == "data-hole" || tc.Scenario == "scan-hole"
				if (err != nil) != failed || !reflect.DeepEqual(actual, tc.Rows) {
					t.Fatal(err, actual, tc.Rows)
				}
			})
		}
	}
	for _, tc := range oracle.Flags {
		t.Run("flags/"+tc.Protection+"/"+strconv.FormatUint(tc.File, 10), func(t *testing.T) {
			e := malfindEngine(t, "x64", "list", "huge", func(data []byte) {
				flags := uint64(0)
				for i, c := range "rwx" {
					if rune(tc.Protection[i]) == c {
						flags |= 1 << i
					}
				}
				binary.LittleEndian.PutUint64(data[0x10028:], flags)
				file := uint64(0)
				if tc.File != 0 {
					file = 0x13100
				}
				binary.LittleEndian.PutUint64(data[0x10038:], file)
			})
			var actual []uint64
			_, err := e.Run(context.Background(), "linux.malfind", map[string]string{"pid": "100", "show-all-dirty-pages": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "malfind_region" {
					start, _ := row.Cells["RegionStart"].Uint()
					size, _ := row.Cells["RegionSize"].Uint()
					reason := map[string]uint64{"RWX": 0, "RX": 1, "X_DIRTY": 2}[row.Cells["Reason"].String()]
					actual = []uint64{start, size, reason}
				}
				return nil
			}})
			if err != nil || !reflect.DeepEqual(actual, tc.Result) {
				t.Fatal(err, actual, tc.Result)
			}
		})
	}
}

func TestLinuxMalfindDumpGaps(t *testing.T) {
	e := malfindEngine(t, "x64", "list", "data-hole")
	var artifact evidence.Artifact
	result, err := e.Run(context.Background(), "linux.malfind", map[string]string{"pid": "100", "dump-regions": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["Reason"].String() == "RWX" {
			artifact = row.Cells["FileOutput"].Data.(evidence.Artifact)
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || artifact.MissingBytes != "4096" || artifact.Size != "8192" {
		t.Fatal(result, err, artifact)
	}
	raw, err := os.ReadFile(filepath.Join(e.Store.Dir, artifact.Path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[:4096], make([]byte, 4096)) || raw[4096] != 0xb8 || raw[4097] != 1 {
		t.Fatal(artifact)
	}
	raw, err = os.ReadFile(filepath.Join(e.Store.Dir, artifact.GapsPath))
	if err != nil {
		t.Fatal(err)
	}
	var gap evidence.ArtifactGap
	if err = json.Unmarshal(bytes.TrimSpace(raw), &gap); err != nil || gap.Address != "0x400000" || gap.Offset != "0x0" || gap.Length != "4096" || gap.Layer != artifact.Provenance.Layer {
		t.Fatal(gap, err)
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
		t.Fatal(err)
	}
}
