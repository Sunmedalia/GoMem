package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Audit an existing real acquisition rather than rerunning or accepting a
// filtered JSON result as evidence that all rows were sealed and source-backed.
func TestWindowStationsCorpusSealedOriginalAndReadAudit(t *testing.T) {
	auditWindowsGUICorpus(t, "windows.windowstations", "windowstation", "GOMEM_WINSTA_")
}
func TestDesktopsCorpusSealedOriginalAndReadAudit(t *testing.T) {
	name := os.Getenv("GOMEM_GUI_PLUGIN")
	if name == "" {
		t.Skip("set GOMEM_GUI_PLUGIN=windows.desktops or windows.deskscan and GOMEM_GUI_* corpus inputs")
	}
	if name == "windows.windows" {
		t.Skip("window corpus is audited by TestWindowListCorpusSealedOriginalAndReadAudit")
	}
	if name != "windows.desktops" && name != "windows.deskscan" {
		t.Fatal("unsupported desktop corpus plugin")
	}
	auditWindowsGUICorpus(t, name, "desktop", "GOMEM_GUI_")
}

func TestWindowListCorpusSealedOriginalAndReadAudit(t *testing.T) {
	if os.Getenv("GOMEM_GUI_PLUGIN") != "windows.windows" {
		t.Skip("set GOMEM_GUI_PLUGIN=windows.windows and GOMEM_GUI_* corpus inputs")
	}
	auditWindowsGUICorpus(t, "windows.windows", "window", "GOMEM_GUI_")
}

type guiCorpusEntity struct {
	Offset        uint64
	Name          string
	SessionID     uint64
	WindowStation string `json:"Window Station"`
	Session       uint64
	Desktop       *string
	Process       string
	PID           uint64
	Station       string
	Window        *string
	Procedure     *uint64
}

func auditWindowsGUICorpus(t *testing.T, pluginName, recordType, prefix string) {
	t.Helper()

	image, symbol, caseDir, taskID, wirePath, referencePath := os.Getenv(prefix+"IMAGE"), os.Getenv(prefix+"SYMBOLS"), os.Getenv(prefix+"CASE"), os.Getenv(prefix+"TASK"), os.Getenv(prefix+"WIRE"), os.Getenv(prefix+"REFERENCE")
	if image == "" || symbol == "" || caseDir == "" || taskID == "" || wirePath == "" || referencePath == "" {
		t.Skip("set " + prefix + "IMAGE/SYMBOLS/CASE/TASK/WIRE/REFERENCE; see docs/windows-windowstations.md")
	}
	raw, err := os.ReadFile(referencePath)
	if err != nil {
		t.Fatal(err)
	}
	var reference []guiCorpusEntity
	if err = json.Unmarshal(raw, &reference); err != nil {
		t.Fatal(err)
	}
	if len(reference) == 0 && recordType != "window" {
		t.Fatal("requires positive original GUI control")
	}
	var manifest struct {
		Baseline     struct{ Commit string }
		ImageSHA256  string `json:"image_sha256"`
		OutputSHA256 string `json:"output_sha256"`
		ConfigSHA256 string `json:"config_sha256"`
		Plugin       string
	}
	manifestRaw, err := os.ReadFile(strings.TrimSuffix(referencePath, ".json") + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	referencePlugin := pluginName
	if pluginName == "windows.windows" {
		referencePlugin = "windows.windows.Windows"
	}
	if manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != referencePlugin || manifest.OutputSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("original GUI reference identity differs")
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: "x64", DTB: "0x6d4000", KernelBase: 0xfffff8043601f000, CaseDir: caseDir, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Env.ImageHash != manifest.ImageSHA256 {
		t.Fatal("GUI image differs from reference")
	}
	configRaw, err := os.ReadFile(strings.TrimSuffix(referencePath, ".json") + ".config.json")
	if err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(configRaw)
	if hex.EncodeToString(configHash[:]) != manifest.ConfigSHA256 {
		t.Fatal("original GUI reference configuration digest differs")
	}
	var config map[string]json.RawMessage
	if err = json.Unmarshal(configRaw, &config); err != nil {
		t.Fatal(err)
	}
	var location string
	if err = json.Unmarshal(config["kernel.symbol_table_name.isf_url"], &location); err != nil {
		t.Fatal(err)
	}
	archive, member, ok := strings.Cut(strings.TrimPrefix(location, "jar:"), "!")
	parsed, err := url.Parse(archive)
	if !ok || err != nil || parsed.Scheme != "file" || parsed.Host != "" {
		t.Fatal("this corpus control requires an original local jar:file symbol archive")
	}
	originalTable, err := symbols.Load(filepath.FromSlash(parsed.Path) + "#" + strings.TrimPrefix(member, "/"))
	if err != nil || originalTable.Digest() != e.Env.Symbols.Digest() {
		t.Fatal("native symbols differ from original archive member", err)
	}
	tasks, err := e.Store.Tasks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	state := ""
	for _, task := range tasks {
		if task.ID == taskID {
			found = true
			state = string(task.State)
			if task.Plugin != pluginName {
				t.Fatal("task is not a GUI station run")
			}
		}
	}
	if !found {
		t.Fatal("acquisition task missing")
	}
	wire, err := os.Open(wirePath)
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	decoder := json.NewDecoder(wire)
	layers := map[string]memory.MemoryLayer{e.Env.Physical.Name(): e.Env.Physical, e.Env.Kernel.Name(): e.Env.Kernel}
	got := []guiCorpusEntity{}
	var seals, reads, captured, rawRows, readFailures uint64
	counts := map[string]uint64{}
	summary := map[string]evidence.Value{}
	for offset := 0; ; offset += 1000 {
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: taskID, Offset: offset, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			seals++
			if err = row.Verify(); err != nil {
				t.Fatal(err)
			}
			if row.Provenance.ImageSHA256 != e.Env.ImageHash || row.Provenance.SymbolsSHA256 != e.Env.Symbols.Digest() {
				t.Fatal("GUI evidence image/symbol identity mismatch")
			}
			var original evidence.Row
			if err = decoder.Decode(&original); err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(row)
			b, _ := json.Marshal(original)
			if !bytes.Equal(a, b) {
				t.Fatal("sealed GUI row differs from streamed evidence", seals)
			}
			kind := row.Cells["RecordType"].String()
			counts[kind]++
			switch kind {
			case "gui_session":
				raw, _ := json.Marshal(row.Cells["Coverage"].Data)
				var coverage map[string]evidence.Value
				if err = json.Unmarshal(raw, &coverage); err != nil {
					t.Fatal(err)
				}
				cr3, err := coverage["CR3"].Uint()
				if err != nil {
					t.Fatal(err)
				}
				tr, err := memory.NewIntelForOS(e.Env.Physical, cr3, "x64", "windows", 1024)
				if err != nil {
					t.Fatal(err)
				}
				id := row.Cells["Layer"].String()
				layers[id] = &memory.Virtual{Physical: e.Env.Physical, Translator: tr, ID: id}
			case "memory_read":
				layer, ok := layers[row.Cells["Layer"].String()]
				if !ok {
					t.Fatal("capture has unknown layer", row.Cells["Layer"])
				}
				at, err := row.Cells["Offset"].Uint()
				if err != nil {
					t.Fatal(err)
				}
				requested, err := row.Cells["Requested"].Uint()
				if err != nil || requested > 1<<20 {
					t.Fatal("invalid GUI read bound", err)
				}
				n, err := row.Cells["Captured"].Uint()
				if err != nil || n > requested {
					t.Fatal("invalid GUI captured count", err)
				}
				data := make([]byte, requested)
				count, cause := layer.ReadAt(context.Background(), data, at)
				if count < 0 || uint64(count) != n {
					t.Fatal("GUI source capture count differs", at, n, count, cause)
				}
				data = data[:count]
				h := sha256.Sum256(data)
				if row.Cells["SHA256"].String() != hex.EncodeToString(h[:]) {
					t.Fatal("GUI capture digest differs from source", at)
				}
				complete, _ := row.Cells["ReadComplete"].Data.(bool)
				if complete != (cause == nil && uint64(count) == requested) {
					t.Fatal("GUI read completeness differs", at, cause)
				}
				if !complete {
					readFailures++
				}
				if v, ok := row.Cells["Raw"]; ok {
					var original []byte
					switch x := v.Data.(type) {
					case []byte:
						original = x
					case string:
						original, err = base64.StdEncoding.DecodeString(x)
					default:
						t.Fatal("invalid GUI byte representation")
					}
					if err != nil || !bytes.Equal(original, data) {
						t.Fatal("GUI raw bytes differ", at, err)
					}
					rawRows++
				}
				if row.Provenance.Layer != layer.Name() || row.Provenance.Offset != fmt.Sprintf("0x%x", at) {
					t.Fatal("GUI source coordinates differ")
				}
				reads++
				captured += n
			case recordType:
				at, _ := row.Cells["Offset"].Uint()
				entity := guiCorpusEntity{Offset: at & 0x0000ffffffffffff}
				if recordType == "windowstation" {
					entity.Name = row.Cells["Name"].String()
					entity.SessionID, _ = row.Cells["SessionId"].Uint()
				} else {
					if recordType == "window" {
						entity.Station = row.Cells["Station"].String()
						if row.Cells["Window"].Kind != "missing" {
							s := row.Cells["Window"].String()
							entity.Window = &s
						}
						if row.Cells["Procedure"].Kind != "missing" {
							n, err := row.Cells["Procedure"].Uint()
							if err != nil {
								t.Fatal(err)
							}
							n &= 0x0000ffffffffffff
							entity.Procedure = &n
						}
					} else {
						entity.WindowStation = row.Cells["WindowStation"].String()
					}
					entity.Session, _ = row.Cells["Session"].Uint()
					entity.Process = row.Cells["Process"].String()
					entity.PID, _ = row.Cells["PID"].Uint()
					if row.Cells["Desktop"].Kind != "missing" {
						name := row.Cells["Desktop"].String()
						entity.Desktop = &name
					}
				}
				got = append(got, entity)
			case "task_summary":
				raw, _ := json.Marshal(row.Cells["Coverage"].Data)
				if err = json.Unmarshal(raw, &summary); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(rows) < 1000 {
			break
		}
	}
	var extra evidence.Row
	if err = decoder.Decode(&extra); err != io.EOF {
		t.Fatal("wire has trailing evidence or error", err)
	}
	if recordType == "window" {
		for i := range reference {
			reference[i].Offset &= 0x0000ffffffffffff
			if reference[i].Procedure != nil {
				n := *reference[i].Procedure & 0x0000ffffffffffff
				reference[i].Procedure = &n
			}
		}
		compare := func(a, b guiCorpusEntity) int {
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			return bytes.Compare(x, y)
		}
		slices.SortFunc(got, compare)
		slices.SortFunc(reference, compare)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatal("original/native GUI rows differ", got, reference)
	}
	if recordType == "window" && len(reference) == 0 && (state != "failed" || readFailures == 0 || counts["gui_candidate"] == 0) {
		t.Fatal("zero-window control requires explicit failed partial acquisition and candidate evidence")
	}
	complete, _ := summary["Completed"].Data.(bool)
	if complete != (state == "completed") {
		t.Fatal("GUI task and coverage disagree", state, complete)
	}
	if readFailures > 0 && state != "failed" {
		t.Fatal("GUI read failures presented as successful")
	}
	audit := map[string]any{"image_sha256": e.Env.ImageHash, "symbols_sha256": e.Env.Symbols.Digest(), "reference_sha256": manifest.OutputSHA256, "task": taskID, "state": state, "ordered_rows": len(got), "seals_verified": seals, "source_reads_verified": reads, "captured_bytes_verified": captured, "raw_captures_verified": rawRows, "failed_reads_verified": readFailures, "record_counts": counts, "coverage": summary, "plugin": pluginName, "scope": "Same ISF archive member; independent native full GUI scan, ordered fields, stored stream and every captured read audited; no independent PDB or full OS acceptance"}
	if recordType == "window" {
		delete(audit, "ordered_rows")
		audit["entity_rows"] = len(got)
		audit["scope"] = "Same ISF archive member; eight-field window entity multiset with duplicate counts and masked addresses, child order normalized because original identity-set order is unstable; every seal and captured read audited; no independent PDB or full OS acceptance"
		if len(reference) == 0 {
			audit["scope"] = "Negative partial control only: both tools emit zero windows, native retains failed candidate/read evidence; every seal and captured source read audited; this does not establish clean absence or positive real-image recovery"
		}
	}
	data, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if path := os.Getenv(prefix + "AUDIT"); path != "" {
		if err = os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
