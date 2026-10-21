package engine_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type fbOracleRow struct {
	Address, Size, BPP                     uint64
	Device                                 string
	ID                                     *string
	Resolution, State, Filename, RGBA, Raw string
}
type fbOracleCase struct {
	Width    int
	Scenario string
	ISF      json.RawMessage
	Writes   [][]json.RawMessage
	Expected []fbOracleRow
}

func loadFBOracle(t testing.TB) []fbOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-fbdev-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []fbOracleCase
	}
	if err = json.Unmarshal(raw, &v); err != nil || len(v.Cases) != 26 || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func TestLinuxFbdevPinnedObjectsExportPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadFBOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s", arch, c.Scenario), func(t *testing.T) {
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, "")
				for _, dump := range []bool{false, true} {
					got := []fbOracleRow{}
					reads := 0
					var fresh, cached bytes.Buffer
					params := map[string]string{"dump": fmt.Sprint(dump)}
					result, err := e.Run(context.Background(), "linux.fbdev", params, engine.RunOptions{Emit: func(row evidence.Row) error {
						if row.Verify() != nil {
							t.Fatal("unsealed")
						}
						switch row.Cells["RecordType"].String() {
						case "framebuffer_read":
							reads++
							verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						case "framebuffer":
							r := fbOracleRow{Device: row.Cells["Device"].String(), Resolution: row.Cells["Virtual resolution"].String(), State: row.Cells["State"].String()}
							r.Address, _ = row.Cells["Address"].Uint()
							r.Size, _ = row.Cells["Size"].Uint()
							r.BPP, _ = row.Cells["BPP"].Uint()
							if row.Cells["ID"].Kind != "missing" {
								s := row.Cells["ID"].String()
								r.ID = &s
							}
							if dump {
								a, ok := row.Cells["Filename"].Data.(evidence.Artifact)
								if !ok || a.State != "completed" {
									t.Fatalf("artifact %+v", row)
								}
								r.Filename = a.Name
								raw, err := os.ReadFile(filepath.Join(e.Config.CaseDir, a.Path))
								if err != nil {
									t.Fatal(err)
								}
								if filepath.Ext(a.Name) == ".png" {
									img, err := png.Decode(bytes.NewReader(raw))
									if err != nil {
										t.Fatal(err)
									}
									var pixels []byte
									for y := 0; y < img.Bounds().Dy(); y++ {
										for x := 0; x < img.Bounds().Dx(); x++ {
											v := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
											pixels = append(pixels, v.R, v.G, v.B, v.A)
										}
									}
									r.RGBA = hex.EncodeToString(pixels)
								} else {
									r.Raw = hex.EncodeToString(raw)
								}
							} else if row.Cells["Filename"].String() != "Disabled" {
								t.Fatal(row)
							}
							got = append(got, r)
						default:
							t.Fatal(row)
						}
						return json.NewEncoder(&fresh).Encode(row)
					}})
					want := make([]fbOracleRow, len(c.Expected))
					copy(want, c.Expected)
					if !dump {
						for i := range want {
							want[i].Filename = ""
							want[i].RGBA = ""
							want[i].Raw = ""
						}
					}
					if err != nil || result.Task.State != "completed" || reads == 0 || !reflect.DeepEqual(got, want) {
						t.Fatalf("dump=%v err=%v state=%s\ngot=%+v\nwant=%+v", dump, err, result.Task.State, got, want)
					}
					if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
						t.Fatal(err)
					}
					rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
					if err != nil || len(rows) != int(result.Task.Rows) {
						t.Fatal(err, len(rows), result)
					}
					for _, row := range rows {
						if row.Verify() != nil {
							t.Fatal("stored seal")
						}
					}
					again, err := e.Run(context.Background(), "linux.fbdev", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
					if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
						t.Fatal(again, err)
					}
				}
			})
		}
	}
}

func TestLinuxFbdevFailedAcquisitionIsNotCached(t *testing.T) {
	for _, c := range loadFBOracle(t) {
		if c.Scenario != "normal" {
			continue
		}
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/fault", arch), func(t *testing.T) {
				at, _ := json.Marshal(0x11000 + 96)
				raw := "00003000"
				if c.Width == 8 {
					raw += "00000000"
				}
				payload, _ := json.Marshal(raw)
				writes := append(append([][]json.RawMessage{}, c.Writes...), []json.RawMessage{at, payload})
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: writes}, arch, "")
				var first string
				for attempt := 0; attempt < 2; attempt++ {
					selected, failed := 0, 0
					result, err := e.Run(context.Background(), "linux.fbdev", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
						if row.Verify() != nil {
							t.Fatal("seal")
						}
						if row.Cells["RecordType"].String() == "framebuffer" {
							selected++
							if row.Cells["Error"].Reason == "framebuffer_incomplete" {
								failed++
							}
						}
						return nil
					}})
					if err == nil || result.Task.State != "failed" || result.Reused || selected != 2 || failed != 1 || result.Task.ID == first {
						t.Fatal(result, err, selected, failed)
					}
					first = result.Task.ID
					artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
					if err != nil || len(artifacts) != 1 || artifacts[0].State != "completed" {
						t.Fatal(artifacts, err)
					}
				}
			})
		}
	}
}
