package wingui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type guiVersionFixture struct {
	Commit  string
	Catalog map[string]struct {
		SHA256 string
		Source string `json:"source_gzip_base64"`
	}
	Cases []struct {
		Label  string
		ISF    json.RawMessage
		Result struct{ Name, Error, Method string }
	}
}

func guiVersions(t testing.TB) guiVersionFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture guiVersionFixture
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 749 || len(fixture.Catalog) != 12 {
		t.Fatal("GUI version fixture drift")
	}
	return fixture
}
func guiSource(t testing.TB, name string) []byte {
	t.Helper()
	entry, ok := guiVersions(t).Catalog[name]
	if !ok {
		t.Fatal("unknown GUI source", name)
	}
	encoded, err := base64.StdEncoding.DecodeString(entry.Source)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		t.Fatal("invalid GUI source", err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		t.Fatal("original GUI source digest differs")
	}
	return raw
}
func TestGUIVersionOriginalTableSelections(t *testing.T) {
	for _, c := range guiVersions(t).Cases {
		t.Run(c.Label, func(t *testing.T) {
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Select(table)
			if c.Result.Error != "" {
				if err == nil {
					t.Fatal("original unsupported but native selected", got)
				}
				return
			}
			if err != nil || got.Name != c.Result.Name {
				t.Fatal(got, c.Result, err)
			}
			if got.Method != c.Result.Method {
				t.Fatal("missing selection provenance", got)
			}
		})
	}
	if _, err := Select(nil); err == nil {
		t.Fatal("nil table accepted")
	}
}
func TestGUILayoutOriginalProjections(t *testing.T) {
	fixture := guiVersions(t)
	for name, entry := range fixture.Catalog {
		t.Run(name, func(t *testing.T) {
			raw := guiSource(t, name)
			layout, err := ParseLayout(raw)
			if err != nil {
				t.Fatal(err)
			}
			if layout.SHA256 != entry.SHA256 || len(layout.Types.Types) != 4 {
				t.Fatal("projection lost source identity", layout)
			}
			var original struct {
				Types map[string]symbols.Type `json:"user_types"`
			}
			if err = json.Unmarshal(raw, &original); err != nil {
				t.Fatal(err)
			}
			for name, typ := range layout.Types.Types {
				if typ.Size != original.Types[name].Size {
					t.Fatal("changed object size")
				}
				for member, field := range typ.Fields {
					a, _ := json.Marshal(field)
					b, _ := json.Marshal(original.Types[name].Fields[member])
					if !bytes.Equal(a, b) {
						t.Fatal("changed original field", name, member)
					}
				}
			}
		})
	}
}
func TestGUILayoutRejectsMalformedFields(t *testing.T) {
	seed := guiSource(t, "gui-win10-19041-x64")
	for _, mode := range []string{"width", "missing", "scalar", "pointer", "list", "list-tail", "pointer-tail", "scalar-tail", "size", "offset"} {
		t.Run(mode, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(seed, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			station := types["tagWINDOWSTATION"].(map[string]any)
			fields := station["fields"].(map[string]any)
			switch mode {
			case "width":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			case "missing":
				delete(types, "tagDESKTOP")
			case "scalar":
				fields["dwSessionId"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "tagDESKTOP"}}
			case "pointer":
				fields["rpwinstaNext"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "wrong"}}
			case "list":
				types["tagDESKTOP"].(map[string]any)["fields"].(map[string]any)["PtiList"].(map[string]any)["type"] = map[string]any{"kind": "struct", "name": "_LIST_ENTRY"}
			case "list-tail":
				desktop := types["tagDESKTOP"].(map[string]any)
				desktop["fields"].(map[string]any)["PtiList"].(map[string]any)["offset"] = desktop["size"].(float64) - 8
			case "pointer-tail":
				fields["rpdeskList"].(map[string]any)["offset"] = station["size"].(float64) - 4
			case "scalar-tail":
				fields["dwSessionId"].(map[string]any)["offset"] = station["size"].(float64) - 2
			case "size":
				station["size"] = 1
			case "offset":
				fields["rpdeskList"].(map[string]any)["offset"] = -1
			}
			raw, _ := json.Marshal(doc)
			if _, err := ParseLayout(raw); err == nil {
				t.Fatal("malformed layout accepted")
			}
		})
	}
}
func FuzzGUILayout(f *testing.F) {
	raw := guiSource(f, "gui-win10-19041-x64")
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		layout, err := ParseLayout(data)
		if err != nil {
			return
		}
		if layout.Types.PointerSize() != 8 || len(layout.Types.Types) != 4 {
			t.Fatal("invalid GUI layout accepted")
		}
	})
}
