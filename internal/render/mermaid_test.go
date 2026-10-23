package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestMermaidEvidenceTree(t *testing.T) {
	var out bytes.Buffer
	w, err := New(&out, "mermaid", []evidence.Column{{Name: "PID", Kind: "number"}, {Name: "Name", Kind: "string"}})
	if err != nil {
		t.Fatal(err)
	}
	rows := []evidence.Row{
		{ID: "root", Cells: map[string]evidence.Value{"PID": evidence.Number(1), "Name": evidence.Text("parent")}},
		{ID: "child", ParentID: "root", Cells: map[string]evidence.Value{"PID": evidence.Number(1), "Name": evidence.Text("child")}},
		{ID: "leaf", ParentID: "child", Cells: map[string]evidence.Value{"PID": evidence.Number(2), "Name": evidence.Text("leaf")}},
		{ID: "sibling", ParentID: "root", Cells: map[string]evidence.Value{"PID": evidence.Number(3), "Name": evidence.Text("sibling")}},
		{ID: "root", Cells: map[string]evidence.Value{"PID": evidence.Number(1), "Name": evidence.Text("parent")}},
	}
	for _, row := range rows {
		if err = w.Row(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	want := "graph TD\n\tn1[\"PID:1<br>Name:parent\"]\n\tn1 --> n2[\"PID:1<br>Name:child\"]\n\tn2 --> n3[\"PID:2<br>Name:leaf\"]\n\tn1 --> n4[\"PID:3<br>Name:sibling\"]\n\tn5[\"PID:1<br>Name:parent\"]\n"
	if out.String() != want {
		t.Fatalf("%s", &out)
	}
	if err = w.Row(evidence.Row{ParentID: "missing"}); err == nil {
		t.Fatal("invented missing parent")
	}
}

func TestMermaidUntrustedLabelsAndMissingData(t *testing.T) {
	var out bytes.Buffer
	w, err := New(&out, "mermaid", []evidence.Column{{Name: "<Name>", Kind: "string"}, {Name: "Address", Kind: "address"}, {Name: "Missing", Kind: "string"}})
	if err != nil {
		t.Fatal(err)
	}
	err = w.Row(evidence.Row{ID: "x\"]\nInjected", Cells: map[string]evidence.Value{"<Name>": evidence.Text("\"]\n<script>&`\\\r\nnext"), "Address": evidence.Address(0xffffffffffffffff)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"&lt;Name&gt;:&quot;]<br>&lt;script&gt;&amp;&#96;&#92;<br>next", "Address:0xffffffffffffffff", "Missing:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
	if strings.Contains(out.String(), "Injected") || strings.Contains(out.String(), "<script>") {
		t.Fatal(&out)
	}
	if strings.Count(out.String(), "\n") != 2 {
		t.Fatal("label escaped node boundary", &out)
	}
}

type mermaidFailWriter struct{ err error }

func (w mermaidFailWriter) Write([]byte) (int, error) { return 0, w.err }
func TestMermaidWriteFailure(t *testing.T) {
	sentinel := errors.New("output failed")
	if _, err := New(mermaidFailWriter{sentinel}, "mermaid", nil); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := New(&out, "mermaid", nil)
	if err != nil {
		t.Fatal(err)
	}
	w.w = mermaidFailWriter{sentinel}
	if err = w.Row(evidence.Row{ID: "root"}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, exists := w.nodes["root"]; exists {
		t.Fatal("failed node published")
	}
}

func TestMermaidPinnedRenderer(t *testing.T) {
	raw, err := os.ReadFile("testdata/mermaid-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Baseline string `json:"baseline_commit"`
		Cases    []struct {
			Name string
			Rows []struct {
				Depth int
				PID   uint64
				Name  string
			}
			Output string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	if oracle.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 6 {
		t.Fatal("oracle drift")
	}
	for _, test := range oracle.Cases {
		t.Run(test.Name, func(t *testing.T) {
			var out bytes.Buffer
			w, err := New(&out, "mermaid", []evidence.Column{{Name: "PID", Kind: "number"}, {Name: "Name", Kind: "string"}})
			if err != nil {
				t.Fatal(err)
			}
			var stack []string
			for i, item := range test.Rows {
				row := evidence.Row{ID: fmt.Sprint(i + 1), Cells: map[string]evidence.Value{"PID": evidence.Number(item.PID), "Name": evidence.Text(item.Name)}}
				if item.Depth > 0 {
					row.ParentID = stack[item.Depth-1]
				}
				stack = append(stack[:item.Depth], row.ID)
				if err = w.Row(row); err != nil {
					t.Fatal(err)
				}
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if out.String() != test.Output {
				t.Fatalf("native:\n%sreference:\n%s", &out, test.Output)
			}
		})
	}
}
