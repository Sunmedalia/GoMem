package render

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

func TestArrowLosslessTypesAndTree(t *testing.T) {
	cols := []evidence.Column{{Name: "Address", Kind: "address"}, {Name: "Count", Kind: "uint64"}, {Name: "Signed", Kind: "int64"}, {Name: "Flag", Kind: "bool"}, {Name: "Name", Kind: "string"}, {Name: "Bytes", Kind: "bytes"}, {Name: "Object", Kind: "structure"}, {Name: "Absent", Kind: "string"}}
	row := evidence.Row{ParentID: "parent", Cells: map[string]evidence.Value{"Address": evidence.Address(math.MaxUint64), "Count": evidence.Number(math.MaxUint64), "Signed": evidence.Integer(math.MinInt64), "Flag": evidence.Bool(false), "Name": evidence.Text(""), "Bytes": evidence.Bytes([]byte{0, 255, 1}), "Object": {Kind: "structure", Data: map[string]any{"large": json.Number("18446744073709551615"), "raw": evidence.Bytes([]byte{255})}}, "Absent": evidence.Missing("unmapped", errors.New("read failure")), "Undeclared": evidence.Text("preserved")}, Provenance: evidence.Provenance{Parameters: map[string]string{"dtb": "0x1000"}}}
	row.Seal()
	var out bytes.Buffer
	allocator := memory.NewCheckedAllocator(memory.DefaultAllocator)
	writer, err := newArrow(&out, cols, nil, allocator)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.RowForTask("task", row); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	allocator.AssertSize(t, 0)
	if err := writer.Row(row); err == nil {
		t.Fatal("closed writer accepted row")
	}
	reader, err := ipc.NewReader(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	if !reader.Next() {
		t.Fatal(reader.Err())
	}
	record := reader.RecordBatch()
	if record.Column(4).(*array.String).Value(0) != "0xffffffffffffffff" || record.Column(5).(*array.Uint64).Value(0) != math.MaxUint64 || record.Column(6).(*array.Int64).Value(0) != math.MinInt64 {
		t.Fatal("numeric precision lost")
	}
	if record.Column(7).(*array.Boolean).Value(0) || record.Column(8).(*array.String).Value(0) != "" || record.Column(8).IsNull(0) || !record.Column(11).IsNull(0) {
		t.Fatal("empty/false/missing confused")
	}
	if !bytes.Equal(record.Column(9).(*array.Binary).Value(0), []byte{0, 255, 1}) {
		t.Fatal("raw bytes changed")
	}
	var restored evidence.Row
	if err := json.Unmarshal(record.Column(3).(*array.Binary).Value(0), &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Verify(); err != nil {
		t.Fatal(err)
	}
	if restored.Cells["Absent"].Error != "read failure" || restored.Cells["Undeclared"].String() != "preserved" || restored.ParentID != "parent" {
		t.Fatal(restored)
	}
	if reader.Next() || reader.Err() != nil {
		t.Fatal(reader.Err())
	}
}
func TestArrowBoundedBatchesAndEmptyStream(t *testing.T) {
	for _, count := range []int{0, 2051} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var out bytes.Buffer
			writer, err := NewArrow(&out, []evidence.Column{{Name: "Name", Kind: "string"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				if err := writer.Row(evidence.Row{ID: fmt.Sprint(i), Cells: map[string]evidence.Value{"Name": evidence.Text("name")}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			reader, err := ipc.NewReader(bytes.NewReader(out.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Release()
			var total int64
			for reader.Next() {
				record := reader.RecordBatch()
				if record.NumRows() > arrowBatchRows {
					t.Fatal("unbounded batch")
				}
				total += record.NumRows()
			}
			if reader.Err() != nil || total != int64(count) {
				t.Fatal(total, reader.Err())
			}
		})
	}
}
func TestArrowRejectsInvalidTypesAndWrites(t *testing.T) {
	for _, cols := range [][]evidence.Column{{{Name: "_gomem_id", Kind: "string"}}, {{Name: "x", Kind: "unknown"}}, {{Name: "x", Kind: "string"}, {Name: "x", Kind: "string"}}} {
		if _, err := NewArrow(&bytes.Buffer{}, cols, nil); err == nil {
			t.Fatal("invalid schema accepted")
		}
	}
	for _, value := range []evidence.Value{evidence.Text("text"), {Kind: "uint64", Data: "18446744073709551616"}} {
		allocator := memory.NewCheckedAllocator(memory.DefaultAllocator)
		w, err := newArrow(&bytes.Buffer{}, []evidence.Column{{Name: "Count", Kind: "uint64"}}, nil, allocator)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Row(evidence.Row{Cells: map[string]evidence.Value{"Count": value}}); err == nil {
			t.Fatal("invalid value accepted")
		}
		if err := w.Close(); err == nil {
			t.Fatal("lost row failure")
		}
		allocator.AssertSize(t, 0)
	}
	failure := errors.New("output failure")
	allocator := memory.NewCheckedAllocator(memory.DefaultAllocator)
	w, err := newArrow(mermaidFailWriter{failure}, nil, nil, allocator)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Row(evidence.Row{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	allocator.AssertSize(t, 0)
}
func TestArrowPersistedBytesNilAndEmpty(t *testing.T) {
	var out bytes.Buffer
	w, err := NewArrow(&out, []evidence.Column{{Name: "Bytes", Kind: "bytes"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []evidence.Value{evidence.Bytes(nil), evidence.Value{Kind: "bytes", Data: []byte{}}, evidence.Bytes([]byte{0, 255})} {
		raw, _ := json.Marshal(evidence.Row{Cells: map[string]evidence.Value{"Bytes": v}})
		var row evidence.Row
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		if err := w.Row(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := ipc.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if !r.Next() {
		t.Fatal(r.Err())
	}
	column := r.RecordBatch().Column(4).(*array.Binary)
	// Explicit nil and empty captures keep distinct Arrow validity bits.
	if !column.IsNull(0) || column.IsNull(1) || !bytes.Equal(column.Value(2), []byte{0, 255}) {
		t.Fatal("persisted bytes differ")
	}
}

func TestArrowActualPinnedRendererOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/arrow-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Baseline string `json:"baseline_commit"`
		Cases    []struct {
			Name   string
			Depths []int
			Rows   []struct {
				Signed  *int64
				Address *string
				Name    *string
				Flag    *bool
				Bytes   *[]byte
				ID      *uint64 `json:"_vol_id"`
				Parent  *uint64 `json:"_vol_parent_id"`
			}
		}
	}
	if err := json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	if oracle.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 6 {
		t.Fatal("oracle baseline changed")
	}
	columns := []evidence.Column{{Name: "Signed", Kind: "int64"}, {Name: "Address", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "Flag", Kind: "bool"}, {Name: "Bytes", Kind: "bytes"}}
	for _, fixture := range oracle.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			var out bytes.Buffer
			w, err := NewArrow(&out, columns, nil)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, len(fixture.Rows))
			for i, source := range fixture.Rows {
				cells := map[string]evidence.Value{}
				for _, col := range columns {
					cells[col.Name] = evidence.Missing("unreadable", nil)
				}
				if source.Signed != nil {
					cells["Signed"] = evidence.Integer(*source.Signed)
				}
				if source.Address != nil {
					cells["Address"] = evidence.Value{Kind: "address", Data: *source.Address}
				}
				if source.Name != nil {
					cells["Name"] = evidence.Text(*source.Name)
				}
				if source.Flag != nil {
					cells["Flag"] = evidence.Bool(*source.Flag)
				}
				if source.Bytes != nil {
					cells["Bytes"] = evidence.Bytes(*source.Bytes)
				}
				row := evidence.Row{Cells: cells}
				if source.Parent != nil {
					if int(*source.Parent) >= i {
						t.Fatal("invalid reference parent")
					}
					row.ParentID = ids[*source.Parent]
				}
				row.Seal()
				ids[i] = row.ID
				if source.ID != nil && *source.ID != uint64(i) {
					t.Fatal("unexpected original row order")
				}
				if err := w.Row(row); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			reader, err := ipc.NewReader(&out)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Release()
			index := 0
			for reader.Next() {
				record := reader.RecordBatch()
				for i := 0; i < int(record.NumRows()); i++ {
					source := fixture.Rows[index]
					if source.Signed == nil {
						for col := 4; col < 9; col++ {
							if !record.Column(col).IsNull(i) {
								t.Fatal("missing original value not null")
							}
						}
					} else {
						if record.Column(4).(*array.Int64).Value(i) != *source.Signed || record.Column(5).(*array.String).Value(i) != *source.Address || record.Column(6).(*array.String).Value(i) != *source.Name || record.Column(7).(*array.Boolean).Value(i) != *source.Flag || !bytes.Equal(record.Column(8).(*array.Binary).Value(i), *source.Bytes) {
							t.Fatal("pinned typed value differs")
						}
					}
					if source.Parent == nil {
						if !record.Column(1).IsNull(i) {
							t.Fatal("invented parent")
						}
					} else if record.Column(1).(*array.String).Value(i) != ids[*source.Parent] {
						t.Fatal("tree parent differs")
					}
					index++
				}
			}
			if reader.Err() != nil || index != len(fixture.Rows) {
				t.Fatal(index, reader.Err())
			}
		})
	}
}

type arrowShortWriter struct{}

func (arrowShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestArrowShortWritesAndByteBatches(t *testing.T) {
	w, err := NewArrow(arrowShortWriter{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err = NewArrow(&out, []evidence.Column{{Name: "Large", Kind: "string"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Row(evidence.Row{Cells: map[string]evidence.Value{"Large": evidence.Text(strings.Repeat("x", 2<<20))}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := ipc.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	records, total := 0, int64(0)
	for reader.Next() {
		record := reader.RecordBatch()
		if record.NumRows() > 3 {
			t.Fatal("byte budget ignored")
		}
		records++
		total += record.NumRows()
	}
	if reader.Err() != nil || records != 2 || total != 5 {
		t.Fatal(records, total, reader.Err())
	}
}

func TestArrowIndependentPyArrowReader(t *testing.T) {
	python := os.Getenv("GOMEM_ARROW_REFERENCE_PYTHON")
	if python == "" {
		t.Skip("set GOMEM_ARROW_REFERENCE_PYTHON with PyArrow 26.0.0")
	}
	columns := []evidence.Column{{Name: "U", Kind: "uint64"}, {Name: "I", Kind: "int64"}, {Name: "Address", Kind: "address"}, {Name: "Bytes", Kind: "bytes"}, {Name: "Text", Kind: "string"}, {Name: "Flag", Kind: "bool"}, {Name: "Object", Kind: "structure"}, {Name: "Missing", Kind: "string"}}
	rows := []evidence.Row{}
	for i := 0; i < 3; i++ {
		row := evidence.Row{Cells: map[string]evidence.Value{"U": evidence.Number(math.MaxUint64), "I": evidence.Integer(math.MinInt64), "Address": evidence.Address(math.MaxUint64), "Text": evidence.Text("进程\x00\n"), "Flag": evidence.Bool(false), "Object": {Kind: "structure", Data: map[string]any{"counter": json.Number("18446744073709551615")}}, "Missing": evidence.Missing("unmapped", errors.New("raw read fault"))}}
		switch i {
		case 0:
			row.Cells["Bytes"] = evidence.Bytes(nil)
		case 1:
			row.Cells["Bytes"] = evidence.Value{Kind: "bytes", Data: []byte{}}
		case 2:
			row.Cells["Bytes"] = evidence.Bytes([]byte{0, 255})
		}
		if i > 0 {
			row.ParentID = rows[i-1].ID
		}
		row.Seal()
		rows = append(rows, row)
	}
	var out bytes.Buffer
	writer, err := NewArrow(&out, columns, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := writer.Row(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, expected := filepath.Join(dir, "evidence.arrow"), filepath.Join(dir, "expected.json")
	wire, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(expected, wire, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "../../tools/verify_arrow.py", "--input", input, "--expected", expected)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("independent reader: %s %v", result, err)
	}
	t.Log(string(result))
}
func FuzzArrowEvidence(f *testing.F) {
	for _, seed := range []string{`{"kind":"uint64","value":"18446744073709551615"}`, `{"kind":"bool","value":false}`, `{"kind":"bytes","value":"AP8="}`, `{"kind":"string","value":""}`, `{"kind":"structure","value":{"raw":18446744073709551615}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		var value evidence.Value
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return
		}
		var out bytes.Buffer
		w, err := NewArrow(&out, []evidence.Column{{Name: "Value", Kind: value.Kind}}, nil)
		if err != nil {
			return
		}
		rowErr := w.Row(evidence.Row{Cells: map[string]evidence.Value{"Value": value}})
		closeErr := w.Close()
		if rowErr != nil || closeErr != nil {
			return
		}
		r, err := ipc.NewReader(&out)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Release()
		if !r.Next() || r.RecordBatch().NumRows() != 1 {
			t.Fatal("missing valid row", r.Err())
		}
	})
}
