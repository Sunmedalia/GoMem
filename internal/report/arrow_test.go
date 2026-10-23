package report

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
)

func TestArrowCaseUnionPagingSealsAndManifest(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for index := 0; index < 2; index++ {
		p := evidence.Provenance{Plugin: "fixture", Layer: "physical"}
		task, err := s.Begin(ctx, string(rune('a'+index)), "fixture", p)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 65; j++ {
			value := evidence.Number(^uint64(0))
			if index == 1 {
				value = evidence.Bool(false)
			}
			row := evidence.Row{Cells: map[string]evidence.Value{"Ordinal": evidence.Number(uint64(index*100 + j)), "Value": value, "Bytes": evidence.Bytes([]byte{0, 255}), "Missing": evidence.Missing("unmapped", errors.New("read fault"))}, Provenance: p}
			row.Seal()
			if err := s.Append(ctx, task.ID, []evidence.Row{row}); err != nil {
				t.Fatal(err)
			}
		}
		state := "completed"
		var failure error
		if index == 1 {
			state = "failed"
			failure = errors.New("partial scan")
		}
		if err := s.Finish(ctx, task.ID, state, failure); err != nil {
			t.Fatal(err)
		}
	}
	path, err := Export(ctx, s, "arrow", "evidence.arrow", "")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := ipc.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	manifestText, ok := reader.Schema().Metadata().GetValue("gomem.manifest")
	if !ok {
		t.Fatal("manifest absent")
	}
	var manifest Manifest
	if err := json.Unmarshal([]byte(manifestText), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Tasks) != 2 {
		t.Fatal(manifest)
	}
	failed := false
	for _, task := range manifest.Tasks {
		if task.State == "failed" && task.Error == "partial scan" {
			failed = true
		}
	}
	if !failed {
		t.Fatal("failed task silently completed")
	}
	valueIndex := reader.Schema().FieldIndices("Value")[0]
	var count int
	for reader.Next() {
		record := reader.RecordBatch()
		for i := 0; i < int(record.NumRows()); i++ {
			var row evidence.Row
			if err := json.Unmarshal(record.Column(3).(*array.Binary).Value(i), &row); err != nil {
				t.Fatal(err)
			}
			if err := row.Verify(); err != nil {
				t.Fatal(err)
			}
			if record.Column(2).IsNull(i) || row.Cells["Missing"].Error != "read fault" {
				t.Fatal("task or failure lost")
			}
			var v evidence.Value
			if err := json.Unmarshal(record.Column(valueIndex).(*array.Binary).Value(i), &v); err != nil {
				t.Fatal(err)
			}
			if v.Kind != row.Cells["Value"].Kind {
				t.Fatal("conflicting column kind lost")
			}
			count++
		}
	}
	if reader.Err() != nil || count != 130 {
		t.Fatal(count, reader.Err())
	}
	if _, err := Export(ctx, s, "arrow", "evidence.arrow", ""); err == nil {
		t.Fatal("overwrote export")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Export(canceled, s, "arrow", "cancel.arrow", ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
