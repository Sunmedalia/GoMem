package plugins

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func spanTestRow(layer string, at uint64, raw []byte) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("memory_read"), "Offset": evidence.Address(at), "Requested": evidence.Number(uint64(len(raw))), "Captured": evidence.Number(uint64(len(raw))), "Raw": evidence.Bytes(raw), "Error": evidence.Missing("no_error", nil), "Resolution": {Kind: "structure", Data: map[string]any{"method": "exports"}}}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", at)}}
}
func TestWindowsReadSpansPreserveCallsAndOwnedBytes(t *testing.T) {
	var output []evidence.Row
	spans := windowsReadSpans{out: func(row evidence.Row) error { output = append(output, row); return nil }}
	for i := range 130 {
		row := spanTestRow("process:a", 0x1000+uint64(i), []byte{byte(i)})
		if err := spans.emit(row); err != nil {
			t.Fatal(err)
		}
		// Mutating a caller's payload must not change buffered acquisitions.
		row.Cells["Raw"].Data.([]byte)[0] = 255
	}
	if err := spans.flush(); err != nil {
		t.Fatal(err)
	}
	if len(output) != 3 {
		t.Fatal(len(output))
	}
	at := uint64(0x1000)
	var actual []byte
	calls := 0
	for _, row := range output {
		detail := row.Cells["Resolution"].Data.(map[string]any)
		acquisitions := detail["acquisitions"].([]windowsSpanRead)
		if len(acquisitions) > 64 {
			t.Fatal("unbounded acquisitions")
		}
		for _, call := range acquisitions {
			if call.Offset != evidence.Address(at).String() || call.Requested != 1 || call.Captured != 1 {
				t.Fatal("boundary drift", call, at)
			}
			at++
			calls++
		}
		raw := row.Cells["Raw"].Data.([]byte)
		actual = append(actual, raw...)
		requested, _ := row.Cells["Requested"].Uint()
		if requested != uint64(len(raw)) {
			t.Fatal("span count drift")
		}
	}
	want := make([]byte, 130)
	for i := range want {
		want[i] = byte(i)
	}
	if calls != 130 || !bytes.Equal(actual, want) {
		t.Fatal("lost acquisition bytes", calls)
	}
}
func TestWindowsReadSpansBoundariesFaultsAndOutputStop(t *testing.T) {
	var rows []evidence.Row
	s := windowsReadSpans{out: func(row evidence.Row) error { rows = append(rows, row); return nil }}
	inputs := []evidence.Row{spanTestRow("a", 10, []byte{1}), spanTestRow("b", 11, []byte{2}), spanTestRow("b", 14, []byte{3})}
	failed := spanTestRow("b", 15, []byte{})
	failed.Cells["Requested"] = evidence.Number(2)
	failed.Cells["Error"] = evidence.Text("hole")
	inputs = append(inputs, failed)
	extra := spanTestRow("b", 16, []byte{4})
	extra.Cells["Additional"] = evidence.Text("preserve me")
	inputs = append(inputs, extra)
	inputs = append(inputs, spanTestRow("b", 17, make([]byte, 4096)), spanTestRow("b", 4113, []byte{5}))
	for _, row := range inputs {
		if err := s.emit(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(inputs) {
		t.Fatal("crossed layer/gap/error/extra-field/size boundaries", len(rows), len(inputs))
	}
	if rows[3].Cells["Error"].String() != "hole" || rows[4].Cells["Additional"].String() != "preserve me" {
		t.Fatal("lost ungrouped metadata")
	}
	sentinel := errors.New("span output rejected")
	count := 0
	stopped := windowsReadSpans{out: func(evidence.Row) error { count++; return sentinel }}
	if err := stopped.emit(spanTestRow("a", 1, []byte{1})); err != nil {
		t.Fatal(err)
	}
	if err := stopped.emit(spanTestRow("b", 2, []byte{2})); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := stopped.flush(); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := stopped.emit(inputs[0]); !errors.Is(err, sentinel) || count != 1 {
		t.Fatal("output continued", err, count)
	}
}
