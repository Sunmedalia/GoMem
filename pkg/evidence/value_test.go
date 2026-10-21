package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestEmptyStringEvidenceIsPreserved(t *testing.T) {
	encoded, err := json.Marshal(Text(""))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"kind":"string","value":""}` {
		t.Fatalf("empty string became %s", encoded)
	}
	var decoded Value
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != "string" || decoded.Data != "" {
		t.Fatalf("round trip %+v", decoded)
	}
	encoded, err = json.Marshal(Text("C:"))
	if err != nil || string(encoded) != `{"kind":"string","value":"C:"}` {
		t.Fatal(err, string(encoded))
	}
	encoded, err = json.Marshal(Missing("not_set", nil))
	if err != nil || string(encoded) != `{"kind":"missing","reason":"not_set"}` {
		t.Fatal(err, string(encoded))
	}
	encoded, err = json.Marshal(Number(5))
	if err != nil || string(encoded) != `{"kind":"uint64","value":"5"}` {
		t.Fatal(err, string(encoded))
	}
}

func TestBoolEvidencePreservesFalse(t *testing.T) {
	encoded, err := json.Marshal(Bool(false))
	if err != nil || string(encoded) != `{"kind":"bool","value":false}` {
		t.Fatal(err, string(encoded))
	}
	encoded, err = json.Marshal(Bool(true))
	if err != nil || string(encoded) != `{"kind":"bool","value":true}` {
		t.Fatal(err, string(encoded))
	}
	var decoded Value
	if err = json.Unmarshal([]byte(`{"kind":"bool","value":false}`), &decoded); err != nil || decoded.Kind != "bool" || decoded.Data != false {
		t.Fatal(err, decoded)
	}
}

func TestZeroByteCaptureRoundTrip(t *testing.T) {
	for _, value := range []Value{Bytes(nil), Bytes([]byte{}), Bytes([]byte{0}), {Kind: "bytes"}, {Kind: "bytes", Data: ""}} {
		r := Row{Cells: map[string]Value{"Raw": value}}
		r.Seal()
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for pass := 0; pass < 3; pass++ {
			var decoded Row
			if err = json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if err = decoded.Verify(); err != nil {
				t.Fatal(string(raw), err)
			}
			round, err := json.Marshal(decoded)
			if err != nil || !bytes.Equal(raw, round) {
				t.Fatal(string(raw), string(round), err)
			}
			raw = round
		}
	}
}

func TestStructuredNumbersSurviveDefaultJSONReader(t *testing.T) {
	r := Row{Cells: map[string]Value{"Details": {Kind: "structure", Data: map[string]any{
		"Unsigned": uint64(18446744073709551615), "Signed": int64(-9223372036854775808),
		"Fraction": json.Number("1.2300"), "Exponent": json.Number("1e100"),
		"Nested": []Value{Bytes(nil), Bool(false), Text("")},
	}}}}
	r.Seal()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Row
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Verify(); err != nil {
		t.Fatal(string(raw), err)
	}
	round, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(raw, round) {
		t.Fatal(string(raw), string(round), err)
	}
}

// Nested Values become generic maps after persistence. Their field ordering,
// false/empty values, raw bytes and full-width integer metadata must survive.
func TestNestedTypedStructureEvidenceRoundTrip(t *testing.T) {
	r := Row{Cells: map[string]Value{"Details": {Kind: "structure", Data: map[string]any{
		"Address": Address(0xffff800012345678), "False": Bool(false), "Empty": Text(""),
		"Bytes": Bytes([]byte{0, 1, 255}), "ReadError": Missing("page", fmt.Errorf("missing page")),
		"Integer": uint64(18446744073709551615),
		"Nested":  map[string]Value{"Raw": Bytes(nil), "MaximumLength": Number(65535)},
	}}}}
	r.Seal()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Row
	// UseNumber is the lossless consumer contract for untyped numeric metadata.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Verify(); err != nil {
		t.Fatal(string(raw), err)
	}
	round, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(raw, round) {
		t.Fatal(string(raw), string(round), err)
	}
	// Typed numbers/addresses also round-trip through an ordinary JSON reader.
	delete(r.Cells["Details"].Data.(map[string]any), "Integer")
	r.Seal()
	raw, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Verify(); err != nil {
		t.Fatal(string(raw), err)
	}

}

func TestArtifactValueRoundTripPreservesSeal(t *testing.T) {
	row := Row{Cells: map[string]Value{"File": {Kind: "artifact", Data: Artifact{ID: "file-id", TaskID: "task-id", Name: "module.elf", Path: "artifacts/module.elf", State: "completed_with_gaps", Size: "18446744073709551615", MissingBytes: "4096", Provenance: Provenance{Offset: "0xffff800000000000", Parameters: map[string]string{"dump": "true"}}}}}}
	row.Seal()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		var decoded Row
		if err = json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if err = decoded.Verify(); err != nil {
			t.Fatal(err)
		}
		round, err := json.Marshal(decoded)
		if err != nil || !bytes.Equal(raw, round) {
			t.Fatal(string(raw), string(round), err)
		}
		raw = round
	}
}
