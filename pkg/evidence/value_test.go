package evidence

import (
	"encoding/json"
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
