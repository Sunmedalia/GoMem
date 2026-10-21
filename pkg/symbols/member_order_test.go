package symbols_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestTypeMemberOrderRoundTrip(t *testing.T) {
	// JSON declaration order differs from both address order and name order.
	raw := []byte(`{"kind":"struct","size":24,"fields":{"z":{"offset":8,"type":{"kind":"pointer"}},"a":{"offset":16,"type":{"kind":"pointer"}},"m":{"offset":0,"type":{"kind":"pointer"}}}}`)
	var typ symbols.Type
	if err := json.Unmarshal(raw, &typ); err != nil {
		t.Fatal(err)
	}
	want := []string{"z", "a", "m"}
	if !reflect.DeepEqual(typ.MemberNames(), want) {
		t.Fatal(typ.MemberNames())
	}
	encoded, err := json.Marshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	var again symbols.Type
	if err = json.Unmarshal(encoded, &again); err != nil || !reflect.DeepEqual(again.MemberNames(), want) {
		t.Fatal(string(encoded), err, again.MemberNames())
	}
	delete(typ.Fields, "a")
	typ.Fields["b"] = symbols.Field{}
	typ.Fields["c"] = symbols.Field{}
	typ.FieldOrder = append(typ.FieldOrder, "z", "deleted")
	if got := typ.MemberNames(); !reflect.DeepEqual(got, []string{"z", "m", "b", "c"}) {
		t.Fatal(got)
	}
}

func TestTypeMemberOrderDuplicateAndNull(t *testing.T) {
	var typ symbols.Type
	if err := json.Unmarshal([]byte(`{"kind":"struct","fields":{"z":{"offset":0},"a":{"offset":1},"z":{"offset":2}}}`), &typ); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(typ.MemberNames(), []string{"z", "a"}) || typ.Fields["z"].Offset != 2 {
		t.Fatal(typ)
	}
	for _, raw := range []string{`{"kind":"struct","fields":null}`, `{"kind":"struct"}`} {
		if err := json.Unmarshal([]byte(raw), &typ); err != nil || len(typ.MemberNames()) != 0 {
			t.Fatal(typ, err)
		}
		encoded, err := json.Marshal(typ)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err = json.Unmarshal(encoded, &decoded); err != nil || decoded["fields"] == nil {
			t.Fatal(string(encoded), err)
		}
	}
	for _, raw := range []string{`{"fields":[]}`, `{"fields":1}`, `{"fields":{"a":false}}`} {
		if err := json.Unmarshal([]byte(raw), &typ); err == nil {
			t.Fatal("invalid fields accepted", raw)
		}
	}
}
