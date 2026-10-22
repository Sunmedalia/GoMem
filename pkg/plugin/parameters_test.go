package plugin

import "testing"

func TestRequiredParameterDistinguishesMissingAndExplicitEmpty(t *testing.T) {
	spec := Spec{Name: "regex", Parameters: []Parameter{{Name: "pattern", Kind: "string", Required: true}, {Name: "limit", Kind: "uint", Default: "12"}}}
	if _, err := Parameters(spec, nil); err == nil {
		t.Fatal("missing required value accepted")
	}
	got, err := Parameters(spec, map[string]string{"pattern": ""})
	if err != nil || got["pattern"] != "" || got["limit"] != "12" {
		t.Fatal(got, err)
	}
	if _, err = Parameters(spec, map[string]string{"pattern": "a", "unknown": "1"}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
}
