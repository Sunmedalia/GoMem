package yara

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestYaraNamespacesGlobalsAndSerializedRoundTrip(t *testing.T) {
	library := nativeLibrary(t)
	config := CompileConfig{Sources: []Source{
		{Namespace: "alpha", Text: []byte(`rule same { strings:$a="test" condition:$a and number==9223372036854775807 and enabled and label=="sample" and ratio==1.5 and group.one==1 }`)},
		{Namespace: "beta", Text: []byte(`rule same { strings:$a="other" condition:$a }`)},
	}, Globals: map[string]json.RawMessage{"number": json.RawMessage(`9223372036854775807`), "enabled": json.RawMessage(`true`), "label": json.RawMessage(`"sample"`), "ratio": json.RawMessage(`1.5`), "group": json.RawMessage(`{"one":1}`)}}
	rules, err := CompileWithOptions(context.Background(), library, config)
	if err != nil {
		var compilation *CompileError
		if errors.As(err, &compilation) {
			t.Log(string(compilation.Diagnostics))
		}
		t.Fatal(err)
	}
	defer rules.Close()
	matches, err := rules.Scan(context.Background(), []byte("test other"), Options{})
	if err != nil || len(matches) != 2 || matches[0].Namespace != "alpha" || matches[1].Namespace != "beta" {
		t.Fatal(matches, err)
	}
	serialized, err := rules.Serialize(context.Background())
	if err != nil || len(serialized) == 0 {
		t.Fatal(err)
	}
	loaded, err := LoadCompiled(context.Background(), library, serialized)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	actual, err := loaded.Scan(context.Background(), []byte("test other"), Options{})
	if err != nil || !reflect.DeepEqual(actual, matches) {
		t.Fatal(actual, matches, err)
	}
	if loaded.Digest() == rules.Digest() {
		t.Fatal("serialized and source identities share an untyped hash")
	}
	config.Globals["number"] = json.RawMessage(`9223372036854775806`)
	changed, err := CompileWithOptions(context.Background(), library, config)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	if changed.Digest() == rules.Digest() {
		t.Fatal("external values omitted from rule identity")
	}
	actual, err = changed.Scan(context.Background(), []byte("test other"), Options{})
	if err != nil || len(actual) != 1 || actual[0].Namespace != "beta" {
		t.Fatal("external integer rounded or ignored", actual, err)
	}
	for _, bad := range [][]byte{nil, []byte("invalid"), serialized[:min(len(serialized), 64)], make([]byte, MaxCompiled+1)} {
		if r, err := LoadCompiled(context.Background(), library, bad); err == nil {
			r.Close()
			t.Fatal("invalid compiled rules accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rules.Serialize(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := LoadCompiled(ctx, library, serialized); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := rules.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Serialize(context.Background()); err == nil {
		t.Fatal("serialized closed rules")
	}
}

func TestYaraInputConfigurationBounds(t *testing.T) {
	for _, config := range []CompileConfig{
		{},
		{Sources: make([]Source, 129)},
		{Sources: []Source{{Text: bytes.Repeat([]byte{'a'}, MaxSource+1)}}},
		{Sources: []Source{{Text: []byte{0xff}}}},
		{Sources: []Source{{Text: []byte("rule r {condition:true}"), Namespace: "a\x00b"}}},
		{Sources: []Source{{Text: []byte("rule r {condition:true}")}}, Globals: map[string]json.RawMessage{"x": json.RawMessage(`invalid`)}},
	} {
		if _, err := prepareConfig(config); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
