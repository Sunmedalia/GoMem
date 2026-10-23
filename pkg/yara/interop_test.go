package yara

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestYaraCompiledPythonInterop(t *testing.T) {
	library := nativeLibrary(t)
	python := os.Getenv("GOMEM_YARAX_REFERENCE_PYTHON")
	if python == "" {
		t.Skip("set GOMEM_YARAX_REFERENCE_PYTHON for independent serialized-rule controls")
	}
	config := CompileConfig{Sources: []Source{{Namespace: "control", Text: []byte(`rule r {strings:$a="test" condition:$a and threshold==9223372036854775807 and allowed}`)}}, Globals: map[string]json.RawMessage{"threshold": json.RawMessage(`9223372036854775807`), "allowed": json.RawMessage(`true`)}}
	ctx := context.Background()
	rules, err := CompileWithOptions(ctx, library, config)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	dir := t.TempDir()
	data := []byte("start test then test")
	dataPath := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(dataPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	wire, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, wire, 0600); err != nil {
		t.Fatal(err)
	}
	serialized, err := rules.Serialize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nativePath := filepath.Join(dir, "native.rules")
	if err := os.WriteFile(nativePath, serialized, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"native-to-python", "python-to-native"} {
		t.Run(mode, func(t *testing.T) {
			compiled := nativePath
			outPath := filepath.Join(dir, mode+".json")
			args := []string{"../../tools/verify_yarax.py", "--data", dataPath, "--output", outPath}
			if mode == "python-to-native" {
				compiled = filepath.Join(dir, "python.rules")
				args = append(args, "--config", configPath)
			}
			args = append(args, "--compiled", compiled)
			if output, err := exec.Command(python, args...).CombinedOutput(); err != nil {
				t.Fatalf("actual Python reference: %s: %v", output, err)
			}
			var expected []struct {
				Offset        uint64
				Rule, Pattern string
				Bytes         []byte
			}
			wire, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(wire, &expected); err != nil {
				t.Fatal(err)
			}
			blob, err := os.ReadFile(compiled)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadCompiled(ctx, library, blob)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.Close()
			matches, err := loaded.Scan(ctx, data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != len(expected) || len(matches) != 2 {
				t.Fatal(matches, expected)
			}
			for n, m := range matches {
				if m.Namespace+"."+m.Rule != expected[n].Rule || m.Offset != expected[n].Offset || m.Pattern != expected[n].Pattern || !reflect.DeepEqual(m.Bytes, expected[n].Bytes) {
					t.Fatal(m, expected[n])
				}
			}
		})
	}
}
