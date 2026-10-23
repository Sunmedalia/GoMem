package plugins

import (
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func TestNativePluginSchemas(t *testing.T) {
	r := plugin.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	for _, spec := range r.List() {
		t.Run(spec.Name, func(t *testing.T) {
			if spec.Description == "" || len(spec.Columns) == 0 {
				t.Fatal("plugin has no description or evidence columns")
			}
			seen := map[string]bool{}
			for _, column := range spec.Columns {
				if column.Name == "" || column.Kind == "" || seen[column.Name] {
					t.Fatalf("invalid or duplicate column: %+v", column)
				}
				seen[column.Name] = true
			}
			seen = map[string]bool{}
			for _, param := range spec.Parameters {
				if param.Name == "" || param.Kind == "" || seen[param.Name] {
					t.Fatalf("invalid or duplicate parameter: %+v", param)
				}
				seen[param.Name] = true
			}
		})
	}
}
