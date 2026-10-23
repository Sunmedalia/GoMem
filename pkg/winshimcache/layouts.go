package winshimcache

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// The layouts are copied byte-for-byte from the pinned Volatility 3 tree.
// They remain data-only ISF fragments; all runtime decoding is native Go.
//
//go:embed layouts/*.json
var embeddedLayouts embed.FS

// LayoutNames returns the embedded Shimcache layout names in lexical order.
func LayoutNames() []string {
	entries, err := fs.ReadDir(embeddedLayouts, "layouts")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".json"))
	}
	return names
}

// LayoutData returns one embedded layout fragment. Names are file stems from the
// pinned _win_version_file_map, not arbitrary filesystem paths.
func LayoutData(name string) ([]byte, error) {
	if name == "" || path.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("invalid Shimcache layout name %q", name)
	}
	raw, err := embeddedLayouts.ReadFile(path.Join("layouts", name+".json"))
	if err != nil {
		return nil, fmt.Errorf("Shimcache layout %q: %w", name, err)
	}
	return raw, nil
}
