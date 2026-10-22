package wingui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const catalogBaseURL = "https://raw.githubusercontent.com/volatilityfoundation/volatility3/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/gui/"
const catalogMaxBytes = 4 << 20

type catalogPin struct {
	sha256 string
}

type CatalogData struct {
	Layout                       *Layout
	Data                         []byte
	Name, SHA256, URL, CachePath string
	FromCache                    bool
}

// Load retrieves data-only symbol layouts, never Python or executable code.
// Both downloads and offline cache entries must match the compiled baseline pin.
func Load(ctx context.Context, cacheDir string, name string, offline bool) (*CatalogData, error) {
	return load(ctx, cacheDir, name, offline, catalogBaseURL, &http.Client{Timeout: 30 * time.Second})
}

func load(ctx context.Context, cacheDir string, name string, offline bool, baseURL string, client *http.Client) (*CatalogData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pin, ok := catalogPins[name]
	if !ok {
		return nil, fmt.Errorf("unknown pinned GUI layout %q", name)
	}
	if cacheDir == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		cacheDir = filepath.Join(root, "gomem", "gui-symbols")
	}
	path := filepath.Join(cacheDir, name+"-"+pin.sha256+".json")
	release, err := acquireCatalog(ctx, path)
	if err != nil {
		return nil, err
	}
	defer release()
	result := &CatalogData{Name: name, SHA256: pin.sha256, URL: baseURL + name + ".json", CachePath: path}
	validate := func(data []byte) error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.sha256 {
			return fmt.Errorf("GUI layout digest mismatch")
		}
		layout, err := ParseLayout(data)
		if err != nil {
			return err
		}
		if layout.Types.PointerSize() != 8 {
			return fmt.Errorf("GUI layout pointer width mismatch")
		}
		result.Data, result.Layout = data, layout
		return nil
	}
	data, cacheErr := readCatalogCache(path)
	if cacheErr == nil {
		cacheErr = validate(data)
	}
	if cacheErr == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result.FromCache = true
		return result, nil
	}
	if offline {
		return nil, fmt.Errorf("offline GUI layout %s unavailable or invalid: %w", name, cacheErr)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, result.URL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GUI layout server returned HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("GUI layout download exceeds 4 MiB")
	}
	if err := validate(data); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(cacheDir, ".gui-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		// Another resolver may have populated the immutable entry meanwhile.
		current, readErr := readCatalogCache(path)
		if readErr == nil && validate(current) == nil {
			return result, nil
		}
		// Windows cannot replace an existing target with Rename. Only remove
		// an invalid regular cache entry after the replacement is complete and
		// verified; never truncate a visible file or remove a directory/link.
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, removeErr
		}
		if installErr := os.Rename(file.Name(), path); installErr != nil {
			current, readErr = readCatalogCache(path)
			if readErr != nil || validate(current) != nil {
				return nil, installErr
			}
		}
	}
	return result, nil
}

func readCatalogCache(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > catalogMaxBytes {
		return nil, fmt.Errorf("invalid GUI symbol cache file")
	}
	data, err := io.ReadAll(io.LimitReader(f, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("GUI symbol cache exceeds bounds")
	}
	return data, nil
}

var catalogPins = map[string]catalogPin{
	"gui-win10-10586-x64": {sha256: "87280455f20b23334a6b53521056ac3605a54e181882ba7759a7196518f35977"},
	"gui-win10-15063-x64": {sha256: "d7c5fb21c720f202ae155ec399f95c8c6fed164c04ec9ec1545d82dacf29081f"},
	"gui-win10-16299-x64": {sha256: "923b68e6e988557d17c63eff25a9ddb33a11fbd7f0221eb5d5eef90044e38ea4"},
	"gui-win10-17134-x64": {sha256: "2dbfb0f911a02e257fd345976065a82d2407090330269fd323e5b1cd813fcd14"},
	"gui-win10-17735-x64": {sha256: "74b5ec6112580c1a267c88b1341d6439129d226207813c1ec0ae2e3cb0679676"},
	"gui-win10-17763-x64": {sha256: "42f3fda32235b61b02b9f21f731dccbc14038be42e36584699e8d9bf1b70d902"},
	"gui-win10-18362-x64": {sha256: "693235e7a3ebed46186cea2b53411ca3f708a3198d386267c322d9931d02a386"},
	"gui-win10-19041-x64": {sha256: "db87d5f9b3ed6e00cfecb227658d451b22e690c65bf909b81f3c87ab85db7d58"},
	"gui-win10-19577-x64": {sha256: "068eeb1d0d33214be6b0eec5383aee1f4b3fb2e54b34a82b499ae0818db13fed"},
	"gui-win7sp0-x64":     {sha256: "f5e9690ee9d1ab54a7b30710601bfb68630840818d345ba07aa893f4d3972735"},
	"gui-win7sp1-x64":     {sha256: "c6ef7781901d59f9c3cfeca6cc95617959b7271fb22bb77d4cec705483caf64b"},
	"gui-win8-x64":        {sha256: "eb22c82c9dfa40d7e573cc8b1d3944436bea60c01bc4f7e896e5496d0441bb24"},
}
