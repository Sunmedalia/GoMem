package winconsole

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

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const catalogBaseURL = "https://raw.githubusercontent.com/volatilityfoundation/volatility3/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/consoles/"
const catalogMaxBytes = 4 << 20

type catalogPin struct {
	sha256 string
}

type CatalogData struct {
	Layout                       *symbols.ISF
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
		return nil, fmt.Errorf("unknown pinned console layout %q", name)
	}
	if cacheDir == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		cacheDir = filepath.Join(root, "gomem", "console-symbols")
	}
	path := filepath.Join(cacheDir, name+"-"+pin.sha256+".json")
	result := &CatalogData{Name: name, SHA256: pin.sha256, URL: baseURL + name + ".json", CachePath: path}
	validate := func(data []byte) error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.sha256 {
			return fmt.Errorf("console layout digest mismatch")
		}
		layout, err := ParseHistoryLayout(data)
		if err != nil {
			return err
		}
		if layout.PointerSize() != 8 {
			return fmt.Errorf("console layout pointer width mismatch")
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
		return nil, fmt.Errorf("offline console layout %s unavailable or invalid: %w", name, cacheErr)
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
		return nil, fmt.Errorf("console layout server returned HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("console layout download exceeds 4 MiB")
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
	file, err := os.CreateTemp(cacheDir, ".console-*.tmp")
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
		return nil, fmt.Errorf("invalid console symbol cache file")
	}
	data, err := io.ReadAll(io.LimitReader(f, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("console symbol cache exceeds bounds")
	}
	return data, nil
}

var catalogPins = map[string]catalogPin{
	"consoles-win10-17763-3232-x64": {sha256: "f9e0ba2d38b616990dab4ba75e658e15c2c008ac683877fdf0df1fe7932bc291"},
	"consoles-win10-17763-x64":      {sha256: "e5b0b1a836e9b3c1e3951d5846e54cd7cac1e9f4d1f2ff050a17e907f9cbc1ce"},
	"consoles-win10-18362-x64":      {sha256: "8bd2dcf099d78b4c57a2b3c18128c87b9b9c7608bc6f64b08eb82eacc3df2c76"},
	"consoles-win10-19041-x64":      {sha256: "dc9546f557c3b544d0bcd71042cfc4d1127a44d309fe83660a58b914cabb61d2"},
	"consoles-win10-20348-1970-x64": {sha256: "e5cf79e05d00f7dd7ac4ede0cc8ec8c62ef487dbb808a04932cfa3fcf619447a"},
	"consoles-win10-20348-2461-x64": {sha256: "4750b0c6c7112e2dea66e53da9984208ad878ecdd6eed84c0dafa3dc8a205d21"},
	"consoles-win10-20348-x64":      {sha256: "563b8485300253cc3b226f4e423330a5b571526640c95432500a65447463c5a3"},
	"consoles-win10-22000-x64":      {sha256: "34508f45adfaff5ff028c28bfc08d61306653c1ad9b7033a6fb64c0b95194598"},
	"consoles-win10-22621-3527-x64": {sha256: "5c91afc2964829d02bfe31c055fc7aa20db134bfed4269b75d7394459a2db651"},
	"consoles-win10-22621-x64":      {sha256: "9ebbf87ff302adf8733b0f2c2208e4d32ec5007456980a8aff1502228fe5c00b"},
	"consoles-win10-25398-x64":      {sha256: "6aa3015a0c529c391420ebd5638928d4c0866bc4d660ddb7508048968b9439a7"},
}
