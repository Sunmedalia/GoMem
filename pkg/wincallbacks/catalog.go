package wincallbacks

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

const catalogBaseURL = "https://raw.githubusercontent.com/volatilityfoundation/volatility3/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/"
const catalogMaxBytes = 4 << 20

type catalogPin struct {
	width  int
	sha256 string
}

type CatalogData struct {
	Layout                       *Table
	Data                         []byte
	Name, SHA256, URL, CachePath string
	FromCache                    bool
}

// Load retrieves data-only symbol layouts, never Python or executable code.
// Both downloads and offline cache entries must match the compiled baseline pin.
func Load(ctx context.Context, cacheDir string, kernel symbols.SymbolTable, offline bool) (*CatalogData, error) {
	return load(ctx, cacheDir, kernel, offline, catalogBaseURL, &http.Client{Timeout: 30 * time.Second})
}

func load(ctx context.Context, cacheDir string, kernel symbols.SymbolTable, offline bool, baseURL string, client *http.Client) (*CatalogData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if absentKernel(kernel) {
		return nil, fmt.Errorf("callback catalog requires kernel symbols")
	}
	name := "callbacks-x86"
	if kernel.PointerSize() == 8 {
		name = "callbacks-x64"
	} else if kernel.PointerSize() != 4 {
		return nil, fmt.Errorf("callback catalog requires 4/8-byte pointers")
	}
	pin, ok := catalogPins[name]
	if !ok {
		return nil, fmt.Errorf("unknown pinned callback layout %q", name)
	}
	if cacheDir == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		cacheDir = filepath.Join(root, "gomem", "callback-symbols")
	}
	path := filepath.Join(cacheDir, name+"-"+pin.sha256+".json")
	result := &CatalogData{Name: name, SHA256: pin.sha256, URL: baseURL + name + ".json", CachePath: path}
	validate := func(data []byte) error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.sha256 {
			return fmt.Errorf("callback layout digest mismatch")
		}
		layout, err := Parse(data, kernel)
		if err != nil {
			return err
		}
		if layout.PointerSize() != pin.width {
			return fmt.Errorf("callback layout pointer width mismatch")
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
		return nil, fmt.Errorf("offline callback layout %s unavailable or invalid: %w", name, cacheErr)
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
		return nil, fmt.Errorf("callback layout server returned HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("callback layout download exceeds 4 MiB")
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
	file, err := os.CreateTemp(cacheDir, ".callback-*.tmp")
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
		if readErr != nil || validate(current) != nil {
			return nil, err
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
		return nil, fmt.Errorf("invalid callback symbol cache file")
	}
	data, err := io.ReadAll(io.LimitReader(f, catalogMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxBytes {
		return nil, fmt.Errorf("callback symbol cache exceeds bounds")
	}
	return data, nil
}

var catalogPins = map[string]catalogPin{
	"callbacks-x86": {width: 4, sha256: "712a16677e973918f8101d83c4493fbe63e913e97b6e1960a3d3ed79b48e4a79"},
	"callbacks-x64": {width: 8, sha256: "f246fe8d9b187546fe78f72336a923a710255d712226bcc2f578c45b95c6c618"},
}
