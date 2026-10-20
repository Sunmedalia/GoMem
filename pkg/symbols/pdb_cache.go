package symbols

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const MicrosoftSymbolServer = "https://msdl.microsoft.com/download/symbols"

var ErrOfflineSymbols = errors.New("matching symbols are unavailable in the offline cache")
var pdbCacheName = regexp.MustCompile(`(?i)^[a-z0-9_][a-z0-9_.-]*\.pdb$`)

type PDBCacheOptions struct {
	Directory   string
	BuildSHA256 string
	Server      string
	Offline     bool
	Client      *http.Client
	MaxDownload uint64
}
type PDBResolution struct {
	Identity      PDBIdentity `json:"identity"`
	SourceSHA256  string      `json:"source_sha256"`
	SymbolsSHA256 string      `json:"symbols_sha256"`
	SourcePath    string      `json:"source_path"`
	TablePath     string      `json:"table_path"`
	ManifestPath  string      `json:"manifest_path"`
	URL           string      `json:"source_url,omitempty"`
	Downloaded    bool        `json:"downloaded"`
	Converted     bool        `json:"converted"`
	Report        Conversion  `json:"conversion"`
}
type pdbCacheManifest struct {
	Schema        string      `json:"schema"`
	BuildSHA256   string      `json:"build_sha256"`
	Identity      PDBIdentity `json:"identity"`
	SourceSHA256  string      `json:"source_sha256"`
	SymbolsSHA256 string      `json:"symbols_sha256"`
	URL           string      `json:"url"`
	Conversion    Conversion  `json:"conversion"`
}
type pdbSourceManifest struct {
	Schema   string      `json:"schema"`
	Identity PDBIdentity `json:"identity"`
	SHA256   string      `json:"sha256"`
	URL      string      `json:"url"`
}

// ResolvePDB reuses a verified native conversion or obtains an exact PDB from
// a symbol server. Only a PDB identity appears in the GET URL; no image data is
// sent. Both the downloaded PDB and the canonical table are hashed on reuse.
func ResolvePDB(ctx context.Context, identity PDBIdentity, options PDBCacheOptions) (*ISF, PDBResolution, error) {
	var result PDBResolution
	if err := ctx.Err(); err != nil {
		return nil, result, err
	}
	if err := identity.validate(); err != nil {
		return nil, result, err
	}
	if !pdbCacheName.MatchString(identity.Database) {
		return nil, result, fmt.Errorf("PDB database is not a supported safe cache basename")
	}
	if options.Directory == "" {
		return nil, result, fmt.Errorf("PDB cache directory is required")
	}
	build, err := hex.DecodeString(options.BuildSHA256)
	if err != nil || len(build) != 32 {
		return nil, result, fmt.Errorf("PDB cache requires the exact converter executable SHA-256")
	}
	options.BuildSHA256 = strings.ToLower(options.BuildSHA256)
	if options.Server == "" {
		options.Server = MicrosoftSymbolServer
	}
	server, err := url.Parse(options.Server)
	if err != nil || server.Scheme != "https" || server.Host == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" {
		return nil, result, fmt.Errorf("PDB server must be an HTTPS base URL without credentials/query/fragment")
	}
	if options.MaxDownload == 0 {
		options.MaxDownload = 512 << 20
	}
	if options.MaxDownload > 2<<30 {
		return nil, result, fmt.Errorf("PDB download limit exceeds 2 GiB")
	}
	guid := strings.ToUpper(strings.ReplaceAll(identity.GUID, "-", ""))
	identity.GUID = guid
	key := fmt.Sprintf("%s%X", guid, identity.Age)
	root, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, result, err
	}
	dir := filepath.Join(root, strings.ToLower(identity.Database), key)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, result, err
	}
	lock := flock.New(filepath.Join(dir, "cache.lock"), flock.SetPermissions(0600))
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return nil, result, err
	}
	if !locked {
		return nil, result, fmt.Errorf("PDB cache lock was not acquired")
	}
	defer lock.Close()
	result.Identity = identity
	result.SourcePath = filepath.Join(dir, strings.ToLower(identity.Database))
	converted := filepath.Join(dir, strings.ToLower(options.BuildSHA256))
	result.TablePath = filepath.Join(converted, "symbols.json")
	result.ManifestPath = filepath.Join(converted, "manifest.json")
	manifest, manifestErr := readPDBManifest(ctx, result.ManifestPath)
	if manifestErr == nil {
		if manifest.Schema != "gomem.pdb-cache/v1" || manifest.BuildSHA256 != options.BuildSHA256 || !manifest.Identity.Equal(identity) {
			return nil, result, fmt.Errorf("PDB conversion cache identity is inconsistent")
		}
		sourceHash, err := hashSymbolFile(ctx, result.SourcePath)
		if err != nil {
			return nil, result, err
		}
		if sourceHash != manifest.SourceSHA256 {
			return nil, result, fmt.Errorf("cached PDB content hash changed")
		}
		table, err := LoadContext(ctx, result.TablePath)
		if err != nil {
			return nil, result, fmt.Errorf("cached converted PDB: %w", err)
		}
		if table.Digest() != manifest.SymbolsSHA256 {
			return nil, result, fmt.Errorf("cached ISF content hash changed")
		}
		if err = table.MatchPDB(identity.Database, identity.GUID, identity.Age); err != nil {
			return nil, result, err
		}
		result.SourceSHA256, result.SymbolsSHA256, result.Report = sourceHash, table.Digest(), manifest.Conversion
		result.URL = manifest.URL
		return table, result, nil
	}
	if !os.IsNotExist(manifestErr) {
		return nil, result, fmt.Errorf("PDB cache manifest: %w", manifestErr)
	}
	_, statErr := os.Stat(result.SourcePath)
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, result, statErr
	}
	downloadURL := strings.TrimRight(server.String(), "/") + "/" + url.PathEscape(identity.Database) + "/" + key + "/" + url.PathEscape(identity.Database)
	var table *ISF
	var report Conversion
	sourceURL := ""
	sourceManifestPath := filepath.Join(dir, "source.json")
	if os.IsNotExist(statErr) {
		if options.Offline {
			return nil, result, fmt.Errorf("%w: %s %s/%d", ErrOfflineSymbols, identity.Database, guid, identity.Age)
		}
		temp, err := downloadPDB(ctx, options, downloadURL, dir)
		if err != nil {
			return nil, result, err
		}
		defer os.Remove(temp)
		table, report, err = ConvertPDB(ctx, temp, PDBOptions{Database: identity.Database})
		if err != nil {
			return nil, result, fmt.Errorf("downloaded PDB: %w", err)
		}
		if err = table.MatchPDB(identity.Database, identity.GUID, identity.Age); err != nil {
			return nil, result, err
		}
		if err = os.Link(temp, result.SourcePath); err != nil {
			return nil, result, fmt.Errorf("publish verified PDB without overwrite: %w", err)
		}
		sourceURL = downloadURL
		metadata, err := json.MarshalIndent(pdbSourceManifest{Schema: "gomem.pdb-source/v1", Identity: identity, SHA256: report.Sources[0].SHA256, URL: sourceURL}, "", "  ")
		if err != nil {
			return nil, result, err
		}
		if err = publishCache(ctx, sourceManifestPath, append(metadata, '\n')); err != nil {
			return nil, result, err
		}
		result.Downloaded = true
	} else {
		table, report, err = ConvertPDB(ctx, result.SourcePath, PDBOptions{Database: identity.Database})
		if err != nil {
			return nil, result, fmt.Errorf("cached raw PDB: %w", err)
		}
		if err = table.MatchPDB(identity.Database, identity.GUID, identity.Age); err != nil {
			return nil, result, err
		}
		if f, err := os.Open(sourceManifestPath); err == nil {
			var metadata pdbSourceManifest
			data, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, f}, 64<<10))
			f.Close()
			if readErr != nil {
				return nil, result, readErr
			}
			if err = json.Unmarshal(data, &metadata); err != nil {
				return nil, result, err
			}
			if metadata.Schema != "gomem.pdb-source/v1" || !metadata.Identity.Equal(identity) || metadata.SHA256 != report.Sources[0].SHA256 {
				return nil, result, fmt.Errorf("raw PDB provenance manifest disagrees with its source")
			}
			sourceURL = metadata.URL
		} else if !os.IsNotExist(err) {
			return nil, result, err
		}
	}
	// Temp download names never become provenance names.
	for n := range report.Sources {
		report.Sources[n].Name = identity.Database
	}
	data, err := table.Encode()
	if err != nil {
		return nil, result, err
	}
	if err = os.MkdirAll(converted, 0700); err != nil {
		return nil, result, err
	}
	if err = publishCache(ctx, result.TablePath, data); err != nil {
		return nil, result, err
	}
	result.SourceSHA256 = report.Sources[0].SHA256
	result.SymbolsSHA256, result.Report, result.Converted = table.Digest(), report, true
	result.URL = sourceURL
	manifest = pdbCacheManifest{Schema: "gomem.pdb-cache/v1", BuildSHA256: options.BuildSHA256, Identity: identity, SourceSHA256: result.SourceSHA256, SymbolsSHA256: result.SymbolsSHA256, URL: sourceURL, Conversion: report}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, result, err
	}
	if err = publishCache(ctx, result.ManifestPath, append(encoded, '\n')); err != nil {
		return nil, result, err
	}
	return table, result, nil
}
func hashSymbolFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("cached symbol source must be regular")
	}
	h := sha256.New()
	if _, err = io.CopyBuffer(h, contextReader{ctx, f}, make([]byte, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func readPDBManifest(ctx context.Context, path string) (pdbCacheManifest, error) {
	var m pdbCacheManifest
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, MaxIndexSize+1))
	if err != nil {
		return m, err
	}
	if len(b) > MaxIndexSize {
		return m, fmt.Errorf("PDB cache manifest exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return m, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return m, fmt.Errorf("trailing PDB cache manifest data")
	}
	return m, nil
}
func publishCache(ctx context.Context, path string, data []byte) error {
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
			return fmt.Errorf("refusing to overwrite different cached symbol data: %s", path)
		}
		current, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, int64(len(data))+1))
		if err != nil {
			return err
		}
		if bytes.Equal(current, data) {
			return nil
		}
		return fmt.Errorf("refusing to overwrite different cached symbol data: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "publish-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	for len(data) > 0 {
		if err = ctx.Err(); err != nil {
			f.Close()
			return err
		}
		n := min(len(data), 1<<20)
		if _, err = f.Write(data[:n]); err != nil {
			f.Close()
			return err
		}
		data = data[n:]
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Link(f.Name(), path)
}
func downloadPDB(ctx context.Context, options PDBCacheOptions, address, dir string) (path string, err error) {
	client := http.Client{Timeout: 2 * time.Minute}
	if options.Client != nil {
		client = *options.Client
	}
	if client.Timeout <= 0 {
		client.Timeout = 2 * time.Minute
	}
	redirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return fmt.Errorf("unsafe or excessive PDB redirect")
		}
		if redirect != nil {
			return redirect(req, via)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "GoMem-native-symbols/0.1")
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PDB symbol server returned %s for exact identity", response.Status)
	}
	if response.ContentLength > int64(options.MaxDownload) {
		return "", fmt.Errorf("PDB download exceeds size limit")
	}
	f, err := os.CreateTemp(dir, "download-*.pdb")
	if err != nil {
		return "", err
	}
	temporaryPath := f.Name()
	path = temporaryPath
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(temporaryPath)
		}
	}()
	n, err := io.CopyBuffer(f, io.LimitReader(response.Body, int64(options.MaxDownload)+1), make([]byte, 1<<20))
	if err != nil {
		return "", err
	}
	if uint64(n) > options.MaxDownload {
		return "", fmt.Errorf("PDB download exceeds size limit")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return path, nil
}
