package library

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const CatalogURL = "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json"
const rawBase = "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/"

type Candidate struct {
	Identity Identity `json:"identity"`
	URL      string   `json:"url"`
	Name     string   `json:"name"`
}
type Remote struct {
	Client  *http.Client
	Offline bool
}

func (r Remote) get(ctx context.Context, address string) (*http.Response, error) {
	if r.Offline {
		return nil, fmt.Errorf("symbol lookup/download disabled by --offline")
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("symbol URL must use HTTPS")
	}
	client := http.Client{Timeout: 2 * time.Minute}
	if r.Client != nil {
		client = *r.Client
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return fmt.Errorf("unsafe symbol redirect")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("symbol server returned %s", resp.Status)
	}
	return resp, nil
}
func (r Remote) Lookup(ctx context.Context, p Probe) ([]Candidate, error) {
	result := []Candidate{}
	needLinux := false
	for _, id := range p.Identities {
		if id.OS == "linux" {
			needLinux = true
		}
	}
	var catalog map[string][]string
	if needLinux {
		resp, err := r.get(ctx, CatalogURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		if err != nil {
			return nil, err
		}
		if len(b) > 32<<20 {
			return nil, fmt.Errorf("symbol catalog exceeds size limit")
		}
		if err = json.Unmarshal(b, &catalog); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, id := range p.Identities {
		if id.OS == "windows" && id.PDB != nil {
			key := strings.ToUpper(strings.ReplaceAll(id.PDB.GUID, "-", "")) + fmt.Sprintf("%X", id.PDB.Age)
			address := symbols.MicrosoftSymbolServer + "/" + id.PDB.Database + "/" + key + "/" + id.PDB.Database
			result = append(result, Candidate{id, address, id.PDB.Database})
			continue
		}
		// The upstream catalog omits the banner's final newline. No version-only
		// or fuzzy fallback is allowed: compiler/build differences matter.
		for _, path := range catalog[strings.TrimRight(id.Banner, "\n")] {
			address := path
			if !strings.HasPrefix(path, "https://") {
				if !filepath.IsLocal(path) || strings.Contains(path, "\\") {
					return nil, fmt.Errorf("unsafe catalog path")
				}
				address = rawBase + (&url.URL{Path: path}).EscapedPath()
			}
			if !strings.HasPrefix(address, rawBase) && !strings.HasPrefix(address, "https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/") {
				return nil, fmt.Errorf("untrusted catalog URL")
			}
			u, err := url.Parse(address)
			if err != nil {
				return nil, err
			}
			name := filepath.Base(u.Path)
			if !validName(name) || !strings.HasSuffix(name, ".json.xz") && !strings.HasSuffix(name, ".json.gz") && !strings.HasSuffix(name, ".json") {
				return nil, fmt.Errorf("unsupported catalog symbol file")
			}
			if !seen[address] {
				seen[address] = true
				result = append(result, Candidate{id, address, name})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result, nil
}

// Download is called only after the UI/CLI has obtained explicit confirmation.
// Identity validation precedes publication; upstream does not supply checksums.
func (r Remote) Download(ctx context.Context, l Library, c Candidate) (string, error) {
	if r.Offline {
		return "", fmt.Errorf("symbol download disabled by --offline")
	}
	root, err := l.open(Symbols)
	if err != nil {
		return "", err
	}
	root.Close()
	if c.Identity.OS == "windows" && c.Identity.PDB != nil {
		build, err := version.Identity()
		if err != nil {
			return "", err
		}
		t, _, err := symbols.ResolvePDB(ctx, *c.Identity.PDB, symbols.PDBCacheOptions{Directory: filepath.Join(l.Directory(Symbols), ".pdb-cache"), BuildSHA256: build, Client: r.Client})
		if err != nil {
			return "", err
		}
		b, err := t.Encode()
		if err != nil {
			return "", err
		}
		return l.save(ctx, Symbols, t.Digest()+".json", strings.NewReader(string(b)))
	}
	resp, err := r.get(ctx, c.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(l.Directory(Symbols), ".download-*"+suffix(c.Name))
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, symbols.MaxSymbolSize+1))
	closeErr := tmp.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n > symbols.MaxSymbolSize {
		return "", fmt.Errorf("symbol download exceeds size limit")
	}
	t, err := symbols.LoadContext(ctx, tmp.Name())
	if err != nil {
		return "", err
	}
	if !c.Identity.Matches(t) {
		return "", fmt.Errorf("downloaded symbols do not match the image kernel identity")
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Stable content naming permits multiple builds with identical upstream names.
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err = f.Seek(0, 0); err != nil {
		return "", err
	}
	return l.save(ctx, Symbols, fmt.Sprintf("%x", h.Sum(nil))+suffix(c.Name), f)
}
func suffix(name string) string {
	for _, ext := range []string{".json.xz", ".json.gz"} {
		if strings.HasSuffix(name, ext) {
			return ext
		}
	}
	return ".json"
}
