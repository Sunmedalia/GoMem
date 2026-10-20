package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/spf13/cobra"
)

func symbolCommands(c *engine.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "symbols", Short: "Inspect, convert or fetch native symbol tables"}
	cmd.AddCommand(convertSymbols(c, out))
	cmd.AddCommand(&cobra.Command{Use: "inspect PATH", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		t, err := symbols.LoadContext(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return jsonOut(out, map[string]any{"sha256": t.Digest(), "metadata": t.Metadata(), "architecture": t.Architecture(), "pointer_size": t.PointerSize(), "types": len(t.Types), "enums": len(t.Enums), "symbols": len(t.Symbols)})
	}})
	var expected string
	fetch := &cobra.Command{Use: "fetch HTTPS_URL", Short: "Fetch a checksum-pinned ISF into CASE/symbols", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) (err error) {
		if c.Offline {
			return fmt.Errorf("symbol download disabled by --offline")
		}
		if c.CaseDir == "" {
			return fmt.Errorf("symbols fetch requires --case")
		}
		if len(expected) != 64 {
			return fmt.Errorf("--sha256 must be a 64-character content checksum")
		}
		if _, err = hex.DecodeString(expected); err != nil {
			return err
		}
		u, err := url.Parse(args[0])
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("symbol URL must be HTTPS without embedded credentials")
		}
		suffix := ".json"
		for _, ext := range []string{".json.gz", ".json.xz", ".json"} {
			if strings.HasSuffix(u.Path, ext) {
				suffix = ext
				break
			}
		}
		dir := filepath.Join(c.CaseDir, "symbols")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		f, err := os.CreateTemp(dir, "download-*"+suffix)
		if err != nil {
			return err
		}
		defer func() { f.Close(); os.Remove(f.Name()) }()
		client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != "https" {
				return fmt.Errorf("unsafe or excessive symbol redirect")
			}
			return nil
		}}
		req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("symbol server returned %s", resp.Status)
		}
		hash := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, symbols.MaxSymbolSize+1))
		if err != nil {
			return err
		}
		if n > symbols.MaxSymbolSize {
			return fmt.Errorf("symbol download exceeds size limit")
		}
		actual := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(actual, expected) {
			return fmt.Errorf("symbol checksum mismatch: got %s", actual)
		}
		if err = f.Close(); err != nil {
			return err
		}
		table, err := symbols.Load(f.Name())
		if err != nil {
			return fmt.Errorf("downloaded ISF: %w", err)
		}
		target := filepath.Join(dir, table.Digest()+suffix)
		dest, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		src, err := os.Open(f.Name())
		if err != nil {
			dest.Close()
			os.Remove(target)
			return err
		}
		_, err = io.Copy(dest, src)
		src.Close()
		closeErr := dest.Close()
		if err != nil || closeErr != nil {
			os.Remove(target)
			if err != nil {
				return err
			}
			return closeErr
		}
		_, err = fmt.Fprintln(out, target)
		return err
	}}
	fetch.Flags().StringVar(&expected, "sha256", "", "Required SHA-256 of downloaded file")
	cmd.AddCommand(fetch)
	return cmd
}
