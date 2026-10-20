package engine_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxRecoverFsSyslogMember(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional locked legacy Linux filesystem archive; full capability acceptance pending")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{
		Image:   filepath.Join(dir, "linux-sample-1.bin"),
		Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz",
		CaseDir: t.TempDir(),
		OS:      "linux",
		DTB:     "0x1605000",
		Offline: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	var syslog, summary evidence.Row
	var symlinks, oversized, duplicates int
	result, err := e.Run(ctx, "linux.recoverfs", map[string]string{"max-file": "65536", "compression": "gz"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "summary":
			summary = row
		case "file":
			if row.Cells["FilePath"].String() == "/var/log/syslog" {
				syslog = row
			}
			msg := row.Cells["Error"].Error
			switch row.Cells["Error"].Reason {
			case "archive_member_incomplete":
				switch {
				case msg == "fast symlink target is unavailable":
					symlinks++
				case strings.HasPrefix(msg, "cached file length "):
					oversized++
				default:
					t.Fatalf("unexpected member failure: %s", msg)
				}
			case "duplicate_archive_path":
				duplicates++
			}
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || symlinks != 2351 || oversized != 391 || duplicates != 6 {
		t.Fatal(result.Task.State, symlinks, oversized, duplicates, err)
	}
	if syslog.Cells["InodeAddr"].String() != "0xffff88001a87e518" || syslog.Cells["RecoveredSize"].String() != "30143" || syslog.Cells["MissingBytes"].String() != "20480" || syslog.Cells["Error"].Reason != "not_applicable" {
		t.Fatal(syslog.Cells)
	}
	artifact, ok := summary.Cells["FileOutput"].Data.(evidence.Artifact)
	if !ok || artifact.State != "completed" || artifact.Name != "recovered_fs.tar.gz" {
		t.Fatal(summary.Cells["FileOutput"], summary.Cells["Error"])
	}
	coverage, _ := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["archive_members"] != "6473" || coverage["archive_logical_bytes"] != "18573745" || coverage["archive_mtime_unix"] != "0" {
		t.Fatal(coverage)
	}
	raw, err := os.ReadFile(filepath.Join(e.Store.Dir, artifact.Path))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	// MTIME 0 is the gzip "no timestamp" value. Readers surface it as the zero
	// Time rather than Unix epoch, and the four header bytes stay zero.
	if !gz.ModTime.IsZero() || string(raw[4:8]) != "\x00\x00\x00\x00" {
		t.Fatal("gzip header time is not pinned", gz.ModTime, raw[4:8])
	}
	tr := tar.NewReader(gz)
	var body []byte
	var header *tar.Header
	for {
		next, er := tr.Next()
		if er == io.EOF {
			break
		}
		if er != nil {
			t.Fatal(er)
		}
		if next.Name != syslog.Cells["ArchivePath"].String() {
			if _, er = io.Copy(io.Discard, tr); er != nil {
				t.Fatal(er)
			}
			continue
		}
		header = next
		body, er = io.ReadAll(tr)
		if er != nil {
			t.Fatal(er)
		}
	}
	sum := sha256.Sum256(body)
	if header == nil || hex.EncodeToString(sum[:]) != "39301d85a3087a5f5736512ccbfe986c606976280e52487594b93f93d949cd8f" || header.Size != 30143 || header.Mode != 0444 || header.ModTime.Unix() != 0 {
		t.Fatal(header, hex.EncodeToString(sum[:]), len(body))
	}
}
