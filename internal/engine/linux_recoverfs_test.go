package engine_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/dsnet/compress/bzip2"
	"github.com/ulikunitz/xz"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxRecoverType(t *testing.T, f testfixture.Fixture, name string) testfixture.Fixture {
	t.Helper()
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	sb := table.Types["super_block"]
	sb.Size = 24
	sb.Fields["s_type"] = symbols.Field{Offset: 16, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["super_block"] = sb
	table.Types["file_system_type"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"name": {Offset: 0, Type: symbols.TypeRef{Kind: "pointer"}}}}
	binary.LittleEndian.PutUint64(data[0x24010:], 0x2b000)
	binary.LittleEndian.PutUint64(data[0x2b000:], 0x2b100)
	copy(data[0x2b100:], append([]byte(name), 0))
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil || os.WriteFile(f.Image, data, 0600) != nil {
		t.Fatal(err)
	}
	return f
}

func recoverArchive(t *testing.T, e *engine.Engine, params map[string]string) (map[string]*tar.Header, map[string][]byte, evidence.Row) {
	t.Helper()
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "linux.recoverfs", params, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if len(rows) == 0 || rows[len(rows)-1].Cells["RecordType"].String() != "summary" {
		t.Fatal(result, rows, err)
	}
	summary := rows[len(rows)-1]
	artifact, ok := summary.Cells["FileOutput"].Data.(evidence.Artifact)
	if !ok || artifact.State != "completed" {
		t.Fatal(summary.Cells["FileOutput"], err)
	}
	raw, err := os.ReadFile(e.Store.Dir + "/" + artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	var reader io.Reader = bytes.NewReader(raw)
	switch params["compression"] {
	case "", "gz":
		reader, err = gzip.NewReader(reader)
	case "xz":
		reader, err = xz.NewReader(reader)
	case "bz2":
		reader, err = bzip2.NewReader(reader, nil)
	default:
		t.Fatal(params["compression"])
	}
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(reader)
	headers, bodies := map[string]*tar.Header{}, map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		headers[header.Name] = header
		bodies[header.Name] = body
		if !header.ModTime.Equal(header.ModTime.UTC()) || header.ModTime.Unix() != 0 {
			t.Fatal("archive time is not the reproducible epoch", header.Name, header.ModTime)
		}
	}
	return headers, bodies, summary
}

func TestLinuxRecoverFsArchivesCachedBytesAndSkipsOversizedFiles(t *testing.T) {
	e := openLinuxELF(t, linuxFilesFixture(t, "normal"), true)
	headers, bodies, summary := recoverArchive(t, e, nil)
	if string(bodies["/8:1/evidence.bin"]) != "HELLO" || headers["/8:1/evidence.bin"].Size != 5 {
		t.Fatal(headers["/8:1/evidence.bin"], bodies["/8:1/evidence.bin"])
	}
	if headers["/8:1/link"].Linkname != "evidence.bin" || headers["/8:1/dir/nested"].Size != 0 || headers["/8:1/"].Typeflag != tar.TypeDir {
		t.Fatal(headers)
	}
	if _, ok := headers["/8:1/alias.bin"]; ok || summary.Cells["Error"].Reason != "not_applicable" {
		t.Fatal("alias archived or unexpected summary", headers, summary.Cells["Error"])
	}
	first, _ := summary.Cells["FileOutput"].Data.(evidence.Artifact)
	repeat := openLinuxELF(t, linuxFilesFixture(t, "normal"), true)
	_, _, again := recoverArchive(t, repeat, nil)
	second, _ := again.Cells["FileOutput"].Data.(evidence.Artifact)
	if first.SHA256 == "" || first.SHA256 != second.SHA256 {
		t.Fatal("compressed archive is not reproducible", first.SHA256, second.SHA256)
	}
	limited := openLinuxELF(t, linuxFilesFixture(t, "normal"), true)
	var skipped evidence.Row
	result, err := limited.Run(context.Background(), "linux.recoverfs", map[string]string{"max-file": "4"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["FilePath"].String() == "/evidence.bin" {
			skipped = row
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || skipped.Cells["Error"].Reason != "archive_member_incomplete" {
		t.Fatal(result, skipped, err)
	}
}

func TestLinuxRecoverFsFilesystemFilterAndCompression(t *testing.T) {
	for _, format := range []string{"gz", "bz2", "xz"} {
		t.Run(format, func(t *testing.T) {
			e := openLinuxELF(t, linuxRecoverType(t, linuxFilesFixture(t, "normal"), "tmpfs"), true)
			headers, bodies, _ := recoverArchive(t, e, map[string]string{"compression": format, "tmpfs-only": "true"})
			if string(bodies["/8:1/evidence.bin"]) != "HELLO" || headers["/8:1/link"].Typeflag != tar.TypeSymlink {
				t.Fatal(headers, bodies["/8:1/evidence.bin"])
			}
		})
	}
	e := openLinuxELF(t, linuxRecoverType(t, linuxFilesFixture(t, "normal"), "ext4"), true)
	headers, _, summary := recoverArchive(t, e, map[string]string{"tmpfs-only": "true"})
	if len(headers) != 0 || summary.Cells["Error"].Reason != "not_applicable" {
		t.Fatal(headers, summary.Cells["Error"])
	}
	bare := openLinuxELF(t, linuxFilesFixture(t, "normal"), false)
	if _, err := bare.Run(context.Background(), "linux.recoverfs", nil, engine.RunOptions{}); err == nil {
		t.Fatal("recovery without a case succeeded")
	}
}
