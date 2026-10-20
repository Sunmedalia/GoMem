package plugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dsnet/compress/bzip2"
	"github.com/ulikunitz/xz"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxRecoverPlugins() []builtin {
	columns := append([]evidence.Column{}, linuxFilesPlugins()[0].spec.Columns...)
	columns = append(columns,
		evidence.Column{Name: "RecoveredSize", Kind: "uint64"},
		evidence.Column{Name: "MissingBytes", Kind: "uint64"},
		evidence.Column{Name: "ArchivePath", Kind: "string"},
		evidence.Column{Name: "FilesystemType", Kind: "string"},
		evidence.Column{Name: "PrefixSource", Kind: "string"},
		evidence.Column{Name: "SymlinkArchive", Kind: "string"},
		evidence.Column{Name: "FileOutput", Kind: "artifact"},
		evidence.Column{Name: "Manifest", Kind: "artifact"},
	)
	return []builtin{{plugin.Spec{Name: "linux.recoverfs", Upstream: "linux.pagecache.RecoverFs", Platform: "linux", NeedsKernel: true,
		Description: "Archive cached directories, regular files and fast symlinks with explicit holes and a reproducible archive time",
		Parameters: []plugin.Parameter{
			{Name: "tmpfs-only", Kind: "bool", Default: "false", Description: "Include only superblocks whose filesystem type is exactly tmpfs"},
			{Name: "compression", Kind: "string", Default: "gz", Description: "Archive compression: gz, bz2 or xz"},
			{Name: "maxsize", Kind: "uint", Default: "1073741824", Description: "Total logical bytes of cached regular files written into the archive, 0..4294967295"},
			{Name: "max-file", Kind: "uint", Default: "134217728", Description: "Per-file logical size eligible for cached expansion, 0..4294967295"},
			{Name: "max-pages", Kind: "uint", Default: "1000000", Description: "Per-inode cache entry bound, 1..1000000"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task, mount and cache-node bound, 1..1000000"},
			{Name: "max-mounts", Kind: "uint", Default: "1000000", Description: "Mount address bound, 1..1000000"},
			{Name: "max-dentries", Kind: "uint", Default: "1000000", Description: "Dentry visit bound, 1..1000000"},
			{Name: "max-depth", Kind: "uint", Default: "256", Description: "Directory depth bound, 1..1024"},
		}, Columns: columns}, linuxRecoverFs}}
}

func linuxTerminatedString(ctx context.Context, layer memory.MemoryLayer, address uint64, limit int) (string, error) {
	if address == 0 {
		return "", fmt.Errorf("null string pointer")
	}
	var out []byte
	for len(out) < limit {
		n := min(64, limit-len(out))
		buf := make([]byte, n)
		got, err := layer.ReadAt(ctx, buf, address+uint64(len(out)))
		if got > 0 {
			if i := bytes.IndexByte(buf[:got], 0); i >= 0 {
				return string(append(out, buf[:i]...)), nil
			}
			out = append(out, buf[:got]...)
		}
		if err != nil || got == 0 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return string(out), err
		}
	}
	return string(out), fmt.Errorf("unterminated string")
}

func linuxSuperblockType(ctx context.Context, e plugin.Environment, sb uint64) (string, error) {
	if _, err := e.Objects.Field("super_block", "s_type"); err != nil {
		return "", err
	}
	pointer, err := e.Objects.Uint(ctx, sb, "super_block", "s_type")
	if err != nil {
		return "", err
	}
	if pointer == 0 {
		return "", fmt.Errorf("superblock type is null")
	}
	namePtr, err := e.Objects.Uint(ctx, pointer, "file_system_type", "name")
	if err != nil {
		return "", err
	}
	name, err := linuxTerminatedString(ctx, e.Kernel, namePtr, 255)
	if err != nil || name == "" {
		if err == nil {
			err = fmt.Errorf("empty filesystem type")
		}
		return name, err
	}
	if _, er := e.Objects.Field("super_block", "s_subtype"); er == nil {
		subPtr, er := e.Objects.Uint(ctx, sb, "super_block", "s_subtype")
		if er != nil {
			return name, er
		}
		if subPtr != 0 {
			sub, er := linuxTerminatedString(ctx, e.Kernel, subPtr, 255)
			if er != nil {
				return name, er
			}
			if sub != "" {
				name += "." + sub
			}
		}
	} else if !errors.Is(er, object.ErrFieldAbsent) {
		return name, er
	}
	return name, nil
}

func linuxRecoveryPrefix(ctx context.Context, e plugin.Environment, sb uint64, device string) (string, string, error) {
	field, err := e.Objects.Field("super_block", "s_uuid")
	if errors.Is(err, object.ErrFieldAbsent) {
		if device == "" {
			return "", "", fmt.Errorf("superblock has neither uuid nor device")
		}
		return "/" + device, "device", nil
	}
	if err != nil {
		return "", "", err
	}
	target, path := sb, "s_uuid"
	if field.Type.Kind == "struct" {
		target, path = sb, "s_uuid.b"
		field, err = e.Objects.Field("super_block", path)
		if err != nil {
			return "", "", err
		}
	}
	if field.Type.Kind != "array" || field.Type.Count != 16 || field.Type.Subtype == nil {
		return "", "", fmt.Errorf("unsupported superblock uuid layout")
	}
	width, err := e.Objects.Size(*field.Type.Subtype)
	if err != nil || width != 1 {
		return "", "", fmt.Errorf("superblock uuid is not 16 bytes")
	}
	address, err := memory.Add(target, field.Offset)
	if err != nil {
		return "", "", err
	}
	raw, err := memory.Read(ctx, e.Kernel, address, 16)
	if err != nil {
		return "", "", err
	}
	text := fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	return "/" + text, "uuid", nil
}

func linuxRelativeSymlink(source, target string) string {
	if !strings.HasPrefix(target, "/") {
		return target
	}
	// Match pathlib.PurePath: collapse repeated separators and resolve "." / "..",
	// then count the symlink's parent components. The filesystem root becomes ".".
	cleaned := path.Clean(target)
	relative := strings.TrimPrefix(cleaned, "/")
	parent := strings.Trim(strings.TrimPrefix(source, "/"), "/")
	if i := strings.LastIndex(parent, "/"); i >= 0 {
		parent = parent[:i]
	} else {
		parent = ""
	}
	ups := 0
	if parent != "" {
		ups = strings.Count(parent, "/") + 1
	}
	parts := make([]string, 0, ups+1)
	for i := 0; i < ups; i++ {
		parts = append(parts, "..")
	}
	if relative != "" {
		parts = append(parts, relative)
	}
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, "/")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func writeArchiveMember(ctx context.Context, tw *tar.Writer, layer memory.MemoryLayer, name string, mode int64, flag byte, link string, size uint64, pages []linuxCachedPage) (uint64, []map[string]string, error) {
	header := &tar.Header{Name: name, Mode: mode, ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Unix(0, 0).UTC(), ChangeTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX, Typeflag: flag, Linkname: link}
	if flag == tar.TypeReg && len(pages) > 0 {
		header.Size = int64(size)
	}
	if err := tw.WriteHeader(header); err != nil {
		return 0, nil, err
	}
	if flag != tar.TypeReg || len(pages) == 0 {
		return 0, nil, nil
	}
	var position, missing uint64
	var gaps []map[string]string
	pad := func(n uint64, reason string) error {
		if n == 0 {
			return nil
		}
		if _, err := io.CopyN(tw, zeroReader{}, int64(n)); err != nil {
			return err
		}
		gaps = append(gaps, map[string]string{"offset": strconv.FormatUint(position, 10), "length": strconv.FormatUint(n, 10), "reason": reason})
		missing += n
		position += n
		return nil
	}
	for _, page := range pages {
		if err := ctx.Err(); err != nil {
			return missing, gaps, err
		}
		offset := page.index * 4096
		if offset < position || offset >= size {
			return missing, gaps, fmt.Errorf("cached page is outside the archive member")
		}
		if err := pad(offset-position, "uncached_page"); err != nil {
			return missing, gaps, err
		}
		want := min(uint64(4096), size-offset)
		data, err := memory.Read(ctx, layer, page.physical, int(want))
		if len(data) > 0 {
			if _, err2 := tw.Write(data); err2 != nil {
				return missing, gaps, err2
			}
			position += uint64(len(data))
		}
		if uint64(len(data)) < want {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			if err2 := pad(want-uint64(len(data)), "physical_read_error: "+err.Error()); err2 != nil {
				return missing, gaps, err2
			}
		}
	}
	if err := pad(size-position, "uncached_page"); err != nil {
		return missing, gaps, err
	}
	return missing, gaps, nil
}

func publishFile(ctx context.Context, e plugin.Environment, file *os.File, name, layer string) (evidence.Value, error) {
	info, err := file.Stat()
	if err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	if info.Size() < 0 {
		err = fmt.Errorf("negative archive size")
		return evidence.Missing("extraction_unavailable", err), err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: name, Size: uint64(info.Size()), Layer: layer, Offset: "0x0"})
	if err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	_, err = io.Copy(w, file)
	artifact, finishErr := w.Finish(ctx, err)
	return evidence.Value{Kind: "artifact", Data: artifact}, errors.Join(err, finishErr)
}

func linuxRecoverFs(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Artifacts == nil {
		return fmt.Errorf("case artifact sink required")
	}
	compression := p["compression"]
	switch compression {
	case "gz", "bz2", "xz":
	default:
		return fmt.Errorf("compression must be gz, bz2 or xz")
	}
	tmpfsOnly, err := strconv.ParseBool(p["tmpfs-only"])
	if err != nil {
		return err
	}
	maxSize, err := strconv.ParseUint(p["maxsize"], 0, 64)
	if err != nil || maxSize > 4294967295 {
		return fmt.Errorf("maxsize must be 0..4294967295")
	}
	maxFile, err := strconv.ParseUint(p["max-file"], 0, 64)
	if err != nil || maxFile > 4294967295 {
		return fmt.Errorf("max-file must be 0..4294967295")
	}
	maxPages, err := strconv.ParseUint(p["max-pages"], 0, 64)
	if err != nil || maxPages == 0 || maxPages > 1000000 {
		return fmt.Errorf("max-pages must be 1..1000000")
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 64)
	if err != nil || maxNodes == 0 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	parameters, err := plugin.Parameters(linuxFilesPlugins()[0].spec, map[string]string{"type": "", "find": "", "follow-symlinks": "false", "max-nodes": p["max-nodes"], "max-mounts": p["max-mounts"], "max-dentries": p["max-dentries"], "max-depth": p["max-depth"]})
	if err != nil {
		return err
	}
	raw, err := os.CreateTemp("", "gomem-recoverfs-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(raw.Name())
	defer raw.Close()
	archive := tar.NewWriter(raw)
	var manifest bytes.Buffer
	var failures pluginFailures
	var used uint64
	var members int
	seen := map[string]bool{}
	identity := map[uint64]struct {
		typ, prefix, source string
		err                 error
	}{}
	var summary evidence.Row
	var outputErr error
	emit := func(row evidence.Row) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		outputErr = out(row)
		return outputErr
	}
	walkErr := linuxFiles(ctx, e, parameters, func(row evidence.Row) error {
		kind := row.Cells["RecordType"].String()
		switch kind {
		case "summary":
			summary = row
			return nil
		case "diagnostic":
			return emit(row)
		case "alias":
			return nil
		case "file":
		default:
			return fmt.Errorf("unexpected filesystem record %s", kind)
		}
		fileType := row.Cells["FileType"].String()
		if fileType != "REG" && fileType != "DIR" && fileType != "LNK" {
			return nil
		}
		path, _ := row.Cells["PathRaw"].Data.([]byte)
		if len(path) == 0 || path[0] != '/' || bytes.IndexByte(path, 0) >= 0 {
			row.Cells["Error"] = evidence.Missing("archive_path_invalid", fmt.Errorf("path is not an absolute NUL-free byte string"))
			failures.add(fmt.Errorf("invalid archive path"))
			return emit(row)
		}
		sb, err := row.Cells["SuperblockAddr"].Uint()
		if err != nil {
			failures.add(err)
			row.Cells["Error"] = evidence.Missing("superblock_unavailable", err)
			return emit(row)
		}
		id, ok := identity[sb]
		if !ok {
			id.typ, err = linuxSuperblockType(ctx, e, sb)
			if errors.Is(err, object.ErrFieldAbsent) {
				id.typ, err = "", nil
			}
			device := ""
			if row.Cells["Device"].Kind == "string" {
				device = row.Cells["Device"].String()
			}
			var prefixErr error
			id.prefix, id.source, prefixErr = linuxRecoveryPrefix(ctx, e, sb, device)
			id.err = errors.Join(err, prefixErr)
			identity[sb] = id
		}
		row.Cells["FilesystemType"] = evidence.Text(id.typ)
		row.Cells["PrefixSource"] = evidence.Text(id.source)
		if id.typ == "" {
			row.Cells["FilesystemType"] = evidence.Missing("filesystem_type_unavailable", id.err)
		}
		if id.err != nil || id.prefix == "" {
			err = id.err
			if err == nil {
				err = fmt.Errorf("missing archive prefix")
			}
			failures.add(err)
			row.Cells["Error"] = evidence.Missing("archive_prefix_unavailable", err)
			return emit(row)
		}
		if tmpfsOnly && id.typ != "tmpfs" {
			return nil
		}
		archivePath := id.prefix + string(path)
		if seen[archivePath] {
			err = fmt.Errorf("duplicate archive path %s", archivePath)
			failures.add(err)
			row.Cells["Error"] = evidence.Missing("duplicate_archive_path", err)
			return emit(row)
		}
		seen[archivePath] = true
		row.Cells["ArchivePath"] = evidence.Text(archivePath)
		row.Cells["RecoveredSize"] = evidence.Number(0)
		row.Cells["MissingBytes"] = evidence.Number(0)
		var gaps []map[string]string
		var memberErr error
		written := false
		abort := false
		switch fileType {
		case "DIR":
			_, _, memberErr = writeArchiveMember(ctx, archive, e.Physical, archivePath, 0755, tar.TypeDir, "", 0, nil)
			written, abort = memberErr == nil, memberErr != nil
		case "LNK":
			inode, err := row.Cells["InodeAddr"].Uint()
			target := evidence.Missing("not_reached", nil)
			if err == nil {
				target, err = linuxFastSymlink(ctx, e, inode)
			}
			row.Cells["SymlinkTargetRaw"] = target
			if err != nil || target.Kind != "bytes" {
				if err == nil {
					err = fmt.Errorf("fast symlink target is unavailable")
				}
				memberErr = err
				break
			}
			rawTarget := target.Data.([]byte)
			display := linuxRelativeSymlink(string(path), string(rawTarget))
			row.Cells["SymlinkArchive"] = evidence.Text(display)
			_, _, memberErr = writeArchiveMember(ctx, archive, e.Physical, archivePath, 0444, tar.TypeSymlink, display, 0, nil)
			written, abort = memberErr == nil, memberErr != nil
		case "REG":
			size, sizeErr := row.Cells["InodeSize"].Int()
			cachedCount, cachedErr := row.Cells["CachedPages"].Uint()
			if sizeErr != nil || size < 0 || cachedErr != nil {
				memberErr = errors.Join(sizeErr, cachedErr, fmt.Errorf("regular file size or cache count is unavailable"))
				break
			}
			payload := uint64(0)
			if cachedCount > 0 {
				payload = uint64(size)
			}
			if payload > maxFile || payload > maxSize-used {
				memberErr = fmt.Errorf("cached file length %d exceeds max-file or remaining maxsize", payload)
				break
			}
			if payload == 0 {
				_, _, memberErr = writeArchiveMember(ctx, archive, e.Physical, archivePath, 0444, tar.TypeReg, "", 0, nil)
				written, abort = memberErr == nil, memberErr != nil
				break
			}
			inode, err := row.Cells["InodeAddr"].Uint()
			var pages []linuxCachedPage
			var dumpErr error
			if err == nil {
				_, pages, dumpErr = linuxDumpablePages(ctx, e, inode, maxNodes, maxPages)
			} else {
				dumpErr = err
			}
			if len(pages) == 0 {
				memberErr = dumpErr
				if memberErr == nil {
					_, _, memberErr = writeArchiveMember(ctx, archive, e.Physical, archivePath, 0444, tar.TypeReg, "", 0, nil)
					written, abort = memberErr == nil, memberErr != nil
				}
				break
			}
			missing, fileGaps, writeErr := writeArchiveMember(ctx, archive, e.Physical, archivePath, 0444, tar.TypeReg, "", payload, pages)
			if writeErr != nil {
				memberErr = errors.Join(dumpErr, writeErr)
				abort = true
				break
			}
			gaps = fileGaps
			row.Cells["RecoveredSize"] = evidence.Number(payload)
			row.Cells["MissingBytes"] = evidence.Number(missing)
			used += payload
			written = true
			memberErr = dumpErr
		}
		if written {
			members++
			record := map[string]any{"path": archivePath, "type": fileType, "inode": row.Cells["InodeAddr"].String(), "recovered_size": row.Cells["RecoveredSize"].String(), "missing_bytes": row.Cells["MissingBytes"].String(), "gaps": gaps}
			line, err := json.Marshal(record)
			if err != nil {
				return err
			}
			manifest.Write(append(line, '\n'))
		} else {
			delete(seen, archivePath)
		}
		if memberErr != nil {
			failures.add(memberErr)
			row.Cells["Error"] = evidence.Missing("archive_member_incomplete", memberErr)
			if abort {
				if err := emit(row); err != nil {
					return err
				}
				return memberErr
			}
		}
		return emit(row)
	})
	if outputErr != nil {
		return outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	closeErr := archive.Close()
	failures.add(walkErr)
	failures.add(closeErr)
	compressed, err := os.CreateTemp("", "gomem-recoverfs-*.bin")
	if err != nil {
		return err
	}
	defer os.Remove(compressed.Name())
	defer compressed.Close()
	if _, err = raw.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var compressor io.WriteCloser
	switch compression {
	case "gz":
		zw := gzip.NewWriter(compressed)
		// The tar members are already pinned to the Unix epoch. Pin the gzip
		// header too, or the artifact hash changes on every run.
		zw.ModTime = time.Unix(0, 0).UTC()
		compressor = zw
	case "bz2":
		compressor, err = bzip2.NewWriter(compressed, nil)
	case "xz":
		compressor, err = xz.NewWriter(compressed)
	}
	if err == nil {
		_, err = io.Copy(compressor, raw)
		err = errors.Join(err, compressor.Close())
	}
	failures.add(err)
	name := "recovered_fs.tar." + compression
	archiveValue := evidence.Missing("extraction_unavailable", err)
	if err == nil {
		archiveValue, err = publishFile(ctx, e, compressed, name, "linux.recoverfs")
		failures.add(err)
	}
	manifestFile, manifestErr := os.CreateTemp("", "gomem-recoverfs-*.jsonl")
	if manifestErr == nil {
		_, manifestErr = manifestFile.Write(manifest.Bytes())
		if manifestErr == nil {
			value, er := publishFile(ctx, e, manifestFile, "recovered_fs.manifest.jsonl", "linux.recoverfs.manifest")
			manifestErr = er
			if summary.Cells == nil {
				summary = evidence.Row{Cells: map[string]evidence.Value{}}
			}
			summary.Cells["Manifest"] = value
		}
		manifestFile.Close()
		os.Remove(manifestFile.Name())
	}
	failures.add(manifestErr)
	if summary.Cells == nil {
		summary.Cells = map[string]evidence.Value{}
	}
	for _, column := range linuxRecoverPlugins()[0].spec.Columns {
		if _, ok := summary.Cells[column.Name]; !ok {
			summary.Cells[column.Name] = evidence.Missing("not_applicable", nil)
		}
	}
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["FileOutput"] = archiveValue
	coverage, _ := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage == nil {
		coverage = map[string]any{}
	}
	coverage["archive_members"] = strconv.Itoa(members)
	coverage["archive_logical_bytes"] = strconv.FormatUint(used, 10)
	coverage["archive_mtime_unix"] = "0"
	coverage["compression"] = compression
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: coverage}
	if cause := failures.err("Linux cached filesystem recovery"); cause != nil {
		summary.Cells["Error"] = evidence.Missing("recovery_incomplete", cause)
	}
	if err = emit(summary); err != nil {
		return err
	}
	return failures.err("Linux cached filesystem recovery")
}
