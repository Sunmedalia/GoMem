// Development-only verifier for sealed pool scanner source captures.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func capture(row evidence.Row, layers map[string]memory.MemoryLayer) error {
	layer, ok := layers[row.Provenance.Layer]
	if !ok {
		return fmt.Errorf("unknown source layer")
	}
	if row.Cells["Layer"].String() != row.Provenance.Layer {
		return fmt.Errorf("source-layer cell differs")
	}
	at, err := row.Cells["Offset"].Uint()
	if err != nil {
		return err
	}
	provenanceOffset, err := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || provenanceOffset != at {
		return fmt.Errorf("source-offset provenance differs")
	}
	requested, err := row.Cells["Requested"].Uint()
	if err != nil || requested > memory.MaxRead {
		return fmt.Errorf("invalid requested length")
	}
	captured, err := row.Cells["Captured"].Uint()
	if err != nil || captured > requested {
		return fmt.Errorf("invalid captured length")
	}
	buf := make([]byte, int(requested))
	n, readErr := layer.ReadAt(context.Background(), buf, at)
	if n < 0 || n > len(buf) || uint64(n) != captured {
		return fmt.Errorf("original captured length differs")
	}
	complete, ok := row.Cells["ReadComplete"].Data.(bool)
	if !ok || row.Cells["ReadComplete"].Kind != "bool" {
		return fmt.Errorf("invalid completeness")
	}
	if complete != (readErr == nil && n == len(buf)) {
		return fmt.Errorf("original read completeness differs")
	}
	if !complete && row.Cells["Error"].Kind != "missing" {
		return fmt.Errorf("incomplete read has no explicit error")
	}
	digest := sha256.Sum256(buf[:n])
	if row.Cells["SHA256"].String() != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("original read digest differs")
	}
	if raw, ok := row.Cells["Raw"]; ok {
		var data []byte
		if raw.Kind != "bytes" {
			return fmt.Errorf("invalid raw capture")
		}
		switch v := raw.Data.(type) {
		case []byte:
			data = v
		case string:
			data, err = base64.StdEncoding.DecodeString(v)
		default:
			return fmt.Errorf("invalid raw bytes")
		}
		if err != nil || !bytes.Equal(data, buf[:n]) {
			return fmt.Errorf("original raw capture differs")
		}
	}
	return nil
}

func run() error {
	image := flag.String("image", "", "Original image")
	rows := flag.String("rows", "", "Sealed pool scanner JSONL")
	dtb := flag.String("dtb", "", "Kernel page root")
	arch := flag.String("arch", "x64", "Intel architecture")
	flag.Parse()
	if *image == "" || *rows == "" || *dtb == "" {
		return fmt.Errorf("--image, --rows and --dtb are required")
	}
	dir, err := os.MkdirTemp("", "gomem-pool-audit-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	eng, err := engine.Open(context.Background(), engine.Config{Image: *image, DTB: *dtb, Arch: *arch, OS: "windows", Offline: true, CaseDir: dir})
	if err != nil {
		return err
	}
	defer eng.Close()
	layers := map[string]memory.MemoryLayer{eng.Env.Physical.Name(): eng.Env.Physical, eng.Env.Kernel.Name(): eng.Env.Kernel}
	f, err := os.Open(*rows)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	var count, reads, objects uint64
	for {
		var row evidence.Row
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		count++
		if err := row.Verify(); err != nil {
			return err
		}
		if row.Provenance.ImageSHA256 != eng.Hash || row.Provenance.Plugin != "windows.poolscanner" {
			return fmt.Errorf("source provenance differs")
		}
		switch row.Cells["RecordType"].String() {
		case "memory_read":
			if err := capture(row, layers); err != nil {
				return fmt.Errorf("row %d: %w", count, err)
			}
			reads++
		case "pool_object":
			objects++
		case "summary", "diagnostic", "task_summary":
		default:
			return fmt.Errorf("unknown pool record type")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"SealedRows": count, "OriginalReads": reads, "PoolObjects": objects, "Scope": "Original captured bytes, digests, read lengths/completeness and seals only; object recovery is validated separately"})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
