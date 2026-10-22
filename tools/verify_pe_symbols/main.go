// Command verify_pe_symbols independently rereads a saved Windows PE-symbol
// JSONL stream through process roots collected afresh from the original image.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	image := flag.String("image", "", "Original image")
	table := flag.String("symbols", "", "Exact kernel ISF")
	rows := flag.String("jsonl", "", "Saved PE-symbol evidence JSONL")
	flag.Parse()
	if *image == "" || *table == "" || *rows == "" {
		return fmt.Errorf("image, symbols and jsonl are required")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: *image, Symbols: *table, Offline: true})
	if err != nil {
		return err
	}
	defer e.Close()
	layers := map[string]memory.MemoryLayer{e.Env.Kernel.Name(): e.Env.Kernel}
	ps, err := e.Registry.Get("windows.pslist")
	if err != nil {
		return err
	}
	params, err := plugin.Parameters(ps.Spec(), nil)
	if err != nil {
		return err
	}
	err = ps.Run(ctx, e.Env, params, func(row evidence.Row) error {
		root, cause := row.Cells["DTB"].Uint()
		if cause != nil || root == 0 {
			return nil
		}
		id := "process:" + row.Cells["Identity"].String()
		translator, cause := memory.NewTranslatorForOS(e.Env.Physical, root, e.Env.Architecture, e.Env.OS, 1024)
		if cause != nil {
			return cause
		}
		layers[id] = &memory.Virtual{Physical: e.Env.Physical, Translator: translator, ID: id}
		return nil
	})
	if err != nil {
		return err
	}
	file, err := os.Open(*rows)
	if err != nil {
		return err
	}
	defer file.Close()
	decode := json.NewDecoder(bufio.NewReaderSize(file, 64<<10))
	var captures, failed, symbols, count, bytesRead uint64
	for {
		var row evidence.Row
		if err := decode.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if err := row.Verify(); err != nil {
			return fmt.Errorf("row %d seal: %w", count, err)
		}
		count++
		if row.Provenance.ImageSHA256 != e.Hash || row.Provenance.Plugin != "windows.pe_symbols" || row.Provenance.SymbolsSHA256 != e.Env.Symbols.Digest() {
			return fmt.Errorf("row %d provenance mismatch", count)
		}
		switch row.Cells["RecordType"].String() {
		case "symbol":
			symbols++
		case "summary":
		case "memory_read":
			layer, ok := layers[row.Provenance.Layer]
			if !ok {
				return fmt.Errorf("unknown original process layer %s", row.Provenance.Layer)
			}
			at, cause := row.Cells["Offset"].Uint()
			if cause != nil {
				return cause
			}
			requested, cause := row.Cells["Requested"].Uint()
			if cause != nil || requested > memory.MaxRead {
				return fmt.Errorf("invalid read length")
			}
			raw, ok := row.Cells["Raw"].Data.([]byte)
			if !ok {
				text, valid := row.Cells["Raw"].Data.(string)
				if !valid {
					return fmt.Errorf("raw bytes unavailable")
				}
				raw, cause = base64.StdEncoding.DecodeString(text)
				if cause != nil {
					return cause
				}
			}
			captured, cause := row.Cells["Captured"].Uint()
			if cause != nil || captured != uint64(len(raw)) {
				return fmt.Errorf("captured byte count mismatch")
			}
			actual := make([]byte, int(requested))
			n, cause := layer.ReadAt(ctx, actual, at)
			if n < 0 || n > len(actual) {
				return fmt.Errorf("invalid original read count")
			}
			if cause == nil && n != len(actual) {
				cause = io.ErrUnexpectedEOF
			}
			actual = actual[:n]
			if !bytes.Equal(actual, raw) || (cause == nil) != (row.Cells["Error"].Kind == "missing") {
				return fmt.Errorf("original read mismatch at %s/%#x: %v", layer.Name(), at, cause)
			}
			captures++
			bytesRead += captured
			if cause != nil {
				failed++
			}
		default:
			return fmt.Errorf("unknown PE-symbol record type")
		}
	}
	if captures == 0 {
		return fmt.Errorf("no read captures in input")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"image_sha256": e.Hash, "rows": count, "captures": captures, "read_faults": failed, "captured_bytes": bytesRead, "symbols": symbols, "process_layers": len(layers) - 1, "all_seals_and_provenance_verified": true, "all_captures_independently_reread": true})
}
