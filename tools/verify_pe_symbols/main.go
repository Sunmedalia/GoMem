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
	rows := flag.String("jsonl", "", "Saved Windows symbol or ETW evidence JSONL")
	expectedPlugin := flag.String("plugin", "windows.pe_symbols", "Expected command: windows.pe_symbols or windows.etwpatch")
	flag.Parse()
	if *expectedPlugin != "windows.pe_symbols" && *expectedPlugin != "windows.etwpatch" {
		return fmt.Errorf("unsupported verification command %s", *expectedPlugin)
	}
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
	var findings, probes, acquisitions, summaries, expectedReads uint64
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
		if summaries > 0 {
			return fmt.Errorf("records follow terminal summary")
		}
		count++
		if row.Provenance.ImageSHA256 != e.Hash || row.Provenance.Plugin != *expectedPlugin || row.Provenance.SymbolsSHA256 != e.Env.Symbols.Digest() {
			return fmt.Errorf("row %d provenance mismatch", count)
		}
		switch row.Cells["RecordType"].String() {
		case "symbol":
			if *expectedPlugin != "windows.pe_symbols" {
				return fmt.Errorf("unexpected symbol record")
			}
			symbols++
		case "finding":
			if *expectedPlugin != "windows.etwpatch" {
				return fmt.Errorf("unexpected finding record")
			}
			findings++
		case "summary":
			summaries++
			if *expectedPlugin == "windows.etwpatch" {
				var coverage struct{ Acquisition struct{ Reads uint64 } }
				encoded, cause := json.Marshal(row.Cells["Coverage"].Data)
				if cause != nil {
					return cause
				}
				if cause = json.Unmarshal(encoded, &coverage); cause != nil {
					return cause
				}
				expectedReads = coverage.Acquisition.Reads
			}
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

			calls, method, cause := readCalls(row.Cells["Resolution"].Data, at, requested, captured, row.Cells["Error"].Kind == "missing")
			if cause != nil {
				return cause
			}
			cursor := uint64(0)
			for _, call := range calls {
				actual := make([]byte, int(call.Requested))
				n, readErr := layer.ReadAt(ctx, actual, call.Offset)
				if n < 0 || n > len(actual) {
					return fmt.Errorf("invalid original read count")
				}
				if readErr == nil && n != len(actual) {
					readErr = io.ErrUnexpectedEOF
				}
				if uint64(n) != call.Captured || !bytes.Equal(actual[:n], raw[cursor:cursor+call.Captured]) || (readErr == nil) != (row.Cells["Error"].Kind == "missing") {
					return fmt.Errorf("original acquisition mismatch at %s/%#x: %v", layer.Name(), call.Offset, readErr)
				}
				if readErr != nil {
					failed++
				}
				cursor += call.Captured
				acquisitions++
			}
			if cursor != captured {
				return fmt.Errorf("unverified captured bytes")
			}
			if method == "opcode" {
				probes++
			}
			captures++
			bytesRead += captured
		default:
			return fmt.Errorf("unknown PE-symbol record type")
		}
	}
	if summaries != 1 {
		return fmt.Errorf("missing terminal summary; input may be incomplete")
	}
	if *expectedPlugin == "windows.etwpatch" && acquisitions != expectedReads {
		return fmt.Errorf("summary/acquisition count mismatch: %d/%d", expectedReads, acquisitions)
	}
	if captures == 0 {
		return fmt.Errorf("no read captures in input")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"image_sha256": e.Hash, "rows": count, "captures": captures, "acquisition_calls": acquisitions, "read_faults": failed, "captured_bytes": bytesRead, "symbols": symbols, "findings": findings, "opcode_probes": probes, "plugin": *expectedPlugin, "process_layers": len(layers) - 1, "all_seals_and_provenance_verified": true, "all_captures_independently_reread": true})
}

type acquisitionCall struct{ Offset, Requested, Captured uint64 }

func readCalls(value any, at, requested, captured uint64, success bool) ([]acquisitionCall, string, error) {
	var detail struct {
		Method       string
		Grouped      bool
		Acquisitions []struct {
			Offset              string
			Requested, Captured uint64
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	if err = json.Unmarshal(encoded, &detail); err != nil {
		return nil, "", err
	}
	if !detail.Grouped {
		if len(detail.Acquisitions) > 0 {
			return nil, "", fmt.Errorf("ungrouped read has acquisition boundaries")
		}
		return []acquisitionCall{{at, requested, captured}}, detail.Method, nil
	}
	if detail.Method != "exports" || !success || requested != captured || requested > 4096 || len(detail.Acquisitions) < 2 || len(detail.Acquisitions) > 64 {
		return nil, "", fmt.Errorf("invalid grouped export acquisition")
	}
	var calls []acquisitionCall
	var total uint64
	for _, call := range detail.Acquisitions {
		offset, err := (evidence.Value{Kind: "address", Data: call.Offset}).Uint()
		if err != nil || total > ^uint64(0)-at || offset != at+total || call.Requested == 0 || call.Requested != call.Captured || call.Captured > captured-total {
			return nil, "", fmt.Errorf("invalid original export acquisition boundary")
		}
		calls = append(calls, acquisitionCall{offset, call.Requested, call.Captured})
		total += call.Captured
	}
	if total != captured {
		return nil, "", fmt.Errorf("grouped acquisition omitted bytes")
	}
	return calls, detail.Method, nil
}
