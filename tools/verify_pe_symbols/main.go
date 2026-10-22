// Command verify_pe_symbols independently rereads a saved Windows PE-symbol
// JSONL stream through process roots collected afresh from the original image.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	rows := flag.String("jsonl", "", "Saved Windows symbol, ETW or IAT evidence JSONL")
	expectedPlugin := flag.String("plugin", "windows.pe_symbols", "Expected command: windows.pe_symbols, windows.etwpatch, windows.iat or windows.malfind")
	flag.Parse()
	if *expectedPlugin != "windows.pe_symbols" && *expectedPlugin != "windows.etwpatch" && *expectedPlugin != "windows.iat" && *expectedPlugin != "windows.malfind" {
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
	layers := map[string]memory.MemoryLayer{e.Env.Kernel.Name(): e.Env.Kernel, e.Env.Physical.Name(): e.Env.Physical}
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
	streamHash := sha256.New()
	decode := json.NewDecoder(bufio.NewReaderSize(io.TeeReader(file, streamHash), 64<<10))
	var captures, failed, symbols, count, bytesRead uint64
	var findings, probes, acquisitions, summaries, expectedReads, imports, diagnostics, expectedImports, expectedFindings uint64
	widths := map[string]int{}
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
			if *expectedPlugin != "windows.etwpatch" && *expectedPlugin != "windows.malfind" {
				return fmt.Errorf("unexpected finding record")
			}
			if *expectedPlugin == "windows.malfind" {
				if cause := verifyMalfindRow(ctx, row, layers); cause != nil {
					return cause
				}
			}
			findings++
		case "import":
			if *expectedPlugin != "windows.iat" {
				return fmt.Errorf("unexpected import record")
			}
			if cause := verifyImportRow(ctx, row, layers, widths); cause != nil {
				return cause
			}
			imports++
		case "diagnostic":
			if *expectedPlugin != "windows.iat" && *expectedPlugin != "windows.malfind" {
				return fmt.Errorf("unexpected diagnostic record")
			}
			diagnostics++
		case "summary":
			summaries++
			if *expectedPlugin == "windows.etwpatch" || *expectedPlugin == "windows.iat" || *expectedPlugin == "windows.malfind" {
				var coverage struct {
					Acquisition struct{ Reads uint64 }
					Imports     uint64
					Findings    uint64
				}
				encoded, cause := json.Marshal(row.Cells["Coverage"].Data)
				if cause != nil {
					return cause
				}
				if cause = json.Unmarshal(encoded, &coverage); cause != nil {
					return cause
				}
				expectedReads = coverage.Acquisition.Reads
				expectedImports = coverage.Imports
				expectedFindings = coverage.Findings
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
	if (*expectedPlugin == "windows.etwpatch" || *expectedPlugin == "windows.iat" || *expectedPlugin == "windows.malfind") && acquisitions != expectedReads {
		return fmt.Errorf("summary/acquisition count mismatch: %d/%d", expectedReads, acquisitions)
	}
	if *expectedPlugin == "windows.iat" && expectedImports != imports {
		return fmt.Errorf("IAT summary/import count mismatch")
	}
	if (*expectedPlugin == "windows.malfind" || *expectedPlugin == "windows.etwpatch") && findings != expectedFindings {
		return fmt.Errorf("summary/finding count mismatch")
	}
	if captures == 0 {
		return fmt.Errorf("no read captures in input")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"image_sha256": e.Hash, "jsonl_sha256": fmt.Sprintf("%x", streamHash.Sum(nil)), "imports": imports, "diagnostics": diagnostics, "all_iat_coordinates_and_available_pointers_verified": *expectedPlugin == "windows.iat", "rows": count, "captures": captures, "acquisition_calls": acquisitions, "read_faults": failed, "captured_bytes": bytesRead, "symbols": symbols, "findings": findings, "opcode_probes": probes, "plugin": *expectedPlugin, "process_layers": len(layers) - 2, "all_seals_and_provenance_verified": true, "all_captures_independently_reread": true})
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

// Independently decode only the PE width; the forensics import parser is not
// used to validate the separate actual slot and captured pointer fields.
func verifyImportRow(ctx context.Context, row evidence.Row, layers map[string]memory.MemoryLayer, widths map[string]int) error {
	layer := layers[row.Provenance.Layer]
	if layer == nil {
		return fmt.Errorf("unknown import process layer")
	}
	base, err := row.Cells["ImageBase"].Uint()
	if err != nil {
		return err
	}
	slot, err := row.Cells["IATSlot"].Uint()
	if err != nil {
		return err
	}
	address, err := row.Cells["Address"].Uint()
	if err != nil {
		return err
	}
	expected, err := memory.Add(base, slot)
	if err != nil || expected != address {
		return fmt.Errorf("IAT baseline/actual coordinates disagree")
	}
	provenance, err := (evidence.Value{Kind: "address", Data: row.Provenance.Offset}).Uint()
	if err != nil || provenance != slot {
		return fmt.Errorf("IAT slot provenance mismatch")
	}
	key := fmt.Sprintf("%s/%x", layer.Name(), base)
	width := widths[key]
	if width == 0 {
		dos, err := memory.Read(ctx, layer, base, 64)
		if err != nil {
			return err
		}
		if string(dos[:2]) != "MZ" {
			return fmt.Errorf("invalid original IAT DOS header")
		}
		nt := uint64(binary.LittleEndian.Uint32(dos[60:]))
		if nt > 16<<20 {
			return fmt.Errorf("invalid original IAT NT offset")
		}
		at, err := memory.Add(base, nt)
		if err != nil {
			return err
		}
		header, err := memory.Read(ctx, layer, at, 26)
		if err != nil {
			return err
		}
		if string(header[:4]) != "PE\x00\x00" {
			return fmt.Errorf("invalid original IAT NT header")
		}
		machine, magic := binary.LittleEndian.Uint16(header[4:]), binary.LittleEndian.Uint16(header[24:])
		switch {
		case machine == 0x14c && magic == 0x10b:
			width = 4
		case machine == 0x8664 && magic == 0x20b:
			width = 8
		default:
			return fmt.Errorf("invalid original IAT machine/magic")
		}
		widths[key] = width
	}
	pointer := row.Cells["ResolvedPointer"]
	if pointer.Kind == "missing" {
		if pointer.Reason != "iat_entry_unavailable" {
			return fmt.Errorf("unknown IAT missing pointer reason")
		}
		return nil
	}
	expectedPointer, err := pointer.Uint()
	if err != nil {
		return err
	}
	raw, err := memory.Read(ctx, layer, slot, width)
	if err != nil {
		return err
	}
	actual := uint64(binary.LittleEndian.Uint32(raw))
	if width == 8 {
		actual = binary.LittleEndian.Uint64(raw)
	}
	if actual != expectedPointer {
		return fmt.Errorf("captured IAT pointer mismatch")
	}
	return nil
}

func evidenceBytes(value evidence.Value) ([]byte, error) {
	if value.Kind != "bytes" {
		return nil, fmt.Errorf("expected bytes evidence")
	}
	switch raw := value.Data.(type) {
	case []byte:
		return raw, nil
	case string:
		return base64.StdEncoding.DecodeString(raw)
	default:
		return nil, fmt.Errorf("invalid bytes evidence encoding")
	}
}
func verifyMalfindRow(ctx context.Context, row evidence.Row, layers map[string]memory.MemoryLayer) error {
	layer := layers[row.Provenance.Layer]
	if layer == nil {
		return fmt.Errorf("unknown malfind process layer")
	}
	start, err := row.Cells["Start"].Uint()
	if err != nil {
		return err
	}
	end, err := row.Cells["End"].Uint()
	if err != nil || end < start {
		return fmt.Errorf("invalid malfind range")
	}
	if row.Cells["Hexdump"].Kind == "missing" {
		if row.Cells["Hexdump"].Reason != "first_bytes_unavailable" || row.Cells["Hexdump"].Error == "" {
			return fmt.Errorf("invalid missing first-byte evidence")
		}
		if _, cause := memory.Read(ctx, layer, start, 64); cause == nil {
			return fmt.Errorf("missing hexdump asserted over readable bytes")
		}
	} else {
		raw, err := evidenceBytes(row.Cells["Hexdump"])
		if err != nil || len(raw) != 64 {
			return fmt.Errorf("invalid malfind first-byte capture")
		}
		actual, err := memory.Read(ctx, layer, start, 64)
		if err != nil || !bytes.Equal(raw, actual) {
			return fmt.Errorf("original malfind first bytes differ: %v", err)
		}
		var disasm struct{ Bytes, Address, Architecture evidence.Value }
		encoded, err := json.Marshal(row.Cells["Disassembly"].Data)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(encoded, &disasm); err != nil {
			return err
		}
		decoded, err := evidenceBytes(disasm.Bytes)
		if err != nil || !bytes.Equal(decoded, raw) {
			return fmt.Errorf("disassembly input differs")
		}
		at, err := disasm.Address.Uint()
		if err != nil || at != start {
			return fmt.Errorf("disassembly origin differs")
		}
		if disasm.Architecture.String() != "intel" && disasm.Architecture.String() != "intel64" {
			return fmt.Errorf("unknown disassembly architecture")
		}
	}
	nonzero, err := row.Cells["NonzeroPage"].Uint()
	if err != nil || nonzero < start || nonzero > end {
		return fmt.Errorf("invalid nonzero-page origin")
	}
	actual, err := memory.Read(ctx, layer, nonzero, 4096)
	if err != nil || bytes.Equal(actual, make([]byte, 4096)) {
		return fmt.Errorf("nonzero-page selection not supported: %v", err)
	}
	if row.Cells["DirtyPage"].Kind != "missing" {
		page, err := row.Cells["DirtyPage"].Uint()
		if err != nil || page < start || page > end {
			return fmt.Errorf("invalid dirty-page origin")
		}
		virtual, ok := layer.(*memory.Virtual)
		if !ok {
			return fmt.Errorf("dirty translator unavailable")
		}
		tr, err := virtual.Translator.Translate(ctx, page)
		if err != nil || !tr.DirtyKnown || !tr.Dirty {
			return fmt.Errorf("dirty-page flag not supported")
		}
		var leaf struct{ PhysicalEntry, Entry, EntryWidth, PageSize, Virtual, Dirty evidence.Value }
		encoded, err := json.Marshal(row.Cells["DirtyLeaf"].Data)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(encoded, &leaf); err != nil {
			return err
		}
		for _, pair := range []struct {
			cell evidence.Value
			want uint64
		}{{leaf.PhysicalEntry, tr.EntryAddress}, {leaf.Entry, tr.Entry}, {leaf.EntryWidth, uint64(tr.EntryWidth)}, {leaf.PageSize, tr.PageSize}, {leaf.Virtual, page}} {
			n, err := pair.cell.Uint()
			if err != nil || n != pair.want {
				return fmt.Errorf("dirty leaf differs from original translator")
			}
		}
		if leaf.Dirty.Data != true {
			return fmt.Errorf("dirty leaf bool differs")
		}
	}
	return nil
}
