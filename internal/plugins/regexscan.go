package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func regexPlugins() []builtin {
	parameters := []plugin.Parameter{
		{Name: "pattern", Kind: "string", Required: true, Description: "Required Python-compatible byte regex; UTF-8 pattern bytes, empty pattern allowed"},
		{Name: "maxsize", Kind: "uint", Default: "128", Description: "Displayed context bytes, 0..16777216; Linux baseline always uses 128"},
		{Name: "max-map-tables", Kind: "uint", Default: "262144", Description: "Task page-table walk reads, 1..16777216"},
		{Name: "max-map-entries", Kind: "uint", Default: "268435456", Description: "Task inspected page entries, 1..4294967296"},
		{Name: "max-mappings", Kind: "uint", Default: "1000000", Description: "Task mapped runs, 1..10000000"},
		{Name: "max-chunks", Kind: "uint", Default: "1000000", Description: "Task scan windows, 1..1000000"},
		{Name: "max-diagnostics", Kind: "uint", Default: "4096", Description: "Detailed diagnostic bound, 1..1000000; summary retains full counts"},
		{Name: "max-matches", Kind: "uint", Default: "1000000", Description: "Task match output bound, 1..1000000"},
		{Name: "max-read-bytes", Kind: "uint", Default: "8589934592", Description: "Task physical acquisition requests, 1..1099511627776"},
		{Name: "max-proof-pages", Kind: "uint", Default: "1048576", Description: "Task hardware correspondence probes, 1..16777216"},
		{Name: "regex-steps", Kind: "uint", Default: "100000000", Description: "VM operations per chunk or result extraction, 1..1000000000"},
	}
	columns := []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Text", Kind: "string"}, {Name: "Hex", Kind: "bytes"}, {Name: "RecordType", Kind: "string"}, {Name: "ChunkIndex", Kind: "uint64"}, {Name: "SectionStart", Kind: "address"}, {Name: "SectionLength", Kind: "uint64"}, {Name: "SpaceIndex", Kind: "uint64"}, {Name: "VirtualAddress", Kind: "address"}, {Name: "MatchLength", Kind: "uint64"}, {Name: "MatchRaw", Kind: "bytes"}, {Name: "Source", Kind: "structure"}, {Name: "Context", Kind: "structure"}, {Name: "Mapping", Kind: "structure"}, {Name: "Coverage", Kind: "structure"}, {Name: "Raw", Kind: "bytes"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "SHA256", Kind: "string"}, {Name: "ReadComplete", Kind: "bool"}, {Name: "Error", Kind: "missing"}}
	return []builtin{{plugin.Spec{Name: "regexscan", Upstream: "regexscan.RegExScan", NeedsTranslation: true, Description: "Scan Intel kernel mappings with native byte regex, original source evidence and explicit incomplete coverage", Parameters: parameters, Columns: columns}, genericRegex}}
}

type regexOptions struct {
	bounds  map[string]uint64
	context int
	limits  byteregex.Limits
}

func parseRegexOptions(p map[string]string) (regexOptions, error) {
	o := regexOptions{bounds: map[string]uint64{}}
	if !utf8.ValidString(p["pattern"]) {
		return o, fmt.Errorf("pattern must be valid UTF-8 text")
	}
	for key, limit := range map[string]uint64{"max-map-tables": 1 << 24, "max-map-entries": 1 << 32, "max-mappings": 10000000, "max-chunks": 1000000, "max-matches": 1000000, "max-diagnostics": 1000000, "max-read-bytes": 1 << 40, "max-proof-pages": 1 << 24, "regex-steps": 1000000000} {
		n, err := strconv.ParseUint(p[key], 0, 64)
		if err != nil || n == 0 || n > limit {
			return o, fmt.Errorf("%s must be 1..%d", key, limit)
		}
		o.bounds[key] = n
	}
	n, err := strconv.ParseUint(p["maxsize"], 0, 32)
	if err != nil || n > memory.MaxRead {
		return o, fmt.Errorf("maxsize must be 0..%d", memory.MaxRead)
	}
	o.context = int(n)
	o.limits = byteregex.Limits{Steps: o.bounds["regex-steps"]}
	return o, nil
}

type regexAnalysis struct {
	ctx                                                  context.Context
	env                                                  plugin.Environment
	o                                                    regexOptions
	out                                                  plugin.Emit
	stop                                                 error
	failures                                             pluginFailures
	stats                                                memory.PageMapStats
	readBytes, mappings, chunks, matches, proofs, spaces uint64
	diagnostics                                          uint64
	owner                                                map[string]evidence.Value
	layer, parent                                        string
}

func (a *regexAnalysis) emit(row evidence.Row) error {
	if a.stop != nil {
		return a.stop
	}
	if err := a.ctx.Err(); err != nil {
		a.stop = err
		return err
	}
	if row.Cells == nil {
		row.Cells = map[string]evidence.Value{}
	}
	for k, v := range a.owner {
		if _, ok := row.Cells[k]; !ok {
			row.Cells[k] = v
		}
	}
	if row.ParentID == "" && row.ID != a.parent {
		row.ParentID = a.parent
	}
	if row.Provenance.Layer == "" {
		row.Provenance.Layer = a.layer
	}
	a.stop = a.out(row)
	if a.stop == nil {
		a.stop = a.ctx.Err()
	}
	return a.stop
}
func (a *regexAnalysis) diagnostic(kind string, at uint64, err error) error {
	a.failures.add(err)
	a.diagnostics++
	if a.diagnostics > a.o.bounds["max-diagnostics"] {
		return a.stop
	}
	return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at), "Error": evidence.Missing("scan_incomplete", err)}, Provenance: evidence.Provenance{Offset: fmt.Sprintf("0x%x", at)}})
}

type regexRead struct {
	memory.MemoryLayer
	a           *regexAnalysis
	scope       string
	raw, charge bool
}

func (l regexRead) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	a := l.a
	if a.stop != nil {
		return 0, a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if l.charge {
		if uint64(len(p)) > a.o.bounds["max-read-bytes"]-a.readBytes {
			a.stop = fmt.Errorf("regex task acquisition byte bound exhausted")
			return 0, a.stop
		}
		a.readBytes += uint64(len(p))
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid physical reader byte count")
	}
	if n != len(p) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	if l.raw {
		cells := map[string]evidence.Value{"RecordType": evidence.Text(l.scope + "_read"), "Offset": evidence.Address(at), "Requested": evidence.Number(uint64(len(p))), "Captured": evidence.Number(uint64(n)), "Raw": evidence.Bytes(p[:n]), "ReadComplete": evidence.Bool(err == nil)}
		if err != nil {
			a.failures.add(err)
			cells["Error"] = evidence.Missing("read_failed", err)
		}
		if outputErr := a.emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: l.Name(), Offset: fmt.Sprintf("0x%x", at)}}); outputErr != nil {
			return n, outputErr
		}
	}
	return n, err
}
func (a *regexAnalysis) physical() memory.MemoryLayer {
	return regexRead{MemoryLayer: a.env.Physical, a: a, charge: true}
}
func (a *regexAnalysis) intel(root uint64, scope string) (*memory.Intel, error) {
	return memory.NewIntelForOS(regexRead{MemoryLayer: a.env.Physical, a: a, scope: scope, raw: true, charge: true}, root, a.env.Architecture, a.env.OS, 1024)
}
func regexFlat(at uint64, arch string) uint64 {
	if arch == "x64" {
		return at & 0x0000ffffffffffff
	}
	return at
}
func (a *regexAnalysis) walk(intel *memory.Intel, sections []memory.Range, out func(memory.PageMapping) error) error {
	if a.stats.Tables >= a.o.bounds["max-map-tables"] || a.stats.Entries >= a.o.bounds["max-map-entries"] {
		a.stop = fmt.Errorf("regex task page-map bound exhausted")
		return a.stop
	}
	var previous memory.PageMapStats
	stats, err := intel.VisitPageMappings(a.ctx, memory.PageMapOptions{Sections: sections, MaxTables: a.o.bounds["max-map-tables"] - a.stats.Tables, MaxEntries: a.o.bounds["max-map-entries"] - a.stats.Entries,
		OnProgress: func(current memory.PageMapStats) error {
			tables, entries := current.Tables-previous.Tables, current.Entries-previous.Entries
			if tables > a.o.bounds["max-map-tables"]-a.stats.Tables || entries > a.o.bounds["max-map-entries"]-a.stats.Entries {
				a.stop = fmt.Errorf("regex task shared page-map bound exhausted")
				return a.stop
			}
			a.stats.Tables += tables
			a.stats.Entries += entries
			previous = current
			return a.stop
		},
		OnReadError: func(_ uint64, _ error) error { return a.stop },
		OnUnavailableMapping: func(m memory.PageMapping) error {
			return a.diagnostic("mapping_unavailable", m.Virtual, fmt.Errorf("physical mapping %#x+%#x is unavailable", m.Physical, m.Length))
		},
	}, func(m memory.PageMapping) error {
		if a.mappings >= a.o.bounds["max-mappings"] {
			a.stop = fmt.Errorf("regex task mapping bound exhausted")
			return a.stop
		}
		a.mappings++
		m.Virtual = regexFlat(m.Virtual, a.env.Architecture)
		return out(m)
	})
	a.stats.Mappings += stats.Mappings
	a.stats.Unavailable += stats.Unavailable
	return err
}
func regexMapping(m memory.PageMapping) evidence.Value {
	return evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Virtual": evidence.Address(m.Virtual), "Physical": evidence.Address(m.Physical), "Length": evidence.Number(m.Length)}}
}

func (a *regexAnalysis) contextBytes(intel *memory.Intel, at uint64) ([]byte, evidence.Value, error) {
	data := make([]byte, a.o.context)
	proof := map[string]evidence.Value{"Address": evidence.Address(at), "Requested": evidence.Number(uint64(len(data)))}
	captures := []map[string]evidence.Value{}
	var position uint64
	var failures pluginFailures
	gap := func(start, length uint64) {
		if length == 0 {
			return
		}
		cause := fmt.Errorf("context virtual bytes %#x+%#x are unavailable; display buffer padded", start, length)
		failures.add(cause)
		captures = append(captures, map[string]evidence.Value{"Virtual": evidence.Address(start), "Length": evidence.Number(length), "Padded": evidence.Bool(true), "Error": evidence.Missing("unmapped_context", cause)})
	}
	if len(data) > 0 {
		err := a.walk(intel, []memory.Range{{Start: at, Length: uint64(len(data))}}, func(m memory.PageMapping) error {
			relative := m.Virtual - at
			if relative < position || relative > uint64(len(data)) || m.Length > uint64(len(data))-relative {
				return fmt.Errorf("context mapping outside requested interval")
			}
			gap(at+position, relative-position)
			n, err := a.physical().ReadAt(a.ctx, data[relative:relative+m.Length], m.Physical)
			if n < 0 || uint64(n) > m.Length {
				n = 0
				err = fmt.Errorf("invalid context reader byte count")
			}
			if uint64(n) != m.Length && err == nil {
				err = io.ErrUnexpectedEOF
			}
			clear(data[relative+uint64(n) : relative+m.Length])
			capture := map[string]evidence.Value{"Virtual": evidence.Address(m.Virtual), "Physical": evidence.Address(m.Physical), "Requested": evidence.Number(m.Length), "Captured": evidence.Number(uint64(n)), "Raw": evidence.Bytes(data[relative : relative+uint64(n)]), "Padded": evidence.Bool(uint64(n) < m.Length), "ReadComplete": evidence.Bool(err == nil)}
			if err != nil {
				failures.add(err)
				capture["Error"] = evidence.Missing("context_read_failed", err)
			}
			captures = append(captures, capture)
			position = relative + m.Length
			return a.stop
		})
		if err != nil {
			failures.add(err)
		}
		gap(at+position, uint64(len(data))-position)
	}
	proof["Parts"] = evidence.Value{Kind: "structure", Data: captures}
	proof["Raw"] = evidence.Bytes(data)
	proof["Complete"] = evidence.Bool(failures.count == 0)
	return data, evidence.Value{Kind: "structure", Data: proof}, failures.err("regex context acquisition")
}
func (a *regexAnalysis) sourceProof(native *memory.Intel, hit memoryscan.Hit) (evidence.Value, error) {
	sources := []map[string]evidence.Value{}
	var failures pluginFailures
	for _, s := range hit.Sources {
		parts := []map[string]evidence.Value{}
		for offset := uint64(0); offset < s.Length; {
			if a.proofs >= a.o.bounds["max-proof-pages"] {
				a.stop = fmt.Errorf("regex task translation proof bound exhausted")
				return evidence.Missing("proof_bound", a.stop), a.stop
			}
			a.proofs++
			virtual := windowsStringsVirtual(s.Virtual+offset, a.env.Architecture)
			translated, err := native.Translate(a.ctx, virtual)
			if a.stop != nil || a.ctx.Err() != nil {
				return evidence.Missing("proof_stopped", nil), errors.Join(a.stop, a.ctx.Err())
			}
			if err != nil {
				failures.add(err)
				parts = append(parts, map[string]evidence.Value{"Virtual": evidence.Address(virtual), "Error": evidence.Missing("hardware_translation_unavailable", err)})
				break
			}
			size := min(translated.Available, s.Length-offset)
			if size == 0 {
				return evidence.Missing("zero_translation_extent", nil), fmt.Errorf("zero translation extent")
			}
			same := translated.Physical == s.Physical+offset
			proof := map[string]evidence.Value{"Virtual": evidence.Address(virtual), "Physical": evidence.Address(translated.Physical), "Length": evidence.Number(size), "EntryAddress": evidence.Address(translated.EntryAddress), "Entry": evidence.Address(translated.Entry), "MatchesAcquisition": evidence.Bool(same)}
			if !same {
				cause := fmt.Errorf("baseline mapping physical %#x differs from hardware translation %#x", s.Physical+offset, translated.Physical)
				failures.add(cause)
				proof["Error"] = evidence.Missing("mapping_translation_disagreement", cause)
			}
			parts = append(parts, proof)
			offset += size
		}
		sources = append(sources, map[string]evidence.Value{"BufferOffset": evidence.Number(s.Offset), "Virtual": evidence.Address(windowsStringsVirtual(s.Virtual, a.env.Architecture)), "Physical": evidence.Address(s.Physical), "Length": evidence.Number(s.Length), "Translation": {Kind: "structure", Data: parts}})
	}
	return evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Parts": {Kind: "structure", Data: sources}, "CoordinatesMatchSource": evidence.Bool(hit.CoordinatesMatchSource), "EmptyMatch": evidence.Bool(hit.Length == 0)}}, failures.err("regex source correspondence")
}

func (a *regexAnalysis) scan(root uint64, sections []memory.Range, scan, extract *byteregex.Regexp, anchored bool) error {
	intel, err := a.intel(root, "page_table")
	if err != nil {
		return err
	}
	native, err := a.intel(root, "translation_table")
	if err != nil {
		return err
	}
	a.spaces++
	oldParent := a.parent
	a.parent = fmt.Sprintf("regex-space:%d", a.spaces)
	defer func() { a.parent = oldParent }()
	spaceID := a.parent
	if err = a.emit(evidence.Row{ID: spaceID, ParentID: oldParent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("address_space"), "SpaceIndex": evidence.Number(a.spaces), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"Root": evidence.Address(root), "Layer": evidence.Text(a.layer)}}}}); err != nil {
		return err
	}
	ranges := sections
	if sections == nil {
		domain := uint64(1) << 32
		if a.env.Architecture == "x64" {
			domain = 1 << 48
		}
		ranges = []memory.Range{{Length: domain - 1}}
	}
	for _, section := range ranges {
		section.Start = regexFlat(section.Start, a.env.Architecture)
		var cursor = section.Start
		end, err := memory.Add(section.Start, section.Length)
		if err != nil {
			return err
		}
		planner, err := memory.NewScanPlanner(a.ctx, memory.ScanPlanOptions{ChunkSize: 16 << 20, Overlap: 4096, MaxChunks: a.o.bounds["max-chunks"]}, func(chunk memory.ScanChunk) error {
			if a.chunks >= a.o.bounds["max-chunks"] {
				return fmt.Errorf("regex task chunk bound exhausted")
			}
			a.chunks++
			chunkID := fmt.Sprintf("regex-chunk:%d", a.chunks)
			b, readErr := memoryscan.Acquire(a.ctx, a.physical(), chunk)
			captures := []map[string]evidence.Value{}
			for _, p := range b.Parts {
				part := map[string]evidence.Value{"Virtual": evidence.Address(p.Part.Virtual), "Physical": evidence.Address(p.Part.Physical), "Requested": evidence.Number(p.Part.Length), "Captured": evidence.Number(p.Captured), "SHA256": evidence.Text(p.SHA256), "ReadComplete": evidence.Bool(p.Complete), "BufferOffset": evidence.Number(p.BufferOffset)}
				if p.Error != nil {
					part["Error"] = evidence.Missing("scan_part_read_failed", p.Error)
				}
				captures = append(captures, part)
			}
			digest := sha256.Sum256(b.Data)
			cells := map[string]evidence.Value{"RecordType": evidence.Text("scan_chunk"), "ChunkIndex": evidence.Number(a.chunks), "SectionStart": evidence.Address(section.Start), "SectionLength": evidence.Number(section.Length), "Offset": evidence.Address(b.Base), "Captured": evidence.Number(uint64(len(b.Data))), "SHA256": evidence.Text(hex.EncodeToString(digest[:])), "ReadComplete": evidence.Bool(b.Complete), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"End": evidence.Address(chunk.End), "Parts": {Kind: "structure", Data: captures}}}}
			if readErr != nil {
				a.failures.add(readErr)
				cells["Error"] = evidence.Missing("scan_acquisition_incomplete", readErr)
			}
			if err := a.emit(evidence.Row{ID: chunkID, Cells: cells}); err != nil {
				return err
			}
			previous := a.parent
			a.parent = chunkID
			defer func() { a.parent = previous }()
			// The per-call bound is complemented by the task-wide counter below.
			findErr := memoryscan.Find(a.ctx, scan, b, 16<<20, a.o.limits, a.o.bounds["max-matches"], func(hit memoryscan.Hit) error {
				if a.matches >= a.o.bounds["max-matches"] {
					return fmt.Errorf("regex task match bound exhausted")
				}
				a.matches++
				source, proofErr := a.sourceProof(native, hit)
				if a.stop != nil {
					return a.stop
				}
				contextBytes, contextProof, contextErr := a.contextBytes(intel, hit.Offset)
				if a.stop != nil {
					return a.stop
				}
				if err := a.ctx.Err(); err != nil {
					return err
				}
				selection, selectErr := memoryscan.Extract(a.ctx, extract, contextBytes, anchored, a.o.limits)
				cause := errors.Join(proofErr, contextErr, selectErr)
				row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("regex_match"), "Offset": evidence.Address(hit.Offset), "VirtualAddress": evidence.Address(windowsStringsVirtual(hit.Offset, a.env.Architecture)), "MatchLength": evidence.Number(hit.Length), "MatchRaw": evidence.Bytes(b.Data[hit.Offset-b.Base : hit.Offset-b.Base+hit.Length]), "Source": source, "Context": contextProof}, Provenance: evidence.Provenance{Offset: fmt.Sprintf("0x%x", windowsStringsVirtual(hit.Offset, a.env.Architecture))}}
				if selectErr == nil {
					row.Cells["Text"] = evidence.Text(selection.Text)
					row.Cells["Hex"] = evidence.Bytes(contextBytes[selection.Start:selection.End])
				} else {
					row.Cells["Text"] = evidence.Missing("extraction_failed", selectErr)
					row.Cells["Hex"] = evidence.Missing("extraction_failed", selectErr)
				}
				if cause != nil {
					a.failures.add(cause)
					row.Cells["Error"] = evidence.Missing("match_evidence_incomplete", cause)
				}
				return a.emit(row)
			})
			if findErr != nil && findErr != memoryscan.ErrIncomplete {
				return findErr
			}
			return a.stop
		})
		if err != nil {
			return err
		}
		missing := func(start, length uint64) error {
			if sections == nil || length == 0 {
				return nil
			}
			return a.diagnostic("section_gap", start, fmt.Errorf("selected section has unmapped bytes %#x+%#x", start, length))
		}
		err = a.walk(intel, []memory.Range{section}, func(m memory.PageMapping) error {
			if err := missing(cursor, m.Virtual-cursor); err != nil {
				return err
			}
			cursor = m.Virtual + m.Length
			if err := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("scan_mapping"), "Mapping": regexMapping(m)}}); err != nil {
				return err
			}
			return planner.Push(m)
		})
		if err != nil {
			return err
		}
		if err = planner.Finish(); err != nil {
			return err
		}
		if err = missing(cursor, end-cursor); err != nil {
			return err
		}
	}
	return nil
}
func (a *regexAnalysis) finish(err error) error {
	err = errors.Join(err, a.failures.err("regex analysis"))
	if a.stop != nil || a.ctx.Err() != nil {
		return errors.Join(err, a.stop, a.ctx.Err())
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("scan_summary"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"Spaces": evidence.Number(a.spaces), "Tables": evidence.Number(a.stats.Tables), "Entries": evidence.Number(a.stats.Entries), "Mappings": evidence.Number(a.mappings), "Chunks": evidence.Number(a.chunks), "Matches": evidence.Number(a.matches), "PhysicalRequestedBytes": evidence.Number(a.readBytes), "ProofPages": evidence.Number(a.proofs), "Diagnostics": evidence.Number(a.diagnostics), "DetailedDiagnostics": evidence.Number(min(a.diagnostics, a.o.bounds["max-diagnostics"])), "OmittedDiagnostics": evidence.Number(a.diagnostics - min(a.diagnostics, a.o.bounds["max-diagnostics"])), "UnavailableMappings": evidence.Number(a.stats.Unavailable), "Completed": evidence.Bool(err == nil)}}}}
	if err != nil {
		summary.Cells["Error"] = evidence.Missing("scan_incomplete", err)
	}
	return errors.Join(err, a.emit(summary))
}
func genericRegex(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	o, err := parseRegexOptions(p)
	if err != nil {
		return err
	}
	scan, err := byteregex.Compile(p["pattern"], true)
	if err != nil {
		return err
	}
	extract, err := byteregex.Compile(p["pattern"], false)
	if err != nil {
		return err
	}
	space, ok := e.Kernel.(*memory.Virtual)
	if !ok || e.Physical == nil {
		return fmt.Errorf("regexscan requires a native Intel translation layer")
	}
	root, ok := space.Translator.(*memory.Intel)
	if !ok {
		return fmt.Errorf("regexscan supports x86, PAE and x64 Intel layers")
	}
	a := &regexAnalysis{ctx: ctx, env: e, o: o, out: out, layer: e.Kernel.Name()}
	return a.finish(a.scan(root.Root(), nil, scan, extract, false))
}
