package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsPoolScannerPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.poolscanner", Upstream: "windows.poolscanner.PoolScanner", Platform: "windows", NeedsKernel: true,
		Description: "Scan all built-in Windows pool tags with object/header provenance and explicit read failures",
		Parameters:  []plugin.Parameter{{Name: "max-read-bytes", Kind: "uint", Default: "17179869184", Description: "Task requested bytes including paging and metadata, 1..1099511627776"}, {Name: "max-reads", Kind: "uint", Default: "4000000", Description: "Task read count, 1..16777216"}, {Name: "max-rows", Kind: "uint", Default: "1000000", Description: "All evidence rows including read captures, 1..10000000"}},
		Columns:     []evidence.Column{{Name: "Type", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "Layer", Kind: "string"}, {Name: "Name", Kind: "string"}, {Name: "ObjectOffset", Kind: "address"}, {Name: "Tag", Kind: "bytes"}, {Name: "ObjectType", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "SHA256", Kind: "string"}, {Name: "ReadComplete", Kind: "bool"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "missing"}}}, windowsPoolScanner}}
}

type poolScannerAnalysis struct {
	ctx                         context.Context
	out                         plugin.Emit
	stop                        error
	failures                    pluginFailures
	reads, requested, rows      uint64
	maxReads, maxBytes, maxRows uint64
}

func (a *poolScannerAnalysis) emit(row evidence.Row) error {
	if a.stop != nil {
		return a.stop
	}
	if err := a.ctx.Err(); err != nil {
		a.stop = err
		return err
	}
	if a.rows >= a.maxRows {
		a.stop = fmt.Errorf("pool scanner evidence row bound exhausted")
		return a.stop
	}
	a.rows++
	a.stop = a.out(row)
	if a.stop == nil {
		a.stop = a.ctx.Err()
	}
	return a.stop
}

type poolScannerLayer struct {
	memory.MemoryLayer
	a        *poolScannerAnalysis
	ranges   []memory.Range
	rawLimit int
}

func (l poolScannerLayer) Ranges() []memory.Range { return l.ranges }
func (l poolScannerLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	a := l.a
	if a.stop != nil {
		return 0, a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a.reads >= a.maxReads || uint64(len(p)) > a.maxBytes-a.requested {
		a.stop = fmt.Errorf("pool scanner read budget exhausted")
		return 0, a.stop
	}
	a.reads++
	a.requested += uint64(len(p))
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid reader byte count")
	}
	if n != len(p) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	digest := sha256.Sum256(p[:n])
	cells := map[string]evidence.Value{"RecordType": evidence.Text("memory_read"), "Layer": evidence.Text(l.Name()), "Offset": evidence.Address(at), "Requested": evidence.Number(uint64(len(p))), "Captured": evidence.Number(uint64(n)), "SHA256": evidence.Text(hex.EncodeToString(digest[:])), "ReadComplete": evidence.Bool(err == nil)}
	// Large scanner reads retain their digest and exact original coordinates;
	// bounded metadata and page-table captures retain the original bytes too.
	if n <= l.rawLimit {
		cells["Raw"] = evidence.Bytes(p[:n])
	}
	if err != nil {
		a.failures.add(err)
		cells["Error"] = evidence.Missing("read_failed", err)
	}
	if emitErr := a.emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: l.Name(), Offset: fmt.Sprintf("0x%x", at)}}); emitErr != nil {
		return n, emitErr
	}
	return n, err
}

func poolScannerRow(layer string, at uint64) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"Layer": evidence.Text(layer), "Offset": evidence.Address(at)}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", at)}}
}

func windowsPoolScanner(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	a := &poolScannerAnalysis{ctx: ctx, out: out}
	for key, target := range map[string]*uint64{"max-read-bytes": &a.maxBytes, "max-reads": &a.maxReads, "max-rows": &a.maxRows} {
		limit := uint64(1 << 40)
		if key == "max-reads" {
			limit = 1 << 24
		}
		if key == "max-rows" {
			limit = 10000000
		}
		n, err := strconv.ParseUint(p[key], 0, 64)
		if err != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", key, limit)
		}
		*target = n
	}
	if e.Physical == nil || e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("pool scanner requires physical memory, kernel translation and Windows symbols")
	}
	physical := poolScannerLayer{MemoryLayer: e.Physical, a: a, ranges: e.Physical.Ranges(), rawLimit: 256}
	kernel := e.Kernel
	if virtual, ok := kernel.(*memory.Virtual); ok {
		intel, ok := virtual.Translator.(*memory.Intel)
		if !ok {
			return fmt.Errorf("pool scanner supports native Intel translation")
		}
		tables := physical
		tables.rawLimit = 4096
		traced, err := memory.NewIntelForOS(tables, intel.Root(), e.Architecture, e.OS, 1024)
		if err != nil {
			return err
		}
		kernel = &memory.Virtual{Physical: physical, Translator: traced, ID: kernel.Name()}
	}
	var ranges []memory.Range
	if windows10OrLater(e.Symbols) {
		var err error
		ranges, err = layerRanges(ctx, kernel)
		if err != nil {
			return errors.Join(err, a.stop, a.failures.err("pool enumeration"))
		}
	}
	env := e
	env.Physical = physical
	env.Kernel = poolScannerLayer{MemoryLayer: kernel, a: a, ranges: ranges, rawLimit: 256}
	env.Objects = &object.Reader{Layer: env.Kernel, Symbols: e.Symbols}
	constraints, err := builtinPoolConstraints()
	if err != nil {
		return err
	}
	err = scanPoolObjects(ctx, env, constraints, "objects", poolScannerRow, a.emit, func(ctx context.Context, hit poolHit) (evidence.Row, bool, error) {
		row := poolScannerRow(hit.layer, hit.header)
		row.Cells["RecordType"] = evidence.Text("pool_object")
		row.Cells["Type"] = evidence.Text(hit.typ)
		row.Cells["ObjectType"] = evidence.Text(hit.objectType)
		row.Cells["ObjectOffset"] = evidence.Address(hit.object)
		row.Cells["Tag"] = evidence.Bytes(hit.tag)
		row.Cells["Name"] = evidence.Missing("not_applicable", nil)
		switch hit.objectType {
		case "Process":
			name, err := hit.scan.String(ctx, hit.object, "_EPROCESS", "ImageFileName", 256)
			if err != nil {
				a.failures.add(err)
				return row, false, err
			}
			row.Cells["Name"] = evidence.Text(memoryscan.DisplayUTF8([]byte(name)))
		case "File":
			name, err := readPoolUnicode(ctx, hit.scan, hit.native, hit.object, "_FILE_OBJECT", "FileName", 65536)
			if err != nil {
				a.failures.add(err)
				return row, false, err
			}
			row.Cells["Name"] = evidence.Text(name)
		}
		return row, true, nil
	})
	cause := errors.Join(err, a.stop, a.failures.err("pool scanner captured reads"))
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("task_summary"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"Reads": evidence.Number(a.reads), "RequestedBytes": evidence.Number(a.requested), "EvidenceRows": evidence.Number(a.rows), "ReadFailures": evidence.Number(uint64(a.failures.count)), "Completed": evidence.Bool(cause == nil)}}}}
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("pool_scan_incomplete", cause)
	}
	return errors.Join(cause, a.emit(summary))
}
