package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxMalfindPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.malfind", Upstream: "linux.malware.malfind.Malfind", Platform: "linux", NeedsKernel: true,
		Description: "Inspect RWX, anonymous RX and executable dirty mappings with original page-table evidence",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated task PIDs"},
			{Name: "hexdump-size", Kind: "uint", Default: "64", Description: "Bytes to display per result, 0..67108864"},
			{Name: "show-all-dirty-pages", Kind: "bool", Default: "false", Description: "Emit every dirty page in executable mappings, rather than the first"},
			{Name: "dump-regions", Kind: "bool", Default: "false", Description: "Extract each selected region/page into the case"},
			{Name: "dump-maxsize", Kind: "uint", Default: "1073741824", Description: "Strict upper extraction size bound; equality and zero skip extraction"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-mm traversal bound"},
			{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VMA traversal bound, 1..1000000"},
			{Name: "max-pages", Kind: "uint", Default: "16777216", Description: "Total executable page-table probes, 1..1073741824"},
		}, Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Path", Kind: "string"}, {Name: "Protection", Kind: "string"}, {Name: "Hexdump", Kind: "bytes"}, {Name: "Disasm", Kind: "string"}, {Name: "FileOutput", Kind: "artifact"},
			{Name: "Reason", Kind: "string"}, {Name: "RegionStart", Kind: "address"}, {Name: "RegionSize", Kind: "uint64"}, {Name: "DataAddress", Kind: "address"}, {Name: "Disassembly", Kind: "structure"}, {Name: "Offset", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "Created", Kind: "uint64"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "missing"},
		}}, linuxMalfind}}
}

type linuxMalfindOptions struct {
	data                    int
	all, dump               bool
	dumpMax, regions, pages uint64
}

func linuxMalfindParameters(p map[string]string) (o linuxMalfindOptions, err error) {
	n, e := strconv.ParseUint(p["hexdump-size"], 0, 32)
	if e != nil || n > memory.MaxRead {
		return o, fmt.Errorf("hexdump-size must be 0..%d", memory.MaxRead)
	}
	o.data = int(n)
	o.all, err = strconv.ParseBool(p["show-all-dirty-pages"])
	if err != nil {
		return
	}
	o.dump, err = strconv.ParseBool(p["dump-regions"])
	if err != nil {
		return
	}
	o.dumpMax, err = strconv.ParseUint(p["dump-maxsize"], 0, 64)
	if err != nil {
		return
	}
	o.regions, err = strconv.ParseUint(p["max-regions"], 0, 32)
	if err != nil || o.regions == 0 || o.regions > 1000000 {
		return o, fmt.Errorf("max-regions must be 1..1000000")
	}
	o.pages, err = strconv.ParseUint(p["max-pages"], 0, 64)
	if err != nil || o.pages == 0 || o.pages > 1<<30 {
		return o, fmt.Errorf("max-pages must be 1..1073741824")
	}
	return
}

func linuxMalfind(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	switch e.Architecture {
	case "x64", "x86", "pae":
	default:
		return fmt.Errorf("linux.malfind requires an Intel kernel layer")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	o, err := linuxMalfindParameters(p)
	if err != nil {
		return err
	}
	var failures pluginFailures
	var regions, pages uint64
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		base := func(r linuxELFRegion) evidence.Row {
			row := evidence.Row{Cells: map[string]evidence.Value{
				"PID": evidence.Number(pid), "Process": evidence.Text(name), "Start": evidence.Address(r.start), "End": evidence.Address(r.end), "Offset": evidence.Address(r.object), "ProcessOffset": evidence.Address(task), "ProcessIdentity": evidence.Text(identity), "Created": created, "RecordType": evidence.Text("malfind_region"), "Error": evidence.Missing("not_applicable", nil), "FileOutput": evidence.Missing("not_requested", nil),
			}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", r.object)}}
			if r.end == 0 {
				row.Cells["Start"] = evidence.Missing("vma_not_available", nil)
				row.Cells["End"] = evidence.Missing("vma_not_available", nil)
			}
			return row
		}
		diagnostic := func(r linuxELFRegion, fields map[string]evidence.Value, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(err)
			row := base(r)
			row.Cells["RecordType"] = evidence.Text("malfind_error")
			row.Cells["Error"] = evidence.Missing("analysis_incomplete", err)
			row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			return out(row)
		}
		processFields := map[string]evidence.Value{}
		mm, _, err := linuxUnsignedField(ctx, e, task, "task_struct", "mm", processFields, "MM")
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		if mm == 0 {
			return nil
		}
		if regions >= o.regions {
			return diagnostic(linuxELFRegion{object: task}, processFields, fmt.Errorf("max-regions %d exhausted", o.regions))
		}
		mappings, visited, err := linuxELFRegions(ctx, e, mm, int(min(uint64(max), o.regions-regions)))
		regions += visited
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		_, proof, pgdErr := linuxCaptureField(ctx, e, mm, "mm_struct", "pgd")
		processFields["PGD"] = proof
		if pgdErr != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, pgdErr)
		}
		space, err := processMemory(ctx, e, task, mm, identity)
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		virtual, ok := space.(*memory.Virtual)
		if !ok {
			return diagnostic(linuxELFRegion{object: task}, processFields, fmt.Errorf("process translator unavailable"))
		}
		for _, r := range mappings {
			if err := ctx.Err(); err != nil {
				return err
			}
			fields := map[string]evidence.Value{"Process": {Kind: "structure", Data: processFields}}
			_, proof, readErr := linuxCaptureField(ctx, e, r.object, "vm_area_struct", "")
			fields["VMA"] = proof
			if readErr != nil {
				if err = diagnostic(r, fields, readErr); err != nil {
					return err
				}
				continue
			}
			flags, _, flagErr := linuxUnsignedField(ctx, e, r.object, "vm_area_struct", "vm_flags", fields, "Flags")
			file, _, fileErr := linuxUnsignedField(ctx, e, r.object, "vm_area_struct", "vm_file", fields, "File")
			if readErr = errors.Join(flagErr, fileErr); readErr != nil {
				if err = diagnostic(r, fields, readErr); err != nil {
					return err
				}
				continue
			}
			path, raw, _, _, _, _, _, scope := linuxVMAFile(ctx, e, task, mm, r.start, r.end, file)
			fields["PathRaw"], fields["PathScope"] = raw, scope
			if path.Kind == "missing" {
				if err = diagnostic(r, fields, fmt.Errorf("VMA %#x path unavailable: %s", r.object, path.String())); err != nil {
					return err
				}
			}
			if path.Kind == "string" && path.String() == "[vdso]" {
				continue
			}
			protection := linuxMalfindProtection(flags)
			emitRegion := func(reason string, start, size uint64, leaf evidence.Value) error {
				row := base(r)
				row.Cells["Path"] = path
				if path.Kind == "missing" {
					row.Cells["Error"] = evidence.Missing("path_unavailable", fmt.Errorf("VMA path unavailable"))
				}
				row.Cells["Protection"] = evidence.Text(protection)
				row.Cells["Reason"] = evidence.Text(reason)
				row.Cells["RegionStart"], row.Cells["RegionSize"] = evidence.Address(start), evidence.Number(size)
				dataAt := r.start
				// Pinned default X_DIRTY displays VMA-start bytes at the dirty-page PC.
				// With --show-all-dirty-pages it instead reads each dirty page itself.
				if reason == "X_DIRTY" && o.all {
					dataAt = start
				}
				row.Cells["DataAddress"] = evidence.Address(dataAt)
				if reason == "X_DIRTY" && path.Kind == "string" {
					row.Cells["Path"] = evidence.Text(fmt.Sprintf("%s, dirty page address: %#x", path.String(), start))
				}
				rowFields := map[string]evidence.Value{"VMA": fields["VMA"], "Process": fields["Process"], "Flags": fields["Flags"], "File": fields["File"], "PathRaw": raw, "PathScope": scope}
				if leaf.Kind != "" {
					rowFields["DirtyLeaf"] = leaf
					if fields, ok := leaf.Data.(map[string]evidence.Value); ok {
						if fault, ok := fields["Error"]; ok {
							row.Cells["Error"] = fault
						}
					}
				}
				data, capture, dataErr := linuxMalfindData(ctx, space, dataAt, o.data)
				rowFields["Data"] = capture
				row.Cells["Hexdump"] = evidence.Bytes(data)
				row.Cells["Disasm"], row.Cells["Disassembly"] = linuxMalfindDisassembly(data, start, e.Architecture)
				if dataErr != nil {
					failures.add(dataErr)
					row.Cells["Error"] = evidence.Missing("display_read_incomplete", dataErr)
				}
				if o.dump {
					if size >= o.dumpMax {
						row.Cells["FileOutput"] = evidence.Missing("maxsize_exceeded", nil)
					} else {
						end, dumpErr := memory.Add(start, size)
						output := evidence.Missing("range_overflow", dumpErr)
						if dumpErr == nil {
							output, dumpErr = extractRegion(ctx, e, space, fmt.Sprintf("pid.%d.vma.%#x-%#x.dmp", pid, start, end), start, size)
						}
						row.Cells["FileOutput"] = output
						if dumpErr != nil {
							failures.add(dumpErr)
							row.Cells["Error"] = evidence.Missing("extraction_failed", dumpErr)
						}
					}
				}
				row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: rowFields}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return out(row)
			}
			if protection == "rwx" {
				if err = emitRegion("RWX", r.start, r.end-r.start, evidence.Value{}); err != nil {
					return err
				}
				continue
			}
			if protection == "r-x" && file == 0 {
				if err = emitRegion("RX", r.start, r.end-r.start, evidence.Value{}); err != nil {
					return err
				}
				continue
			}
			if flags&4 == 0 {
				continue
			}
			scanned, missing, dirty := uint64(0), uint64(0), uint64(0)
			complete := true
			digest := sha256.New()
			stateDigest := sha256.New()
			var scanErr error
			var scanFailures pluginFailures
			var firstMissing, lastMissing uint64
			for address := r.start; address < r.end; {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if pages >= o.pages {
					complete = false
					scanErr = fmt.Errorf("max-pages %d exhausted", o.pages)
					break
				}
				pages++
				scanned++
				tr, translateErr := virtual.Translator.Translate(ctx, address)
				size := uint64(4096)
				if translateErr != nil {
					missing++
					if missing == 1 {
						firstMissing = address
					}
					lastMissing = address
					scanFailures.add(fmt.Errorf("page %#x: %w", address, translateErr))
					var encoded [16]byte
					binary.LittleEndian.PutUint64(encoded[:], address)
					binary.LittleEndian.PutUint64(encoded[8:], ^uint64(0))
					digest.Write(encoded[:])
					stateDigest.Write(encoded[:])
				} else {
					if !tr.DirtyKnown || tr.PageSize < 4096 || tr.PageSize&(tr.PageSize-1) != 0 || tr.EntryWidth != 4 && tr.EntryWidth != 8 {
						complete = false
						scanErr = fmt.Errorf("hardware dirty state unavailable at %#x", address)
						break
					}
					size = tr.PageSize
					var encoded [40]byte
					for n, value := range []uint64{address, tr.PageSize, tr.EntryAddress, tr.Entry, uint64(tr.EntryWidth)} {
						binary.LittleEndian.PutUint64(encoded[n*8:], value)
					}
					digest.Write(encoded[:])
					var state [32]byte
					for n, value := range []uint64{address, tr.PageSize, tr.Entry, uint64(tr.EntryWidth)} {
						binary.LittleEndian.PutUint64(state[n*8:], value)
					}
					stateDigest.Write(state[:])
					if tr.Dirty {
						dirty++
						leaf, leafErr := linuxMalfindLeaf(ctx, e, tr, address)
						if leafErr != nil {
							if err = diagnostic(r, fields, leafErr); err != nil {
								return err
							}
							scanFailures.add(leafErr)
						}
						if err = emitRegion("X_DIRTY", address, size, leaf); err != nil {
							return err
						}
						if !o.all {
							complete = false
							break
						}
					}
				}
				// Match the baseline's full hardware-page stride even for a VMA that
				// starts inside a large mapping. Do not wrap at the address-space end.
				if size >= r.end-address {
					break
				}
				address += size
			}
			scanErr = errors.Join(scanErr, scanFailures.err("dirty page probes"))
			summary := base(r)
			summary.Cells["RecordType"] = evidence.Text("dirty_scan")
			summary.Cells["Path"] = path
			summary.Cells["Protection"] = evidence.Text(protection)
			summary.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"VMA": fields["VMA"], "Process": fields["Process"], "Flags": fields["Flags"], "File": fields["File"], "Probes": evidence.Number(scanned), "MissingPages": evidence.Number(missing), "FirstMissing": evidence.Address(firstMissing), "LastMissing": evidence.Address(lastMissing), "DirtyPages": evidence.Number(dirty), "Completed": evidence.Bool(complete && missing == 0), "StoppedAfterFirstDirty": evidence.Bool(dirty > 0 && !o.all), "LeafDigest": evidence.Text(hex.EncodeToString(digest.Sum(nil))), "StateDigest": evidence.Text(hex.EncodeToString(stateDigest.Sum(nil)))}}
			if scanErr != nil {
				failures.add(scanErr)
				summary.Cells["Error"] = evidence.Missing("dirty_scan_incomplete", scanErr)
			}
			if err = out(summary); err != nil {
				return err
			}
		}
		return nil
	})
	return errors.Join(err, failures.err("Linux suspicious executable mappings"), ctx.Err())
}

func linuxMalfindProtection(flags uint64) string {
	out := []byte("---")
	for i, c := range []byte("rwx") {
		if flags&(1<<i) != 0 {
			out[i] = c
		}
	}
	return string(out)
}

func linuxMalfindLeaf(ctx context.Context, e plugin.Environment, tr memory.Translation, address uint64) (evidence.Value, error) {
	raw, capture, err := linuxCaptureRange(ctx, e.Physical, tr.EntryAddress, int(tr.EntryWidth))
	if err == nil {
		actual := uint64(binary.LittleEndian.Uint32(raw))
		if tr.EntryWidth == 8 {
			actual = binary.LittleEndian.Uint64(raw)
		}
		if actual != tr.Entry {
			err = fmt.Errorf("cached page-table leaf differs from physical bytes at %#x", tr.EntryAddress)
		}
	}
	fields := map[string]evidence.Value{"Virtual": evidence.Address(address), "PageSize": evidence.Number(tr.PageSize), "Entry": evidence.Address(tr.Entry), "Capture": capture, "Layer": evidence.Text(e.Physical.Name()), "Dirty": evidence.Bool(tr.Dirty)}
	if err != nil {
		fields["Error"] = evidence.Missing("dirty_leaf_unverified", err)
	}
	return evidence.Value{Kind: "structure", Data: fields}, err
}

// Preserve actual per-page captures separately from the padded display bytes.
func linuxMalfindData(ctx context.Context, space memory.MemoryLayer, start uint64, size int) ([]byte, evidence.Value, error) {
	data := make([]byte, size)
	fields := map[string]evidence.Value{"Layer": evidence.Text(space.Name()), "Address": evidence.Address(start), "RequestedBytes": evidence.Number(uint64(size))}
	var failures pluginFailures
	for offset := 0; offset < size; {
		at, err := memory.Add(start, uint64(offset))
		if err != nil {
			return data, evidence.Value{Kind: "structure", Data: fields}, err
		}
		n := min(size-offset, 4096-int(at&4095))
		actual, proof, err := linuxCaptureRange(ctx, space, at, n)
		fields[fmt.Sprintf("Page_%x", at)] = proof
		copy(data[offset:], actual)
		if err != nil {
			if ctx.Err() != nil {
				return data, evidence.Value{Kind: "structure", Data: fields}, ctx.Err()
			}
			failures.add(err)
		}
		offset += n
	}
	err := failures.err("malfind display read")
	fields["ReadComplete"] = evidence.Bool(err == nil)
	return data, evidence.Value{Kind: "structure", Data: fields}, err
}

func linuxMalfindDisassembly(data []byte, address uint64, arch string) (evidence.Value, evidence.Value) {
	mode := 64
	architecture := "intel64"
	if arch != "x64" {
		mode = 32
		architecture = "intel"
	}
	var text strings.Builder
	instructions := map[string]evidence.Value{}
	decoded := 0
	for decoded < len(data) && len(instructions) < 4096 {
		inst, err := x86asm.Decode(data[decoded:], mode)
		if err != nil || inst.Len == 0 || inst.Op == 0 {
			break
		}
		at, err := memory.Add(address, uint64(decoded))
		if err != nil {
			break
		}
		syntax := x86asm.IntelSyntax(inst, at, nil)
		fmt.Fprintf(&text, "\n%#x:\t%s", at, syntax)
		instructions[fmt.Sprintf("0x%x", at)] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(at), "Bytes": evidence.Bytes(data[decoded : decoded+inst.Len]), "Text": evidence.Text(syntax)}}
		decoded += inst.Len
	}
	return evidence.Text(text.String()), evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Architecture": evidence.Text(architecture), "Address": evidence.Address(address), "Bytes": evidence.Bytes(data), "DecodedBytes": evidence.Number(uint64(decoded)), "Complete": evidence.Bool(decoded == len(data)), "InstructionLimit": evidence.Number(4096), "Instructions": {Kind: "structure", Data: instructions}}}
}
