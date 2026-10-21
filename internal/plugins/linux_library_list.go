package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxLibraryListPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.library_list", Upstream: "linux.library_list.LibraryList", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate dynamic-linker GOT link maps with process-space and original-byte evidence",
		Parameters:  []plugin.Parameter{{Name: "pids", Kind: "string", Description: "Optional comma-separated task PID filter (upstream pids)"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task and per-mm VMA traversal bound"}, {Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VMA scan bound, 1..1000000"}, {Name: "max-link-maps", Kind: "uint", Default: "131072", Description: "Total link-map object read bound, 1..1000000"}},
		Columns:     []evidence.Column{{Name: "Name", Kind: "string"}, {Name: "Pid", Kind: "uint64"}, {Name: "LoadAddress", Kind: "address"}, {Name: "Path", Kind: "string"}, {Name: "PathRaw", Kind: "bytes"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "Created", Kind: "uint64"}, {Name: "ProcessLayer", Kind: "string"}, {Name: "VMAOffset", Kind: "address"}, {Name: "VMAStart", Kind: "address"}, {Name: "VMAEnd", Kind: "address"}, {Name: "LinkMap", Kind: "address"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "missing"}},
	}, linuxLibraryList}}
}

type linuxLibraryObservation struct {
	address, load uint64
	path          evidence.Value
	raw           []byte
	fields        map[string]evidence.Value
	err           error
}

// scanLinuxLibraries follows the pinned GOT[1] algorithm. Dynamic d_ptr values
// are already relocated runtime addresses. Only PT_DYNAMIC p_vaddr is rebased
// for ET_DYN; a DT_DEBUG fallback would change the selected evidence source.
func scanLinuxLibraries(ctx context.Context, space memory.MemoryLayer, base uint64, kernelWidth int, remaining *uint64, selected map[uint64]bool, emit func(linuxLibraryObservation) error) (map[string]evidence.Value, error) {
	fields := map[string]evidence.Value{"Layer": evidence.Text(space.Name()), "Base": evidence.Address(base)}
	capture := func(at uint64, size int) ([]byte, evidence.Value, error) {
		return linuxCaptureRange(ctx, space, at, size)
	}
	sig, proof, err := capture(base, 4)
	fields["Signature"] = proof
	if err != nil {
		return fields, err
	}
	if !bytes.Equal(sig, []byte("\x7fELF")) {
		fields["ELF"] = evidence.Bool(false)
		return fields, nil
	}
	fields["ELF"] = evidence.Bool(true)
	ident, proof, err := capture(base, 16)
	fields["Ident"] = proof
	if err != nil {
		return fields, err
	}
	width, headerSize, phSize := 8, 64, 56
	if ident[4] == 1 {
		width, headerSize, phSize = 4, 52, 32
	} else if ident[4] != 2 {
		return fields, fmt.Errorf("unsupported ELF class %d", ident[4])
	}
	if ident[5] != 1 {
		return fields, fmt.Errorf("Intel library-list requires little-endian ELF")
	}
	if kernelWidth != 4 && kernelWidth != 8 {
		return fields, fmt.Errorf("invalid kernel pointer width")
	}
	fields["ELFWidth"], fields["GOTPointerWidth"] = evidence.Number(uint64(width)), evidence.Number(uint64(kernelWidth))
	word := func(b []byte) uint64 {
		if width == 4 {
			return uint64(binary.LittleEndian.Uint32(b))
		}
		return binary.LittleEndian.Uint64(b)
	}
	header, headerProof, err := capture(base, headerSize)
	fields["Header"] = headerProof
	if err != nil {
		return fields, err
	}
	typ := binary.LittleEndian.Uint16(header[16:])
	var phoff uint64
	var count uint16
	if width == 8 {
		phoff, count = binary.LittleEndian.Uint64(header[32:]), binary.LittleEndian.Uint16(header[56:])
	}
	if width == 4 {
		phoff, count = uint64(binary.LittleEndian.Uint32(header[28:])), binary.LittleEndian.Uint16(header[44:])
	}
	if count > 4096 || phoff > 16<<20 {
		return fields, fmt.Errorf("ELF program-header bounds exceeded")
	}
	seen := map[uint64]bool{}
	var failures pluginFailures
	var reads, dynamicCount, duplicates uint64
	defer func() {
		fields["LinkMapsRead"] = evidence.Number(reads)
		fields["DynamicEntries"] = evidence.Number(dynamicCount)
		fields["DuplicateLoads"] = evidence.Number(duplicates)
	}()
	for index := uint64(0); index < uint64(count); index++ {
		if err := ctx.Err(); err != nil {
			return fields, err
		}
		at, err := memory.Add(base, phoff+index*uint64(phSize))
		if err != nil {
			return fields, err
		}
		ph, phProof, err := capture(at, phSize)
		fields[fmt.Sprintf("ProgramHeader_%d", index)] = phProof
		if err != nil {
			failures.add(err)
			continue
		}
		if binary.LittleEndian.Uint32(ph) != 2 {
			continue
		}
		vaddr := word(ph[16:])
		if width == 4 {
			vaddr = word(ph[8:])
		}
		dynamic := vaddr
		if typ == 3 {
			dynamic, err = memory.Add(base, vaddr)
			if err != nil {
				failures.add(err)
				continue
			}
		}
		terminated := false
		for entry := uint64(0); entry < 256; entry++ {
			if dynamicCount >= 4096 {
				return fields, fmt.Errorf("per-VMA dynamic entry bound 4096 exhausted")
			}
			at, err := memory.Add(dynamic, entry*uint64(width*2))
			if err != nil {
				failures.add(err)
				break
			}
			dyn, dynProof, err := capture(at, width*2)
			fields[fmt.Sprintf("Dynamic_%d_%d", index, entry)] = dynProof
			if err != nil {
				failures.add(err)
				break
			}
			dynamicCount++
			tag := word(dyn)
			if tag == 0 {
				terminated = true
				break
			}
			if tag != 3 {
				continue
			}
			got, err := memory.Add(word(dyn[width:]), uint64(width))
			if err != nil {
				failures.add(err)
				continue
			}
			pointer, gotProof, err := capture(got, kernelWidth)
			fields[fmt.Sprintf("GOT_%d_%d", index, entry)] = gotProof
			if err != nil {
				failures.add(err)
				continue
			}
			link := uint64(binary.LittleEndian.Uint32(pointer))
			if kernelWidth == 8 {
				link = binary.LittleEndian.Uint64(pointer)
			}
			chain := map[uint64]bool{}
			for link != 0 {
				if err := ctx.Err(); err != nil {
					return fields, err
				}
				if chain[link] {
					failures.add(fmt.Errorf("cyclic link_map at %#x", link))
					break
				}
				if seen[link] {
					break
				}
				if *remaining == 0 {
					return fields, fmt.Errorf("max-link-maps exhausted")
				}
				*remaining--
				reads++
				seen[link] = true
				chain[link] = true
				raw, linkProof, readErr := capture(link, width*5)
				if readErr != nil {
					fields[fmt.Sprintf("LinkMapError_%x", link)] = linkProof
					failures.add(readErr)
					break
				}
				load, name, next := word(raw), word(raw[width:]), word(raw[width*3:])
				proof := map[string]evidence.Value{"Header": headerProof, "ProgramHeader": phProof, "Dynamic": dynProof, "GOT": gotProof, "LinkMap": linkProof, "LoadAddress": evidence.Address(load), "NameAddress": evidence.Address(name), "Next": evidence.Address(next), "Previous": evidence.Address(word(raw[width*4:]))}
				// Match upstream deduplication before reading the name. An empty/unreadable
				// first name must not allow a later duplicate load address to replace it.
				if load != 0 && name != 0 {
					if selected[load] {
						duplicates++
					} else {
						selected[load] = true
						nameRaw, nameProof, nameErr := capture(name, 256)
						proof["Name"] = nameProof
						path := evidence.Missing("library_name_unreadable", nameErr)
						displayRaw := nameRaw
						if nameErr == nil {
							if n := bytes.IndexByte(displayRaw, 0); n >= 0 {
								displayRaw = displayRaw[:n]
							}
							text, _ := replaceInvalidUTF8(displayRaw)
							path = evidence.Text(text)
						}
						if nameErr != nil || path.String() != "" {
							if err := emit(linuxLibraryObservation{address: link, load: load, path: path, raw: displayRaw, fields: proof, err: nameErr}); err != nil {
								return fields, err
							}
						}
						if nameErr != nil {
							failures.add(nameErr)
						}
					}
				}
				link = next
			}
		}
		if !terminated {
			failures.add(fmt.Errorf("PT_DYNAMIC %d lacks a readable DT_NULL within 256 entries", index))
		}
	}
	return fields, failures.err("ELF link-map scan")
}

func linuxLibraryList(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return fmt.Errorf("linux.library_list requires an Intel kernel layer")
	}
	limitParams := map[string]string{"max-nodes": p["max-nodes"], "pid": p["pids"]}
	max, pids, err := limits(limitParams)
	if err != nil {
		return err
	}
	bound := func(name string) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 32)
		if err != nil || n == 0 || n > 1000000 {
			return 0, fmt.Errorf("%s must be 1..1000000", name)
		}
		return n, nil
	}
	maxRegions, err := bound("max-regions")
	if err != nil {
		return err
	}
	remaining, err := bound("max-link-maps")
	if err != nil {
		return err
	}
	var regions uint64
	var failures pluginFailures
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		rowBase := func(r linuxELFRegion) evidence.Row {
			row := evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text(name), "Pid": evidence.Number(pid), "ProcessOffset": evidence.Address(task), "ProcessIdentity": evidence.Text(identity), "Created": created, "VMAOffset": evidence.Address(r.object), "VMAStart": evidence.Address(r.start), "VMAEnd": evidence.Address(r.end), "LoadAddress": evidence.Missing("not_applicable", nil), "Path": evidence.Missing("not_applicable", nil), "PathRaw": evidence.Missing("not_applicable", nil), "LinkMap": evidence.Missing("not_applicable", nil), "ProcessLayer": evidence.Missing("not_available", nil), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", r.object)}}
			if r.end == 0 {
				for _, key := range []string{"VMAOffset", "VMAStart", "VMAEnd"} {
					row.Cells[key] = evidence.Missing("vma_not_available", nil)
				}
			}
			return row
		}
		diagnostic := func(r linuxELFRegion, fields map[string]evidence.Value, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(err)
			row := rowBase(r)
			row.Cells["RecordType"] = evidence.Text("library_error")
			row.Cells["Error"] = evidence.Missing("library_scan_incomplete", err)
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
		_, proof, err := linuxCaptureField(ctx, e, mm, "mm_struct", "pgd")
		processFields["PGD"] = proof
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		if regions >= maxRegions {
			return diagnostic(linuxELFRegion{object: task}, processFields, fmt.Errorf("max-regions exhausted"))
		}
		mappings, visited, err := linuxELFRegions(ctx, e, mm, int(min(uint64(max), maxRegions-regions)))
		regions += visited
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		space, err := processMemory(ctx, e, task, mm, identity)
		if err != nil {
			return diagnostic(linuxELFRegion{object: task}, processFields, err)
		}
		selected := map[uint64]bool{}
		for _, r := range mappings {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, vmaProof, err := linuxCaptureField(ctx, e, r.object, "vm_area_struct", "")
			if err != nil {
				if err = diagnostic(r, map[string]evidence.Value{"VMA": vmaProof, "Process": {Kind: "structure", Data: processFields}}, err); err != nil {
					return err
				}
				continue
			}
			var outputErr error
			fields, scanErr := scanLinuxLibraries(ctx, space, r.start, e.Symbols.PointerSize(), &remaining, selected, func(o linuxLibraryObservation) error {
				row := rowBase(r)
				row.Cells["ProcessLayer"] = evidence.Text(space.Name())
				row.Cells["LinkMap"] = evidence.Address(o.address)
				row.Cells["LoadAddress"] = evidence.Address(o.load)
				row.Cells["Path"], row.Cells["PathRaw"] = o.path, evidence.Bytes(o.raw)
				row.Cells["RecordType"] = evidence.Text("library")
				row.Provenance.Layer = space.Name()
				row.Provenance.Offset = fmt.Sprintf("0x%x", o.address)
				o.fields["VMA"], o.fields["Process"] = vmaProof, evidence.Value{Kind: "structure", Data: processFields}
				row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: o.fields}
				if o.err != nil {
					row.Cells["RecordType"] = evidence.Text("library_error")
					row.Cells["Error"] = evidence.Missing("library_name_unreadable", o.err)
				}
				outputErr = out(row)
				return outputErr
			})
			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fields["VMA"], fields["Process"] = vmaProof, evidence.Value{Kind: "structure", Data: processFields}
			scan := rowBase(r)
			scan.Cells["ProcessLayer"] = evidence.Text(space.Name())
			scan.Cells["RecordType"] = evidence.Text("library_scan")
			fields["Completed"] = evidence.Bool(scanErr == nil)
			scan.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			if scanErr != nil {
				failures.add(scanErr)
				scan.Cells["Error"] = evidence.Missing("library_scan_incomplete", scanErr)
			}
			if err := out(scan); err != nil {
				return err
			}
		}
		return nil
	})
	return errors.Join(err, failures.err("Linux dynamic-linker libraries"), ctx.Err())
}
