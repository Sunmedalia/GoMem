package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsTrueCryptPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.truecrypt", Upstream: "windows.truecrypt.Passphrase", Platform: "windows", NeedsKernel: true,
		Description: "Find cached TrueCrypt passphrases in the .data section of truecrypt.sys",
		Parameters: []plugin.Parameter{
			{Name: "min-length", Kind: "uint", Default: "5", Description: "Minimum passphrase length, 0..64"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Loaded-module list traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"}, {Name: "Length", Kind: "uint64"}, {Name: "Password", Kind: "string"},
			{Name: "ModuleBase", Kind: "address"}, {Name: "ModuleName", Kind: "string"},
			{Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		},
	}, windowsTrueCrypt}}
}

type trueCryptHit struct {
	offset   uint64
	password string
}

func windowsTrueCrypt(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil {
		return fmt.Errorf("windows.truecrypt requires a kernel layer")
	}
	if p == nil {
		p = map[string]string{}
	}
	if p["min-length"] == "" {
		p["min-length"] = "5"
	}
	if p["max-nodes"] == "" {
		p["max-nodes"] = "131072"
	}
	minimum, err := strconv.ParseUint(p["min-length"], 0, 32)
	if err != nil || minimum > 64 {
		return fmt.Errorf("min-length must be 0..64")
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || maxNodes == 0 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	links, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		links, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return err
	}
	var found bool
	var base uint64
	var moduleName string
	var hits []trueCryptHit
	err = e.Objects.WalkList(ctx, head, links.Offset, int(maxNodes), func(module uint64) error {
		if found {
			return nil
		}
		name, err := unicodeString(ctx, e, module, typ, "BaseDllName")
		if err != nil {
			return err
		}
		if strings.ToLower(name) != "truecrypt.sys" {
			return nil
		}
		base, err = e.Objects.Uint(ctx, module, typ, "DllBase")
		if err != nil {
			return fmt.Errorf("truecrypt.sys DllBase: %w", err)
		}
		moduleName = name
		found = true
		dataAddress, size, err := trueCryptDataSection(ctx, e.Kernel, base)
		if err != nil {
			return err
		}
		hits, err = scanTrueCryptData(ctx, e.Kernel, dataAddress, size, int32(minimum))
		return err
	})
	if err != nil {
		return err
	}
	for _, hit := range hits {
		row := trueCryptRow(e.Kernel.Name(), hit.offset)
		row.Cells["Length"] = evidence.Number(uint64(len(hit.password)))
		row.Cells["Password"] = evidence.Text(hit.password)
		row.Cells["ModuleBase"] = evidence.Address(base)
		row.Cells["ModuleName"] = evidence.Text(moduleName)
		row.Cells["RecordType"] = evidence.Text("password")
		if err = out(row); err != nil {
			return err
		}
	}
	summary := trueCryptRow(e.Kernel.Name(), 0)
	summary.Provenance.Offset = ""
	summary.Cells["Offset"] = evidence.Missing("not_applicable", nil)
	summary.Cells["RecordType"] = evidence.Text("summary")
	foundText := "false"
	if found {
		foundText = "true"
	}
	summary.Cells["Coverage"] = poolCoverage(map[string]string{
		"module_found": foundText,
		"module_base":  fmt.Sprintf("0x%x", base),
		"module_name":  moduleName,
		"passwords":    formatCount(uint64(len(hits))),
		"min_length":   strconv.FormatUint(minimum, 10),
	})
	return out(summary)
}

func trueCryptRow(layer string, offset uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", offset)}}
	for _, column := range windowsTrueCryptPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(offset)
	return row
}

func trueCryptDataSection(ctx context.Context, layer memory.MemoryLayer, base uint64) (uint64, uint64, error) {
	dos, err := memory.Read(ctx, layer, base, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("windows.truecrypt: DOS header: %w", err)
	}
	if string(dos[:2]) != "MZ" {
		return 0, 0, fmt.Errorf("windows.truecrypt: invalid DOS signature")
	}
	nt, err := memory.Add(base, uint64(binary.LittleEndian.Uint32(dos[60:])))
	if err != nil {
		return 0, 0, err
	}
	header, err := memory.Read(ctx, layer, nt, 24)
	if err != nil {
		return 0, 0, fmt.Errorf("windows.truecrypt: PE header: %w", err)
	}
	if string(header[:4]) != "PE\x00\x00" {
		return 0, 0, fmt.Errorf("windows.truecrypt: invalid NT signature")
	}
	sections := int(binary.LittleEndian.Uint16(header[6:]))
	optional := int(binary.LittleEndian.Uint16(header[20:]))
	if sections < 1 || sections > 96 || optional < 2 || optional > 4096 {
		return 0, 0, fmt.Errorf("windows.truecrypt: invalid PE section count or optional header")
	}
	tableAddress, err := memory.Add(nt, uint64(24+optional))
	if err != nil {
		return 0, 0, err
	}
	table, err := memory.Read(ctx, layer, tableAddress, sections*40)
	if err != nil {
		return 0, 0, fmt.Errorf("windows.truecrypt: section table: %w", err)
	}
	for i := 0; i < sections; i++ {
		section := table[i*40 : i*40+40]
		name := section[:8]
		if end := bytes.IndexByte(name, 0); end >= 0 {
			name = name[:end]
		}
		if string(name) != ".data" {
			continue
		}
		address, err := memory.Add(base, uint64(binary.LittleEndian.Uint32(section[12:16])))
		if err != nil {
			return 0, 0, err
		}
		return address, uint64(binary.LittleEndian.Uint32(section[8:12])), nil
	}
	return 0, 0, fmt.Errorf("windows.truecrypt: truecrypt.sys has no .data section")
}

func scanTrueCryptData(ctx context.Context, layer memory.MemoryLayer, address, size uint64, minimum int32) ([]trueCryptHit, error) {
	if size%4 != 0 {
		return nil, fmt.Errorf("windows.truecrypt: PE data section is not DWORD-aligned")
	}
	if size > uint64(memory.MaxRead) {
		return nil, fmt.Errorf("windows.truecrypt: .data section exceeds the bounded read")
	}
	buf, err := memory.Read(ctx, layer, address, int(size))
	if err != nil {
		return nil, fmt.Errorf("windows.truecrypt: .data section: %w", err)
	}
	var hits []trueCryptHit
	for off := 0; off < len(buf); off += 4 {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		length := int32(binary.LittleEndian.Uint32(buf[off : off+4]))
		if length < minimum || length > 64 {
			continue
		}
		phrase, err := trueCryptBytes(ctx, layer, address, buf, off+4, int(length))
		if err != nil {
			return nil, err
		}
		if !trueCryptPrintable(phrase) {
			continue
		}
		padding, err := trueCryptBytes(ctx, layer, address, buf, off+4+int(length)+1, 3)
		if err != nil {
			return nil, err
		}
		if bytes.IndexFunc(padding, func(r rune) bool { return r != 0 }) >= 0 {
			continue
		}
		hits = append(hits, trueCryptHit{offset: address + uint64(off+4), password: string(phrase)})
	}
	return hits, nil
}

func trueCryptBytes(ctx context.Context, layer memory.MemoryLayer, base uint64, buf []byte, off, n int) ([]byte, error) {
	if n < 0 || off < 0 {
		return nil, fmt.Errorf("windows.truecrypt: invalid passphrase range")
	}
	out := make([]byte, n)
	if off < len(buf) {
		copied := copy(out, buf[off:])
		if copied == n {
			return out, nil
		}
		rest, err := memory.Read(ctx, layer, base+uint64(off+copied), n-copied)
		if err != nil {
			return nil, fmt.Errorf("windows.truecrypt: passphrase tail: %w", err)
		}
		copy(out[copied:], rest)
		return out, nil
	}
	read, err := memory.Read(ctx, layer, base+uint64(off), n)
	if err != nil {
		return nil, fmt.Errorf("windows.truecrypt: passphrase tail: %w", err)
	}
	return read, nil
}

func trueCryptPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}
