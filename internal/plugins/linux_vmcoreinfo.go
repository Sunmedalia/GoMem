package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxVMCoreInfoPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.vmcoreinfo", Upstream: "linux.vmcoreinfo.VMCoreInfo", Platform: "linux", Description: "Scan physical memory for VMCOREINFO ELF notes with lossless values and raw note evidence", Parameters: []plugin.Parameter{{Name: "max-candidates", Kind: "uint", Default: "131072", Description: "Maximum signature candidates, 1..1000000"}, {Name: "max-descriptor", Kind: "uint", Default: "1048576", Description: "Maximum descriptor bytes, 1..16777216"}, {Name: "max-rows", Kind: "uint", Default: "1000000", Description: "Maximum final key/value rows, 1..1000000"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Key", Kind: "string"}, {Name: "Value", Kind: "string"}, {Name: "TypedValue", Kind: "integer"}, {Name: "LineOffset", Kind: "address"}, {Name: "LineLength", Kind: "uint64"}, {Name: "HeaderEvidence", Kind: "structure"}, {Name: "DescriptorEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Status", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}}}, linuxVMCoreInfo}}
}

type vmcoreEntry struct {
	key, value, integer string
	offset, length      int
}

// Python int's printable-ASCII grammar; base=0 excludes legacy nonzero octal.
// Values remain arbitrary precision and are never converted through JSON floats.
func vmcoreInteger(value string, base int) (*big.Int, error) {
	s := strings.Trim(value, " \t\r\n\v\f")
	negative := false
	invalid := func() (*big.Int, error) { return nil, fmt.Errorf("invalid base-%d integer %q", base, value) }
	if s == "" {
		return invalid()
	}
	if s[0] == '+' || s[0] == '-' {
		negative = s[0] == '-'
		s = s[1:]
		if s == "" {
			return invalid()
		}
	}
	radix := base
	leadingZero := false
	prefix := false
	if radix == 0 {
		radix = 10
		leadingZero = len(s) > 1 && s[0] == '0'
	}
	if len(s) >= 2 && s[0] == '0' {
		r := 0
		switch s[1] {
		case 'x', 'X':
			r = 16
		case 'o', 'O':
			r = 8
		case 'b', 'B':
			r = 2
		}
		if r != 0 && (base == 0 || base == r) {
			radix = r
			prefix = true
			s = s[2:]
			leadingZero = false
		}
	}
	if prefix && strings.HasPrefix(s, "_") {
		s = s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' {
		return invalid()
	}
	previousUnderscore := false
	digits := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if c == '_' {
			if previousUnderscore {
				return invalid()
			}
			previousUnderscore = true
			continue
		}
		previousUnderscore = false
		digit := int(c - '0')
		if c >= 'a' && c <= 'f' {
			digit = int(c-'a') + 10
		} else if c >= 'A' && c <= 'F' {
			digit = int(c-'A') + 10
		}
		if digit < 0 || digit >= radix {
			return invalid()
		}
		if leadingZero && digit != 0 {
			return invalid()
		}
		digits = append(digits, c)
	}
	if len(digits) > 65536 {
		return nil, fmt.Errorf("integer exceeds native 65536-digit bound")
	}
	if len(digits) == 0 {
		return invalid()
	}
	// Match the fixed reference's default Python decimal conversion bound.
	if radix == 10 && len(digits) > 4300 {
		return nil, fmt.Errorf("decimal integer exceeds Python default 4300-digit bound")
	}
	n, ok := new(big.Int).SetString(string(digits), radix)
	if !ok {
		return invalid()
	}
	if negative {
		n.Neg(n)
	}
	return n, nil
}

func vmcoreParse(data []byte) ([]vmcoreEntry, string, error) {
	return vmcoreParseBounded(context.Background(), data, 1000000)
}
func vmcoreParseBounded(ctx context.Context, data []byte, maxEntries int) ([]vmcoreEntry, string, error) {
	for i, b := range data {
		if i&16383 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, "canceled", err
			}
		}
		if !(b >= 32 && b <= 126 || b >= 9 && b <= 13) {
			return nil, "nonprintable_descriptor", nil
		}
	}
	entries := []vmcoreEntry{}
	byKey := map[string]int{}
	for start := 0; start < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, "canceled", err
		}
		end := start
		for end < len(data) && data[end] != '\n' && data[end] != '\r' && data[end] != '\v' && data[end] != '\f' {
			end++
		}
		line := data[start:end]
		if len(line) == 0 {
			break
		}
		separator := bytes.IndexByte(line, '=')
		if separator < 0 {
			return nil, "malformed_line", fmt.Errorf("VMCOREINFO line at +%d has no equals sign", start)
		}
		key, value := string(line[:separator]), string(line[separator+1:])
		entry := vmcoreEntry{key: key, value: value, offset: start, length: len(line)}
		base := -1
		if strings.HasPrefix(key, "SYMBOL(") || key == "KERNELOFFSET" {
			base = 16
		} else if strings.HasPrefix(key, "NUMBER(") || strings.HasPrefix(key, "LENGTH(") || strings.HasPrefix(key, "SIZE(") || strings.HasPrefix(key, "OFFSET(") || key == "PAGESIZE" {
			base = 0
		}
		if base >= 0 {
			n, err := vmcoreInteger(value, base)
			if err != nil {
				return nil, "invalid_numeric_value", fmt.Errorf("VMCOREINFO %q: %w", key, err)
			}
			entry.integer = n.String()
			entry.value = entry.integer
			if base == 16 {
				if n.Sign() < 0 {
					entry.value = "-0x" + new(big.Int).Abs(n).Text(16)
				} else {
					entry.value = "0x" + n.Text(16)
				}
			}
		}
		if index, ok := byKey[key]; ok {
			entries[index] = entry
		} else {
			if len(entries) >= maxEntries {
				return nil, "entry_bound", fmt.Errorf("VMCOREINFO table exceeds %d distinct keys", maxEntries)
			}
			byKey[key] = len(entries)
			entries = append(entries, entry)
		}
		start = end
		if start < len(data) {
			start++
			if data[end] == '\r' && start < len(data) && data[start] == '\n' {
				start++
			}
		}
	}
	if len(entries) == 0 {
		return nil, "empty_table", nil
	}
	return entries, "parsed", nil
}

func linuxVMCoreInfo(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Physical == nil {
		return fmt.Errorf("VMCOREINFO requires physical memory")
	}
	bound := func(name string, ceiling uint64) (uint64, error) {
		v, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || v < 1 || v > ceiling {
			return 0, fmt.Errorf("%s must be 1..%d", name, ceiling)
		}
		return v, nil
	}
	maxCandidates, err := bound("max-candidates", 1000000)
	if err != nil {
		return err
	}
	maxDesc, err := bound("max-descriptor", 16777216)
	if err != nil {
		return err
	}
	maxRows, err := bound("max-rows", 1000000)
	if err != nil {
		return err
	}
	var candidates, tables, rows, rejected, diagnostics uint64
	var failures pluginFailures
	var emitErr error
	base := func(kind string, address *uint64) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Physical.Name()}}
		for _, c := range linuxVMCoreInfoPlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["RecordType"] = evidence.Text(kind)
		if address != nil {
			r.Cells["Offset"] = evidence.Address(*address)
			r.Provenance.Offset = fmt.Sprintf("0x%x", *address)
		}
		return r
	}
	emit := func(r evidence.Row) error {
		if emitErr != nil {
			return emitErr
		}
		emitErr = out(r)
		return emitErr
	}
	diagnose := func(r evidence.Row, reason string, cause error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if emitErr != nil {
			return emitErr
		}
		diagnostics++
		failures.add(cause)
		r.Cells["RecordType"] = evidence.Text("diagnostic")
		r.Cells["Status"] = evidence.Text(reason)
		r.Cells["Error"] = evidence.Missing(reason, cause)
		return emit(r)
	}
	scanErr := memory.Scan(ctx, e.Physical, []byte("VMCOREINFO\x00\x00"), func(magic uint64) error {
		if candidates >= maxCandidates {
			return fmt.Errorf("VMCOREINFO candidate bound %d exceeded", maxCandidates)
		}
		candidates++
		if magic < 12 {
			return diagnose(base("diagnostic", &magic), "header_underflow", fmt.Errorf("VMCOREINFO signature before complete note header"))
		}
		address := magic - 12
		r := base("note_observation", &address)
		header, proof, err := linuxCaptureRange(ctx, e.Physical, address, 24)
		r.Cells["HeaderEvidence"] = proof
		if err != nil {
			return diagnose(r, "header_unreadable", err)
		}
		namesz, descsz, typ := binary.LittleEndian.Uint32(header), binary.LittleEndian.Uint32(header[4:]), binary.LittleEndian.Uint32(header[8:])
		reject := func(reason string) error { rejected++; r.Cells["Status"] = evidence.Text(reason); return emit(r) }
		if namesz != 11 || typ != 0 || descsz == 0 {
			return reject("header_mismatch")
		}
		if uint64(descsz) > maxDesc {
			return diagnose(r, "descriptor_bound", fmt.Errorf("VMCOREINFO descriptor %d exceeds max-descriptor %d", descsz, maxDesc))
		}
		descAddress, err := memory.Add(magic, 12)
		if err != nil {
			return diagnose(r, "descriptor_address_invalid", err)
		}
		if _, err := memory.Add(descAddress, uint64(descsz)); err != nil {
			return diagnose(r, "descriptor_address_invalid", err)
		}
		data, proof, err := linuxCaptureRange(ctx, e.Physical, descAddress, int(descsz))
		r.Cells["DescriptorEvidence"] = proof
		if err != nil {
			return diagnose(r, "descriptor_unreadable", err)
		}
		if !bytes.HasPrefix(data, []byte("OSRELEASE=")) {
			return reject("missing_osrelease_tag")
		}
		entries, status, err := vmcoreParseBounded(ctx, data, int(maxRows))
		if err != nil {
			return diagnose(r, status, err)
		}
		if status != "parsed" {
			return reject(status)
		}
		tables++
		r.Cells["Status"] = evidence.Text("parsed")
		if err := emit(r); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if rows >= maxRows {
				return fmt.Errorf("VMCOREINFO row bound %d exceeded", maxRows)
			}
			row := base("entry", &address)
			row.Cells["Key"], row.Cells["Value"] = evidence.Text(entry.key), evidence.Text(entry.value)
			row.Cells["Status"] = evidence.Text("parsed")
			if entry.integer != "" {
				row.Cells["TypedValue"] = evidence.Value{Kind: "integer", Data: entry.integer}
			}
			line, err := memory.Add(descAddress, uint64(entry.offset))
			if err != nil {
				return err
			}
			row.Cells["LineOffset"], row.Cells["LineLength"] = evidence.Address(line), evidence.Number(uint64(entry.length))
			rows++
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})
	if emitErr != nil {
		return emitErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		if err := diagnose(base("diagnostic", nil), "scan_incomplete", scanErr); err != nil {
			return err
		}
	}
	summary := base("summary", nil)
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"candidates": strconv.FormatUint(candidates, 10), "tables": strconv.FormatUint(tables, 10), "rows": strconv.FormatUint(rows, 10), "rejected": strconv.FormatUint(rejected, 10), "diagnostics": strconv.FormatUint(diagnostics, 10), "scan_layer": e.Physical.Name(), "note_endian": "little", "scope": "physical VMCOREINFO ELF notes; complete acceptance pending"})
	if err := emit(summary); err != nil {
		return err
	}
	return failures.err("VMCOREINFO scan")
}
