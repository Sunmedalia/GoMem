package plugins

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// linuxCaptureField preserves even an empty or partial read and its coordinates.
func linuxCaptureField(ctx context.Context, e plugin.Environment, base uint64, typ, field string) ([]byte, evidence.Value, error) {
	var f symbols.Field
	var err error
	if field == "" {
		f.Type = symbols.TypeRef{Kind: "struct", Name: typ}
	} else {
		f, err = e.Objects.Field(typ, field)
	}
	if err != nil {
		return nil, evidence.Missing("field_layout_unavailable", err), err
	}
	address, err := memory.Add(base, f.Offset)
	if err != nil {
		return nil, evidence.Missing("field_address_invalid", err), err
	}
	size, err := e.Objects.Size(f.Type)
	if err != nil || size == 0 || size > 4096 {
		err = fmt.Errorf("invalid %s.%s field extent %d: %v", typ, field, size, err)
		return nil, evidence.Missing("field_extent_invalid", err), err
	}
	raw := make([]byte, int(size))
	got, err := e.Kernel.ReadAt(ctx, raw, address)
	if got < 0 || got > len(raw) {
		err = fmt.Errorf("invalid field capture length %d", got)
		return nil, evidence.Missing("capture_invalid", err), err
	}
	if err == nil && got != len(raw) {
		err = io.ErrUnexpectedEOF
	}
	fields := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw[:got]), "RequestedBytes": evidence.Number(size), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(err == nil)}
	if err != nil {
		fields["Error"] = evidence.Missing("field_unreadable", err)
	}
	return raw[:got], evidence.Value{Kind: "structure", Data: fields}, err
}

func linuxEnumChoices(e plugin.Environment, name string, fallback map[string]uint64) (map[string]uint64, error) {
	enum, err := e.Symbols.Enumeration(name)
	if err != nil {
		if fallback != nil {
			return fallback, nil
		}
		return nil, err
	}
	choices := map[string]uint64{}
	if enum.Size == 0 || enum.Size > 8 {
		return nil, fmt.Errorf("invalid %s enum size %d", name, enum.Size)
	}
	for k, n := range enum.Constants {
		v, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid %s.%s: %w", name, k, err)
		}
		choices[k] = v
	}
	return choices, nil
}

// linuxCaptureRange preserves a caller-bounded physical or virtual read.
func linuxCaptureRange(ctx context.Context, layer memory.MemoryLayer, address uint64, size int) ([]byte, evidence.Value, error) {
	if size < 0 || size > memory.MaxRead || layer == nil {
		err := fmt.Errorf("invalid capture extent %d or missing layer", size)
		return nil, evidence.Missing("capture_extent_invalid", err), err
	}
	raw := make([]byte, size)
	got, err := layer.ReadAt(ctx, raw, address)
	if got < 0 || got > size {
		got = 0
		err = fmt.Errorf("invalid memory capture count")
	}
	if err == nil && got != size {
		err = io.ErrUnexpectedEOF
	}
	fields := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw[:got]), "RequestedBytes": evidence.Number(uint64(size)), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(err == nil)}
	if err != nil {
		fields["Error"] = evidence.Missing("capture_incomplete", err)
	}
	return raw[:got], evidence.Value{Kind: "structure", Data: fields}, err
}
