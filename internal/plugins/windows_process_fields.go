package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// Keep failures bounded while continuing independent entities. Cancellation and
// emit errors are returned by the traversal, never accumulated here.
type pluginFailures struct {
	count int
	first error
}

func (f *pluginFailures) add(err error) {
	if err != nil {
		f.count++
		if f.first == nil {
			f.first = err
		}
	}
}

func (f pluginFailures) err(scope string) error {
	if f.count == 0 {
		return nil
	}
	return fmt.Errorf("%s: %d failures; first error: %w", scope, f.count, f.first)
}

func windowsHandleCount(ctx context.Context, e plugin.Environment, process uint64) evidence.Value {
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "ObjectTable")
	if err != nil {
		return evidence.Missing("handle_table_unavailable", err)
	}
	if pointer == 0 {
		return evidence.Missing("handle_table_not_set", nil)
	}
	if _, err := e.Objects.Field("_HANDLE_TABLE", "HandleCount"); err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			return evidence.Missing("unsupported_handle_count", nil)
		}
		return evidence.Missing("handle_count_layout_unavailable", err)
	}
	return optionalUint(ctx, e, pointer, "_HANDLE_TABLE", "HandleCount", false)
}

func windowsSessionID(ctx context.Context, e plugin.Environment, process uint64) evidence.Value {
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Session")
	if err != nil {
		return evidence.Missing("session_pointer_unavailable", err)
	}
	if pointer == 0 {
		return evidence.Missing("not_applicable", nil)
	}
	// The Windows 11 opaque _PSP_SESSION_SPACE fallback is intentionally not
	// guessed from a fixed offset. A verified layout is required for every field.
	return optionalUint(ctx, e, pointer, "_MM_SESSION_SPACE", "SessionId", false)
}

func windowsIsWow64(ctx context.Context, e plugin.Environment, process uint64) evidence.Value {
	for _, path := range []string{"Wow64Process", "WoW64Process"} {
		if _, err := e.Objects.Field("_EPROCESS", path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return evidence.Missing("wow64_layout_unavailable", err)
		}
		value, err := e.Objects.Uint(ctx, process, "_EPROCESS", path)
		if err != nil {
			return evidence.Missing("wow64_pointer_unavailable", err)
		}
		return evidence.Value{Kind: "bool", Data: value != 0}
	}
	return evidence.Value{Kind: "bool", Data: false}
}

func dumpProcessPE(ctx context.Context, e plugin.Environment, process, pid uint64, name string, row evidence.Row) error {
	fail := func(stage string, err error) error {
		for _, key := range []string{"ImageBase", "FileOutput", "Patches"} {
			row.Cells[key] = evidence.Missing(stage, err)
		}
		return err
	}
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil {
		return fail("peb_pointer_unreadable", err)
	}
	if peb == 0 {
		return fail("no_process_peb", nil)
	}
	layer, err := processMemory(ctx, e, process, 0, row.Cells["Identity"].String())
	if err != nil {
		return fail("process_address_space_unavailable", err)
	}
	reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
	base, err := reader.Uint(ctx, peb, "_PEB", "ImageBaseAddress")
	if err != nil {
		return fail("peb_image_base_unreadable", err)
	}
	row.Cells["ImageBase"] = evidence.Address(base)
	file, image, err := dumpPE(ctx, e, layer, fmt.Sprintf("%d.%s.%#x.dmp", pid, name, base), base)
	row.Cells["FileOutput"] = file
	if image != nil {
		row.Cells["Patches"] = evidence.Value{Kind: "structure", Data: image.Patches}
	} else {
		row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", err)
	}
	return err
}
