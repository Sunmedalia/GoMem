package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsHiveScanPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "Offset"},
		{"uint64", "Key Signature Entries"},
		{"string", "Tag RecordType Error"},
		{"structure", "Coverage"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.hivescan", Upstream: "windows.registry.hivescan.HiveScan", Platform: "windows", NeedsKernel: true,
		Description: "List in-use CM10 allocations from PoolBigPageTable on 64-bit Windows 8.1 and later",
		Parameters: []plugin.Parameter{
			{Name: "max-entries", Kind: "uint", Default: "2000000", Description: "Upper bound for PoolBigPageTableSize, 1..5000000"},
		},
		Columns: columns,
	}, windowsHiveScan}}
}

func windowsHiveScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, err := strconv.ParseUint(p["max-entries"], 0, 32)
	if err != nil || max < 1 || max > 5000000 {
		return fmt.Errorf("max-entries must be 1..5000000")
	}
	bigPool, err := windowsUsesBigPoolHives(e)
	if err != nil {
		return err
	}
	if !bigPool {
		return fmt.Errorf("windows.hivescan on this symbol table needs the paged pool header scanner, which is not implemented; 64-bit Windows 8.1 and later use PoolBigPageTable")
	}
	table, count, stride, err := windowsBigPoolTable(ctx, e)
	if err != nil {
		return err
	}
	if count > max {
		return fmt.Errorf("PoolBigPageTableSize %d exceeds max-entries %d", count, max)
	}
	var failures pluginFailures
	var hits int
	for index := uint64(0); index < count; index++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		entry, err := memory.Add(table, index*stride)
		if err != nil {
			return err
		}
		va, key, err := readBigPoolEntry(ctx, e, entry)
		if err != nil {
			failures.add(fmt.Errorf("big pool entry %d: %w", index, err))
			continue
		}
		if key == 0 || va&1 == 1 || key != cm10Tag {
			continue
		}
		row := hiveScanRow(e, va)
		row.Cells["RecordType"] = evidence.Text("hive")
		row.Cells["Tag"] = evidence.Text("CM10")
		row.Cells["Key"] = evidence.Number(key)
		signature, sigErr := readLE(ctx, e.Kernel, va, 4)
		if sigErr != nil {
			row.Cells["Signature"] = evidence.Missing("hive_signature_unreadable", sigErr)
		} else {
			row.Cells["Signature"] = evidence.Number(signature)
		}
		hits++
		if err = out(row); err != nil {
			return err
		}
	}
	summary := hiveScanRow(e, table)
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Entries"] = evidence.Number(count)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"entries":       strconv.FormatUint(count, 10),
		"hits":          strconv.Itoa(hits),
		"read_failures": strconv.Itoa(failures.count),
	}}
	cause := failures.err("Windows hive pool scan")
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("hive_scan_incomplete", cause)
		diagnostic := hiveScanRow(e, table)
		diagnostic.Cells["RecordType"] = evidence.Text("diagnostic")
		diagnostic.Cells["Error"] = evidence.Missing("hive_scan_incomplete", cause)
		if err = out(diagnostic); err != nil {
			return err
		}
	}
	if err = out(summary); err != nil {
		return err
	}
	return cause
}

const cm10Tag = uint64('C') | uint64('M')<<8 | uint64('1')<<16 | uint64('0')<<24

func windowsUsesBigPoolHives(e plugin.Environment) (bool, error) {
	if e.Symbols.PointerSize() != 8 {
		return false, nil
	}
	kprcb, err := e.Symbols.Type("_KPRCB")
	if err != nil {
		return false, nil
	}
	_, ok := kprcb.Fields["PendingTickFlags"]
	return ok, nil
}

func windowsBigPoolTable(ctx context.Context, e plugin.Environment) (table, count, stride uint64, err error) {
	typ, err := e.Symbols.Type("_POOL_TRACKER_BIG_PAGES")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("big pool tracker type: %w", err)
	}
	va, err := e.Objects.Field("_POOL_TRACKER_BIG_PAGES", "Va")
	if err != nil {
		return 0, 0, 0, err
	}
	key, err := e.Objects.Field("_POOL_TRACKER_BIG_PAGES", "Key")
	if err != nil {
		return 0, 0, 0, err
	}
	if typ.Size == 0 || va.Offset > typ.Size || key.Offset > typ.Size-4 {
		return 0, 0, 0, fmt.Errorf("incomplete big pool tracker layout")
	}
	pointer, err := e.Symbol("PoolBigPageTable")
	if err != nil {
		return 0, 0, 0, err
	}
	sizeSymbol, err := e.Symbol("PoolBigPageTableSize")
	if err != nil {
		return 0, 0, 0, err
	}
	table, err = readLE(ctx, e.Kernel, pointer, e.Symbols.PointerSize())
	if err != nil {
		return 0, 0, 0, fmt.Errorf("PoolBigPageTable: %w", err)
	}
	if table == 0 {
		return 0, 0, 0, fmt.Errorf("PoolBigPageTable is not set")
	}
	count, err = readLE(ctx, e.Kernel, sizeSymbol, 4)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("PoolBigPageTableSize: %w", err)
	}
	return table, count, typ.Size, nil
}

func readBigPoolEntry(ctx context.Context, e plugin.Environment, entry uint64) (uint64, uint64, error) {
	va, err := e.Objects.Uint(ctx, entry, "_POOL_TRACKER_BIG_PAGES", "Va")
	if err != nil {
		return 0, 0, err
	}
	key, err := e.Objects.Uint(ctx, entry, "_POOL_TRACKER_BIG_PAGES", "Key")
	if err != nil {
		return 0, 0, err
	}
	return va, key, nil
}

func hiveScanRow(e plugin.Environment, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsHiveScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func readLE(ctx context.Context, layer memory.MemoryLayer, address uint64, n int) (uint64, error) {
	buf, err := memory.Read(ctx, layer, address, n)
	if err != nil {
		return 0, err
	}
	var value uint64
	for i, b := range buf {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}
