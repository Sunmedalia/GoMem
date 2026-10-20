package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsBigPoolPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Allocation", Kind: "address"},
		{Name: "Tag", Kind: "string"},
		{Name: "PoolType", Kind: "string"},
		{Name: "NumberOfBytes", Kind: "uint64"},
		{Name: "Status", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.bigpools", Upstream: "windows.bigpools.BigPools", Platform: "windows", NeedsKernel: true,
		Description: "List PoolBigPageTable allocations, keeping the free bit and printable pool tag",
		Parameters: []plugin.Parameter{
			{Name: "tags", Kind: "string", Description: "Comma-separated exact tags after printable-byte filtering; empty disables filtering and spaces are not trimmed"},
			{Name: "show-free", Kind: "bool", Default: "false", Description: "Include freed allocations; their Allocation value keeps the low bit"},
			{Name: "max-entries", Kind: "uint", Default: "2000000", Description: "Upper bound for PoolBigPageTableSize, 1..5000000"},
		},
		Columns: columns,
	}, windowsBigPools}}
}

func windowsBigPools(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, err := strconv.ParseUint(p["max-entries"], 0, 32)
	if err != nil || max < 1 || max > 5000000 {
		return fmt.Errorf("max-entries must be 1..5000000")
	}
	showFree, err := strconv.ParseBool(p["show-free"])
	if err != nil {
		return fmt.Errorf("show-free: %w", err)
	}
	table, count, stride, err := windowsBigPoolTable(ctx, e)
	if err != nil {
		return fmt.Errorf("windows.bigpools requires _POOL_TRACKER_BIG_PAGES and does not load a fallback symbol table: %w", err)
	}
	// The pinned plugin reads this symbol as unsigned long long on every architecture.
	pointer, err := e.Symbol("PoolBigPageTable")
	if err != nil {
		return err
	}
	table, err = readLE(ctx, e.Kernel, pointer, 8)
	if err != nil {
		return fmt.Errorf("PoolBigPageTable: %w", err)
	}
	if table == 0 {
		return fmt.Errorf("PoolBigPageTable is not set")
	}
	if count > max {
		return fmt.Errorf("PoolBigPageTableSize %d exceeds max-entries %d", count, max)
	}
	numberPresent, err := bigPoolMember(e, "NumberOfBytes")
	if err != nil {
		return err
	}
	poolPresent, err := bigPoolMember(e, "PoolType")
	if err != nil {
		return err
	}
	var poolNames map[uint64]string
	if poolPresent {
		poolNames, err = poolTypeNames(e)
		if err != nil {
			return err
		}
	}
	tags := poolTagFilter(p["tags"])
	var hits, skippedInvalid, skippedFree, skippedTag int
	for index := uint64(0); index < count; index++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		entry, err := memory.Add(table, index*stride)
		if err != nil {
			return err
		}
		key, err := e.Objects.Uint(ctx, entry, "_POOL_TRACKER_BIG_PAGES", "Key")
		if err != nil {
			return bigPoolRead(index, err)
		}
		if key == 0 {
			skippedInvalid++
			continue
		}
		tag := poolTag(key)
		if tags != nil && !tagSelected(tag, tags) {
			skippedTag++
			continue
		}
		// show-free short-circuits the Va read. A free row is dropped before
		// NumberOfBytes, matching the pinned generator. show-free reads the
		// byte count first and only then Va.
		var va uint64
		var haveVA bool
		if !showFree {
			va, _, err = readBigPoolEntry(ctx, e, entry)
			if err != nil {
				return bigPoolRead(index, err)
			}
			haveVA = true
			if va&1 == 1 {
				skippedFree++
				continue
			}
		}
		number, err := bigPoolBytes(ctx, e, entry, numberPresent)
		if err != nil {
			return bigPoolRead(index, err)
		}
		poolType, err := bigPoolType(ctx, e, entry, poolPresent, poolNames)
		if err != nil {
			return bigPoolRead(index, err)
		}
		if !haveVA {
			va, _, err = readBigPoolEntry(ctx, e, entry)
			if err != nil {
				return bigPoolRead(index, err)
			}
		}
		status := "Allocated"
		if va&1 == 1 {
			status = "Free"
		}
		row := bigPoolRow(e, va)
		row.Cells["Allocation"] = evidence.Address(va)
		row.Cells["Tag"] = evidence.Text(tag)
		row.Cells["PoolType"] = poolType
		row.Cells["NumberOfBytes"] = number
		row.Cells["Status"] = evidence.Text(status)
		row.Cells["RecordType"] = evidence.Text("allocation")
		hits++
		if err = out(row); err != nil {
			return err
		}
	}
	summary := bigPoolRow(e, table)
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"entries":         strconv.FormatUint(count, 10),
		"hits":            strconv.Itoa(hits),
		"skipped_invalid": strconv.Itoa(skippedInvalid),
		"skipped_free":    strconv.Itoa(skippedFree),
		"skipped_tag":     strconv.Itoa(skippedTag),
	}}
	return out(summary)
}

func bigPoolMember(e plugin.Environment, name string) (bool, error) {
	_, err := e.Objects.Field("_POOL_TRACKER_BIG_PAGES", name)
	if errors.Is(err, object.ErrFieldAbsent) {
		return false, nil
	}
	return err == nil, err
}

func bigPoolBytes(ctx context.Context, e plugin.Environment, entry uint64, present bool) (evidence.Value, error) {
	if !present {
		return evidence.Missing("not_applicable", nil), nil
	}
	n, err := e.Objects.Uint(ctx, entry, "_POOL_TRACKER_BIG_PAGES", "NumberOfBytes")
	if err != nil {
		return evidence.Value{}, err
	}
	return evidence.Number(n), nil
}

func bigPoolType(ctx context.Context, e plugin.Environment, entry uint64, present bool, names map[uint64]string) (evidence.Value, error) {
	if !present {
		return evidence.Missing("not_applicable", nil), nil
	}
	value, err := e.Objects.Uint(ctx, entry, "_POOL_TRACKER_BIG_PAGES", "PoolType")
	if err != nil {
		return evidence.Value{}, err
	}
	name, ok := names[value]
	if !ok {
		name = fmt.Sprintf("Unknown choice %d", value)
	}
	return evidence.Text(name), nil
}

func poolTypeNames(e plugin.Environment) (map[uint64]string, error) {
	en, err := e.Symbols.Enumeration("_POOL_TYPE")
	if err != nil {
		return nil, fmt.Errorf("windows.bigpools PoolType: %w", err)
	}
	type choice struct {
		name  string
		value uint64
	}
	choices := make([]choice, 0, len(en.Constants))
	for name, raw := range en.Constants {
		value, err := poolEnumValue(en, raw)
		if err != nil {
			return nil, fmt.Errorf("windows.bigpools PoolType %s: %w", name, err)
		}
		choices = append(choices, choice{name, value})
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].name < choices[j].name })
	names := make(map[uint64]string, len(choices))
	for _, choice := range choices {
		if _, ok := names[choice.value]; !ok {
			names[choice.value] = choice.name
		}
	}
	return names, nil
}

func poolEnumValue(en symbols.Enumeration, raw json.Number) (uint64, error) {
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		signed, serr := strconv.ParseInt(string(raw), 10, 64)
		if serr != nil {
			return 0, err
		}
		value = uint64(signed)
	}
	if en.Size > 0 && en.Size < 8 {
		value &= uint64(1)<<(en.Size*8) - 1
	}
	return value, nil
}

func poolTagFilter(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func tagSelected(tag string, tags []string) bool {
	for _, item := range tags {
		if item == tag {
			return true
		}
	}
	return false
}

func poolTag(key uint64) string {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		c := byte(key >> (8 * i))
		if c > 32 && c < 127 {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func bigPoolRead(index uint64, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("big pool entry %d: %w", index, err)
}

func bigPoolRow(e plugin.Environment, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsBigPoolPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Allocation"] = evidence.Address(address)
	return row
}
