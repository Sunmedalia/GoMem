package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsBigPoolsFiltersTagsAndFreeBit(t *testing.T) {
	f := bigPoolFixture(t, bigPoolLayout{poolType: true, number: true, enum: true})
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put32 := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
		put(0x9000, 0xa000)
		put32(0x9008, 6)
		putPool := func(addr, va uint64, key, pool uint32, size uint64) {
			put(addr, va)
			put32(addr+8, key)
			put32(addr+12, pool<<8)
			put(addr+16, size)
		}
		putPool(0xa000, 0xb000, cm10, 512, 0x1000)
		putPool(0xa018, 0xb100|1, cm10, 1, 0x2000)
		putPool(0xa030, 0xb200, 0, 512, 0x10)
		putPool(0xa048, 0xb300, uint32('C')|uint32('M')<<8|1<<16|uint32('0')<<24, 100, 0x20)
		putPool(0xa060, 0xb400, 0x01020304, 0, 0x30)
		putPool(0xa078, 0xb500, uint32('Z')|uint32('z')<<8, 1, 0x40)
	})
	rows, state, err := bigPoolRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 5 {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	want := []struct {
		addr, size        uint64
		tag, pool, status string
	}{
		{0xb000, 0x1000, "CM10", "NonPagedPoolNx", "Allocated"},
		{0xb300, 0x20, "CM0", "Unknown choice 100", "Allocated"},
		{0xb400, 0x30, "", "NonPagedPool", "Allocated"},
		{0xb500, 0x40, "Zz", "PagedPool", "Allocated"},
	}
	for i, item := range want {
		if err = bigPoolEqual(rows[i], item.addr, item.size, item.tag, item.pool, item.status); err != nil {
			t.Fatal(i, err, rows[i].Cells)
		}
	}
	coverage := rows[4].Cells["Coverage"].Data.(map[string]any)
	if rows[4].Cells["RecordType"].String() != "summary" || coverage["entries"] != "6" || coverage["hits"] != "4" || coverage["skipped_invalid"] != "1" || coverage["skipped_free"] != "1" || coverage["skipped_tag"] != "0" {
		t.Fatal(rows[4].Cells)
	}

	rows, state, err = bigPoolRows(t, f, map[string]string{"show-free": "true"})
	if err != nil || state != "completed" || len(rows) != 6 {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	if err = bigPoolEqual(rows[1], 0xb101, 0x2000, "CM10", "PagedPool", "Free"); err != nil {
		t.Fatal(err, rows[1].Cells)
	}

	rows, state, err = bigPoolRows(t, f, map[string]string{"tags": "CM10"})
	if err != nil || state != "completed" || len(rows) != 2 || bigPoolEqual(rows[0], 0xb000, 0x1000, "CM10", "NonPagedPoolNx", "Allocated") != nil {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	rows, state, err = bigPoolRows(t, f, map[string]string{"tags": "CM10,CM0"})
	if err != nil || state != "completed" || len(rows) != 3 {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	if rows[1].Cells["Tag"].String() != "CM0" {
		t.Fatal(rows[1].Cells["Tag"])
	}
	rows, state, err = bigPoolRows(t, f, map[string]string{"tags": "CM10, CM0"})
	if err != nil || state != "completed" || len(rows) != 2 || rows[0].Cells["Tag"].String() != "CM10" {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	if _, _, err = bigPoolRows(t, f, map[string]string{"tags-extra": "1"}); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatal(err)
	}
	rows, state, err = bigPoolRows(t, f, map[string]string{"show-free": "true", "tags": "CM10"})
	if err != nil || state != "completed" || len(rows) != 3 {
		t.Fatal(state, len(rows), err, bigPoolSummary(rows))
	}
	if err = bigPoolEqual(rows[1], 0xb101, 0x2000, "CM10", "PagedPool", "Free"); err != nil {
		t.Fatal(err)
	}
	if _, err = openWindowsImage(t, f).Run(context.Background(), "windows.bigpools", map[string]string{"max-entries": "1"}, engine.RunOptions{}); err == nil || !strings.Contains(err.Error(), "exceeds max-entries") {
		t.Fatal(err)
	}
}

func TestWindowsBigPoolsMissingTrackerFailsBeforeRows(t *testing.T) {
	f := hiveFixture(t)
	rows, state, err := bigPoolRows(t, f, nil)
	if err == nil || state != "failed" || len(rows) != 0 || !strings.Contains(err.Error(), "_POOL_TRACKER_BIG_PAGES") || !strings.Contains(err.Error(), "fallback") {
		t.Fatal(state, len(rows), err)
	}
}

func TestWindowsBigPoolsAbsentMembersAndReadOrder(t *testing.T) {
	f := bigPoolFixture(t, bigPoolLayout{number: true})
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x9000:], 0xa000)
		binary.LittleEndian.PutUint32(data[0x9008:], 1)
		binary.LittleEndian.PutUint64(data[0xa000:], 0xb000)
		binary.LittleEndian.PutUint32(data[0xa008:], cm10)
		binary.LittleEndian.PutUint64(data[0xa010:], 0x80)
	})
	rows, state, err := bigPoolRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 2 || rows[0].Cells["PoolType"].Reason != "not_applicable" || rows[0].Cells["NumberOfBytes"].String() != "128" {
		t.Fatal(state, len(rows), err, rows)
	}

	f = bigPoolFixture(t, bigPoolLayout{poolType: true, number: true, enum: true})
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x9000:], 0x1fff0)
		binary.LittleEndian.PutUint32(data[0x9008:], 1)
		binary.LittleEndian.PutUint64(data[0x1fff0:], 0xb000|1)
		binary.LittleEndian.PutUint32(data[0x1fff8:], cm10)
	})
	rows, state, err = bigPoolRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "summary" {
		t.Fatal(state, len(rows), err)
	}
	coverage := rows[0].Cells["Coverage"].Data.(map[string]any)
	if coverage["hits"] != "0" || coverage["skipped_free"] != "1" {
		t.Fatal(coverage)
	}
	rows, state, err = bigPoolRows(t, f, map[string]string{"show-free": "true"})
	if err == nil || state == "completed" || len(rows) != 0 || !strings.Contains(err.Error(), "big pool entry 0") {
		t.Fatal(state, len(rows), err)
	}
	f = bigPoolFixture(t, bigPoolLayout{poolType: true, number: true})
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x9000:], 0xa000)
		binary.LittleEndian.PutUint32(data[0x9008:], 1)
		binary.LittleEndian.PutUint64(data[0xa000:], 0xb000)
		binary.LittleEndian.PutUint32(data[0xa008:], cm10)
		binary.LittleEndian.PutUint64(data[0xa010:], 0x80)
	})
	rows, state, err = bigPoolRows(t, f, nil)
	if err == nil || len(rows) != 0 || !strings.Contains(err.Error(), "_POOL_TYPE") {
		t.Fatal(state, len(rows), err)
	}
}

func TestWindowsBigPoolsReadsTablePointerAsEightBytes(t *testing.T) {
	f := bigPoolFixture(t, bigPoolLayout{poolType: true, number: true, enum: true, pointer32: true})
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x9000:], 0x1_0000_a000)
		binary.LittleEndian.PutUint32(data[0x9008:], 1)
		binary.LittleEndian.PutUint64(data[0xa000:], 0xb000)
		binary.LittleEndian.PutUint32(data[0xa008:], cm10)
		binary.LittleEndian.PutUint32(data[0xa00c:], 512<<8)
		binary.LittleEndian.PutUint64(data[0xa010:], 0x1000)
	})
	rows, state, err := bigPoolRows(t, f, nil)
	if err == nil || state == "completed" || len(rows) != 0 {
		t.Fatal("4-byte pointer read would accept the low half", state, len(rows), err)
	}
}

type bigPoolLayout struct {
	poolType, number, enum, pointer32 bool
}

func bigPoolFixture(t *testing.T, layout bigPoolLayout) testfixture.Fixture {
	t.Helper()
	f := hiveFixture(t)
	raw, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: off, Type: ref}
	}
	fields := map[string]symbols.Field{"Va": field(0, u64), "Key": field(8, u32)}
	if layout.poolType {
		bits := symbols.TypeRef{Kind: "bitfield", BitType: &u32, BitPosition: 8, BitLength: 12}
		fields["PoolType"] = field(12, bits)
	}
	if layout.number {
		fields["NumberOfBytes"] = field(16, u64)
	}
	table.Types["_POOL_TRACKER_BIG_PAGES"] = symbols.Type{Kind: "struct", Size: 24, Fields: fields}
	table.Symbols["PoolBigPageTable"] = symbols.Symbol{Address: 0x5000}
	table.Symbols["PoolBigPageTableSize"] = symbols.Symbol{Address: 0x5008}
	if layout.enum {
		table.Enums = map[string]symbols.Enumeration{"_POOL_TYPE": {Base: "u32", Size: 4, Constants: map[string]json.Number{
			"NonPagedPool": "0", "NonPagedPoolExecute": "0", "PagedPool": "1", "NonPagedPoolNx": "512",
		}}}
	}
	if layout.pointer32 {
		pointer := table.Bases["pointer"]
		pointer.Size = 4
		table.Bases["pointer"] = pointer
	}
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func bigPoolRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.bigpools", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func bigPoolEqual(row evidence.Row, addr, size uint64, tag, pool, status string) error {
	got, err := row.Cells["Allocation"].Uint()
	if err != nil {
		return err
	}
	n, err := row.Cells["NumberOfBytes"].Uint()
	if err != nil {
		return err
	}
	if row.Cells["RecordType"].String() != "allocation" || got != addr || n != size || row.Cells["Tag"].String() != tag || row.Cells["PoolType"].String() != pool || row.Cells["Status"].String() != status {
		return errString("row mismatch")
	}
	if tag == "" && (row.Cells["Tag"].Kind != "string" || row.Cells["Tag"].Data != "") {
		return errString("empty tag was not preserved")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func bigPoolSummary(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Tag"].String()+" "+row.Cells["Status"].String())
	}
	return out
}
