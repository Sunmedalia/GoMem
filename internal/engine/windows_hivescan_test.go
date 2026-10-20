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

func TestWindowsHiveScanBigPoolTag(t *testing.T) {
	f := hiveScanFixture(t, true)
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put32 := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
		put(0x9000, 0xa000)
		put32(0x9008, 4)
		put(0xa000, 0xb000)
		put32(0xa008, cm10)
		put32(0xb000, 0xBEE0BEE0)
		put(0xa018, 0xb100|1)
		put32(0xa020, cm10)
		put(0xa030, 0xb200)
		put32(0xa038, 0)
		put(0xa048, 0xb300)
		put32(0xa050, binary.LittleEndian.Uint32([]byte("MmLd")))
	})
	rows, state, err := hiveScanRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 2 {
		t.Fatal(state, len(rows), err, hiveScanSummary(rows))
	}
	offset, err := rows[0].Cells["Offset"].Uint()
	signature, sigErr := rows[0].Cells["Signature"].Uint()
	if rows[0].Cells["RecordType"].String() != "hive" || rows[0].Cells["Tag"].String() != "CM10" || err != nil || offset != 0xb000 || sigErr != nil || signature != 0xBEE0BEE0 {
		t.Fatal(rows[0].Cells, err, sigErr)
	}
	coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
	if rows[1].Cells["RecordType"].String() != "summary" || rows[1].Cells["Error"].Reason != "not_applicable" || coverage["entries"] != "4" || coverage["hits"] != "1" || coverage["read_failures"] != "0" {
		t.Fatal(rows[1].Cells)
	}
	if _, err = openWindowsImage(t, f).Run(context.Background(), "windows.hivescan", map[string]string{"max-entries": "1"}, engine.RunOptions{}); err == nil || !strings.Contains(err.Error(), "exceeds max-entries") {
		t.Fatal(err)
	}
}

func TestWindowsHiveScanWithoutBigPoolLayoutFailsBeforeRows(t *testing.T) {
	f := hiveScanFixture(t, false)
	rows, state, err := hiveScanRows(t, f, nil)
	if err == nil || state != "failed" || len(rows) != 0 || !strings.Contains(err.Error(), "paged pool header scanner") {
		t.Fatal(state, len(rows), err)
	}
}

func hiveScanFixture(t *testing.T, bigPool bool) testfixture.Fixture {
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
	if bigPool {
		table.Types["_KPRCB"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"PendingTickFlags": field(0, u32)}}
		table.Types["_POOL_TRACKER_BIG_PAGES"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"Va": field(0, u64), "Key": field(8, u32)}}
		table.Symbols["PoolBigPageTable"] = symbols.Symbol{Address: 0x5000}
		table.Symbols["PoolBigPageTableSize"] = symbols.Symbol{Address: 0x5008}
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

func hiveScanRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.hivescan", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func hiveScanSummary(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Tag"].String()+" "+row.Cells["Error"].String())
	}
	return out
}

const cm10 = uint32('C') | uint32('M')<<8 | uint32('1')<<16 | uint32('0')<<24
