package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsPrintKey(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 registry keys; not full capability acceptance")
	}
	reference := loadPrintKeyReference(t, filepath.Join(dir, "reference-windows-printkey.json"))
	if len(reference) != 478 {
		t.Fatal(len(reference))
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.printkey", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	const mask = uint64(0x0000ffffffffffff)
	got := map[string]int{}
	var dataDiff, timeFormatDiff, diagnostics int
	entities := make([]evidence.Row, 0, len(rows))
	for _, row := range rows {
		kind := row.Cells["RecordType"].String()
		if kind == "diagnostic" {
			diagnostics++
			continue
		}
		if kind != "key" && kind != "value" {
			t.Fatal("unexpected record", kind, row.Cells["Error"])
		}
		entities = append(entities, row)
		got[printIdentity(row, mask)]++
		if row.Cells["Type"].String() == "Key" && row.Cells["Data"].String() != "" {
			t.Fatal("key data", row.Cells["Data"])
		}
	}
	rows = entities
	want := map[string]int{}
	for _, ref := range reference {
		want[ref.identity()]++
	}
	if len(got) != len(want) {
		t.Fatalf("identities native %d reference %d rows %d", len(got), len(want), len(rows))
	}
	for key, n := range want {
		if got[key] != n {
			t.Fatalf("mismatch %s native %d reference %d", key, got[key], n)
		}
	}
	nativeTimes := map[string]int{}
	referenceTimes := map[string]int{}
	nativeData := map[string]int{}
	referenceData := map[string]int{}
	for _, row := range rows {
		id := printIdentity(row, mask)
		nativeTimes[id+"\x00"+printTimeSecond(row.Cells["LastWriteTime"])]++
		nativeData[id+"\x00"+printData(row)]++
		if row.Cells["LastWriteTime"].Kind == "string" && strings.Contains(row.Cells["LastWriteTime"].String(), ".") {
			timeFormatDiff++
		}
	}
	for _, ref := range reference {
		id := ref.identity()
		referenceTimes[id+"\x00"+refTimeSecond(ref.Time)]++
		referenceData[id+"\x00"+normalizeRefData(ref)]++
		if ref.Type != "Key" && ref.Data != "" && strings.HasPrefix(ref.Data, `"`) && strings.HasSuffix(ref.Data, `"`) {
			dataDiff++
		}
	}
	if len(nativeTimes) != len(referenceTimes) {
		t.Fatalf("time buckets native %d reference %d", len(nativeTimes), len(referenceTimes))
	}
	for key, n := range referenceTimes {
		if nativeTimes[key] != n {
			t.Fatalf("time mismatch %q native %d reference %d", key, nativeTimes[key], n)
		}
	}
	for key, n := range referenceData {
		if nativeData[key] != n {
			t.Fatalf("data mismatch %q native %d reference %d", key, nativeData[key], n)
		}
	}
	t.Logf("rows %d diagnostics %d time-format differences %d quoted-data differences %d build %s", len(rows), diagnostics, timeFormatDiff, dataDiff, rows[0].Provenance.EngineBuild)
}

type printRef struct {
	Data     string  `json:"Data"`
	Hive     uint64  `json:"Hive Offset"`
	Key      string  `json:"Key"`
	Time     *string `json:"Last Write Time"`
	Name     *string `json:"Name"`
	Type     string  `json:"Type"`
	Volatile *bool   `json:"Volatile"`
}

func (r printRef) identity() string {
	name, vol := "<missing>", "<missing>"
	if r.Name != nil {
		name = *r.Name
	}
	if r.Volatile != nil {
		if *r.Volatile {
			vol = "true"
		} else {
			vol = "false"
		}
	}
	return strings.Join([]string{formatHex(r.Hive & 0x0000ffffffffffff), r.Type, r.Key, name, vol}, "\x00")
}

func loadPrintKeyReference(t *testing.T, path string) []printRef {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []printRef
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func printIdentity(row evidence.Row, mask uint64) string {
	offset, err := row.Cells["HiveOffset"].Uint()
	if err != nil {
		return "bad-offset"
	}
	name, vol := "<missing>", "<missing>"
	if row.Cells["Name"].Kind == "string" {
		name = row.Cells["Name"].String()
	} else if row.Cells["Name"].Kind != "missing" || row.Cells["Name"].Error != "" {
		name = "<invalid>"
	}
	if row.Cells["Volatile"].Kind == "bool" {
		if row.Cells["Volatile"].Data == true {
			vol = "true"
		} else {
			vol = "false"
		}
	} else if row.Cells["Volatile"].Kind != "missing" || row.Cells["Volatile"].Error != "" {
		vol = "<invalid>"
	}
	return strings.Join([]string{formatHex(offset & mask), row.Cells["Type"].String(), row.Cells["Key"].String(), name, vol}, "\x00")
}

func formatHex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return string(buf[i:])
}

func printTimeSecond(v evidence.Value) string {
	if v.Kind == "missing" {
		return "<missing>"
	}
	parsed, err := time.Parse(time.RFC3339Nano, v.String())
	if err != nil {
		return "bad"
	}
	return parsed.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func refTimeSecond(v *string) string {
	if v == nil {
		return "<missing>"
	}
	parsed, err := time.Parse(time.RFC3339Nano, *v)
	if err != nil {
		return "bad"
	}
	return parsed.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func printData(row evidence.Row) string {
	if row.Cells["Type"].String() == "Key" {
		return ""
	}
	if row.Cells["Data"].Kind != "string" {
		return "<" + row.Cells["Data"].Kind + ">"
	}
	return row.Cells["Data"].String()
}

func normalizeRefData(ref printRef) string {
	if ref.Type == "Key" {
		return ""
	}
	if strings.HasPrefix(ref.Data, `"`) && strings.HasSuffix(ref.Data, `"`) && len(ref.Data) >= 2 {
		return ref.Data[1 : len(ref.Data)-1]
	}
	return ref.Data
}
