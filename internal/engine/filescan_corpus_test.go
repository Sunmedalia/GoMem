package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestFileScanKnownOffsets(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Windows 10 file-object spot check; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-filescan.json")
	raw, err := os.ReadFile(reference)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name   string `json:"Name"`
		Offset uint64 `json:"Offset"`
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4866 {
		t.Fatalf("reference rows %d", len(rows))
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{
		Image:   filepath.Join(dir, "win-10_19041-2025_03.dmp"),
		Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"),
		CaseDir: t.TempDir(),
		Offline: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	virtual, ok := e.Env.Kernel.(*memory.Virtual)
	if !ok {
		t.Fatalf("kernel layer %T", e.Env.Kernel)
	}
	intel, ok := virtual.Translator.(*memory.Intel)
	if !ok {
		t.Fatalf("translator %T", virtual.Translator)
	}
	ranges, err := intel.MappedRanges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, r := range ranges {
		total += r.Length
	}
	t.Logf("mapped ranges %d bytes %#x", len(ranges), total)
	indexes := []int{0, 1, 100, 1000, 2500, 4000, 4865}
	for i, row := range rows {
		if row.Name == "\uFFFD" {
			indexes = append(indexes, i)
			break
		}
	}
	for _, index := range indexes {
		row := rows[index]
		addr := row.Offset
		if addr&(1<<47) != 0 {
			addr |= 0xffff000000000000
		}
		name, err := fileObjectName(ctx, e, addr)
		if err != nil {
			t.Errorf("index %d offset %#x: %v", index, addr, err)
			continue
		}
		if name != row.Name {
			t.Errorf("index %d offset %#x\n got %q\nwant %q", index, addr, name, row.Name)
		}
		if !rangeContains(ranges, addr) {
			t.Errorf("index %d offset %#x is outside mapped ranges", index, addr)
		}
	}
}

func fileObjectName(ctx context.Context, e *engine.Engine, addr uint64) (string, error) {
	length, err := e.Env.Objects.Uint(ctx, addr, "_FILE_OBJECT", "FileName.Length")
	if err != nil {
		return "", err
	}
	buffer, err := e.Env.Objects.Uint(ctx, addr, "_FILE_OBJECT", "FileName.Buffer")
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, e.Env.Kernel, buffer, int(length))
	if err != nil {
		return "", err
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	decoded := utf16.Decode(units)
	if len(raw)%2 == 1 {
		decoded = append(decoded, '\uFFFD')
	}
	text := string(decoded)
	for i, r := range text {
		if r == 0 {
			return text[:i], nil
		}
	}
	return text, nil
}

func rangeContains(ranges []memory.Range, addr uint64) bool {
	for _, r := range ranges {
		if addr >= r.Start && addr < r.Start+r.Length {
			return true
		}
	}
	return false
}

func TestOfficialWindowsFileScan(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 file-object rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-filescan.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.filescan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(out)
	for _, row := range rows {
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.filescan.json"))
	report, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diff failed: %v\n%s", err, report)
	}
	var build string
	var coverage any
	files := 0
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		if row.Cells["RecordType"].Data == "file" {
			files++
		}
		if row.Cells["RecordType"].Data == "summary" {
			coverage = row.Cells["Coverage"].Data
		}
	}
	t.Logf("files %d build %s coverage %#v\nrows %d\n%s", files, build, coverage, len(rows), report)
}
