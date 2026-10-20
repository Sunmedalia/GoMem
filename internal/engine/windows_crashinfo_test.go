package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsCrashInfoHeaderAndBitmap(t *testing.T) {
	full := crashDump(t, false)
	rows, state, err := crashInfoRows(t, full)
	if err != nil || state != "completed" || len(rows) != 1 {
		t.Fatal(state, len(rows), err)
	}
	row := rows[0]
	if row.Cells["Signature"].String() != "PAGE" || row.Cells["MajorVersion"].String() != "15" || row.Cells["MinorVersion"].String() != "19041" || row.Cells["DumpType"].String() != "Full Dump (0x1)" || row.Cells["Comment"].String() != "hello" || row.Cells["SystemUpTime"].String() != "0:00:00.000002" || row.Cells["SystemTime"].String() != "2025-03-06T17:59:20+00:00" {
		t.Fatal(row.Cells)
	}
	if row.Cells["BitmapHeaderSize"].Reason != "not_applicable" || row.Cells["NumberProcessors"].String() != "2" || row.Cells["MachineImageType"].String() != "34404" {
		t.Fatal(row.Cells)
	}
	dtb, err := row.Cells["DirectoryTableBase"].Uint()
	if err != nil || dtb != 0x12345000 {
		t.Fatal(row.Cells["DirectoryTableBase"], err)
	}

	tie := crashDump(t, false)
	editFile(t, tie, func(data []byte) { binary.LittleEndian.PutUint64(data[4144:], 5) })
	rows, state, err = crashInfoRows(t, tie)
	if err != nil || state != "completed" || rows[0].Cells["SystemUpTime"].String() != "0:00:00" {
		t.Fatal(state, err, rows[0].Cells["SystemUpTime"])
	}

	bitmap := crashDump(t, true)
	rows, state, err = crashInfoRows(t, bitmap)
	if err != nil || state != "completed" || rows[0].Cells["DumpType"].String() != "Bitmap Dump (0x5)" || rows[0].Cells["BitmapHeaderSize"].String() != "12288" || rows[0].Cells["BitmapPages"].String() != "2" || rows[0].Cells["BitmapSize"].String() != "8" {
		t.Fatal(state, err, rows[0].Cells)
	}

	raw, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	rows, state, err = crashInfoRows(t, raw.Image)
	if err == nil || state != "failed" || len(rows) != 0 {
		t.Fatal(state, len(rows), err)
	}

	cut := crashDump(t, false)
	editFile(t, cut, func(data []byte) {
		for i := 4016; i < 4144; i++ {
			data[i] = 0
		}
		copy(data[4016:], []byte("hi\xffthere"))
	})
	rows, state, err = crashInfoRows(t, cut)
	if err != nil || state != "completed" || rows[0].Cells["Comment"].String() != "hi" {
		t.Fatal(state, err, rows[0].Cells["Comment"])
	}
	editFile(t, cut, func(data []byte) {
		for i := 4016; i < 4144; i++ {
			data[i] = 0
		}
		copy(data[4016:], []byte("ab\xef\xbf\xbdcd"))
	})
	rows, state, err = crashInfoRows(t, cut)
	if err != nil || state != "completed" || rows[0].Cells["Comment"].String() != "ab" {
		t.Fatal(state, err, rows[0].Cells["Comment"])
	}

	narrow := crashDump32(t)
	rows, state, err = crashInfoRows(t, narrow)
	if err != nil || state != "completed" || len(rows) != 1 {
		t.Fatal(state, len(rows), err)
	}
	row = rows[0]
	if row.Cells["Signature"].String() != "PAGE" || row.Cells["MajorVersion"].String() != "6" || row.Cells["MinorVersion"].String() != "1" || row.Cells["DumpType"].String() != "Full Dump (0x1)" || row.Cells["Comment"].String() != "hi" || row.Cells["NumberProcessors"].String() != "4" || row.Cells["MachineImageType"].String() != "332" || row.Cells["BitmapPages"].Reason != "not_applicable" || row.Cells["SystemUpTime"].String() != "0:00:00.000002" || row.Cells["SystemTime"].String() != "2025-03-06T17:59:20+00:00" {
		t.Fatal(row.Cells)
	}
	pfn, err := row.Cells["PfnDataBase"].Uint()
	if err != nil || pfn != 0x80000000 {
		t.Fatal(row.Cells["PfnDataBase"], err)
	}
}

func crashDump32(t *testing.T) string {
	t.Helper()
	data := make([]byte, 4096+4096)
	copy(data, "PAGEDUMP")
	binary.LittleEndian.PutUint32(data[8:], 6)
	binary.LittleEndian.PutUint32(data[12:], 1)
	binary.LittleEndian.PutUint32(data[16:], 0x12345000)
	binary.LittleEndian.PutUint32(data[20:], 0x80000000)
	binary.LittleEndian.PutUint32(data[24:], 0x80001000)
	binary.LittleEndian.PutUint32(data[28:], 0x80002000)
	binary.LittleEndian.PutUint32(data[32:], 0x14c)
	binary.LittleEndian.PutUint32(data[36:], 4)
	binary.LittleEndian.PutUint32(data[96:], 0x80003000)
	binary.LittleEndian.PutUint32(data[100:], 1)
	binary.LittleEndian.PutUint32(data[108:], 1)
	binary.LittleEndian.PutUint32(data[112:], 1)
	copy(data[2080:], []byte("hi\xffthere"))
	binary.LittleEndian.PutUint32(data[3976:], 1)
	binary.LittleEndian.PutUint64(data[4024:], 15)
	binary.LittleEndian.PutUint64(data[4032:], 133857575609568401)
	copy(data[4096:], "crash")
	path := filepath.Join(t.TempDir(), "dump32.dmp")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func crashDump(t *testing.T, bitmap bool) string {
	t.Helper()
	var data []byte
	if !bitmap {
		data = make([]byte, 8192+4096)
		copy(data, "PAGEDU64")
		binary.LittleEndian.PutUint32(data[3992:], 1)
		binary.LittleEndian.PutUint32(data[136:], 1)
		binary.LittleEndian.PutUint64(data[136+16:], 3)
		binary.LittleEndian.PutUint64(data[136+24:], 1)
		copy(data[8192:], "crash")
	} else {
		data = make([]byte, 8192+4096+8192)
		copy(data, "PAGEDU64")
		binary.LittleEndian.PutUint32(data[3992:], 5)
		copy(data[8192:], "SDMPDUMP")
		binary.LittleEndian.PutUint64(data[8192+32:], 12288)
		binary.LittleEndian.PutUint64(data[8192+40:], 2)
		binary.LittleEndian.PutUint64(data[8192+48:], 8)
		data[8192+56] = 0b00001010
	}
	binary.LittleEndian.PutUint32(data[8:], 15)
	binary.LittleEndian.PutUint32(data[12:], 19041)
	binary.LittleEndian.PutUint64(data[16:], 0x12345000)
	binary.LittleEndian.PutUint64(data[24:], 0xfffff20000000000)
	binary.LittleEndian.PutUint64(data[32:], 0xfffff80012345678)
	binary.LittleEndian.PutUint64(data[40:], 0xfffff80012345000)
	binary.LittleEndian.PutUint32(data[48:], 0x8664)
	binary.LittleEndian.PutUint32(data[52:], 2)
	binary.LittleEndian.PutUint64(data[128:], 0xfffff80012340000)
	copy(data[4016:], "hello")
	binary.LittleEndian.PutUint64(data[4008:], 133857575609568401)
	binary.LittleEndian.PutUint64(data[4144:], 15)
	path := filepath.Join(t.TempDir(), "dump.dmp")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func editFile(t *testing.T, path string, edit func([]byte)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edit(data)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func crashInfoRows(t *testing.T, image string) ([]evidence.Row, string, error) {
	t.Helper()
	e, err := engine.Open(context.Background(), engine.Config{Image: image, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "windows.crashinfo", nil, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}
