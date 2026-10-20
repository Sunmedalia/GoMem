package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func commandUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func TestCommandLinesLinkProcessesAndUseIndependentAddressSpaces(t *testing.T) {
	for _, independent := range []bool{false, true} {
		f := dllFixture(t, "native")
		if independent {
			f = dllFixture(t, "independent-process-root")
			editWindowsImage(t, f, func(data []byte) {
				binary.LittleEndian.PutUint64(data[0x1b010:], 0x21e100)
				binary.LittleEndian.PutUint64(data[0x1e108:], 0x21e200)
			})
		}
		e := openWindowsImage(t, f)
		ctx := context.Background()
		var identity string
		if _, err := e.Run(ctx, "windows.pslist", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(r evidence.Row) error { identity = r.Cells["Identity"].String(); return nil }}); err != nil {
			t.Fatal(err)
		}
		var rows []evidence.Row
		r, err := e.Run(ctx, "windows.cmdline", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
		if err != nil || r.Task.Rows != 2 || rows[0].Cells["Args"].Reason != "no_process_peb" || rows[0].Cells["Args"].Error != "" {
			t.Fatal(r, rows, err)
		}
		row := rows[1]
		want := `"C:\Windows\worker.exe" --flag sample`
		if row.Verify() != nil || row.Cells["ProcessIdentity"].String() != identity || row.Provenance.Layer != "process:"+identity || row.Cells["Args"].String() != want || row.Cells["ArgsFull"].String() != want || string(row.Cells["ArgsRaw"].Data.([]byte)) != string(commandUTF16(want)) || row.Cells["ReadComplete"].Data != true {
			t.Fatal(row)
		}
		address := "0x1e200"
		if independent {
			address = "0x21e200"
		}
		if row.Provenance.Offset != address {
			t.Fatal("incorrect source buffer", row)
		}
		for _, tc := range []struct {
			pid string
			n   int64
		}{{"104", 1}, {"4,104", 2}, {"999", 0}} {
			r, err := e.Run(ctx, "windows.cmdline", map[string]string{"pid": tc.pid}, engine.RunOptions{})
			if err != nil || r.Task.Rows != tc.n {
				t.Fatal(tc, r, err)
			}
		}
	}
}

func TestCommandLineBytesAndDisplayAnomalies(t *testing.T) {
	for _, tc := range []struct {
		name, args, full, warning string
		raw                       []byte
		capacity                  uint16
	}{{"empty", "", "", "", []byte{}, 0}, {"unicode", "取证🔎", "取证🔎", "", commandUTF16("取证🔎"), 8}, {"embedded-nul", "safe", "safe\x00hidden", "embedded_nul", commandUTF16("safe\x00hidden"), 22}, {"odd-byte", "A�", "A�", "odd_byte_length", []byte{'A', 0, 65}, 4}, {"surrogate", "�x", "�x", "unpaired_surrogate", []byte{0, 0xd8, 'x', 0}, 4}, {"capacity", "x", "x", "length_exceeds_maximum", commandUTF16("x"), 0}, {"bom", "\ufeffx", "\ufeffx", "leading_bom", []byte{255, 254, 'x', 0}, 4}} {
		t.Run(tc.name, func(t *testing.T) {
			f := dllFixture(t, "native")
			editWindowsImage(t, f, func(data []byte) {
				binary.LittleEndian.PutUint16(data[0x1e100:], uint16(len(tc.raw)))
				binary.LittleEndian.PutUint16(data[0x1e102:], tc.capacity)
				if len(tc.raw) == 0 {
					binary.LittleEndian.PutUint64(data[0x1e108:], 0)
				}
				copy(data[0x1e200:], tc.raw)
			})
			e := openWindowsImage(t, f)
			var row evidence.Row
			r, err := e.Run(context.Background(), "windows.cmdline", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if err != nil || r.Task.Rows != 1 || row.Cells["Args"].Kind != "string" || row.Cells["Args"].String() != tc.args || row.Cells["ArgsFull"].String() != tc.full || string(row.Cells["ArgsRaw"].Data.([]byte)) != string(tc.raw) || row.Cells["ReadComplete"].Data != true {
				t.Fatal(r, row, err)
			}
			warnings := row.Cells["Validation"].Data.([]string)
			if tc.warning != "" && !strings.Contains(strings.Join(warnings, ","), tc.warning) || tc.warning == "" && len(warnings) != 0 {
				t.Fatal(warnings)
			}
			b, _ := json.Marshal(row.Cells["ArgsRaw"])
			if tc.name == "empty" && string(b) != `{"kind":"bytes","value":""}` {
				t.Fatal("empty capture became null", string(b))
			}
		})
	}
}

func TestCommandLineFailuresRetainMetadataAndCapturedPrefix(t *testing.T) {
	for _, stage := range []string{"peb", "parameters-pointer", "parameters-null", "parameters", "buffer-null", "buffer-prefix", "root"} {
		t.Run(stage, func(t *testing.T) {
			f := dllFixture(t, "native")
			editWindowsImage(t, f, func(data []byte) {
				put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
				switch stage {
				case "peb":
					put(0x9058, 0x300000)
				case "parameters-pointer":
					put(0x9058, 0x1ffff)
				case "parameters-null":
					put(0x1b010, 0)
				case "parameters":
					put(0x1b010, 0x300000)
				case "buffer-null":
					put(0x1e108, 0)
				case "buffer-prefix":
					put(0x1e108, 0x1fffe)
					binary.LittleEndian.PutUint16(data[0x1e100:], 8)
					binary.LittleEndian.PutUint16(data[0x1fffe:], 'A')
				case "root":
					put(0x9038, 0)
				}
			})
			e := openWindowsImage(t, f)
			var row evidence.Row
			r, err := e.Run(context.Background(), "windows.cmdline", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if r.Task.Rows != 1 || row.Cells["Args"].Kind != "missing" || (err == nil) != (stage == "parameters-null") {
				t.Fatal(r, row, err)
			}
			if stage != "parameters-null" && row.Cells["Args"].Error == "" {
				t.Fatal("read failure lost", row)
			}
			if stage == "buffer-prefix" {
				if row.Cells["Length"].String() != "8" || row.Cells["CapturedBytes"].String() != "2" || row.Cells["ReadComplete"].Data != false || string(row.Cells["ArgsRaw"].Data.([]byte)) != "A\x00" || row.Cells["Args"].Reason != "command_line_buffer_unreadable" {
					t.Fatal("captured prefix lost or became a full string", row)
				}
			}
		})
	}
}

func TestCommandLineIndependentFailuresCancellationAndLimits(t *testing.T) {
	f := dllFixture(t, "native")
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x8058:], 0x1b800)
		binary.LittleEndian.PutUint64(data[0x1b810:], 0x300000)
	})
	e := openWindowsImage(t, f)
	var rows []evidence.Row
	r, err := e.Run(context.Background(), "windows.cmdline", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 2 || rows[0].Cells["Args"].Error == "" || rows[1].Cells["Args"].Kind != "string" {
		t.Fatal(r, rows, err)
	}
	for _, cancel := range []bool{false, true} {
		ctx, stop := context.WithCancel(context.Background())
		output := errors.New("output closed")
		r, err := e.Run(ctx, "windows.cmdline", nil, engine.RunOptions{Fresh: true, Emit: func(row evidence.Row) error {
			if cancel {
				stop()
				return nil
			}
			return output
		}})
		stop()
		want := output
		if cancel {
			want = context.Canceled
		}
		if !errors.Is(err, want) || r.Task.Rows != 1 {
			t.Fatal(r, err)
		}
	}
	if r, err := e.Run(context.Background(), "windows.cmdline", map[string]string{"max-nodes": "1"}, engine.RunOptions{}); err == nil || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	if _, err := e.Run(context.Background(), "windows.cmdline", map[string]string{"pid": "bad"}, engine.RunOptions{}); err == nil {
		t.Fatal("invalid PID accepted")
	}
}

func TestCommandLineX86AndPAEUseTyped32BitUnicodeLayout(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		f := writeWindowsCrash(t, mode, "decoded")
		table, err := symbols.Load(f.Symbols)
		if err != nil {
			t.Fatal(err)
		}
		u := table.Types["_UNICODE_STRING"]
		u.Size = 8
		buffer := u.Fields["Buffer"]
		buffer.Offset = 4
		u.Fields["Buffer"] = buffer
		table.Types["_UNICODE_STRING"] = u
		b, err := table.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(f.Symbols, b, 0600); err != nil {
			t.Fatal(err)
		}
		editWindowsImage(t, f, func(data []byte) {
			physical := data[4096:]
			binary.LittleEndian.PutUint32(physical[0x1e104:], 0x1e200)
		})
		e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, Offline: true})
		if err != nil {
			t.Fatal(err)
		}
		var row evidence.Row
		r, err := e.Run(context.Background(), "windows.cmdline", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
		e.Close()
		if err != nil || r.Task.Rows != 1 || row.Cells["Args"].String() != `"C:\Windows\worker.exe" --flag sample` {
			t.Fatal(mode, r, row, err)
		}
	}
}
