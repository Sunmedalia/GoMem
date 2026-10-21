package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func libraryEngine(t *testing.T, arch, layout, fault string) *engine.Engine {
	width := uint64(8)
	if arch != "x64" {
		width = 4
	}
	return malfindEngine(t, arch, layout, "", func(data []byte) {
		put := func(at, n uint64) {
			if width == 4 {
				binary.LittleEndian.PutUint32(data[at:], uint32(n))
			} else {
				binary.LittleEndian.PutUint64(data[at:], n)
			}
		}
		header := func(at uint64) {
			clear(data[at : at+128])
			copy(data[at:], "\x7fELF")
			data[at+4] = 2
			if width == 4 {
				data[at+4] = 1
			}
			data[at+5] = 1
			data[at+6] = 1
			binary.LittleEndian.PutUint16(data[at+16:], 2)
			if width == 8 {
				put(at+32, 64)
				binary.LittleEndian.PutUint16(data[at+56:], 1)
				binary.LittleEndian.PutUint32(data[at+64:], 2)
				put(at+80, 0x400800)
			} else {
				put(at+28, 52)
				binary.LittleEndian.PutUint16(data[at+44:], 1)
				binary.LittleEndian.PutUint32(data[at+52:], 2)
				put(at+60, 0x400800)
			}
		}
		header(0x24000)
		header(0x28000)
		clear(data[0x24800:0x25000])
		put(0x24800, 3)
		put(0x24800+width, 0x400900)
		put(0x24900+width, 0x400a00)
		put(0x24a00, 0x700000)
		put(0x24a00+width, 0x400c00)
		put(0x24a00+width*3, 0x400a40)
		put(0x24a40, 0x800000)
		put(0x24a40+width, 0x400d00)
		copy(data[0x24c00:], "/lib/one.so\x00")
		copy(data[0x24d00:], "/lib/two.so\x00")
		switch fault {
		case "name-hole":
			put(0x24a00+width, 0x600000)
		case "cycle":
			put(0x24a40+width*3, 0x400a00)
		case "signature-hole":
			put(0x20000, 0)
		case "class":
			data[0x24004] = 9
			data[0x28004] = 9
		}
	})
}
func TestLinuxLibraryListNativePagingLayoutsCacheAndSeals(t *testing.T) {
	for _, tc := range []struct{ arch, layout string }{{"x64", "list"}, {"x64", "dense"}, {"x64", "range"}, {"x86", "list"}, {"pae", "list"}} {
		t.Run(tc.arch+"/"+tc.layout, func(t *testing.T) {
			e := libraryEngine(t, tc.arch, tc.layout, "")
			var fresh, cached bytes.Buffer
			libraries, scans := 0, 0
			result, err := e.Run(context.Background(), "linux.library_list", map[string]string{"pids": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Verify() != nil {
					t.Fatal("unsealed evidence")
				}
				if row.Cells["RecordType"].String() == "library" {
					libraries++
					if row.Provenance.Layer != row.Cells["ProcessLayer"].String() || row.Cells["FieldEvidence"].Kind != "structure" {
						t.Fatal(row)
					}
				} else if row.Cells["RecordType"].String() == "library_scan" {
					scans++
				} else {
					t.Fatal(row)
				}
				return json.NewEncoder(&fresh).Encode(row)
			}})
			if err != nil || result.Task.State != "completed" || libraries != 2 || scans != 4 {
				t.Fatal(result, err, libraries, scans)
			}
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(rows) != 6 {
				t.Fatal(rows, err)
			}
			for _, r := range rows {
				if err := r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			again, err := e.Run(context.Background(), "linux.library_list", map[string]string{"pids": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
			if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
				t.Fatal(again, err)
			}
		})
	}
}
func TestLinuxLibraryListFailuresPreserveAvailableLibraries(t *testing.T) {
	for _, fault := range []string{"name-hole", "cycle", "signature-hole", "class"} {
		t.Run(fault, func(t *testing.T) {
			e := libraryEngine(t, "x64", "list", fault)
			var first, second bytes.Buffer
			valid, failures := 0, 0
			run := func(buffer *bytes.Buffer) engine.RunOptions {
				return engine.RunOptions{Emit: func(r evidence.Row) error {
					if r.Cells["RecordType"].String() == "library" {
						valid++
					}
					if r.Cells["Error"].Error != "" {
						failures++
					}
					return json.NewEncoder(buffer).Encode(r)
				}}
			}
			res, err := e.Run(context.Background(), "linux.library_list", map[string]string{"pids": "100"}, run(&first))
			want := 2
			if fault == "name-hole" {
				want = 1
			}
			if fault == "class" || fault == "signature-hole" {
				want = 0
			}
			if err == nil || res.Task.State != "failed" || valid != want || failures == 0 {
				t.Fatal(res, err, valid, failures)
			}
			res, err = e.Run(context.Background(), "linux.library_list", map[string]string{"pids": "100"}, run(&second))
			if err == nil || res.Reused || !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatal(res, err)
			}
		})
	}
}
func TestLinuxLibraryListLimitsFilteringAndOutputFailure(t *testing.T) {
	e := libraryEngine(t, "x64", "list", "")
	ctx := context.Background()
	for _, p := range []map[string]string{{"pids": "bad"}, {"max-regions": "0"}, {"max-link-maps": "1000001"}, {"max-link-maps": "1"}, {"max-regions": "1"}} {
		result, err := e.Run(ctx, "linux.library_list", p, engine.RunOptions{})
		if err == nil || result.Task.State == "completed" {
			t.Fatal(p, result, err)
		}
	}
	result, err := e.Run(ctx, "linux.library_list", map[string]string{"pids": "999"}, engine.RunOptions{})
	if err != nil || result.Task.Rows != 0 {
		t.Fatal(result, err)
	}
	sentinel := fmt.Errorf("stop emitter")
	calls := 0
	_, err = e.Run(ctx, "linux.library_list", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return sentinel }})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(calls, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	calls = 0
	_, err = e.Run(ctx, "linux.library_list", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(calls, err)
	}
}
