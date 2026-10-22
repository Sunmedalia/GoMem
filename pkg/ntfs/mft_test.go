package ntfs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type testMemory []byte

func (m testMemory) Name() string { return "physical" }
func (m testMemory) Ranges() []memory.Range {
	return []memory.Range{{Start: 0, Length: uint64(len(m))}}
}
func (m testMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at > uint64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[at:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func absent(name string) any { return map[string]any{"missing": name} }
func oracleTime(ticks uint64) any {
	seconds := ticks / 10000000
	if seconds == 0 {
		return absent("NotApplicableValue")
	}
	at := time.Unix(int64(seconds)-11644473600, 0).UTC()
	if at.Year() < 1 || at.Year() > 9999 {
		return absent("UnparsableValue")
	}
	return at.Format("2006-01-02T15:04:05-07:00")
}
func oracleRows(r Record, kind string) []any {
	rows := []any{}
	add := func(level int, values []any) { rows = append(rows, map[string]any{"level": level, "values": values}) }
	if kind == "mftscan" {
		for _, a := range r.Attributes {
			if a.Standard != nil {
				s := a.Standard
				v := []any{s.Offset, r.Signature, r.Number, r.Links, r.Type(), absent("NotApplicableValue"), "STANDARD_INFORMATION"}
				for _, stamp := range s.Times {
					v = append(v, oracleTime(stamp))
				}
				v = append(v, absent("NotApplicableValue"))
				add(0, v)
			}
		}
		for _, a := range r.Attributes {
			if a.Filename != nil {
				f := a.Filename
				v := []any{f.Offset, r.Signature, r.Number, r.Links, r.Type(), f.Permissions(), "FILE_NAME"}
				for _, stamp := range f.Times {
					v = append(v, oracleTime(stamp))
				}
				v = append(v, f.Name)
				add(1, v)
			}
		}
	} else {
		for _, a := range r.Attributes {
			if a.Resident == nil || (kind == "ads") != (a.NameLength > 0) {
				continue
			}
			d := a.Resident
			var filename any = r.LongestFilename()
			if filename == "" {
				if kind == "ads" {
					filename = absent("NotAvailableValue")
				} else {
					filename = "N/A"
				}
			}
			v := []any{a.Offset + 24, r.Signature, r.Number, "DATA", filename}
			if kind == "ads" {
				var name any = d.Name
				if name == "" {
					name = absent("NotAvailableValue")
				}
				v = append(v, name)
			}
			var content any = absent("NotAvailableValue")
			if d.ContentError == nil && len(d.Content) > 0 {
				content = map[string]any{"offset": d.Offset, "length": len(d.Content), "raw": hex.EncodeToString(d.Content)}
			}
			add(0, append(v, content))
			if kind == "residentdata" {
				break
			}
		}
	}
	return rows
}
func TestActualMFTGenerators(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/windows-mft-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Name   string
			Size   int
			Writes []struct {
				Offset int
				Data   string
			}
			Expected map[string]struct {
				Rows  []any
				Error any
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 70 {
		t.Fatal("fixture drift")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			data := make(testMemory, c.Size)
			for _, w := range c.Writes {
				p, _ := hex.DecodeString(w.Data)
				copy(data[w.Offset:], p)
			}
			var records []Record
			err := Scan(context.Background(), data, func(at uint64) error {
				r, _ := ReadRecord(context.Background(), data, at, Limits{1024, 64 << 20})
				records = append(records, r)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range c.Expected {
				rows := []any{}
				for _, r := range records {
					rows = append(rows, oracleRows(r, name)...)
				}
				canonical, _ := json.Marshal(rows)
				var got []any
				json.Unmarshal(canonical, &got)
				if want.Error != nil || !reflect.DeepEqual(got, want.Rows) {
					t.Fatalf("%s\ngot %s\nwant %s", name, canonical, mustJSON(want.Rows))
				}
			}
		})
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestReadRecordLimitsCancellationAndOverflow(t *testing.T) {
	for _, limits := range []Limits{{0, 1}, {1, 0}, {1, 47}, {1 << 21, 64 << 20}} {
		if _, err := ReadRecord(context.Background(), testMemory(make([]byte, 256)), 0, limits); err == nil {
			t.Fatal(limits)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadRecord(ctx, testMemory(make([]byte, 256)), 0, Limits{1, 64 << 20}); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := ReadRecord(context.Background(), testMemory{}, ^uint64(0)-1, Limits{1, 64 << 20}); err == nil {
		t.Fatal("overflow")
	}
}
func FuzzMFTRecord(f *testing.F) {
	f.Add([]byte("FILE0"), uint16(0))
	f.Add([]byte("BAAD"), uint16(48))
	f.Fuzz(func(t *testing.T, raw []byte, first uint16) {
		if len(raw) > 1<<20 {
			return
		}
		data := make(testMemory, max(48, len(raw)))
		copy(data, raw)
		data[20] = byte(first)
		data[21] = byte(first >> 8)
		r, _ := ReadRecord(context.Background(), data, 0, Limits{64, 1 << 20})
		if len(r.Attributes) > 64 {
			t.Fatal(fmt.Sprint(len(r.Attributes)))
		}
	})
}
