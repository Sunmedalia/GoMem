package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type bashTestLayer struct {
	capabilityLayer
	spans []memory.Range
	fault func([]byte, uint64) (int, error)
}

func (b bashTestLayer) Ranges() []memory.Range { return b.spans }
func (b bashTestLayer) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if b.fault != nil {
		return b.fault(p, a)
	}
	return b.capabilityLayer.ReadAt(ctx, p, a)
}

func TestBashARM64HeapMappings(t *testing.T) {
	data := make(capabilityLayer, 0x8000)
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(data[at:], value) }
	put(0x1000, 0x2003)
	put(0x2000, 0x3003)
	put(0x3000, 0x4003)
	put(0x4008, 0x5003)
	put(0x4010, 0x6003)
	put(0x4020, 0x7003)
	tr, err := memory.NewARM64(data, 0x1000, 8)
	if err != nil {
		t.Fatal(err)
	}
	regions := []linuxELFRegion{{1, 0x1000, 0x5000}}
	got, err := linuxBashMappings(context.Background(), tr, regions, 0x1800, 0x2800, 0x4000)
	want := []memory.Range{{Start: 0x1000, Length: 0x2000}, {Start: 0x4000, Length: 0x1000}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	if _, err := linuxBashMappings(context.Background(), tr, regions, 0x1800, 0x2800, 0x3fff); err == nil {
		t.Fatal("heap limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := linuxBashMappings(ctx, tr, regions, 0x1800, 0x2800, 0x4000); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	broken, _ := memory.NewARM64(data, 0x8000, 8)
	if _, err := linuxBashMappings(context.Background(), broken, regions, 0x1800, 0x2800, 0x4000); err == nil || errors.Is(err, memory.ErrUnmapped) {
		t.Fatal("missing table was treated as an unmapped page", err)
	}
	sparse := bashTestLayer{capabilityLayer: data, fault: func(p []byte, at uint64) (int, error) {
		return 0, &memory.ReadError{Address: at, Length: len(p), Layer: "sparse", Cause: memory.ErrUnmapped}
	}}
	broken, _ = memory.NewARM64(sparse, 0x1000, 8)
	if _, err := linuxBashMappings(context.Background(), broken, regions, 0x1800, 0x2800, 0x4000); err == nil {
		t.Fatal("missing physical table page was treated as an unmapped virtual page")
	}
}

func TestBashHeapVMASelectionAndCoverage(t *testing.T) {
	regions := []linuxELFRegion{{1, 0x1000, 0x3000}, {2, 0x3000, 0x4000}, {3, 0x5000, 0x6000}}
	// One mapped run crosses the heap, an adjacent VMA and a VMA gap.
	ranges, selected, resident, err := linuxBashRanges(regions, []memory.Range{{Start: 0, Length: 0x5800}}, 0x1800, 0x2800, 0x2000)
	if err != nil || selected != 0x2000 || resident != 0x2000 || !reflect.DeepEqual(ranges, []memory.Range{{Start: 0x1000, Length: 0x2000}}) {
		t.Fatal(ranges, selected, resident, err)
	}
	// The fixed heap filter includes the whole VMA even when only its boundary
	// equals a break, and reports every byte omitted by missing mappings.
	ranges, selected, resident, err = linuxBashRanges(regions, []memory.Range{{Start: 0x1800, Length: 0x800}}, 0x3000, 0x3000, 0x3000)
	if err != nil || selected != 0x3000 || resident != 0x800 || len(ranges) != 1 {
		t.Fatal(ranges, selected, resident, err)
	}
	if _, _, _, err = linuxBashRanges(regions, nil, 0x1800, 0x2800, 0x1fff); err == nil {
		t.Fatal("heap limit ignored")
	}
}

func TestBashUnalignedPointersBatchesAndStableOrder(t *testing.T) {
	for _, width := range []int{4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			const chunk = 1 << 20
			data := make(capabilityLayer, 2*chunk)
			// More than one batch of hash markers. Equal-time entries have marker
			// addresses in reverse order, so per-batch emission would be incorrect.
			copy(data[0x4000:], bytes.Repeat([]byte{'#'}, 4097))
			put := func(at, value uint64) {
				if width == 4 {
					binary.LittleEndian.PutUint32(data[at:], uint32(value))
				} else {
					binary.LittleEndian.PutUint64(data[at:], value)
				}
			}
			entries := []uint64{0x101, chunk - uint64(width) - 2}
			for i, entry := range entries {
				marker := uint64(0x180000 - i*0x10000)
				command := uint64(0x190000 + i*0x1000)
				copy(data[marker:], "#1403606200\x00")
				copy(data[command:], fmt.Sprintf("command-%d\x00", i))
				put(entry, command)
				put(entry+uint64(width), marker)
			}
			layer := bashTestLayer{capabilityLayer: data, spans: []memory.Range{{Start: 0, Length: chunk}, {Start: chunk, Length: chunk}}}
			diagnostics := 0
			found, err := linuxBashScan(context.Background(), layer, layer, width, 10, func(h bashHistory, err error) error { diagnostics++; return err })
			if err != nil || len(found) != 2 || diagnostics != 0 {
				t.Fatal(found, diagnostics, err)
			}
			for i, h := range found {
				if h.entry != entries[i] || h.command != fmt.Sprintf("command-%d", i) || h.stamp.String() != "2014-06-24T10:36:40Z" || len(h.fields) != 3 {
					t.Fatal(i, h)
				}
			}
			if _, err = linuxBashScan(context.Background(), layer, layer, width, 1, func(h bashHistory, err error) error { return err }); err == nil {
				t.Fatal("entry limit ignored")
			}
		})
	}
}

func TestBashStringErrorsPreserveCapture(t *testing.T) {
	boom := errors.New("read failed")
	for _, mode := range []string{"partial-error", "short-nil", "bad-count", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			layer := bashTestLayer{fault: func(p []byte, a uint64) (int, error) {
				copy(p, "abc")
				switch mode {
				case "partial-error":
					return 3, boom
				case "short-nil":
					return 3, nil
				default:
					return len(p) + 1, nil
				}
			}}
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, capture, err := linuxBashString(ctx, layer, 0x1234, 1024)
			fields := capture.Data.(map[string]evidence.Value)
			if err == nil || fields["ReadComplete"].Data != false || fields["Error"].Error == "" {
				t.Fatal(capture, err)
			}
			got, _ := fields["CapturedBytes"].Uint()
			if (mode == "partial-error" || mode == "short-nil") && (got != 3 || !bytes.Equal(fields["Raw"].Data.([]byte), []byte("abc"))) {
				t.Fatal(capture)
			}
			if mode == "partial-error" && !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
	// A terminator in the last bytes of a page does not require the next page.
	data := make(capabilityLayer, 4096)
	copy(data[4092:], "ok\x00")
	text, capture, err := linuxBashString(context.Background(), bashTestLayer{capabilityLayer: data}, 4092, 1024)
	if err != nil || text != "ok" || capture.Data.(map[string]evidence.Value)["ReadComplete"].Data != true {
		t.Fatal(text, capture, err)
	}
	// Partial hist_entry pointer reads remain evidence, rather than invalid entries.
	h, valid, err := linuxBashEntry(context.Background(), bashTestLayer{capabilityLayer: data}, 4090, 8)
	if err == nil || valid || h.fields["EntryPointers"].Data.(map[string]evidence.Value)["ReadComplete"].Data != false {
		t.Fatal(h, valid, err)
	}
}

func TestBashCandidateReadErrorAndDiagnosticEmitter(t *testing.T) {
	data := make(capabilityLayer, 4096)
	binary.LittleEndian.PutUint64(data[0x100:], 0x2000) // missing command
	binary.LittleEndian.PutUint64(data[0x108:], 0x200)
	copy(data[0x200:], "#1403606200\x00")
	layer := bashTestLayer{capabilityLayer: data, spans: []memory.Range{{Start: 0, Length: 4096}}}
	outputErr := errors.New("stop output")
	calls := 0
	_, err := linuxBashScan(context.Background(), layer, layer, 8, 10, func(h bashHistory, err error) error {
		calls++
		if !errors.Is(err, io.EOF) || h.fields["Line"].Data.(map[string]evidence.Value)["ReadComplete"].Data != false {
			t.Fatal(h, err)
		}
		return outputErr
	})
	if !errors.Is(err, outputErr) || calls != 1 {
		t.Fatal(calls, err)
	}
}

func TestBashTimestampAndInvalidEntries(t *testing.T) {
	for _, test := range []struct {
		stamp, want string
		valid       bool
	}{
		{"#1403606200", "1403606200", true}, {"#-000000001", "-1", true},
		{"# +1_403_606_200 ", "1403606200", true}, {"#000000000", "0", true},
		{"#999999999999999999999999999999", "999999999999999999999999999999", true},
		{"#12345678", "", false}, {"#1__403606200", "", false}, {"#1403606200_", "", false}, {"#not-a-time", "", false},
	} {
		got, valid := linuxBashSeconds(test.stamp)
		if valid != test.valid || valid && got.String() != test.want {
			t.Fatal(test, got, valid)
		}
		data := make(capabilityLayer, 4096)
		binary.LittleEndian.PutUint64(data[0x100:], 0x300)
		binary.LittleEndian.PutUint64(data[0x108:], 0x200)
		copy(data[0x200:], test.stamp+"\x00")
		copy(data[0x300:], "cmd\x00")
		h, ok, err := linuxBashEntry(context.Background(), data, 0x100, 8)
		if err != nil || ok != test.valid {
			t.Fatal(test, h, ok, err)
		}
		if ok && (test.want == "-1" || test.want == "0" || len(test.want) > 12) && h.stamp.Kind != "missing" {
			t.Fatal("invalid datetime rendered", h)
		}
		data[0x300] = 0
		if _, ok, err = linuxBashEntry(context.Background(), data, 0x100, 8); ok || err != nil {
			t.Fatal("empty command accepted", ok, err)
		}
	}
}
