package plugins

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type rangeScanSource []byte

func (s rangeScanSource) Name() string { return "ranges-fixture" }
func (s rangeScanSource) Size() uint64 { return uint64(len(s)) }
func (s rangeScanSource) Close() error { return nil }
func (s rangeScanSource) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a > uint64(len(s)) {
		return 0, io.EOF
	}
	n := copy(p, s[a:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func TestScansCarryAcrossAdjacentRecordsButNotHoles(t *testing.T) {
	banner := []byte("Linux version 6.8.11-fixture (test) #1 SMP\x00")
	cv := make([]byte, 24)
	copy(cv, "RSDS")
	binary.LittleEndian.PutUint32(cv[20:], 1)
	cv = append(cv, []byte("ntkrnlmp.pdb\x00")...)
	for _, tc := range []struct {
		name  string
		data  []byte
		split int
	}{{"linux-banner", banner, 16}, {"pdb-name", cv, 28}, {"pdb-signature", cv, 2}} {
		for _, gap := range []uint64{0, 4096} {
			// Separate source bytes with unrelated stored padding. Physical
			// contiguity, not a container's file layout, controls scan carry.
			data := append(append(append([]byte(nil), tc.data[:tc.split]...), 1, 2, 3), tc.data[tc.split:]...)
			ranges := []memory.Range{{Start: 0x1000, Length: uint64(tc.split)}, {Start: 0x1000 + uint64(tc.split) + gap, Length: uint64(len(tc.data) - tc.split), FileOffset: uint64(tc.split + 3)}}
			layer, err := memory.NewMapped(rangeScanSource(data), "test", ranges)
			if err != nil {
				t.Fatal(err)
			}
			var rows []evidence.Row
			if err = banners(context.Background(), plugin.Environment{Physical: layer}, nil, func(r evidence.Row) error { rows = append(rows, r); return nil }); err != nil {
				t.Fatal(err)
			}
			want := 1
			if gap != 0 {
				want = 0
			}
			if len(rows) != want {
				t.Fatal(tc.name, gap, rows)
			}
			if want == 1 && (rows[0].Provenance.Offset != "0x1000" || tc.name == "linux-banner" && rows[0].Cells["Banner"].String() != string(banner[:len(banner)-1]) || tc.name != "linux-banner" && !strings.HasPrefix(rows[0].Cells["Banner"].String(), "ntkrnlmp.pdb|")) {
				t.Fatal(tc.name, rows)
			}
		}
	}
}
