package engine

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type peFuzzLayer []byte

func (l peFuzzLayer) Name() string           { return "mapped-pe-fuzz" }
func (l peFuzzLayer) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(l))}} }
func (l peFuzzLayer) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if address > uint64(len(l)) {
		return 0, io.EOF
	}
	n := copy(p, l[address:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func FuzzMappedPE(f *testing.F) {
	fixture, err := testfixture.Write(f.TempDir(), "windows")
	if err != nil {
		f.Fatal(err)
	}
	data, err := os.ReadFile(fixture.Image)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data[0x4000:0x5000])
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		image, err := readKernelPE(context.Background(), peFuzzLayer(data), 0)
		if err == nil && (image.Identity.Database == "" || image.Size == 0) {
			t.Fatal("incomplete PE accepted")
		}
	})
}
