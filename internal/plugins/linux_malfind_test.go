package plugins

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type malfindReadLayer struct {
	data []byte
	hole uint64
}

func (v malfindReadLayer) Name() string           { return "malfind-read-fixture" }
func (v malfindReadLayer) Ranges() []memory.Range { return nil }
func (v malfindReadLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at >= v.hole && at < v.hole+4096 {
		return 0, io.ErrUnexpectedEOF
	}
	if at >= uint64(len(v.data)) {
		return 0, io.EOF
	}
	n := copy(p, v.data[at:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func TestMalfindPaddedDisplayRetainsLaterPages(t *testing.T) {
	data := bytes.Repeat([]byte{0x90}, 4*4096)
	layer := malfindReadLayer{data, 4096}
	actual, proof, err := linuxMalfindData(context.Background(), layer, 4094, 4100)
	if err == nil || len(actual) != 4100 || !bytes.Equal(actual[:2], []byte{0x90, 0x90}) || !bytes.Equal(actual[2:4098], make([]byte, 4096)) || !bytes.Equal(actual[4098:], []byte{0x90, 0x90}) {
		t.Fatal(err, len(actual))
	}
	fields := proof.Data.(map[string]evidence.Value)
	if fields["ReadComplete"].Data != false || len(fields) != 7 {
		t.Fatal(fields)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = linuxMalfindData(ctx, layer, 0, 64)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMalfindNativeDisassemblyBounds(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		text, proof := linuxMalfindDisassembly([]byte{0xb8, 1, 0, 0, 0, 0xc3}, 0x400000, arch)
		fields := proof.Data.(map[string]evidence.Value)
		if text.String() == "" || fields["DecodedBytes"].String() != "6" || fields["Complete"].Data != true {
			t.Fatal(text, proof)
		}
	}
	_, proof := linuxMalfindDisassembly(bytes.Repeat([]byte{0x90}, 10000), 0, "x64")
	fields := proof.Data.(map[string]evidence.Value)
	if fields["DecodedBytes"].String() != "4096" || fields["Complete"].Data != false {
		t.Fatal(proof)
	}
	_, proof = linuxMalfindDisassembly([]byte{0xe8}, 0, "x64")
	fields = proof.Data.(map[string]evidence.Value)
	if fields["DecodedBytes"].String() != "0" || fields["Complete"].Data != false {
		t.Fatal(proof)
	}
}

func FuzzLinuxMalfindDisassembly(f *testing.F) {
	f.Add([]byte{0x90, 0xc3}, uint64(0x400000), true)
	f.Add([]byte{0x0f, 0xff, 0xe8}, ^uint64(0), false)
	f.Fuzz(func(t *testing.T, data []byte, at uint64, x64 bool) {
		if len(data) > 131072 {
			return
		}
		arch := "x86"
		if x64 {
			arch = "x64"
		}
		_, proof := linuxMalfindDisassembly(data, at, arch)
		fields := proof.Data.(map[string]evidence.Value)
		decoded, err := fields["DecodedBytes"].Uint()
		if err != nil || decoded > uint64(len(data)) {
			t.Fatal(proof, err)
		}
		instructions := fields["Instructions"].Data.(map[string]evidence.Value)
		if len(instructions) > 4096 {
			t.Fatal("unbounded decoded output")
		}
	})
}
