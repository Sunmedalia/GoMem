package disasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCapstonePinnedOracle(t *testing.T) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !Supported() {
		t.Skip("set GOMEM_CAPSTONE_LIBRARY for actual native oracle")
	}
	data, err := os.ReadFile("testdata/capstone-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name, Arch   string
			Address      uint64
			Data         []byte
			Instructions []Instruction
			Text         string
			Consumed     int
			Incomplete   bool
		}
	}
	if err := json.Unmarshal(data, &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Cases) != 270 {
		t.Fatal("incomplete oracle", len(oracle.Cases))
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := Open(context.Background(), library, tc.Arch)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			var got []Instruction
			var text strings.Builder
			consumed := 0
			err = d.Decode(context.Background(), tc.Data, tc.Address, func(i Instruction) error {
				got = append(got, i)
				consumed += len(i.Bytes)
				fmt.Fprintf(&text, "\n%#x:\t%s\t%s", i.Address, i.Mnemonic, i.Operands)
				return nil
			})
			if (err != nil) != tc.Incomplete {
				t.Fatalf("incomplete=%v: %v", tc.Incomplete, err)
			}
			if tc.Incomplete && !strings.Contains(err.Error(), fmt.Sprintf("%#x", tc.Address+uint64(tc.Consumed))) {
				t.Fatal("wrong failure address", err)
			}
			if consumed != tc.Consumed || text.String() != tc.Text || (len(got) != 0 && !reflect.DeepEqual(got, tc.Instructions)) || len(got) != len(tc.Instructions) {
				t.Fatalf("native output differs from actual reference: got=%+v want=%+v", got, tc.Instructions)
			}
		})
	}
}

type testNative struct {
	calls, closed int
	bad           bool
}

func (n *testNative) Next(p []byte, at uint64) (Instruction, error) {
	n.calls++
	b := append([]byte(nil), p[:1]...)
	if n.bad {
		b[0] ^= 1
	}
	return Instruction{Address: at, Bytes: b, Mnemonic: "nop"}, nil
}
func (n *testNative) Close()          { n.closed++ }
func (n *testNative) Version() string { return "test" }
func (n *testNative) Reset() error    { return nil }

func TestCapstoneIndependentThumbStreams(t *testing.T) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !Supported() {
		t.Skip("set GOMEM_CAPSTONE_LIBRARY for native Thumb state tests")
	}
	d, err := Open(context.Background(), library, "thumb")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// A prior stream ends inside an IT block. The next stream must start with
	// fresh state, just like the pinned cs_disasm entry point.
	if err := d.Decode(context.Background(), []byte{0x08, 0xbf}, 0x1000, func(Instruction) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := d.Decode(context.Background(), []byte{0x01, 0x20}, 0x2000, func(i Instruction) error { got = i.Text(); return nil }); err != nil {
		t.Fatal(err)
	}
	if got != "movs r0, #1" {
		t.Fatal("prior IT state leaked into independent stream", got)
	}
}
func TestDecoderCancellationBoundsAndCallbackFailures(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "output", "corrupt", "limit", "overflow", "nested"} {
		t.Run(mode, func(t *testing.T) {
			native := &testNative{}
			d := &Decoder{native: native}
			defer d.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			data := []byte{0x90, 0x90}
			address := uint64(0x1000)
			count := 0
			sentinel := errors.New("output failure")
			switch mode {
			case "corrupt":
				native.bad = true
			case "limit":
				data = make([]byte, MaxInput+1)
			case "overflow":
				address = ^uint64(0)
			}
			err := d.Decode(ctx, data, address, func(inst Instruction) error {
				count++
				switch mode {
				case "cancel":
					cancel()
				case "close":
					d.Close()
				case "output":
					return sentinel
				case "nested":
					return d.Decode(context.Background(), []byte{0x90}, 0x2000, func(Instruction) error {
						t.Fatal("interleaved native stream accepted")
						return nil
					})
				}
				return nil
			})
			if err == nil {
				t.Fatal("failure accepted")
			}
			if count > 1 {
				t.Fatal("continued past callback failure")
			}
			if mode == "output" && !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			d.Close()
			d.Close()
			if native.closed != 1 {
				t.Fatal("native resources closed more than once")
			}
		})
	}
}
func TestCapstoneValidationBeforeLoading(t *testing.T) {
	for _, args := range [][2]string{{"relative", "x64"}, {"/missing", "unknown"}, {"/missing\x00secret", "x64"}} {
		if d, err := Open(context.Background(), args[0], args[1]); err == nil {
			d.Close()
			t.Fatal("invalid input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, "/missing", "x64"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCapstoneActualArchitectures(t *testing.T) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !Supported() {
		t.Skip("set GOMEM_CAPSTONE_LIBRARY for actual native Capstone")
	}
	for _, tc := range []struct {
		arch string
		code []byte
		want []string
	}{{"x86", []byte{0x48, 0x89, 0xd8, 0xc3}, []string{"dec eax", "mov eax, ebx", "ret"}}, {"x64", []byte{0x48, 0x89, 0xd8, 0xc3}, []string{"mov rax, rbx", "ret"}}, {"arm", []byte{0x1e, 0xff, 0x2f, 0xe1}, []string{"bx lr"}}, {"arm64", []byte{0xc0, 0x03, 0x5f, 0xd6}, []string{"ret"}}, {"thumb", []byte{0x70, 0x47}, []string{"bx lr"}}} {
		t.Run(tc.arch, func(t *testing.T) {
			d, err := Open(context.Background(), library, tc.arch)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if !strings.HasPrefix(d.Version(), "5.") {
				t.Fatal(d.Version())
			}
			var got []string
			if err := d.Decode(context.Background(), tc.code, 0x1000, func(i Instruction) error { got = append(got, i.Text()); return nil }); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ";") != strings.Join(tc.want, ";") {
				t.Fatal(got)
			}
		})
	}
	d, err := Open(context.Background(), library, "x64")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	count := 0
	if err := d.Decode(context.Background(), []byte{0x90, 0x0f}, 0x1000, func(i Instruction) error { count++; return nil }); err == nil || count != 1 || !strings.Contains(err.Error(), "0x1001") {
		t.Fatal(count, err)
	}
	if err := d.Decode(context.Background(), nil, 0, func(Instruction) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestCapstoneUnicodeLibraryPath(t *testing.T) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !Supported() {
		t.Skip("set GOMEM_CAPSTONE_LIBRARY for Unicode native library loading")
	}
	source, err := os.Open(library)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "原生 decoder "+filepath.Base(library))
	dest, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(dest, source)
	closeErr := dest.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	d, err := Open(context.Background(), path, "x64")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var text string
	if err := d.Decode(context.Background(), []byte{0x90}, 0x1000, func(i Instruction) error { text = i.Text(); return nil }); err != nil || text != "nop" {
		t.Fatal(text, err)
	}
}
func FuzzCapstoneDecode(f *testing.F) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !Supported() {
		f.Skip("set GOMEM_CAPSTONE_LIBRARY for native decode fuzzing")
	}
	decoders := []*Decoder{}
	for _, arch := range []string{"x86", "x64", "arm", "arm64", "thumb"} {
		d, err := Open(context.Background(), library, arch)
		if err != nil {
			f.Fatal(err)
		}
		defer d.Close()
		decoders = append(decoders, d)
	}
	for _, seed := range [][]byte{{0x90, 0xc3}, {0x0f}, {0xc0, 0x03, 0x5f, 0xd6}, {0x70, 0x47}, {0xc5, 0xf8, 0x77}} {
		f.Add(seed, uint8(1))
	}
	f.Fuzz(func(t *testing.T, data []byte, mode uint8) {
		if len(data) > MaxInput {
			return
		}
		offset := 0
		err := decoders[int(mode)%len(decoders)].Decode(context.Background(), data, 0x1000, func(i Instruction) error {
			if len(i.Bytes) == 0 || offset+len(i.Bytes) > len(data) || i.Address != 0x1000+uint64(offset) {
				t.Fatal("invalid native instruction boundaries")
			}
			offset += len(i.Bytes)
			return nil
		})
		if err == nil && offset != len(data) {
			t.Fatal("unreported undecoded bytes")
		}
	})
}
