package object_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type viewOracleCase struct {
	Width            int
	Endian, Scenario string
	ISF              json.RawMessage
	Physical, Native string
	Operations       map[string]struct {
		Value json.RawMessage
		Error string
	}
}

func viewFixture(t *testing.T, c viewOracleCase) (object.View, *object.Reader, memory.MemoryLayer) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	layers := make([]memory.MemoryLayer, 2)
	for i, encoded := range []string{c.Physical, c.Native} {
		data, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "bytes")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := memory.OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { source.Close() })
		layers[i], err = memory.NewMapped(source, []string{"physical", "kernel"}[i], []memory.Range{{Length: uint64(len(data))}})
		if err != nil {
			t.Fatal(err)
		}
	}
	v, err := object.NewView(layers[0], layers[1], table, 0x40, "root")
	if err != nil {
		t.Fatal(err)
	}
	return v, &object.Reader{Layer: layers[0], Symbols: table}, layers[1]
}

func viewCases(t *testing.T) []viewOracleCase {
	t.Helper()
	data, err := os.ReadFile("testdata/view-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []viewOracleCase
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 16 {
		t.Fatal("wrong object oracle")
	}
	return fixture.Cases
}

func describeView(ctx context.Context, v object.View, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	value, err := v.Uint(ctx, "value")
	if err != nil {
		return nil, err
	}
	return map[string]any{"address": v.Address(), "layer": v.Layer().Name(), "native": v.NativeLayer().Name(), "value": value}, nil
}

func TestViewPinnedDataAndNativeLayers(t *testing.T) {
	ctx := context.Background()
	for _, c := range viewCases(t) {
		t.Run(fmt.Sprintf("%d/%s/%s", c.Width, c.Endian, c.Scenario), func(t *testing.T) {
			v, reader, native := viewFixture(t, c)
			operations := map[string]func() (any, error){
				"file-socket": func() (any, error) {
					file, err := object.NewView(reader.Layer, native, reader.Symbols, 0x100, "file")
					if err != nil {
						return nil, err
					}
					dentry, err := file.Dereference(ctx, "f_path.dentry")
					if err != nil {
						return nil, err
					}
					inode, err := dentry.Dereference(ctx, "d_inode")
					if err != nil {
						return nil, err
					}
					allocation, err := inode.Container("socket_alloc", "vfs_inode")
					if err != nil {
						return nil, err
					}
					socket, err := allocation.Embedded("socket")
					if err != nil {
						return nil, err
					}
					sock, err := socket.Dereference(ctx, "sk")
					return describeView(ctx, sock, err)
				},
				"root":     func() (any, error) { return describeView(ctx, v, nil) },
				"cast":     func() (any, error) { v, err := v.Cast("leaf"); return describeView(ctx, v, err) },
				"embedded": func() (any, error) { v, err := v.Embedded("embedded"); return describeView(ctx, v, err) },
				"embedded-peer": func() (any, error) {
					e, err := v.Embedded("embedded")
					if err != nil {
						return nil, err
					}
					p, err := e.Dereference(ctx, "peer")
					return describeView(ctx, p, err)
				},
				"peer": func() (any, error) { p, err := v.Dereference(ctx, "peer"); return describeView(ctx, p, err) },
				"peer-peer": func() (any, error) {
					p, err := v.Dereference(ctx, "peer")
					if err != nil {
						return nil, err
					}
					p, err = p.Dereference(ctx, "peer")
					return describeView(ctx, p, err)
				},
				"signed": func() (any, error) { return v.Int(ctx, "signed") },
				"enum": func() (any, error) {
					raw, names, err := v.Enum(ctx, "state")
					if err == nil && !reflect.DeepEqual(names, []string{"READY"}) {
						t.Fatal(names)
					}
					return raw, err
				},
				"string": func() (any, error) { return v.String(ctx, "name", 8) },
			}
			if len(operations) != len(c.Operations) {
				t.Fatal("oracle operation set differs")
			}
			for name, fn := range operations {
				want, ok := c.Operations[name]
				if !ok {
					t.Fatalf("missing upstream operation %s", name)
				}
				got, err := fn()
				if want.Error != "" {
					if err == nil {
						t.Fatalf("%s: wanted %s, got %v", name, want.Error, got)
					}
					if want.Error == "null" && !errors.Is(err, object.ErrNullPointer) {
						t.Fatal(err)
					}
					if want.Error == "read" && errors.Is(err, object.ErrNullPointer) {
						t.Fatal(err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				encoded, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				var actual, expected any
				json.Unmarshal(encoded, &actual)
				json.Unmarshal(want.Value, &expected)
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("%s: %s != %s", name, encoded, want.Value)
				}
			}
			if c.Scenario != "truncated-pointer" {
				e, err := v.Embedded("embedded")
				if err != nil {
					t.Fatal(err)
				}
				root, err := e.Container("root", "embedded")
				if err != nil || root.Address() != v.Address() || root.Layer() != v.Layer() || root.NativeLayer() != v.NativeLayer() {
					t.Fatal(root, err)
				}
				p, err := root.Dereference(ctx, "embedded.peer")
				if err != nil {
					t.Fatal(err)
				}
				value, err := p.Uint(ctx, "value")
				if err != nil || value != 2 {
					t.Fatal(value, err)
				}
			}
		})
	}
}

func TestViewRejectsInvalidTransitionsAndRanges(t *testing.T) {
	ctx := context.Background()
	v, r, native := viewFixture(t, viewCases(t)[0])
	for _, fn := range []func() error{
		func() error { _, err := object.NewView(nil, native, r.Symbols, 0, "root"); return err },
		func() error { _, err := object.NewView(r.Layer, native, nil, 0, "root"); return err },
		func() error {
			_, err := object.NewView(r.Layer, native, r.Symbols, math.MaxUint64-62, "root")
			return err
		},
		func() error { _, err := v.Cast("u32"); return err },
		func() error { _, err := v.Cast("missing"); return err },
		func() error { _, err := v.Embedded("peer"); return err },
		func() error { _, err := v.Embedded("value"); return err },
		func() error { _, err := v.Dereference(ctx, "embedded"); return err },
		func() error { _, err := v.Dereference(ctx, "peer.value"); return err },
		func() error { _, err := v.Container("root", "embedded"); return err },
		func() error { _, err := v.Bytes(ctx, "name", 9); return err },
		func() error { _, err := v.Bytes(ctx, "name", -1); return err },
		func() error {
			x, err := v.Cast("leaf")
			if err != nil {
				return err
			}
			_, err = x.Container("root", "peer")
			return err
		},
		func() error {
			x, err := object.NewView(r.Layer, native, r.Symbols, 0, "leaf")
			if err != nil {
				return err
			}
			_, err = x.Container("root", "embedded")
			return err
		},
		func() error {
			x, err := object.NewView(r.Layer, nil, r.Symbols, v.Address(), "root")
			if err != nil {
				return err
			}
			_, err = x.Dereference(ctx, "peer")
			return err
		},
	} {
		if err := fn(); err == nil {
			t.Fatal("invalid view operation succeeded")
		}
	}
	b, err := v.Bytes(ctx, "name", 8)
	if err != nil || string(b) != "root\x00\x00\x00\x00" {
		t.Fatal(b, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = v.Dereference(cancelled, "peer"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = v.Uint(cancelled, "value"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = v.Bytes(cancelled, "name", 4); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var zero object.View
	if _, err = zero.Uint(ctx, "value"); err == nil {
		t.Fatal("zero view read")
	}
	if _, err = zero.Cast("root"); err == nil {
		t.Fatal("zero view cast")
	}
	if _, err = zero.Dereference(ctx, "peer"); err == nil {
		t.Fatal("zero view dereference")
	}
}

// A short read without an error still must not produce a scalar or pointer.
type shortViewLayer struct{ memory.MemoryLayer }

func (s shortViewLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}

func TestViewShortReadsAndPointerBase(t *testing.T) {
	v, r, native := viewFixture(t, viewCases(t)[0])
	ctx := context.Background()
	short, err := object.NewView(shortViewLayer{r.Layer}, native, r.Symbols, v.Address(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = short.Uint(ctx, "value"); err == nil {
		t.Fatal("short scalar became zero")
	}
	if _, err = short.Dereference(ctx, "peer"); err == nil || errors.Is(err, object.ErrNullPointer) {
		t.Fatal("short pointer became null", err)
	}
	if _, err = short.Bytes(ctx, "name", 8); err == nil {
		t.Fatal("short bytes succeeded")
	}
	// A 32-bit pointer declaration inside a 64-bit table controls the read width.
	// The following four bytes are deliberately nonzero and cannot be included.
	table := r.Symbols.(*symbols.ISF)
	p := table.Bases["pointer"]
	p.Size = 8
	table.Bases["pointer"] = p
	table.Bases["ptr32"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
	root := table.Types["root"]
	peer := root.Fields["peer"]
	peer.Type.Base = "ptr32"
	root.Fields["peer"] = peer
	table.Types["root"] = root
	data, err := hex.DecodeString(viewCases(t)[0].Physical)
	if err != nil {
		t.Fatal(err)
	}
	copy(data[0x4c:0x50], []byte{0xff, 0xff, 0xff, 0xff})
	v, err = object.NewView(listBytes(data), native, table, 0x40, "root")
	if err != nil {
		t.Fatal(err)
	}
	peerView, err := v.Dereference(ctx, "peer")
	if err != nil || peerView.Address() != 0x80 {
		t.Fatal(peerView, err)
	}
	value, err := peerView.Uint(ctx, "value")
	if err != nil || value != 2 {
		t.Fatal(value, err)
	}
}

func FuzzViewDataAndNativeLayers(f *testing.F) {
	encoded, err := os.ReadFile("testdata/view-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct{ Cases []viewOracleCase }
	if err = json.Unmarshal(encoded, &fixture); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0}, uint64(0x40), uint8(0), uint8(0))
	f.Add([]byte{0xff, 0xff}, uint64(math.MaxUint64), uint8(4), uint8(1))
	f.Add([]byte{0xc0}, uint64(0x40), uint8(8), uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, address uint64, caseIndex, operation uint8) {
		if len(payload) > 128 {
			return
		}
		c := fixture.Cases[int(caseIndex)%len(fixture.Cases)]
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		physical, _ := hex.DecodeString(c.Physical)
		native, _ := hex.DecodeString(c.Native)
		copy(physical[0x48:], payload)
		// Correct native contents deliberately differ from physical contents.
		copy(native[0x80:], payload)
		physicalLayer, nativeLayer := listBytes(physical), listBytes(native)
		v, err := object.NewView(physicalLayer, nativeLayer, table, address, "root")
		if err != nil {
			return
		}
		ctx := context.Background()
		switch operation % 4 {
		case 0:
			_, _ = v.Uint(ctx, "peer")
			_, _ = v.Bytes(ctx, "name", len(payload))
		case 1:
			embedded, err := v.Embedded("embedded")
			if err != nil {
				return
			}
			parent, err := embedded.Container("root", "embedded")
			if err != nil || parent.Address() != v.Address() {
				t.Fatal("container lost address", err)
			}
		case 2, 3:
			for step := 0; step < 3; step++ {
				v, err = v.Dereference(ctx, "peer")
				if err != nil {
					return
				}
				// Every successful hop switches to native data, even if the
				// target numerical address also happens to exist physically.
				got, readErr := v.Uint(ctx, "value")
				expected, expectedErr := (&object.Reader{Layer: nativeLayer, Symbols: table}).Uint(ctx, v.Address(), "leaf", "value")
				if (readErr == nil) != (expectedErr == nil) || readErr == nil && got != expected {
					t.Fatal("pointer read escaped native layer")
				}
			}
		}
	})
}
