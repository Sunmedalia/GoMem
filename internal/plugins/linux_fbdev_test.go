package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func fbTestFixture(t testing.TB, width int) (plugin.Environment, flatMemory) {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-fbdev-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Width    int
			Scenario string
			ISF      json.RawMessage
			Writes   [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, c := range oracle.Cases {
		if c.Width != width || c.Scenario != "normal" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		data := make(flatMemory, 0x18000)
		for _, w := range c.Writes {
			var at int
			var s string
			if err = json.Unmarshal(w[0], &at); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &s); err != nil {
				t.Fatal(err)
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[at:], b)
		}
		arch := "x64"
		if width == 4 {
			arch = "x86"
		}
		return plugin.Environment{Kernel: data, Physical: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}, OS: "linux", Architecture: arch}, data
	}
	t.Fatal("fixture missing")
	return plugin.Environment{}, nil
}
func fbTestParams() map[string]string {
	return map[string]string{"dump": "false", "max-framebuffers": "8", "max-bytes": "16384"}
}
func TestLinuxFbdevEveryOutputBoundary(t *testing.T) {
	for _, width := range []int{4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			e, _ := fbTestFixture(t, width)
			total := 0
			if err := linuxFbdev(context.Background(), e, fbTestParams(), func(evidence.Row) error { total++; return nil }); err != nil {
				t.Fatal(err)
			}
			for boundary := 1; boundary <= total; boundary++ {
				stop := errors.New("sink failure")
				calls := 0
				err := linuxFbdev(context.Background(), e, fbTestParams(), func(evidence.Row) error {
					calls++
					if calls == boundary {
						return stop
					}
					return nil
				})
				if !errors.Is(err, stop) || calls != boundary {
					t.Fatal(boundary, calls, err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				calls = 0
				err = linuxFbdev(ctx, e, fbTestParams(), func(evidence.Row) error {
					calls++
					if calls == boundary {
						cancel()
					}
					return nil
				})
				cancel()
				if !errors.Is(err, context.Canceled) || calls != boundary {
					t.Fatal(boundary, calls, err)
				}
			}
		})
	}
}
func TestLinuxFbdevMalformedAndBounds(t *testing.T) {
	for _, name := range []string{"count-bound", "negative-count", "count-hole", "info-hole", "device-hole", "metadata-budget", "source-budget", "source-hole", "invalid-bpp", "huge-dimensions", "color-field", "no-storage", "untyped-count"} {
		t.Run(name, func(t *testing.T) {
			e, data := fbTestFixture(t, 8)
			p := fbTestParams()
			put := func(at int, v uint64, n int) {
				if n == 4 {
					binary.LittleEndian.PutUint32(data[at:], uint32(v))
				} else {
					binary.LittleEndian.PutUint64(data[at:], v)
				}
			}
			switch name {
			case "count-bound":
				p["max-framebuffers"] = "1"
			case "negative-count":
				put(0x10000, 0xffffffff, 4)
			case "count-hole":
				table := e.Symbols.(*symbols.ISF)
				s := table.Symbols["num_registered_fb"]
				s.Address = 0x300000
				table.Symbols["num_registered_fb"] = s
			case "untyped-count":
				table := e.Symbols.(*symbols.ISF)
				s := table.Symbols["num_registered_fb"]
				s.Type = nil
				table.Symbols["num_registered_fb"] = s
			case "info-hole":
				put(0x10010, 0x300000, 8)
			case "device-hole":
				put(0x12000, 0x300000, 8)
			case "metadata-budget":
				p["max-bytes"] = "16"
			case "source-budget":
				p["dump"] = "true"
				put(0x11000+16, 9000, 4)
			case "source-hole":
				p["dump"] = "true"
				put(0x11000+96, 0x300000, 8)
			case "invalid-bpp":
				p["dump"] = "true"
				put(0x11000+40, 7, 4)
			case "huge-dimensions":
				p["dump"] = "true"
				put(0x11000+32, 0xffffffff, 4)
			case "color-field":
				p["dump"] = "true"
				put(0x11000+48+4, 65, 4)
			case "no-storage":
				p["dump"] = "true"
			}
			// The failing sink permits validation before Create, without filesystem writes.
			if name != "no-storage" {
				e.Artifacts = fbTestSink{}
			}
			observed := 0
			err := linuxFbdev(context.Background(), e, p, func(row evidence.Row) error { observed++; return nil })
			if err == nil {
				t.Fatal("missing explicit error", observed)
			}
			expected := map[string]string{"count-bound": "exceeds bound", "negative-count": "exceeds bound", "count-hole": "EOF", "info-hole": "EOF", "device-hole": "EOF", "metadata-budget": "byte budget exhausted", "source-budget": "source size exceeds byte budget", "source-hole": "EOF", "invalid-bpp": "bits per pixel", "huge-dimensions": "decoded dimensions", "color-field": "invalid framebuffer color field", "no-storage": "requires case artifact storage", "untyped-count": "has no type"}[name]
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("expected %q: %v", expected, err)
			}
		})
	}
	for _, key := range []string{"max-framebuffers", "max-bytes"} {
		for _, v := range []string{"0", "-1", "18446744073709551615", "invalid"} {
			e, _ := fbTestFixture(t, 8)
			p := fbTestParams()
			p[key] = v
			if err := linuxFbdev(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(key, v)
			}
		}
	}
}

type fbTestSink struct{ cause error }

func (s fbTestSink) Create(context.Context, evidence.ArtifactRequest) (evidence.ArtifactWriter, error) {
	return nil, fmt.Errorf("test sink: %w", s.cause)
}
func TestLinuxFbdevArtifactFailure(t *testing.T) {
	e, _ := fbTestFixture(t, 8)
	stop := errors.New("disk full")
	e.Artifacts = fbTestSink{stop}
	p := fbTestParams()
	p["dump"] = "true"
	rows := 0
	err := linuxFbdev(context.Background(), e, p, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "framebuffer" {
			rows++
			if row.Cells["Error"].Kind != "missing" || row.Cells["Filename"].Kind != "missing" {
				t.Fatal(row)
			}
		}
		return nil
	})
	if !errors.Is(err, stop) || rows != 2 {
		t.Fatal(err, rows)
	}
}
func FuzzLinuxFramebufferPixels(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, uint8(2), uint8(2), uint8(32), uint8(8), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, x, y, bpp, length, offset uint8) {
		if len(raw) > 4096 {
			return
		}
		fields := [4]fbBitfield{{uint64(offset), uint64(length), 1}, {8, 8, 0}, {0, 8, 0}, {24, 8, 0}}
		img, err := fbPixels(context.Background(), raw, uint64(x), uint64(y), uint64(bpp), 16384, fields)
		if err == nil && len(img.Pix) > 16384 {
			t.Fatal("unbounded pixels")
		}
	})
}

func TestLinuxFbdevPNGOutputBoundsAndCancellation(t *testing.T) {
	b := &fbPNGBuffer{ctx: context.Background(), limit: 2}
	if n, err := b.Write([]byte{1, 2}); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte{3}); n != 0 || err == nil || b.Len() != 2 {
		t.Fatal(n, err, b.Len())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b = &fbPNGBuffer{ctx: ctx, limit: 8}
	if _, err := b.Write([]byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := fbPixels(ctx, []byte{1, 2, 3, 4}, 1, 1, 32, 64, [4]fbBitfield{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func FuzzLinuxFramebufferAcquisition(f *testing.F) {
	e, original := fbTestFixture(f, 8)
	f.Add([]byte{1, 2, 3, 4}, uint8(0))
	f.Add([]byte{255, 255, 255, 255}, uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x10000, 0x10010, 0x11000, 0x12000, 0x14000}[int(region)%5]
		copy(data[at:], payload)
		env := e
		env.Kernel = data
		env.Objects = &object.Reader{Layer: data, Symbols: e.Symbols}
		env.Artifacts = fbTestSink{}
		params := fbTestParams()
		params["max-bytes"] = "4096"
		params["dump"] = "true"
		calls := 0
		_ = linuxFbdev(context.Background(), env, params, func(evidence.Row) error {
			calls++
			if calls > 1000 {
				return errors.New("fuzz output bound")
			}
			return nil
		})
		if calls > 1001 {
			t.Fatal("unbounded output")
		}
	})
}
