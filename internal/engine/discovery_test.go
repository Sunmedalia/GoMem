package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

func TestLinuxRootDiscoveryVerifiesCopiesAndSharesCache(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	// A duplicate banner without a working page table is insufficient proof.
	copy(data[0x18000:0x18100], data[0x8000:0x8100])
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := engine.Config{Image: f.Image, Symbols: f.Symbols, CaseDir: t.TempDir(), Offline: true}
	e, err := engine.Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if e.Config.DTB != "0x1000" || e.Discovery == nil || e.Discovery.BannerPhysical != "0x8000" || e.Discovery.PGDSymbol != "init_top_pgt" {
		t.Fatal(e.Config, e.Discovery)
	}
	result, err := e.Run(ctx, "linux.pslist", nil, engine.RunOptions{})
	if err != nil || result.Task.Rows != 2 {
		t.Fatal(result, err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	c.DTB = "4096" // normalized to the same address as the discovered root
	e, err = engine.Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	result, err = e.Run(ctx, "linux.pslist", nil, engine.RunOptions{})
	if err != nil || !result.Reused || e.Discovery != nil {
		t.Fatal("explicit roots must override discovery and share the normalized cache", result, err)
	}
}

func TestLinuxRootDiscoveryRejectsCorruptionSlideAndAmbiguity(t *testing.T) {
	for _, scenario := range []string{"corrupt", "slide", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), "linux")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			c := engine.Config{Image: f.Image, Symbols: f.Symbols}
			want := "no page table passed"
			switch scenario {
			case "corrupt":
				clear(data[0x1000:0x2000])
			case "slide":
				c.KernelSlide = 0x200000
			case "ambiguous":
				want = "ambiguous"
				// A second root maps a second banner copy and its own virtual
				// PGD address correctly, so neither root may be chosen silently.
				copy(data[0x18000:0x18100], data[0x8000:0x8100])
				put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
				put(0x11000, 0x12003)
				put(0x12000, 0x13003)
				put(0x13000, 0x14003)
				for i := uint64(0); i < 512; i++ {
					put(0x14000+i*8, 0x10000+i*4096|3)
				}
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), c)
			if e != nil {
				e.Close()
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("expected", want, "got", err)
			}
		})
	}
}

func TestLinuxRootDiscoveryWithExplicitVirtualSlide(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	// Map the same physical kernel at virtual +2 MiB. Physical relocation
	// is derived independently from the observed banner and symbol distances.
	binary.LittleEndian.PutUint64(data[0x3000:], 0)
	binary.LittleEndian.PutUint64(data[0x3008:], 0x83)
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, KernelSlide: 0x200000})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Discovery == nil || e.Discovery.PGDVirtual != "0x201000" || e.Discovery.DTB != "0x1000" {
		t.Fatal(e.Discovery)
	}
}

func TestARM64AutoDiscoveryAndProcessList(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the Intel 2 MiB leaf with an ARM64 level-2 block descriptor.
	binary.LittleEndian.PutUint64(data[0x3000:], 1)
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]any
	if err = json.Unmarshal(b, &table); err != nil {
		t.Fatal(err)
	}
	table["metadata"].(map[string]any)["zero"] = map[string]any{"architecture": "aarch64", "page_shift": 12, "va_bits": 48}
	b, err = json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, b, 0600); err != nil {
		t.Fatal(err)
	}
	c := engine.Config{Image: f.Image, Symbols: f.Symbols, Offline: true}
	for _, root := range []string{"", "0x1000"} {
		c.DTB = root
		e, err := engine.Open(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if e.Config.Arch != "arm64" || e.Env.Architecture != "arm64" || e.Config.DTB != "0x1000" {
			t.Fatal(e.Config)
		}
		result, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{})
		e.Close()
		if err != nil || result.Task.Rows != 2 {
			t.Fatal(result, err)
		}
	}
	c.Arch = "x64"
	if e, err := engine.Open(context.Background(), c); err == nil {
		e.Close()
		t.Fatal("accepted mismatched architecture")
	}
}
