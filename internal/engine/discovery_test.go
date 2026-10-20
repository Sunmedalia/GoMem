package engine_test

import (
	"context"
	"encoding/binary"
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
