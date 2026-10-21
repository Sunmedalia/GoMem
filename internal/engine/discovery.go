package engine

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type LinuxDiscovery struct {
	Method         string `json:"method"`
	DTB            string `json:"dtb"`
	BannerPhysical string `json:"banner_physical"`
	PGDSymbol      string `json:"pgd_symbol"`
	PGDVirtual     string `json:"pgd_virtual"`
	KernelSlide    string `json:"kernel_slide"`
}

// discoverLinux applies only where the kernel banner and initial page table
// share a linear kernel-image mapping. A physical offset is merely a candidate:
// both the page table's own virtual address and the exact banner must translate
// back to the observed physical addresses before it can be used.
func (e *Engine) discoverLinux(ctx context.Context) (*memory.Virtual, *LinuxDiscovery, error) {
	table, ok := e.Env.Symbols.(*symbols.ISF)
	if !ok || e.Env.OS != "linux" || (e.Config.Arch != "x64" && e.Config.Arch != "arm64") || table.PointerSize() != 8 {
		return nil, nil, nil
	}
	if arch := table.Architecture(); !architectureMatches(arch, e.Config.Arch) {
		return nil, nil, nil
	}
	if pointer, err := table.Type("pointer"); err != nil || pointer.Endian != "" && pointer.Endian != "little" {
		return nil, nil, nil
	}
	var pgd symbols.Symbol
	var name string
	for _, candidate := range []string{"init_top_pgt", "init_level4_pgt", "swapper_pg_dir"} {
		if symbol, err := table.Lookup(candidate); err == nil {
			pgd, name = symbol, candidate
			break
		}
	}
	if name == "" {
		return nil, nil, nil
	}
	banner, err := table.Banner()
	if err != nil {
		return nil, nil, err
	}
	if len(banner) == 0 || len(banner) > 4096 {
		return nil, nil, fmt.Errorf("invalid Linux discovery banner length")
	}
	bannerSymbol, err := table.Lookup("linux_banner")
	if err != nil {
		return nil, nil, err
	}
	pgdVirtual, err := memory.Add(pgd.Address, e.Config.KernelSlide)
	if err != nil {
		return nil, nil, err
	}
	bannerVirtual, err := memory.Add(bannerSymbol.Address, e.Config.KernelSlide)
	if err != nil {
		return nil, nil, err
	}
	needle := append(append([]byte(nil), banner...), 0)
	type candidate struct {
		layer *memory.Virtual
		proof *LinuxDiscovery
	}
	matches := map[uint64]candidate{}
	var failures []string
	hits := 0
	err = memory.Scan(ctx, e.Env.Physical, needle, func(physical uint64) error {
		hits++
		if hits > 4096 {
			return fmt.Errorf("Linux discovery exceeds 4096 exact banner candidates; provide --dtb")
		}
		var root uint64
		if pgd.Address >= bannerSymbol.Address {
			var err error
			root, err = memory.Add(physical, pgd.Address-bannerSymbol.Address)
			if err != nil {
				return nil
			}
		} else {
			delta := bannerSymbol.Address - pgd.Address
			if physical < delta {
				return nil
			}
			root = physical - delta
		}
		if root == 0 || root&0xfff != 0 {
			return nil
		}
		tr, err := memory.NewTranslatorForOS(e.Env.Physical, root, e.Config.Arch, e.Env.OS, 1024)
		if err != nil {
			return err
		}
		layer := &memory.Virtual{Physical: e.Env.Physical, Translator: tr, ID: fmt.Sprintf("kernel:%s:dtb=%#x", e.Config.Arch, root)}
		verify := func() error {
			self, err := tr.Translate(ctx, pgdVirtual)
			if err != nil {
				return err
			}
			if self.Physical != root {
				return fmt.Errorf("candidate %#x does not map %s back to its root", root, name)
			}
			location, err := tr.Translate(ctx, bannerVirtual)
			if err != nil {
				return err
			}
			if location.Physical != physical {
				return fmt.Errorf("candidate %#x maps the banner to a different physical copy", root)
			}
			got, err := memory.Read(ctx, layer, bannerVirtual, len(needle))
			if err != nil {
				return err
			}
			if !bytes.Equal(got, needle) {
				return fmt.Errorf("candidate %#x banner identity differs", root)
			}
			return nil
		}
		if err = verify(); err != nil {
			if len(failures) < 5 {
				failures = append(failures, err.Error())
			}
			return ctx.Err()
		}
		matches[root] = candidate{layer, &LinuxDiscovery{Method: "linux-" + e.Config.Arch + "-linear-kernel-image", DTB: fmt.Sprintf("0x%x", root), BannerPhysical: fmt.Sprintf("0x%x", physical), PGDSymbol: name, PGDVirtual: fmt.Sprintf("0x%x", pgdVirtual), KernelSlide: fmt.Sprintf("0x%x", e.Config.KernelSlide)}}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(matches) == 0 {
		detail := "no page table passed root mapping and exact banner verification"
		if len(failures) > 0 {
			detail += ": " + strings.Join(failures, "; ")
		}
		return nil, nil, fmt.Errorf("Linux DTB discovery failed: %s; provide --dtb and the correct --kernel-slide", detail)
	}
	if len(matches) > 1 {
		return nil, nil, fmt.Errorf("Linux DTB discovery is ambiguous (%d verified roots); provide --dtb", len(matches))
	}
	for _, match := range matches {
		return match.layer, match.proof, nil
	}
	panic("unreachable Linux discovery")
}
