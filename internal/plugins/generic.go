package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type builtin struct {
	spec plugin.Spec
	run  func(context.Context, plugin.Environment, map[string]string, plugin.Emit) error
}

func (b builtin) Spec() plugin.Spec { return b.spec }
func (b builtin) Run(c context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	return b.run(c, e, p, out)
}
func Register(r *plugin.Registry) error {
	specs := []builtin{
		{plugin.Spec{Name: "generic.info", Description: "Physical memory segments and layer metadata", Columns: []evidence.Column{{Name: "Start", Kind: "address"}, {Name: "Length", Kind: "uint64"}, {Name: "FileOffset", Kind: "address"}}}, info},
		{plugin.Spec{Name: "banners", Upstream: "banners.Banners", Description: "Scan validated Linux/Darwin banners and Windows kernel PDB identities", Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Banner", Kind: "string"}}}, banners},
		{plugin.Spec{Name: "generic.strings", Description: "Bounded printable ASCII strings with physical offsets", Parameters: []plugin.Parameter{{Name: "min", Kind: "uint", Default: "8", Description: "Minimum length, 1..4096"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Text", Kind: "string"}, {Name: "Truncated", Kind: "string"}}}, ascii},
		{plugin.Spec{Name: "generic.ioc", Description: "Exact literal byte search; overlap-safe, no regex or YARA", Parameters: []plugin.Parameter{{Name: "needle", Kind: "string", Description: "Nonempty UTF-8 literal, at most 4096 bytes"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Match", Kind: "bytes"}}}, ioc},
	}
	specs = append(specs, processPlugins()...)
	specs = append(specs, modulePlugins()...)
	specs = append(specs, threadPlugins()...)
	specs = append(specs, vadPlugins()...)
	specs = append(specs, linuxMapPlugins()...)
	specs = append(specs, dllPlugins()...)
	specs = append(specs, pePlugins()...)
	for _, b := range specs {
		if err := r.Register(b); err != nil {
			return err
		}
	}
	return nil
}
func info(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	for _, r := range e.Physical.Ranges() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := out(evidence.Row{Cells: map[string]evidence.Value{"Start": evidence.Address(r.Start), "Length": evidence.Number(r.Length), "FileOffset": evidence.Address(r.FileOffset)}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", r.Start)}}); err != nil {
			return err
		}
	}
	return nil
}

// scanASCII carries a bounded string across read boundaries and never joins
// strings across holes or physical segments. Long strings are marked truncated.
func scanASCII(ctx context.Context, l memory.MemoryLayer, minLen int, emit func(uint64, string, bool) error) error {
	if minLen < 1 || minLen > 4096 {
		return fmt.Errorf("minimum string length must be 1..4096")
	}
	buf := make([]byte, 1<<20)
	for _, r := range l.Ranges() {
		var start uint64
		word := make([]byte, 0, 256)
		long := false
		flush := func() error {
			if len(word) >= minLen {
				if err := emit(start, string(word), long); err != nil {
					return err
				}
			}
			word = word[:0]
			long = false
			return nil
		}
		for off := uint64(0); off < r.Length; {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := int(min(uint64(len(buf)), r.Length-off))
			got, err := l.ReadAt(ctx, buf[:n], r.Start+off)
			if err != nil {
				return err
			}
			if got != n {
				return fmt.Errorf("short scan read")
			}
			for j, b := range buf[:n] {
				if b >= 32 && b <= 126 || b == 9 {
					if len(word) == 0 {
						start = r.Start + off + uint64(j)
					}
					if len(word) < 4096 {
						word = append(word, b)
					} else {
						long = true
					}
				} else {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			off += uint64(n)
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return nil
}

var bannerVersion = regexp.MustCompile(`(?:Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+`)

func banners(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	err := scanASCII(ctx, e.Physical, 12, func(a uint64, s string, long bool) error {
		if loc := bannerVersion.FindStringIndex(s); loc != nil {
			i := loc[0]
			a += uint64(i)
			n := uint64(4095)
			for _, run := range e.Physical.Ranges() {
				if a >= run.Start && a-run.Start < run.Length {
					n = min(n, run.Length-(a-run.Start))
					break
				}
			}
			data, err := memory.Read(ctx, e.Physical, a, int(n))
			if err != nil {
				return err
			}
			end := bytes.IndexByte(data, 0)
			if end < 0 {
				return nil
			}
			data = bytes.TrimSpace(data[:end])
			const allowed = " #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
			for _, b := range data {
				if !strings.ContainsRune(allowed, rune(b)) {
					return nil
				}
			}
			return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Banner": evidence.Text(string(data))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return pdbBanners(ctx, e, out)
}

func pdbBanners(ctx context.Context, e plugin.Environment, out plugin.Emit) error {
	names := map[string]bool{"ntoskrnl.pdb": true, "ntkrnlmp.pdb": true, "ntkrnlpa.pdb": true, "ntkrpamp.pdb": true}
	buf := make([]byte, 1<<20)
	for _, r := range e.Physical.Ranges() {
		var tail []byte
		for off := uint64(0); off < r.Length; {
			n := int(min(uint64(len(buf)), r.Length-off))
			got, err := e.Physical.ReadAt(ctx, buf[:n], r.Start+off)
			if err != nil {
				return err
			}
			if got != n {
				return fmt.Errorf("short PDB signature read")
			}
			window := append(append(make([]byte, 0, len(tail)+n), tail...), buf[:n]...)
			base := r.Start + off - uint64(len(tail))
			for from := 0; from < len(window); {
				idx := bytes.Index(window[from:], []byte("RSDS"))
				if idx < 0 {
					break
				}
				idx += from
				from = idx + 4
				if idx+25 > len(window) {
					continue
				}
				cv := window[idx:]
				end := bytes.IndexByte(cv[24:min(len(cv), 24+512)], 0)
				if end < 0 {
					continue
				}
				end += 24
				if base+uint64(idx+end+1) <= r.Start+off {
					continue
				}
				name := string(cv[24:end])
				if j := strings.LastIndexAny(name, "/\\"); j >= 0 {
					name = name[j+1:]
				}
				if !names[strings.ToLower(name)] {
					continue
				}
				g := cv[4:20]
				guid := fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:])
				age := binary.LittleEndian.Uint32(cv[20:])
				a := base + uint64(idx)
				if err := out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Banner": evidence.Text(fmt.Sprintf("%s|%s|%d", name, guid, age))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}}); err != nil {
					return err
				}
			}
			keep := min(4096, len(window))
			tail = append(tail[:0], window[len(window)-keep:]...)
			off += uint64(n)
		}
	}
	return nil
}
func ascii(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	n, err := strconv.ParseUint(p["min"], 0, 64)
	if err != nil || n < 1 || n > 4096 {
		return fmt.Errorf("minimum string length must be 1..4096")
	}
	return scanASCII(ctx, e.Physical, int(n), func(a uint64, s string, long bool) error {
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Text": evidence.Text(s), "Truncated": evidence.Text(strconv.FormatBool(long))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
func ioc(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	needle := p["needle"]
	if len(needle) < 1 || len(needle) > 4096 {
		return fmt.Errorf("needle must be 1..4096 bytes")
	}
	return memory.Scan(ctx, e.Physical, []byte(needle), func(a uint64) error {
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Match": evidence.Bytes([]byte(needle))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
