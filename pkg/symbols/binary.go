package symbols

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type DWARFOptions struct {
	OS            string
	Arch          string
	SystemMap     string
	SymbolsFrom   string
	MaxDebugBytes uint64
	MaxEntries    int
}
type SymbolSource struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}
type Conversion struct {
	Format       string         `json:"format"`
	Architecture string         `json:"architecture"`
	BuildID      string         `json:"build_id,omitempty"`
	Sources      []SymbolSource `json:"sources"`
	Entries      int            `json:"entries"`
	Types        int            `json:"types"`
	Symbols      int            `json:"symbols"`
	Enums        int            `json:"enums"`
	Warnings     []string       `json:"warnings,omitempty"`
}
type nativeSymbol struct {
	name     string
	address  uint64
	function bool
}
type nativeFile struct {
	file                    *os.File
	initial                 os.FileInfo
	elf                     *elf.File
	macho                   *macho.File
	platform, arch, buildID string
	pointer                 int
	order                   binary.ByteOrder
	ctx                     context.Context
	options                 DWARFOptions
}
type contextReadAt struct {
	ctx       context.Context
	r         io.ReaderAt
	remaining uint64
}

func (r *contextReadAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > r.remaining {
		return 0, fmt.Errorf("object parser exceeds read budget")
	}
	n, err := r.r.ReadAt(p, off)
	r.remaining -= uint64(n)
	return n, err
}
func nativeMagic(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	if string(p[:4]) == "\x7fELF" {
		return true
	}
	switch binary.BigEndian.Uint32(p) {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return true
	}
	return false
}
func normalizeDWARFOptions(o DWARFOptions) (DWARFOptions, error) {
	if o.MaxDebugBytes == 0 {
		o.MaxDebugBytes = 512 << 20
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = 2000000
	}
	if o.MaxDebugBytes > 2<<30 || o.MaxDebugBytes < 1024 || o.MaxEntries < 1 || o.MaxEntries > 10000000 {
		return o, fmt.Errorf("invalid DWARF resource bounds")
	}
	return o, nil
}
func openNative(ctx context.Context, path string, o DWARFOptions) (n *nativeFile, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("debug input must be a regular file")
	}
	n = &nativeFile{file: f, initial: info, ctx: ctx, options: o}
	r := &contextReadAt{ctx: ctx, r: f, remaining: o.MaxDebugBytes}
	var magic [4]byte
	if _, err = r.ReadAt(magic[:], 0); err != nil {
		return nil, err
	}
	if string(magic[:]) == "\x7fELF" {
		n.elf, err = elf.NewFile(r)
		if err != nil {
			return nil, err
		}
		n.platform = "linux"
		n.order = n.elf.ByteOrder
		n.pointer = 8
		if n.elf.Class == elf.ELFCLASS32 {
			n.pointer = 4
		}
		n.arch = n.elf.Machine.String()
		var total uint64
		for _, s := range n.elf.Sections {
			if s.Type == elf.SHT_NOBITS {
				continue
			}
			size := s.Size
			if strings.HasPrefix(s.Name, ".zdebug_") {
				var header [12]byte
				if _, e := io.ReadFull(s.Open(), header[:]); e != nil {
					return nil, e
				}
				if string(header[:4]) != "ZLIB" {
					return nil, fmt.Errorf("invalid GNU compressed debug section")
				}
				size = binary.BigEndian.Uint64(header[4:])
			}
			if size > o.MaxDebugBytes || s.FileSize > o.MaxDebugBytes {
				return nil, fmt.Errorf("section %s exceeds DWARF byte limit", s.Name)
			}
			if strings.Contains(s.Name, "debug") || s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_STRTAB || s.Type == elf.SHT_DYNSYM {
				if size > o.MaxDebugBytes-total {
					return nil, fmt.Errorf("debug sections exceed total byte limit")
				}
				total += size
			}
			if (s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM) && s.Entsize > 0 && s.Size/s.Entsize > uint64(o.MaxEntries) {
				return nil, fmt.Errorf("symbol count exceeds limit")
			}
		}
		if s := n.elf.Section(".note.gnu.build-id"); s != nil && s.Size <= 65536 {
			b, e := s.Data()
			if e != nil {
				return nil, e
			}
			for len(b) >= 12 {
				namesz, descsz, kind := n.order.Uint32(b), n.order.Uint32(b[4:]), n.order.Uint32(b[8:])
				na, da := (uint64(namesz)+3)&^uint64(3), (uint64(descsz)+3)&^uint64(3)
				if na+da > uint64(len(b)-12) {
					return nil, fmt.Errorf("truncated ELF build-id note")
				}
				if kind == 3 && string(bytes.TrimRight(b[12:12+namesz], "\x00")) == "GNU" {
					n.buildID = hex.EncodeToString(b[12+na : 12+na+uint64(descsz)])
					break
				}
				b = b[12+na+da:]
			}
		}
	} else {
		selected, expected, e := selectMacho(r, uint64(info.Size()), o.Arch)
		if e != nil {
			return nil, e
		}
		n.macho, err = macho.NewFile(selected)
		if err != nil {
			return nil, err
		}
		if expected != "" && expected != machoArch(n.macho.Cpu) {
			return nil, fmt.Errorf("fat Mach-O CPU disagrees with selected slice")
		}
		n.platform = "mac"
		n.order = n.macho.ByteOrder
		n.arch = machoArch(n.macho.Cpu)
		if o.Arch != "" && o.Arch != n.arch {
			return nil, fmt.Errorf("Mach-O architecture mismatch")
		}
		n.pointer = 4
		if n.macho.Magic == macho.Magic64 {
			n.pointer = 8
		}
		var total uint64
		for _, s := range n.macho.Sections {
			kind := s.Flags & 0xff
			if kind == 1 || kind == 0xc || kind == 0x12 {
				continue
			}
			size := s.Size
			if strings.HasPrefix(s.Name, "__zdebug_") {
				var h [12]byte
				if _, e := io.ReadFull(s.Open(), h[:]); e != nil {
					return nil, e
				}
				if string(h[:4]) != "ZLIB" {
					return nil, fmt.Errorf("invalid Mach-O compressed debug section")
				}
				size = binary.BigEndian.Uint64(h[4:])
			}
			if size > o.MaxDebugBytes {
				return nil, fmt.Errorf("Mach-O section %s exceeds byte limit", s.Name)
			}
			if strings.Contains(s.Name, "debug") {
				if size > o.MaxDebugBytes-total {
					return nil, fmt.Errorf("Mach-O debug sections exceed total limit")
				}
				total += size
			}
		}
		if n.macho.Symtab != nil && len(n.macho.Symtab.Syms) > o.MaxEntries {
			return nil, fmt.Errorf("Mach-O symbol count exceeds limit")
		}
		for _, load := range n.macho.Loads {
			b := load.Raw()
			if len(b) >= 24 && n.order.Uint32(b) == 0x1b {
				n.buildID = hex.EncodeToString(b[8:24])
			}
		}
	}
	if o.OS != "" && o.OS != n.platform {
		return nil, fmt.Errorf("debug file platform %s disagrees with --os %s", n.platform, o.OS)
	}
	return n, nil
}
func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.Cpu386:
		return "i386"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuArm:
		return "arm"
	}
	return c.String()
}
func (n *nativeFile) DWARF() (*dwarf.Data, error) {
	if n.elf != nil {
		return n.elf.DWARF()
	}
	return n.macho.DWARF()
}
func (n *nativeFile) eachSymbol(emit func(nativeSymbol) error) error {
	if n.elf != nil {
		syms, err := n.elf.Symbols()
		if err == elf.ErrNoSymbols {
			syms, err = n.elf.DynamicSymbols()
		}
		if err == elf.ErrNoSymbols {
			return nil
		}
		if err != nil {
			return err
		}
		if len(syms) > n.options.MaxEntries {
			return fmt.Errorf("ELF symbol count exceeds limit")
		}
		for _, s := range syms {
			if err := n.ctx.Err(); err != nil {
				return err
			}
			kind := elf.ST_TYPE(s.Info)
			if s.Name == "" || s.Section == elf.SHN_UNDEF || kind != elf.STT_OBJECT && kind != elf.STT_FUNC && kind != elf.STT_NOTYPE {
				continue
			}
			if err = emit(nativeSymbol{s.Name, s.Value, kind == elf.STT_FUNC}); err != nil {
				return err
			}
		}
		return nil
	}
	if n.macho.Symtab == nil {
		return nil
	}
	for _, s := range n.macho.Symtab.Syms {
		if err := n.ctx.Err(); err != nil {
			return err
		}
		if s.Type&0xe0 != 0 || s.Type&0x0e == 0 || s.Name == "" {
			continue
		}
		if err := emit(nativeSymbol{strings.TrimPrefix(s.Name, "_"), s.Value, false}); err != nil {
			return err
		}
	}
	return nil
}
func (n *nativeFile) banner(address uint64) ([]byte, error) {
	var reader io.ReadSeeker
	var offset, size uint64
	if n.elf != nil {
		for _, s := range n.elf.Sections {
			if s.Type == elf.SHT_NOBITS || address < s.Addr || address-s.Addr >= s.Size {
				continue
			}
			reader = s.Open()
			offset = address - s.Addr
			size = s.Size - offset
			break
		}
	} else {
		for _, s := range n.macho.Sections {
			if address < s.Addr || address-s.Addr >= s.Size || s.Flags&0xff == 1 {
				continue
			}
			reader = s.Open()
			offset = address - s.Addr
			size = s.Size - offset
			break
		}
	}
	if reader == nil {
		return nil, fmt.Errorf("banner address %#x is not file-backed", address)
	}
	if offset > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("banner offset overflow")
	}
	if _, err := reader.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(contextReader{n.ctx, reader}, int64(min(size, 4096))))
	if err != nil {
		return nil, err
	}
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return nil, fmt.Errorf("kernel banner is not terminated within 4096 bytes")
	}
	if !bytes.HasPrefix(b, []byte("Linux version ")) && !bytes.HasPrefix(b, []byte("Darwin Kernel Version ")) {
		return nil, fmt.Errorf("kernel banner has an unexpected signature")
	}
	return b[:end+1], nil
}
func (n *nativeFile) source(kind string) (SymbolSource, error) {
	if _, err := n.file.Seek(0, io.SeekStart); err != nil {
		return SymbolSource{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, contextReader{n.ctx, n.file}); err != nil {
		return SymbolSource{}, err
	}
	info, err := n.file.Stat()
	if err != nil {
		return SymbolSource{}, err
	}
	if info.Size() != n.initial.Size() || !info.ModTime().Equal(n.initial.ModTime()) {
		return SymbolSource{}, fmt.Errorf("debug file changed during conversion")
	}
	return SymbolSource{filepath.Base(n.file.Name()), hex.EncodeToString(h.Sum(nil)), kind}, nil
}
