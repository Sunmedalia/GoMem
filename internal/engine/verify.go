package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func (e *Engine) verifySymbols(ctx context.Context) error {
	table, ok := e.Env.Symbols.(*symbols.ISF)
	if !ok {
		return fmt.Errorf("symbol identity verifier needs ISF")
	}
	switch e.Env.OS {
	case "linux":
		banner, err := table.Banner()
		if err != nil {
			return err
		}
		if len(banner) == 0 || len(banner) > 4096 {
			return fmt.Errorf("invalid symbol banner length")
		}
		a, err := e.Env.Symbol("linux_banner")
		if err != nil {
			return err
		}
		got, err := memory.Read(ctx, e.Env.Kernel, a, len(banner)+1)
		if err != nil {
			return fmt.Errorf("verify linux_banner: %w", err)
		}
		if !bytes.Equal(got[:len(banner)], banner) || got[len(banner)] != 0 {
			return fmt.Errorf("Linux kernel banner mismatch; exact symbol/build identity is required")
		}
		return nil
	case "windows":
		if e.Config.KernelBase == 0 {
			return fmt.Errorf("Windows analysis needs --kernel-base")
		}
		return verifyPE(ctx, e.Env.Kernel, e.Config.KernelBase, table)
	default:
		return fmt.Errorf("symbol identity verification for %s is not implemented", e.Env.OS)
	}
}
func verifyPE(ctx context.Context, l memory.MemoryLayer, base uint64, t *symbols.ISF) error {
	image, err := readKernelPE(ctx, l, base)
	if err != nil {
		return err
	}
	if arch := t.Architecture(); arch == "x86_64" && image.Machine != 0x8664 || arch == "i386" && image.Machine != 0x14c || arch == "arm64" && image.Machine != 0xaa64 {
		return fmt.Errorf("PDB machine and mapped PE machine disagree")
	}
	return t.MatchPDB(image.Identity.Database, image.Identity.GUID, image.Identity.Age)
}

var errNoMappedPDB = errors.New("mapped PE has no supported PDB identity")

type kernelPE struct {
	Identity symbols.PDBIdentity
	Machine  uint16
	Size     uint64
}

func readKernelPDB(ctx context.Context, l memory.MemoryLayer, base uint64) (symbols.PDBIdentity, error) {
	pe, err := readKernelPE(ctx, l, base)
	return pe.Identity, err
}
func readKernelPE(ctx context.Context, l memory.MemoryLayer, base uint64) (image kernelPE, err error) {
	read := func(off uint64, n int) ([]byte, error) {
		a, e := memory.Add(base, off)
		if e != nil {
			return nil, e
		}
		return memory.Read(ctx, l, a, n)
	}
	dos, err := read(0, 64)
	if err != nil {
		return image, err
	}
	if string(dos[:2]) != "MZ" {
		return image, fmt.Errorf("kernel base lacks PE DOS signature")
	}
	peOff := uint64(binary.LittleEndian.Uint32(dos[60:]))
	if peOff < 64 || peOff > 16<<20 {
		return image, fmt.Errorf("invalid kernel PE offset")
	}
	h, err := read(peOff, 24)
	if err != nil {
		return image, err
	}
	if string(h[:4]) != "PE\x00\x00" {
		return image, fmt.Errorf("invalid kernel PE signature")
	}
	size := int(binary.LittleEndian.Uint16(h[20:]))
	if size < 96 || size > 4096 {
		return image, fmt.Errorf("invalid PE optional header size")
	}
	opt, err := read(peOff+24, size)
	if err != nil {
		return image, err
	}
	image.Machine = binary.LittleEndian.Uint16(h[4:])
	data := 112
	count := 108
	switch binary.LittleEndian.Uint16(opt) {
	case 0x20b:
		if image.Machine != 0x8664 && image.Machine != 0xaa64 {
			return image, fmt.Errorf("PE machine and optional header width disagree")
		}
	case 0x10b:
		if image.Machine != 0x14c && image.Machine != 0x1c0 && image.Machine != 0x1c4 {
			return image, fmt.Errorf("PE machine and optional header width disagree")
		}
		data = 96
		count = 92
	default:
		return image, fmt.Errorf("unsupported PE optional header")
	}
	image.Size = uint64(binary.LittleEndian.Uint32(opt[56:]))
	if image.Size == 0 || image.Size > 1<<30 {
		return image, fmt.Errorf("invalid mapped PE image size")
	}
	if peOff+24+uint64(size) > image.Size {
		return image, fmt.Errorf("PE headers exceed mapped image size")
	}
	if len(opt) < data {
		return image, fmt.Errorf("truncated PE optional header")
	}
	if binary.LittleEndian.Uint32(opt[count:]) < 7 {
		return image, fmt.Errorf("kernel PE debug directory is absent: %w", errNoMappedPDB)
	}
	if len(opt) < data+7*8 {
		return image, fmt.Errorf("truncated PE debug data directory")
	}
	rva := uint64(binary.LittleEndian.Uint32(opt[data+6*8:]))
	n := uint64(binary.LittleEndian.Uint32(opt[data+6*8+4:]))
	if n == 0 && rva == 0 {
		return image, errNoMappedPDB
	}
	if n == 0 || n > 65536 || n%28 != 0 || rva > image.Size || n > image.Size-rva {
		return image, fmt.Errorf("invalid PE debug directory length")
	}
	entries, err := read(rva, int(n))
	if err != nil {
		return image, err
	}
	for i := 0; i < len(entries); i += 28 {
		d := entries[i : i+28]
		if binary.LittleEndian.Uint32(d[12:]) != 2 {
			continue
		}
		lenCV := int(binary.LittleEndian.Uint32(d[16:]))
		if lenCV < 25 || lenCV > 4096 {
			return image, fmt.Errorf("invalid PE CodeView record length")
		}
		cvRVA := uint64(binary.LittleEndian.Uint32(d[20:]))
		if cvRVA > image.Size || uint64(lenCV) > image.Size-cvRVA {
			return image, fmt.Errorf("CodeView data exceeds mapped PE image")
		}
		cv, err := read(cvRVA, lenCV)
		if err != nil {
			return image, err
		}
		if string(cv[:4]) != "RSDS" {
			continue
		}
		g := cv[4:20]
		guid := fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:])
		age := uint64(binary.LittleEndian.Uint32(cv[20:]))
		name := cv[24:]
		end := bytes.IndexByte(name, 0)
		if end < 0 {
			return image, fmt.Errorf("unterminated PDB path")
		}
		name = name[:end]
		if slash := bytes.LastIndexAny(name, "/\\"); slash >= 0 {
			name = name[slash+1:]
		}
		image.Identity = symbols.PDBIdentity{Database: string(name), GUID: guid, Age: age}
		return image, nil
	}
	return image, fmt.Errorf("kernel PE has no supported RSDS PDB identity: %w", errNoMappedPDB)
}
