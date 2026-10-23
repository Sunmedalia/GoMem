package explore

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/disasm"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

func (s *Session) disassemble(ctx context.Context, args []string, w io.Writer) error {
	if len(args) < 2 || len(args) > 4 {
		return fmt.Errorf("dis ADDRESS [LENGTH] [x86|x64|arm|arm64|thumb]")
	}
	address, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return err
	}
	length := uint64(128)
	if len(args) >= 3 {
		length, err = strconv.ParseUint(args[2], 0, 32)
		if err != nil {
			return err
		}
	}
	if length == 0 || length > 65536 {
		return fmt.Errorf("dis length must be 1..65536")
	}
	arch := s.Engine.Env.Architecture
	if len(args) == 4 {
		arch = args[3]
	}
	if arch == "intel64" {
		arch = "x64"
	}
	if arch == "intel" {
		arch = "x86"
	}
	if arch == "pae" {
		arch = "x86"
	}
	if arch != "x86" && arch != "x64" && arch != "arm" && arch != "arm64" && (arch != "thumb" || s.Engine.Config.CapstoneLibrary == "") {
		return fmt.Errorf("dis requires x86, x64, arm, arm64; thumb requires --capstone-library")
	}
	if (arch == "arm" || arch == "arm64") && (address%4 != 0 || length%4 != 0) {
		return fmt.Errorf("ARM disassembly requires aligned address and length")
	}
	if arch == "thumb" && (address%2 != 0 || length%2 != 0) {
		return fmt.Errorf("Thumb disassembly requires two-byte aligned address and length")
	}
	if _, err = memory.Add(address, length); err != nil {
		return err
	}
	// Check source identity before exposing cached or freshly read image bytes.
	if err = s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	data, err := memory.Read(ctx, s.Layer, address, int(length))
	if err != nil {
		return err
	}
	if s.Engine.Config.CapstoneLibrary != "" {
		decoder, err := disasm.Open(ctx, s.Engine.Config.CapstoneLibrary, arch)
		if err != nil {
			return err
		}
		defer decoder.Close()
		if _, err := fmt.Fprintf(w, "%s @ %#x (%s; Capstone %s)\n", s.Layer.Name(), address, arch, decoder.Version()); err != nil {
			return err
		}
		if err := decoder.Decode(ctx, data, address, func(inst disasm.Instruction) error {
			_, err := fmt.Fprintf(w, "%#016x  %-30x %s\n", inst.Address, inst.Bytes, inst.Text())
			return err
		}); err != nil {
			return err
		}
		return s.Engine.ValidateSource(ctx)
	}
	if _, err = fmt.Fprintf(w, "%s @ %#x (%s)\n", s.Layer.Name(), address, arch); err != nil {
		return err
	}
	for offset := 0; offset < len(data); {
		if err = ctx.Err(); err != nil {
			return err
		}
		at := address + uint64(offset)
		var text string
		size := 4
		if arch == "arm64" {
			inst, decodeErr := arm64asm.Decode(data[offset:])
			if decodeErr != nil {
				return fmt.Errorf("decode at %#x: %w", at, decodeErr)
			}
			text = arm64asm.GNUSyntax(inst)
		} else if arch == "arm" {
			inst, decodeErr := armasm.Decode(data[offset:], armasm.ModeARM)
			if decodeErr != nil {
				return fmt.Errorf("decode at %#x: %w", at, decodeErr)
			}
			text = armasm.GNUSyntax(inst)
		} else {
			mode := 64
			if arch == "x86" {
				mode = 32
			}
			inst, decodeErr := x86asm.Decode(data[offset:], mode)
			if decodeErr != nil {
				return fmt.Errorf("decode at %#x: %w", at, decodeErr)
			}
			if inst.Op == 0 || inst.Len <= 0 {
				return fmt.Errorf("invalid or incomplete instruction at %#x", at)
			}
			size = inst.Len
			text = x86asm.IntelSyntax(inst, at, nil)
		}
		if _, err = fmt.Fprintf(w, "%#016x  %-30x %s\n", at, data[offset:offset+size], text); err != nil {
			return err
		}
		offset += size
	}
	return s.Engine.ValidateSource(ctx)
}
