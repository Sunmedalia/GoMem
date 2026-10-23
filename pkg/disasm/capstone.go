// Package disasm provides bounded, cancellable access to the optional native
// Capstone decoder. Native libraries are explicitly selected local code.
package disasm

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

const MaxInput = 65536

type Instruction struct {
	Address  uint64 `json:"address"`
	Bytes    []byte `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands"`
}

func (i Instruction) Text() string {
	if i.Operands == "" {
		return i.Mnemonic
	}
	return i.Mnemonic + " " + i.Operands
}

type nativeDecoder interface {
	Next([]byte, uint64) (Instruction, error)
	Reset() error
	Close()
	Version() string
}
type Decoder struct {
	mu      sync.Mutex
	native  nativeDecoder
	version string
	closed  bool
	active  bool
}

func Open(ctx context.Context, library, arch string) (*Decoder, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(library) || strings.ContainsRune(library, 0) {
		return nil, fmt.Errorf("Capstone requires an absolute native library path")
	}
	switch arch {
	case "x86", "x64", "arm", "arm64", "thumb":
	default:
		return nil, fmt.Errorf("unsupported Capstone architecture %q", arch)
	}
	native, err := openNative(library, arch)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		native.Close()
		return nil, err
	}
	return &Decoder{native: native, version: native.Version()}, nil
}
func (d *Decoder) Version() string { return d.version }
func (d *Decoder) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.native.Close()
	}
	return nil
}
func (d *Decoder) Decode(ctx context.Context, data []byte, address uint64, emit func(Instruction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) > MaxInput {
		return fmt.Errorf("Capstone input exceeds %d byte budget", MaxInput)
	}
	if uint64(len(data)) > ^uint64(0)-address {
		return fmt.Errorf("Capstone instruction address overflows")
	}
	if emit == nil {
		return fmt.Errorf("Capstone instruction callback required")
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return fmt.Errorf("Capstone decoder closed")
	}
	if d.active {
		d.mu.Unlock()
		return fmt.Errorf("Capstone decoder already decoding a stream")
	}
	// cs_disasm_iter retains ARM IT state. Independent Decode calls must not
	// inherit a previous stream's unfinished conditional block.
	if err := d.native.Reset(); err != nil {
		d.mu.Unlock()
		return err
	}
	d.active = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.active = false; d.mu.Unlock() }()
	for offset := 0; offset < len(data); {
		if err := ctx.Err(); err != nil {
			return err
		}
		at := address + uint64(offset)
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return fmt.Errorf("Capstone decoder closed")
		}
		inst, err := d.native.Next(data[offset:], at)
		d.mu.Unlock()
		if err != nil {
			return fmt.Errorf("Capstone decode at %#x: %w", at, err)
		}
		if inst.Address != at || len(inst.Bytes) == 0 || len(inst.Bytes) > 24 || len(inst.Bytes) > len(data)-offset || !bytes.Equal(inst.Bytes, data[offset:offset+len(inst.Bytes)]) || inst.Mnemonic == "" {
			return fmt.Errorf("Capstone returned inconsistent instruction at %#x", at)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Callback runs outside the native lock, so it may cancel or close safely.
		if err := emit(inst); err != nil {
			return err
		}
		offset += len(inst.Bytes)
	}
	return ctx.Err()
}
