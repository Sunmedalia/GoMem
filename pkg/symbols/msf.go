package symbols

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

const msfMagic = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

type msfStream struct {
	size   uint32
	blocks []uint32
}
type msfFile struct {
	ctx       context.Context
	r         io.ReaderAt
	blockSize uint64
	streams   []msfStream
	remaining uint64
}

// MSF maps logical streams onto non-contiguous file blocks. The directory and
// each requested stream are bounded; unneeded streams are never materialized.
func openMSF(ctx context.Context, r io.ReaderAt, size, budget uint64) (*msfFile, error) {
	read := func(off uint64, length int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if off > size || uint64(length) > size-off {
			return nil, io.ErrUnexpectedEOF
		}
		b := make([]byte, length)
		_, err := r.ReadAt(b, int64(off))
		return b, err
	}
	h, err := read(0, 56)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(h[:32], []byte(msfMagic)) {
		return nil, fmt.Errorf("unsupported MSF signature (requires PDB/MSF 7.0)")
	}
	bs, fpm, blocks := uint64(binary.LittleEndian.Uint32(h[32:])), binary.LittleEndian.Uint32(h[36:]), uint64(binary.LittleEndian.Uint32(h[40:]))
	directorySize, blockMap := uint64(binary.LittleEndian.Uint32(h[44:])), uint64(binary.LittleEndian.Uint32(h[52:]))
	if bs < 512 || bs > 65536 || bs&(bs-1) != 0 || fpm != 1 && fpm != 2 || blocks < 4 || blocks*bs != size {
		return nil, fmt.Errorf("invalid MSF block geometry or truncated acquisition")
	}
	if directorySize < 4 || directorySize > budget || directorySize > 64<<20 {
		return nil, fmt.Errorf("MSF directory exceeds bounds")
	}
	pages := (directorySize + bs - 1) / bs
	if pages*4 > bs || blockMap >= blocks || blockMap <= 2 {
		return nil, fmt.Errorf("invalid MSF directory block map")
	}
	indices, err := read(blockMap*bs, int(pages*4))
	if err != nil {
		return nil, err
	}
	claimed := map[uint32]bool{0: true, 1: true, 2: true, uint32(blockMap): true}
	claim := func(block uint32) error {
		if uint64(block) >= blocks || claimed[block] {
			return fmt.Errorf("invalid or multiply referenced MSF block %d", block)
		}
		claimed[block] = true
		return nil
	}
	directory := make([]byte, 0, int(directorySize))
	for n := uint64(0); n < pages; n++ {
		block := binary.LittleEndian.Uint32(indices[n*4:])
		if err = claim(block); err != nil {
			return nil, err
		}
		data, err := read(uint64(block)*bs, int(min(bs, directorySize-uint64(len(directory)))))
		if err != nil {
			return nil, err
		}
		directory = append(directory, data...)
	}
	count := uint64(binary.LittleEndian.Uint32(directory))
	if count < 4 || count > 65536 || count*4 > directorySize-4 {
		return nil, fmt.Errorf("invalid MSF stream count")
	}
	m := &msfFile{ctx: ctx, r: r, blockSize: bs, remaining: budget - directorySize, streams: make([]msfStream, count)}
	offset := uint64(4) + count*4
	for n := range m.streams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := &m.streams[n]
		s.size = binary.LittleEndian.Uint32(directory[4+n*4:])
		if s.size == 0xffffffff {
			continue
		}
		length := (uint64(s.size) + bs - 1) / bs
		if length*4 > directorySize-offset {
			return nil, fmt.Errorf("truncated MSF stream block list")
		}
		s.blocks = make([]uint32, length)
		for i := range s.blocks {
			s.blocks[i] = binary.LittleEndian.Uint32(directory[offset:])
			offset += 4
			if err := claim(s.blocks[i]); err != nil {
				return nil, err
			}
		}
	}
	if offset != directorySize {
		return nil, fmt.Errorf("unconsumed MSF directory data")
	}
	return m, nil
}

func (m *msfFile) stream(index uint16) ([]byte, error) {
	if int(index) >= len(m.streams) || m.streams[index].size == 0xffffffff {
		return nil, fmt.Errorf("MSF stream %d is absent", index)
	}
	s := m.streams[index]
	if uint64(s.size) > m.remaining {
		return nil, fmt.Errorf("MSF stream %d exceeds cumulative read budget", index)
	}
	m.remaining -= uint64(s.size)
	b := make([]byte, int(s.size))
	for n, block := range s.blocks {
		if err := m.ctx.Err(); err != nil {
			return nil, err
		}
		start := uint64(n) * m.blockSize
		length := min(m.blockSize, uint64(s.size)-start)
		if _, err := m.r.ReadAt(b[start:start+length], int64(uint64(block)*m.blockSize)); err != nil {
			return nil, fmt.Errorf("MSF stream %d: %w", index, err)
		}
	}
	return b, nil
}
