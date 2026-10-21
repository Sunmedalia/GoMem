// Package kallsyms decodes the kernel's resident compressed symbol tables.
// It consumes read-only memory layers; it never substitutes an ISF symbol list
// for the symbols actually present in the captured kernel.
package kallsyms

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Config records addresses in the acquisition layer. AddressMask applies to
// decoded symbol values, not to these acquisition coordinates.
type Config struct {
	Count, Names, TokenTable, TokenIndex uint64
	Markers, TextStart                   uint64
	HasText                              bool
	Addresses, Offsets, RelativeBase     uint64
	InitStart, InitEnd, TextEnd, End     uint64
	HasInit, HasEnd                      bool
	Width, CountSize                     int
	MarkerSize                           int
	Endian                               string
	AddressMask                          uint64
}

type Limits struct {
	Symbols, Bytes        uint64
	TokenBytes, NameBytes int
}

// Symbol retains both the official size presentation and its source interval.
// A zero/negative interval is unavailable in the pinned plugin's Size column.
type Symbol struct {
	Index, Address, Size, SizeStart, SizeEnd uint64
	SizeAvailable                            bool
	Name, Type                               string
	Exported                                 *bool
	NameOffset, NextOffset                   uint64
	CompressedLength, HeaderBytes            uint64
}

type Stats struct{ Symbols, ReadCalls, AcquiredBytes, Tokens uint64 }

// Core holds bounded resident indices and mutable decoder caches. An instance
// must not be used concurrently, including Lookup, Stream, Expand and Stats.
type Core struct {
	layer       memory.MemoryLayer
	config      Config
	limits      Limits
	order       binary.ByteOrder
	addresses   []uint64
	index       [256]uint16
	tokens      map[byte]string
	relative    uint64
	stats       Stats
	namesCursor uint64
	nameOffsets map[uint64]*list.Element
	nameLRU     *list.List
}

// Open acquires the bounded address index and token offsets. Full table
// ordering is checked before deriving sizes; malformed indices cannot produce
// plausible but unsupported intervals. The name stream remains incremental.
func Open(ctx context.Context, layer memory.MemoryLayer, config Config, limits Limits) (*Core, error) {
	if layer == nil {
		return nil, fmt.Errorf("kallsyms requires a memory layer")
	}
	if config.Width != 4 && config.Width != 8 || config.CountSize != 4 && config.CountSize != 8 {
		return nil, fmt.Errorf("kallsyms requires four/eight byte pointers and count")
	}
	if config.AddressMask == 0 {
		return nil, fmt.Errorf("kallsyms requires an explicit address mask")
	}
	if limits.Symbols == 0 || limits.Symbols > 10000000 || limits.Bytes == 0 || limits.Bytes > 1<<30 || limits.TokenBytes < 1 || limits.TokenBytes > 65536 || limits.NameBytes < 1 || limits.NameBytes > 1<<20 {
		return nil, fmt.Errorf("invalid kallsyms resource limits")
	}
	c := &Core{layer: layer, config: config, limits: limits, tokens: map[byte]string{}, nameOffsets: map[uint64]*list.Element{}, nameLRU: list.New()}
	switch config.Endian {
	case "little":
		c.order = binary.LittleEndian
	case "big":
		c.order = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported kallsyms byte order %q", config.Endian)
	}
	count, err := c.uint(ctx, config.Count, config.CountSize)
	if err != nil {
		return nil, err
	}
	if count > limits.Symbols {
		return nil, fmt.Errorf("kallsyms count %d exceeds symbol limit %d", count, limits.Symbols)
	}
	c.stats.Symbols = count
	if config.Offsets != 0 {
		if config.RelativeBase == 0 {
			return nil, fmt.Errorf("relative kallsyms offsets lack a base")
		}
		c.relative, err = c.uint(ctx, config.RelativeBase, config.Width)
		if err != nil {
			return nil, err
		}
		c.relative &= config.AddressMask
	} else if config.Addresses == 0 && count != 0 {
		return nil, fmt.Errorf("kallsyms lacks absolute or relative addresses")
	}
	raw, err := c.read(ctx, config.TokenIndex, 512)
	if err != nil {
		return nil, err
	}
	for i := range c.index {
		c.index[i] = c.order.Uint16(raw[i*2 : i*2+2])
	}
	c.addresses = make([]uint64, int(count))
	// Read the address index in bounded blocks, never the whole memory image.
	stride, base := config.Width, config.Addresses
	if config.Offsets != 0 {
		stride, base = 4, config.Offsets
	}
	for first := uint64(0); first < count; {
		n := min(uint64(4096/stride), count-first)
		at, err := memory.Add(base, first*uint64(stride))
		if err != nil {
			return nil, err
		}
		raw, err := c.read(ctx, at, int(n)*stride)
		if err != nil {
			return nil, err
		}
		for j := uint64(0); j < n; j++ {
			p := raw[int(j)*stride : int(j+1)*stride]
			var value uint64
			if config.Offsets != 0 {
				offset := int64(int32(c.order.Uint32(p)))
				if offset < 0 {
					// Pinned CONFIG_KALLSYMS_ABSOLUTE_PERCPU interpretation: negative
					// offsets are relative_base-1-offset; positive values are absolute.
					delta := uint64(-offset - 1)
					value, err = memory.Add(c.relative, delta)
					if err != nil {
						return nil, err
					}
				} else {
					value = uint64(offset) & config.AddressMask
				}
			} else if stride == 4 {
				value = uint64(c.order.Uint32(p)) & config.AddressMask
			} else {
				value = c.order.Uint64(p) & config.AddressMask
			}
			idx := first + j
			if idx > 0 && value < c.addresses[idx-1] {
				return nil, fmt.Errorf("unordered kallsyms address at index %d", idx)
			}
			c.addresses[idx] = value
		}
		first += n
	}
	return c, nil
}

func (c *Core) Stats() Stats  { return c.stats }
func (c *Core) Count() uint64 { return uint64(len(c.addresses)) }

func (c *Core) read(ctx context.Context, at uint64, length int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if length < 0 || length > memory.MaxRead || uint64(length) > c.limits.Bytes-c.stats.AcquiredBytes {
		return nil, fmt.Errorf("kallsyms acquisition byte limit exhausted")
	}
	if _, err := memory.Add(at, uint64(length)); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	n, err := c.layer.ReadAt(ctx, data, at)
	c.stats.ReadCalls++
	if n < 0 || n > length {
		return nil, fmt.Errorf("invalid kallsyms read count %d for %d bytes", n, length)
	}
	c.stats.AcquiredBytes += uint64(n)
	if err == nil && n != length {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}
func (c *Core) uint(ctx context.Context, at uint64, width int) (uint64, error) {
	p, err := c.read(ctx, at, width)
	if err != nil {
		return 0, err
	}
	switch width {
	case 1:
		return uint64(p[0]), nil
	case 4:
		return uint64(c.order.Uint32(p)), nil
	case 8:
		return c.order.Uint64(p), nil
	}
	return 0, fmt.Errorf("unsupported kallsyms integer width")
}
func (c *Core) token(ctx context.Context, id byte) (string, error) {
	if value, ok := c.tokens[id]; ok {
		return value, nil
	}
	at, err := memory.Add(c.config.TokenTable, uint64(c.index[id]))
	if err != nil {
		return "", err
	}
	var name strings.Builder
	for i := 0; i < c.limits.TokenBytes; i++ {
		pos, err := memory.Add(at, uint64(i))
		if err != nil {
			return "", err
		}
		value, err := c.uint(ctx, pos, 1)
		if err != nil {
			return "", err
		}
		if value == 0 {
			result := name.String()
			c.tokens[id] = result
			c.stats.Tokens++
			return result, nil
		}
		// The fixed decoder calls UTF-8 decode on each individual byte. A
		// non-ASCII token therefore fails rather than being replacement-decoded.
		if value >= 128 {
			return "", fmt.Errorf("non-ASCII kallsyms token at %#x", pos)
		}
		name.WriteByte(byte(value))
	}
	return "", fmt.Errorf("unterminated kallsyms token exceeds %d bytes", c.limits.TokenBytes)
}

// Expand decodes a name at the exact stream offset, without selecting an
// address. HeaderBytes makes the 6.1+ two-byte length visible in evidence.
func (c *Core) Expand(ctx context.Context, offset uint64) (name, typ string, length, header uint64, err error) {
	at, err := memory.Add(c.config.Names, offset)
	if err != nil {
		return "", "", 0, 0, err
	}
	c.namesCursor = offset
	length, err = c.uint(ctx, at, 1)
	if err != nil {
		return "", "", 0, 0, err
	}
	c.namesCursor++
	header = 1
	if length&0x80 != 0 {
		next, cause := memory.Add(at, 1)
		if cause != nil {
			return "", "", 0, 0, cause
		}
		upper, cause := c.uint(ctx, next, 1)
		if cause != nil {
			return "", "", 0, 0, cause
		}
		c.namesCursor++
		length = upper<<7 | length&0x7f
		header = 2
	}
	start, err := memory.Add(at, header)
	if err != nil {
		return "", "", length, header, err
	}
	ids, err := c.read(ctx, start, int(length))
	if err != nil {
		return "", "", length, header, err
	}
	c.namesCursor += length
	var expanded strings.Builder
	for _, id := range ids {
		text, cause := c.token(ctx, id)
		if cause != nil {
			return "", "", length, header, cause
		}
		if expanded.Len()+len(text) > c.limits.NameBytes {
			return "", "", length, header, fmt.Errorf("expanded kallsyms name exceeds %d bytes", c.limits.NameBytes)
		}
		expanded.WriteString(text)
	}
	text := expanded.String()
	if text != "" {
		typ, name = text[:1], text[1:]
	}
	return name, typ, length, header, nil
}

func (c *Core) interval(address uint64) (start, end uint64) {
	// Match pinned lookup: last <= target, then backtrack to the first alias.
	i := sort.Search(len(c.addresses), func(i int) bool { return c.addresses[i] > address }) - 1
	if i < 0 {
		i = 0
	}
	alias := c.addresses[i]
	i = sort.Search(len(c.addresses), func(i int) bool { return c.addresses[i] >= alias })
	start = c.addresses[i]
	next := sort.Search(len(c.addresses), func(i int) bool { return c.addresses[i] > start })
	if next < len(c.addresses) {
		return start, c.addresses[next]
	}
	if c.config.HasInit && c.config.InitStart <= address && address < c.config.InitEnd {
		return start, c.config.InitEnd
	}
	if c.config.HasEnd {
		return start, c.config.End
	}
	return start, c.config.TextEnd
}

// Stream follows the fixed core enumerator's compressed_length+1 advance,
// including its two-byte-header quirk. Each record separately retains actual
// header width, permitting forensic consumers to identify this discrepancy.
// Errors and cancellation stop enumeration and are never an empty success.
func (c *Core) Stream(ctx context.Context, emit func(Symbol) error) error {
	if emit == nil {
		return fmt.Errorf("nil kallsyms emitter")
	}
	offset := uint64(0)
	for i, address := range c.addresses {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, typ, length, header, err := c.Expand(ctx, offset)
		if err != nil {
			return fmt.Errorf("kallsyms name index %d offset %#x: %w", i, offset, err)
		}
		next, err := memory.Add(offset, length+1)
		if err != nil {
			return err
		}
		start, end := c.interval(address)
		symbol := Symbol{Index: uint64(i), Address: address, Name: name, Type: typ, NameOffset: offset, NextOffset: next, CompressedLength: length, HeaderBytes: header, SizeStart: start, SizeEnd: end}
		if end > start {
			symbol.Size = end - start
			symbol.SizeAvailable = true
		}
		if typ != "" {
			exported := typ >= "A" && typ <= "Z" || typ == "u" || typ == "v" || typ == "w"
			symbol.Exported = &exported
		}
		if err := emit(symbol); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		offset = next
	}
	return ctx.Err()
}
