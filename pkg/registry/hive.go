// Package registry reads Windows hive cells through the kernel HMAP.
// Bin addresses in the upper canonical range are read from the kernel.
// Lower addresses are read from the supplied process layer, which on
// Windows 10 is normally the Registry process.
package registry

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

const (
	hiveSignature   = 0xBEE0BEE0
	keyCompressed   = 0x20
	valueCompressed = 0x01
	bigDataLimit    = 0x4000
	bigDataBlock    = 0x3FD8
	maxCell         = 1 << 20
	maxName         = 4096
	maxIndex        = 1 << 20
	rootFallback    = 0x20
)

// Offsets are the in-memory _HHIVE / _DUAL / _HMAP_ENTRY layout from symbols.
// Key and value cells use the stable registry file format.
type Offsets struct {
	BaseBlock      uint64
	Storage        uint64
	Version        uint64
	DualSize       uint64
	Map            uint64
	Length         uint64
	EntrySize      uint64
	BlockOffset    uint64
	Permanent      uint64
	BlockWidth     int
	PermanentWidth int
	PointerSize    int
}

func (o Offsets) validate() error {
	if o.PointerSize != 4 && o.PointerSize != 8 {
		return fmt.Errorf("unsupported hive pointer size %d", o.PointerSize)
	}
	if o.DualSize == 0 || o.EntrySize < 8 || o.BlockWidth < 4 || o.BlockWidth > 8 || o.PermanentWidth < 4 || o.PermanentWidth > 8 {
		return fmt.Errorf("incomplete hive map layout")
	}
	if o.Storage < o.BaseBlock || o.Map < o.Length {
		return fmt.Errorf("hive storage layout is inconsistent")
	}
	return nil
}

// Hive is one _CMHIVE and the two storage maps that translate its cell indexes.
type Hive struct {
	Offsets   Offsets
	Address   uint64
	Name      string
	Kernel    memory.MemoryLayer
	Process   memory.MemoryLayer
	Version   uint32
	Root      uint32
	RootFrom  string
	Fallbacks int
	storage   [2]store
}

type store struct {
	length uint32
	dir    uint64
}

// Key is one nk cell.
type Key struct {
	Index     uint32
	Address   uint64
	Name      string
	Flags     uint16
	LastWrite uint64
	Volatile  bool
	values    uint32
	valueList uint32
	lists     [2]uint32
	counts    [2]uint32
}

// Value is one vk cell. DataErr is set when the declared bytes could not be read.
type Value struct {
	Index    uint32
	Name     string
	Type     uint32
	Data     []byte
	DataErr  error
	Volatile bool
}

func Open(ctx context.Context, kernel, process memory.MemoryLayer, address uint64, name string, off Offsets) (*Hive, error) {
	if err := off.validate(); err != nil {
		return nil, err
	}
	if kernel == nil {
		return nil, fmt.Errorf("kernel layer is required")
	}
	signature, err := readAt(ctx, kernel, address, 4)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(signature) != hiveSignature {
		return nil, fmt.Errorf("hive %#x signature is not %#x", address, hiveSignature)
	}
	h := &Hive{Offsets: off, Address: address, Name: name, Kernel: kernel, Process: process}
	if h.Name == "" {
		h.Name = "[NONAME]"
	}
	base, err := readPointer(ctx, kernel, address+off.BaseBlock, off.PointerSize)
	if err != nil {
		return nil, fmt.Errorf("hive base block pointer: %w", err)
	}
	version, err := readAt(ctx, kernel, address+off.Version, 4)
	if err != nil {
		return nil, fmt.Errorf("hive version: %w", err)
	}
	h.Version = binary.LittleEndian.Uint32(version)
	for i := range h.storage {
		origin := address + off.Storage + uint64(i)*off.DualSize
		length, err := readAt(ctx, kernel, origin+off.Length, 4)
		if err != nil {
			h.storage[i].length = 0x7fffffff
		} else {
			h.storage[i].length = binary.LittleEndian.Uint32(length)
		}
		dir, err := readPointer(ctx, kernel, origin+off.Map, off.PointerSize)
		if err != nil {
			return nil, fmt.Errorf("hive storage %d map: %w", i, err)
		}
		h.storage[i].dir = dir
	}
	h.Root, h.RootFrom, err = h.root(ctx, base)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Hive) root(ctx context.Context, base uint64) (uint32, string, error) {
	if base == 0 {
		return rootFallback, "fallback", nil
	}
	sig, err := h.read(ctx, base, 4)
	if err != nil || string(sig) != "regf" {
		return rootFallback, "fallback", nil
	}
	raw, err := h.read(ctx, base+36, 4)
	if err != nil {
		return rootFallback, "fallback", nil
	}
	return binary.LittleEndian.Uint32(raw), "base_block", nil
}

// read selects the kernel layer for canonical addresses and the process layer
// for lower addresses. A kernel page that is prototype or otherwise unreadable
// is retried through the Registry process, which is the layer that actually
// maps those hive bins. User addresses are never read from the kernel.
func (h *Hive) read(ctx context.Context, address uint64, n int) ([]byte, error) {
	layer, err := h.layer(address)
	if err != nil {
		return nil, err
	}
	buf, err := readAt(ctx, layer, address, n)
	if err == nil || h.Process == nil || layer == h.Process {
		return buf, err
	}
	alt, altErr := readAt(ctx, h.Process, address, n)
	if altErr != nil {
		return nil, err
	}
	h.Fallbacks++
	return alt, nil
}

// LayerName reports the kernel or process layer that would read address.
func (h *Hive) LayerName(address uint64) (string, bool) {
	layer, err := h.layer(address)
	if err != nil || layer == nil {
		return "", false
	}
	return layer.Name(), true
}

func (h *Hive) layer(address uint64) (memory.MemoryLayer, error) {
	var kernelMin uint64 = 0x80000000
	if h.Offsets.PointerSize == 8 {
		kernelMin = 0xffff800000000000
	}
	if address >= kernelMin {
		return h.Kernel, nil
	}
	if h.Process == nil {
		return nil, fmt.Errorf("registry process layer is required for %#x", address)
	}
	return h.Process, nil
}

func (h *Hive) translate(ctx context.Context, index uint32) (uint64, error) {
	volatile := index >> 31
	logical := index & 0x7fffffff
	st := h.storage[volatile]
	if logical > st.length {
		return 0, fmt.Errorf("cell %#x exceeds store length %#x", index, st.length)
	}
	if st.dir == 0 {
		return 0, fmt.Errorf("cell %#x has no storage map", index)
	}
	dirIndex := uint64((index >> 21) & 0x3ff)
	tableIndex := uint64((index >> 12) & 0x1ff)
	sub := uint64(index & 0xfff)
	table, err := h.readPointer(ctx, st.dir+dirIndex*uint64(h.Offsets.PointerSize), h.Offsets.PointerSize)
	if err != nil {
		return 0, fmt.Errorf("hive directory %d: %w", dirIndex, err)
	}
	entry := table + tableIndex*h.Offsets.EntrySize
	block, err := h.readWidth(ctx, entry+h.Offsets.BlockOffset, h.Offsets.BlockWidth)
	if err != nil {
		return 0, fmt.Errorf("hive map entry: %w", err)
	}
	permanent, err := h.readWidth(ctx, entry+h.Offsets.Permanent, h.Offsets.PermanentWidth)
	if err != nil {
		return 0, fmt.Errorf("hive bin address: %w", err)
	}
	return (permanent &^ 0xF) + block + sub, nil
}

func (h *Hive) cell(ctx context.Context, index uint32) (uint64, []byte, error) {
	address, err := h.translate(ctx, index)
	if err != nil {
		return 0, nil, err
	}
	header, err := h.read(ctx, address, 4)
	if err != nil {
		return 0, nil, err
	}
	size := int32(binary.LittleEndian.Uint32(header))
	if size >= 0 {
		return 0, nil, fmt.Errorf("free cell %#x", index)
	}
	total := int(-size)
	if total < 6 || total > maxCell {
		return 0, nil, fmt.Errorf("cell %#x has size %d", index, total)
	}
	buf, err := h.read(ctx, address, total)
	if err != nil {
		return 0, nil, err
	}
	return address + 4, buf[4:], nil
}

func (h *Hive) RootKey(ctx context.Context) (Key, error) {
	return h.key(ctx, h.Root)
}

func (h *Hive) key(ctx context.Context, index uint32) (Key, error) {
	address, payload, err := h.cell(ctx, index)
	if err != nil {
		return Key{}, err
	}
	if len(payload) < 76 || string(payload[:2]) != "nk" {
		return Key{}, fmt.Errorf("cell %#x is not a key node", index)
	}
	nameLen := int(binary.LittleEndian.Uint16(payload[72:74]))
	if nameLen < 0 || nameLen > maxName || 76+nameLen > len(payload) {
		return Key{}, fmt.Errorf("key %#x name length %d", index, nameLen)
	}
	flags := binary.LittleEndian.Uint16(payload[2:4])
	name, err := decodeLabel(flags, keyCompressed, payload[76:76+nameLen])
	if err != nil {
		return Key{}, err
	}
	key := Key{
		Index: index, Address: address, Name: name, Flags: flags,
		LastWrite: binary.LittleEndian.Uint64(payload[4:12]),
		Volatile:  index&0x80000000 != 0,
		values:    binary.LittleEndian.Uint32(payload[36:40]),
		valueList: binary.LittleEndian.Uint32(payload[40:44]),
	}
	for i := 0; i < 2; i++ {
		key.counts[i] = binary.LittleEndian.Uint32(payload[20+i*4 : 24+i*4])
		key.lists[i] = binary.LittleEndian.Uint32(payload[28+i*4 : 32+i*4])
	}
	return key, nil
}

// Subkeys returns stable keys first, then volatile keys, in index order.
func (h *Hive) Subkeys(ctx context.Context, key Key) ([]Key, error) {
	var out []Key
	var errs []error
	seen := map[uint32]bool{}
	for i := 0; i < 2; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if key.counts[i] == 0 {
			continue
		}
		keys, err := h.indexKeys(ctx, key.lists[i], seen, 0)
		out = append(out, keys...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func (h *Hive) indexKeys(ctx context.Context, index uint32, seen map[uint32]bool, depth int) ([]Key, error) {
	if depth > 8 {
		return nil, fmt.Errorf("registry index nesting exceeded")
	}
	_, payload, err := h.cell(ctx, index)
	if err != nil {
		return nil, err
	}
	if len(payload) < 4 {
		return nil, fmt.Errorf("short registry index %#x", index)
	}
	signature := string(payload[:2])
	if signature == "nk" {
		key, err := h.key(ctx, index)
		if err != nil {
			return nil, err
		}
		return []Key{key}, nil
	}
	count := int(binary.LittleEndian.Uint16(payload[2:4]))
	if count < 0 || count > maxIndex {
		return nil, fmt.Errorf("registry index %#x count %d", index, count)
	}
	jump := 0
	switch signature {
	case "lf", "lh":
		jump = 2
	case "ri":
		jump = 1
	default:
		return nil, fmt.Errorf("registry index %#x signature %q", index, signature)
	}
	need := 4 + count*jump*4
	if need > len(payload) {
		return nil, fmt.Errorf("registry index %#x truncated", index)
	}
	var out []Key
	var errs []error
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		child := binary.LittleEndian.Uint32(payload[4+i*jump*4 : 8+i*jump*4])
		if seen[child] {
			continue
		}
		seen[child] = true
		if signature == "ri" {
			nested, err := h.indexKeys(ctx, child, seen, depth+1)
			out = append(out, nested...)
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		key, err := h.key(ctx, child)
		if err != nil {
			errs = append(errs, fmt.Errorf("subkey %#x: %w", child, err))
			continue
		}
		out = append(out, key)
	}
	return out, errors.Join(errs...)
}

func (h *Hive) Values(ctx context.Context, key Key) ([]Value, error) {
	if key.values == 0 {
		return nil, nil
	}
	if key.values > maxIndex {
		return nil, fmt.Errorf("key %#x has %d values", key.Index, key.values)
	}
	_, payload, err := h.cell(ctx, key.valueList)
	if err != nil {
		return nil, err
	}
	if len(payload) < int(key.values)*4 {
		return nil, fmt.Errorf("value list %#x truncated", key.valueList)
	}
	out := make([]Value, 0, key.values)
	var errs []error
	for i := uint32(0); i < key.values; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		index := binary.LittleEndian.Uint32(payload[i*4 : i*4+4])
		if index == 0 {
			continue
		}
		value, err := h.value(ctx, index, key.Volatile)
		if err != nil {
			errs = append(errs, fmt.Errorf("value %#x: %w", index, err))
			continue
		}
		out = append(out, value)
	}
	return out, errors.Join(errs...)
}

func (h *Hive) value(ctx context.Context, index uint32, parentVolatile bool) (Value, error) {
	_, payload, err := h.cell(ctx, index)
	if err != nil {
		return Value{}, err
	}
	if len(payload) < 20 || string(payload[:2]) != "vk" {
		return Value{}, fmt.Errorf("cell %#x is not a value", index)
	}
	nameLen := int(binary.LittleEndian.Uint16(payload[2:4]))
	if nameLen > maxName || 20+nameLen > len(payload) {
		return Value{}, fmt.Errorf("value %#x name length %d", index, nameLen)
	}
	flags := binary.LittleEndian.Uint16(payload[16:18])
	name, err := decodeLabel(flags, valueCompressed, payload[20:20+nameLen])
	if err != nil {
		return Value{}, err
	}
	value := Value{
		Index: index, Name: name, Type: binary.LittleEndian.Uint32(payload[12:16]),
		Volatile: parentVolatile,
	}
	dataLen := binary.LittleEndian.Uint32(payload[4:8])
	dataCell := binary.LittleEndian.Uint32(payload[8:12])
	value.Data, value.DataErr = h.valueBytes(ctx, dataLen, dataCell, payload[8:12])
	return value, nil
}

func (h *Hive) valueBytes(ctx context.Context, dataLen, dataCell uint32, inline []byte) ([]byte, error) {
	if dataLen&0x80000000 != 0 {
		n := dataLen & 0x7fffffff
		if n > 4 {
			return nil, fmt.Errorf("inline registry value length %d", n)
		}
		return append([]byte(nil), inline[:n]...), nil
	}
	if dataLen == 0 {
		return []byte{}, nil
	}
	if dataLen > maxCell {
		return nil, fmt.Errorf("registry value length %d", dataLen)
	}
	if h.Version == 5 && dataLen > bigDataLimit {
		return h.bigData(ctx, dataCell, dataLen)
	}
	_, payload, err := h.cell(ctx, dataCell)
	if err != nil {
		return nil, err
	}
	if uint32(len(payload)) < dataLen {
		return nil, fmt.Errorf("registry value cell has %d bytes, declared %d", len(payload), dataLen)
	}
	return append([]byte(nil), payload[:dataLen]...), nil
}

// bigData follows the on-disk CM_BIG_DATA list. Each pointer is read at
// translate(list+i*4)+4, which lands on successive uint32 cell indexes inside
// one list cell because the cell header is four bytes. Short or unreadable
// blocks are errors. Missing bytes are not replaced with zeroes.
func (h *Hive) bigData(ctx context.Context, index, dataLen uint32) ([]byte, error) {
	_, payload, err := h.cell(ctx, index)
	if err != nil {
		return nil, err
	}
	if len(payload) < 8 || string(payload[:2]) != "db" {
		return nil, fmt.Errorf("cell %#x is not big data", index)
	}
	count := int(binary.LittleEndian.Uint16(payload[2:4]))
	list := binary.LittleEndian.Uint32(payload[4:8])
	if count < 0 || count > maxIndex {
		return nil, fmt.Errorf("big data cell %#x count %d", index, count)
	}
	out := make([]byte, 0, dataLen)
	remain := dataLen
	for i := 0; i < count && remain > 0; i++ {
		pointerIndex, err := addCell(list, uint32(i*4))
		if err != nil {
			return nil, err
		}
		block, err := h.cellU32(ctx, pointerIndex)
		if err != nil {
			return nil, err
		}
		_, blockPayload, err := h.cell(ctx, block)
		if err != nil {
			return nil, err
		}
		n := remain
		if n > bigDataBlock {
			n = bigDataBlock
		}
		if uint32(len(blockPayload)) < n {
			return nil, fmt.Errorf("big data block %d has %d bytes", i, len(blockPayload))
		}
		out = append(out, blockPayload[:n]...)
		remain -= n
	}
	if remain != 0 {
		return nil, fmt.Errorf("big data ended %d bytes early", remain)
	}
	return out, nil
}

func (h *Hive) cellU32(ctx context.Context, index uint32) (uint32, error) {
	address, err := h.translate(ctx, index)
	if err != nil {
		return 0, err
	}
	target, err := memory.Add(address, 4)
	if err != nil {
		return 0, err
	}
	raw, err := h.read(ctx, target, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func addCell(index, delta uint32) (uint32, error) {
	if delta > ^uint32(0)-index {
		return 0, fmt.Errorf("registry cell index overflow")
	}
	return index + delta, nil
}

func decodeLabel(flags uint16, compressed uint16, raw []byte) (string, error) {
	if flags&compressed != 0 {
		buf := make([]rune, len(raw))
		for i, b := range raw {
			buf[i] = rune(b)
		}
		return string(buf), nil
	}
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("utf-16 registry name has odd length %d", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	decoded := string(utf16.Decode(units))
	if !utf8.ValidString(decoded) {
		return "", fmt.Errorf("registry name is not utf-8")
	}
	return decoded, nil
}

func (h *Hive) readPointer(ctx context.Context, address uint64, size int) (uint64, error) {
	return h.readWidth(ctx, address, size)
}

func (h *Hive) readWidth(ctx context.Context, address uint64, size int) (uint64, error) {
	buf, err := h.read(ctx, address, size)
	if err != nil {
		return 0, err
	}
	var value uint64
	for i, b := range buf {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func readPointer(ctx context.Context, layer memory.MemoryLayer, address uint64, size int) (uint64, error) {
	return readWidth(ctx, layer, address, size)
}

func readWidth(ctx context.Context, layer memory.MemoryLayer, address uint64, size int) (uint64, error) {
	buf, err := readAt(ctx, layer, address, size)
	if err != nil {
		return 0, err
	}
	var value uint64
	for i, b := range buf {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func readAt(ctx context.Context, layer memory.MemoryLayer, address uint64, n int) ([]byte, error) {
	if layer == nil {
		return nil, fmt.Errorf("registry data layer is unavailable")
	}
	return memory.Read(ctx, layer, address, n)
}
