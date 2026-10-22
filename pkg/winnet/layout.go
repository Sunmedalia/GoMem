// Package winnet decodes Windows TCP/IP layouts with independently bounded
// field reads. Acquisition, kernel owner validation and version selection are
// responsibilities of its callers.
package winnet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const maxExtent = 1 << 20

var ErrInvalidState = errors.New("unknown TCP state")
var ErrClassExtension = errors.New("UDP layout requires an unavailable x86 class extension")

// Layout preserves the declared allocation size. Shipped TCP/IP descriptions
// can place fields outside it, so each field address/length is checked against
// its own finite limit and the actual source rather than resizing the type.
type Layout struct {
	table symbols.ISF
	hash  string
}

func Parse(data []byte) (*Layout, error) {
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, fmt.Errorf("network layout must be 1..4194304 bytes")
	}
	l := &Layout{}
	if err := json.Unmarshal(data, &l.table); err != nil {
		return nil, err
	}
	var format string
	if err := json.Unmarshal(l.table.Meta["format"], &format); err != nil || !strings.HasPrefix(format, "6.") {
		return nil, fmt.Errorf("network layout requires ISF format 6")
	}
	if l.table.PointerSize() != 4 && l.table.PointerSize() != 8 {
		return nil, fmt.Errorf("network layout requires 4/8 byte pointers")
	}
	if pointer := l.table.Bases["pointer"]; pointer.Kind != "int" || pointer.Endian != "little" {
		return nil, fmt.Errorf("Windows network pointers require little-endian integers")
	}
	if len(l.table.Types) == 0 || len(l.table.Types) > 4096 {
		return nil, fmt.Errorf("network type count outside 1..4096")
	}
	for name, typ := range l.table.Types {
		if typ.Size > maxExtent || len(typ.Fields) > 4096 {
			return nil, fmt.Errorf("network type %s exceeds bounds", name)
		}
		for field, definition := range typ.Fields {
			if definition.Offset > maxExtent {
				return nil, fmt.Errorf("network field %s.%s exceeds offset bound", name, field)
			}
		}
	}
	sum := sha256.Sum256(data)
	l.hash = hex.EncodeToString(sum[:])
	return l, nil
}

func (l *Layout) Digest() string   { return l.hash }
func (l *Layout) PointerSize() int { return l.table.PointerSize() }
func (l *Layout) DeclaredSize(name string) (uint64, error) {
	t, ok := l.table.Types[name]
	if !ok {
		return 0, fmt.Errorf("network type %q absent", name)
	}
	return t.Size, nil
}

func (l *Layout) size(ref symbols.TypeRef, depth int) (uint64, error) {
	if depth > 64 {
		return 0, fmt.Errorf("network field nesting exceeds 64")
	}
	switch ref.Kind {
	case "pointer":
		return uint64(l.PointerSize()), nil
	case "array":
		if ref.Subtype == nil {
			return 0, fmt.Errorf("network array has no subtype")
		}
		n, err := l.size(*ref.Subtype, depth+1)
		if err != nil {
			return 0, err
		}
		if ref.Count > maxExtent || n > maxExtent || n != 0 && ref.Count > maxExtent/n {
			return 0, fmt.Errorf("network array exceeds bounds")
		}
		return n * ref.Count, nil
	case "base", "struct", "union", "enum":
		typ, err := l.table.Type(ref.Name)
		if err != nil {
			return 0, err
		}
		if typ.Size > maxExtent {
			return 0, fmt.Errorf("network field type %q exceeds size bound", ref.Name)
		}
		return typ.Size, nil
	default:
		return 0, fmt.Errorf("unsupported network field kind %q", ref.Kind)
	}
}

func (l *Layout) field(typ, path string) (symbols.Field, uint64, error) {
	parts := strings.Split(path, ".")
	if len(parts) > 64 {
		return symbols.Field{}, 0, fmt.Errorf("network path exceeds bounds")
	}
	var at uint64
	var result symbols.Field
	for i, name := range parts {
		t, ok := l.table.Types[typ]
		if !ok {
			return result, 0, fmt.Errorf("network type %q absent", typ)
		}
		f, ok := t.Fields[name]
		if !ok {
			return result, 0, fmt.Errorf("network field %s.%s absent", typ, name)
		}
		if f.Offset > maxExtent-at {
			return result, 0, fmt.Errorf("network field offset exceeds bound")
		}
		at += f.Offset
		if i+1 < len(parts) && f.Type.Kind != "struct" && f.Type.Kind != "union" {
			return result, 0, fmt.Errorf("network path traverses a nonembedded member")
		}
		result, typ = f, f.Type.Name
	}
	n, err := l.size(result.Type, 0)
	if err != nil {
		return result, 0, err
	}
	if n > maxExtent-at {
		return result, 0, fmt.Errorf("network field extent exceeds bound")
	}
	result.Offset = at
	return result, n, nil
}

func (l *Layout) uint(ctx context.Context, layer memory.MemoryLayer, base uint64, typ, path string) (uint64, error) {
	f, size, err := l.field(typ, path)
	if err != nil {
		return 0, err
	}
	if f.Type.Kind != "base" && f.Type.Kind != "pointer" && f.Type.Kind != "enum" || size == 0 || size > 8 {
		return 0, fmt.Errorf("network field is not a bounded scalar")
	}
	at, err := memory.Add(base, f.Offset)
	if err != nil {
		return 0, err
	}
	buf, err := read(ctx, layer, at, int(size))
	if err != nil {
		return 0, err
	}
	endian := "little"
	if f.Type.Kind != "pointer" {
		t, err := l.table.Type(f.Type.Name)
		if err != nil {
			return 0, err
		}
		if t.Kind != "int" && t.Kind != "char" && t.Kind != "enum" {
			return 0, fmt.Errorf("network scalar is not an integer")
		}
		endian = t.Endian
	}
	var value uint64
	if endian == "big" {
		for _, b := range buf {
			value = value<<8 | uint64(b)
		}
	} else if endian == "little" {
		for i := len(buf) - 1; i >= 0; i-- {
			value = value<<8 | uint64(buf[i])
		}
	} else {
		return 0, fmt.Errorf("network scalar has unknown byte order %q", endian)
	}
	return value, nil
}

type Object struct {
	Layout *Layout
	Layer  memory.MemoryLayer
	// Native holds pointer targets when the allocation itself was scanned in
	// physical memory. Nil uses Layer, as for a kernel-virtual allocation.
	Native  memory.MemoryLayer
	Address uint64
	Type    string
}

func (o Object) native() memory.MemoryLayer {
	if o.Native != nil {
		return o.Native
	}
	return o.Layer
}

func read(ctx context.Context, layer memory.MemoryLayer, at uint64, n int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if layer == nil || n <= 0 || n > maxExtent {
		return nil, fmt.Errorf("invalid network read extent")
	}
	if _, err := memory.Add(at, uint64(n-1)); err != nil {
		return nil, err
	}
	return memory.Read(ctx, layer, at, n)
}

func (o Object) Scalar(ctx context.Context, path string) (uint64, error) {
	if o.Layout == nil || o.Layer == nil {
		return 0, fmt.Errorf("network object requires layout and source layer")
	}
	return o.Layout.uint(ctx, o.Layer, o.Address, o.Type, path)
}

func (o Object) Family(ctx context.Context) (uint64, error) {
	at, err := o.Scalar(ctx, "InetAF")
	if err != nil {
		return 0, err
	}
	return o.Layout.uint(ctx, o.native(), at, "_INETAF", "AddressFamily")
}

func (o Object) State(ctx context.Context) (string, error) {
	value, err := o.Scalar(ctx, "State")
	if err != nil {
		return "", err
	}
	f, _, err := o.Layout.field(o.Type, "State")
	if err != nil || f.Type.Kind != "enum" {
		return "", fmt.Errorf("network state is not an enumeration")
	}
	enum, err := o.Layout.table.Enumeration(f.Type.Name)
	if err != nil {
		return "", err
	}
	names := enum.Names(value)
	if len(names) != 1 {
		return "", ErrInvalidState
	}
	return names[0], nil
}

func (o Object) pointerAt(ctx context.Context, at uint64) (uint64, error) {
	buf, err := read(ctx, o.native(), at, o.Layout.PointerSize())
	if err != nil {
		return 0, err
	}
	if len(buf) == 4 {
		return uint64(binary.LittleEndian.Uint32(buf)), nil
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func (o Object) ip(ctx context.Context, at, family uint64) (string, error) {
	size := 16
	member := "addr6"
	if family == 2 {
		size = 4
		member = "addr4"
	}
	f, extent, err := o.Layout.field("_IN_ADDR", member)
	if err != nil {
		return "", err
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil || f.Type.Count != uint64(size) || extent != uint64(size) {
		return "", fmt.Errorf("network address array has unexpected extent")
	}
	address, err := memory.Add(at, f.Offset)
	if err != nil {
		return "", err
	}
	buf, err := read(ctx, o.native(), address, size)
	if err != nil {
		return "", err
	}
	// The pinned TCP helper treats any non-IPv4 family as IPv6. Validity is
	// separate; callers must retain the family/read error with these bytes.
	if size == 4 {
		return netip.AddrFrom4([4]byte(buf)).String(), nil
	}
	return netip.AddrFrom16([16]byte(buf)).String(), nil
}

func (o Object) TCPAddresses(ctx context.Context) (string, string, error) {
	family, familyErr := o.Family(ctx)
	info, err := o.Scalar(ctx, "AddrInfo")
	if err != nil {
		return "", "", errors.Join(familyErr, err)
	}
	local, localErr := o.Layout.uint(ctx, o.native(), info, "_ADDRINFO", "Local")
	if localErr == nil {
		local, localErr = o.Layout.uint(ctx, o.native(), local, "_LOCAL_ADDRESS", "pData")
	}
	if localErr == nil {
		local, localErr = o.pointerAt(ctx, local)
	}
	var localIP string
	if localErr == nil {
		localIP, localErr = o.ip(ctx, local, family)
	}
	remote, remoteErr := o.Layout.uint(ctx, o.native(), info, "_ADDRINFO", "Remote")
	var remoteIP string
	if remoteErr == nil {
		remoteIP, remoteErr = o.ip(ctx, remote, family)
	}
	return localIP, remoteIP, errors.Join(familyErr, localErr, remoteErr)
}

type Socket struct{ Version, Local, Remote string }

func (o Object) ListenerSockets(ctx context.Context) ([]Socket, error) {
	if o.Layout == nil || o.Layer == nil {
		return nil, fmt.Errorf("network object requires layout and source layer")
	}
	family, familyErr := o.Family(ctx)
	local, localErr := o.Scalar(ctx, "LocalAddr")
	f, _, err := o.Layout.field(o.Type, "LocalAddr")
	if err != nil || f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" {
		return nil, fmt.Errorf("listener address has no structure subtype")
	}
	addressType := f.Type.Subtype.Name
	if localErr == nil {
		local, localErr = o.Layout.uint(ctx, o.native(), local, addressType, "pData")
	}
	pdata, _, err := o.Layout.field(addressType, "pData")
	if err != nil || pdata.Type.Subtype == nil {
		return nil, fmt.Errorf("listener data pointer has no subtype")
	}
	double := pdata.Type.Subtype.Kind == "pointer"
	if double && localErr == nil {
		local, localErr = o.pointerAt(ctx, local)
	}
	if localErr == nil {
		var probe symbols.Field
		probe, _, localErr = o.Layout.field("_IN_ADDR", "addr4")
		if localErr == nil {
			var at uint64
			at, localErr = memory.Add(local, probe.Offset)
			if localErr == nil {
				_, localErr = read(ctx, o.native(), at, 1)
			}
		}
	}
	if localErr == nil && (!double || local != 0) {
		if addressType == "_LOCAL_ADDRESS_WIN10_UDP" && o.Layout.PointerSize() == 4 {
			return nil, errors.Join(familyErr, ErrClassExtension)
		}
		if family != 2 && family != 23 {
			return nil, familyErr
		}
		ip, err := o.ip(ctx, local, family)
		if err != nil {
			return nil, errors.Join(familyErr, err)
		}
		if family == 2 {
			return []Socket{{"v4", ip, "0.0.0.0"}}, familyErr
		}
		return []Socket{{"v6", ip, "::"}}, familyErr
	}
	result := []Socket{{"v4", "0.0.0.0", "0.0.0.0"}}
	if family == 23 {
		result = append(result, Socket{"v6", "::", "::"})
	}
	return result, errors.Join(familyErr, localErr)
}
