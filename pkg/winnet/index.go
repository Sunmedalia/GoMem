package winnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Index walks native TCP/IP indexes, independently of pool carving. Kernel
// types are kept separate from the pinned network schema. All reads use Layer
// so callers can preserve original byte captures and failed accesses.
type Index struct {
	Layout     *Layout
	Layer      memory.MemoryLayer
	Kernel     symbols.SymbolTable
	TCPIP      symbols.SymbolTable
	ModuleBase uint64
	MaxNodes   uint64
	nodes      uint64
	first      error
	failures   uint64
	stop       error
}

type IndexEntry struct {
	Address     uint64
	Type, Route string
	Port        uint64
}
type IndexEmit func(IndexEntry) error

func (x *Index) failed(err error) {
	if err != nil {
		x.failures++
		if x.first == nil {
			x.first = err
		}
	}
}
func (x *Index) cause() error {
	if x.first == nil {
		return nil
	}
	return fmt.Errorf("network index: %d failure observations; first: %w", x.failures, x.first)
}
func (x *Index) step(ctx context.Context) error {
	if x.stop != nil {
		return x.stop
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if x.nodes >= x.MaxNodes {
		x.stop = fmt.Errorf("network index node bound exhausted")
		return x.stop
	}
	x.nodes++
	return nil
}
func (x *Index) pointer(ctx context.Context, at uint64) (uint64, error) {
	b, err := read(ctx, x.Layer, at, x.Layout.PointerSize())
	if err != nil {
		return 0, err
	}
	if len(b) == 4 {
		return uint64(binary.LittleEndian.Uint32(b)), nil
	}
	return binary.LittleEndian.Uint64(b), nil
}
func (x *Index) symbol(ctx context.Context, name string) (uint64, error) {
	s, err := x.TCPIP.Lookup(name)
	if err != nil {
		return 0, err
	}
	at, err := memory.Add(x.ModuleBase, s.Address)
	if err != nil {
		return 0, err
	}
	return x.pointer(ctx, at)
}

// indexNode is a bounded typed cursor. Dereference changes the coordinates,
// while nt_symbols! references switch type lookup to the kernel table only.
type indexNode struct {
	x   *Index
	at  uint64
	ref symbols.TypeRef
}

func (n indexNode) aggregate(ctx context.Context) (indexNode, error) {
	for depth := 0; n.ref.Kind == "pointer"; depth++ {
		if depth >= 64 || n.ref.Subtype == nil {
			return n, fmt.Errorf("invalid index pointer nesting")
		}
		at, err := n.x.pointer(ctx, n.at)
		if err != nil {
			return n, err
		}
		n.at, n.ref = at, *n.ref.Subtype
	}
	return n, nil
}
func (n indexNode) typ() (symbols.Type, error) {
	if strings.HasPrefix(n.ref.Name, "nt_symbols!") {
		return n.x.Kernel.Type(strings.TrimPrefix(n.ref.Name, "nt_symbols!"))
	}
	return n.x.Layout.table.Type(n.ref.Name)
}
func (n indexNode) field(ctx context.Context, name string) (indexNode, error) {
	n, err := n.aggregate(ctx)
	if err != nil {
		return n, err
	}
	if n.ref.Kind != "struct" && n.ref.Kind != "union" {
		return n, fmt.Errorf("network index field on nonaggregate")
	}
	typ, err := n.typ()
	if err != nil {
		return n, err
	}
	f, ok := typ.Fields[name]
	if !ok {
		return n, fmt.Errorf("network index field %s.%s absent", n.ref.Name, name)
	}
	if f.Offset > maxExtent {
		return n, fmt.Errorf("network index field offset exceeds bounds")
	}
	if strings.HasPrefix(n.ref.Name, "nt_symbols!") {
		f.Type = kernelIndexRef(f.Type)
	}
	at, err := memory.Add(n.at, f.Offset)
	return indexNode{n.x, at, f.Type}, err
}
func (n indexNode) size(ref symbols.TypeRef) (uint64, error) {
	if ref.Kind == "pointer" {
		return uint64(n.x.Layout.PointerSize()), nil
	}
	if strings.HasPrefix(ref.Name, "nt_symbols!") {
		t, err := n.x.Kernel.Type(strings.TrimPrefix(ref.Name, "nt_symbols!"))
		return t.Size, err
	}
	return n.x.Layout.size(ref, 0)
}
func (n indexNode) element(index uint64, override bool) (indexNode, error) {
	if n.ref.Kind != "array" || n.ref.Subtype == nil || (!override && index >= n.ref.Count) {
		return n, fmt.Errorf("network index array bounds")
	}
	if index > 655359 {
		return n, fmt.Errorf("network index array index exceeds bounds")
	}
	size, err := n.size(*n.ref.Subtype)
	if err != nil {
		return n, err
	}
	if size == 0 || size > maxExtent || index > ^uint64(0)/size {
		return n, fmt.Errorf("invalid network index stride")
	}
	at, err := memory.Add(n.at, index*size)
	return indexNode{n.x, at, *n.ref.Subtype}, err
}
func (n indexNode) scalar(ctx context.Context) (uint64, error) {
	if n.ref.Kind == "pointer" {
		return n.x.pointer(ctx, n.at)
	}
	table := symbols.SymbolTable(&n.x.Layout.table)
	ref := n.ref
	if strings.HasPrefix(ref.Name, "nt_symbols!") {
		table = n.x.Kernel
		ref.Name = strings.TrimPrefix(ref.Name, "nt_symbols!")
	}
	return (&object.Reader{Layer: n.x.Layer, Symbols: table}).Scalar(ctx, n.at, ref)
}
func (n indexNode) uint(ctx context.Context, name string) (uint64, error) {
	f, err := n.field(ctx, name)
	if err != nil {
		return 0, err
	}
	return f.scalar(ctx)
}
func (x *Index) node(at uint64, typ string) indexNode {
	return indexNode{x, at, symbols.TypeRef{Kind: "struct", Name: typ}}
}

// Bitmap preserves the baseline's byte-wise reads and least-significant-bit
// ordering. An unreasonable declared length fails explicitly rather than being
// silently interpreted as an empty index. Independent readable bytes survive.
func (x *Index) Bitmap(ctx context.Context, at, size uint64) ([]uint64, error) {
	if x == nil || x.Layer == nil || x.MaxNodes == 0 || x.MaxNodes > 16777216 {
		return nil, fmt.Errorf("invalid network bitmap configuration")
	}
	if size > 81920 {
		return nil, fmt.Errorf("network bitmap exceeds 81920 bytes")
	}
	var ports []uint64
	var first error
	for i := uint64(0); i < size; i++ {
		if err := x.step(ctx); err != nil {
			return ports, errors.Join(first, err)
		}
		current, err := memory.Add(at, i)
		if err != nil {
			return ports, errors.Join(first, err)
		}
		b, err := read(ctx, x.Layer, current, 1)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		for bit := uint64(0); bit < 8; bit++ {
			if b[0]&(1<<bit) != 0 {
				ports = append(ports, i*8+bit)
			}
		}
	}
	return ports, first
}

func (x *Index) partitions(ctx context.Context, emit IndexEmit) error {
	root, err := x.symbol(ctx, "PartitionTable")
	if err != nil {
		return err
	}
	countSymbol, err := x.TCPIP.Lookup("PartitionCount")
	if err != nil {
		return err
	}
	countAt, err := memory.Add(x.ModuleBase, countSymbol.Address)
	if err != nil {
		return err
	}
	b, err := read(ctx, x.Layer, countAt, 1)
	if err != nil {
		return err
	}
	partitions, err := x.node(root, "_PARTITION_TABLE").field(ctx, "Partitions")
	if err != nil {
		return err
	}
	member, err := x.member("_TCP_ENDPOINT", "ListEntry")
	if err != nil {
		return err
	}
	alignment := uint64(x.Layout.PointerSize() * 2)
	for i := uint64(0); i < uint64(b[0]); i++ {
		if err := x.step(ctx); err != nil {
			return err
		}
		partition, err := partitions.element(i, true)
		if err != nil {
			return err
		}
		endpoints, err := partition.field(ctx, "Endpoints")
		if err != nil {
			x.failed(err)
			continue
		}
		count, err := endpoints.uint(ctx, "NumEntries")
		if err != nil {
			x.failed(err)
			continue
		}
		if count == 0 {
			continue
		}
		directory, err := endpoints.uint(ctx, "Directory")
		if err != nil {
			x.failed(err)
			continue
		}
		length, err := endpoints.uint(ctx, "TableSize")
		if err != nil {
			x.failed(err)
			continue
		}
		if length > 4096 {
			x.failed(fmt.Errorf("network hash table exceeds 4096 entries"))
			continue
		}
		for j := uint64(0); j < length; j++ {
			if err := x.step(ctx); err != nil {
				return err
			}
			at, err := memory.Add(directory, j*alignment)
			if err != nil {
				return err
			}
			target, err := x.pointer(ctx, at)
			if err != nil {
				x.failed(err)
				continue
			}
			if target == at {
				continue
			}
			if target < member.Offset {
				x.failed(fmt.Errorf("network endpoint container underflow"))
				continue
			}
			if err := emit(IndexEntry{Address: target - member.Offset, Type: "_TCP_ENDPOINT", Route: "partition"}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (x *Index) pools(ctx context.Context) (uint64, uint64, error) {
	if _, err := x.TCPIP.Lookup("UdpPortPool"); err == nil {
		udp, err := x.symbol(ctx, "UdpPortPool")
		if err != nil {
			return 0, 0, err
		}
		tcp, err := x.symbol(ctx, "TcpPortPool")
		return udp, tcp, err
	}
	get := func(name string) (uint64, error) {
		at, err := x.symbol(ctx, name)
		if err != nil {
			return 0, err
		}
		node, err := x.node(at, "_INET_COMPARTMENT_SET").field(ctx, "InetCompartment")
		if err != nil {
			return 0, err
		}
		node, err = node.field(ctx, "ProtocolCompartment")
		if err != nil {
			return 0, err
		}
		return node.uint(ctx, "PortPool")
	}
	udp, err := get("UdpCompartmentSet")
	if err != nil {
		return 0, 0, err
	}
	tcp, err := get("TcpCompartmentSet")
	return udp, tcp, err
}
func (x *Index) port(ctx context.Context, pool, port uint64, typ string, emit IndexEmit) error {
	assignments, err := x.node(pool, "_INET_PORT_POOL").field(ctx, "PortAssignments")
	if err != nil {
		return err
	}
	assignment, err := assignments.element(port>>8, false)
	if err != nil {
		return err
	}
	big, err := assignment.field(ctx, "InPaBigPoolBase")
	if err != nil {
		return err
	}
	entries, err := big.field(ctx, "Assignments")
	if err != nil {
		return err
	}
	entry, err := entries.element(port&255, false)
	if err != nil {
		return err
	}
	target, err := entry.uint(ctx, "Entry")
	if err != nil {
		return err
	}
	next, err := x.member(typ, "Next")
	if err != nil {
		return err
	}
	visited := map[uint64]bool{}
	for target&^uint64(3) != 0 {
		if err := x.step(ctx); err != nil {
			return err
		}
		target &^= 3
		if target < next.Offset {
			return fmt.Errorf("network port container underflow")
		}
		at := target - next.Offset
		if visited[at] {
			return fmt.Errorf("network port chain cycle at %#x", at)
		}
		visited[at] = true
		if err := emit(IndexEntry{Address: at, Type: typ, Route: "port_pool", Port: port}); err != nil {
			return err
		}
		target, err = x.node(at, typ).uint(ctx, "Next")
		if err != nil {
			return err
		}
	}
	return nil
}

// Walk follows partitions, then TCP listener ports, then UDP ports. It preserves
// repeated entities across independent indexes; it never infers pool recovery
// or deduplicates by PID/address. Read/schema failures remain explicit.
func (x *Index) Walk(ctx context.Context, emit IndexEmit) error {
	if x == nil || x.Layout == nil || x.Layer == nil || x.Kernel == nil || x.TCPIP == nil || emit == nil || x.MaxNodes == 0 || x.MaxNodes > 16777216 {
		return fmt.Errorf("invalid network index configuration")
	}
	if x.Layout.PointerSize() != x.Kernel.PointerSize() || x.Layout.PointerSize() != x.TCPIP.PointerSize() {
		return fmt.Errorf("network index pointer width mismatch")
	}
	x.nodes, x.failures, x.first, x.stop = 0, 0, nil, nil
	if err := ctx.Err(); err != nil {
		return err
	}
	// Emitter failures are terminal, while an unreadable independent index can
	// still leave useful other indexes. Capture the original emitter error.
	var outputErr error
	send := func(entry IndexEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = emit(entry)
		return outputErr
	}
	x.failed(x.partitions(ctx, send))
	if outputErr != nil || ctx.Err() != nil || x.stop != nil {
		return errors.Join(x.cause(), outputErr, ctx.Err(), x.stop)
	}
	udp, tcp, err := x.pools(ctx)
	if err != nil {
		return errors.Join(x.cause(), err)
	}
	for _, pool := range []struct {
		at  uint64
		typ string
	}{{tcp, "_TCP_LISTENER"}, {udp, "_UDP_ENDPOINT"}} {
		bitmap, err := x.node(pool.at, "_INET_PORT_POOL").field(ctx, "PortBitMap")
		if err != nil {
			x.failed(err)
			continue
		}
		at, err := bitmap.uint(ctx, "Buffer")
		if err != nil {
			x.failed(err)
			continue
		}
		size, err := bitmap.uint(ctx, "SizeOfBitMap")
		if err != nil {
			x.failed(err)
			continue
		}
		ports, err := x.Bitmap(ctx, at, size/8)
		x.failed(err)
		for _, port := range ports {
			if port == 0 {
				continue
			}
			x.failed(x.port(ctx, pool.at, port, pool.typ, send))
			if outputErr != nil || ctx.Err() != nil || x.stop != nil {
				return errors.Join(x.cause(), outputErr, ctx.Err(), x.stop)
			}
		}
	}
	return errors.Join(x.cause(), ctx.Err())
}

func (x *Index) member(typ, name string) (symbols.Field, error) {
	t, ok := x.Layout.table.Types[typ]
	if !ok {
		return symbols.Field{}, fmt.Errorf("index type %s absent", typ)
	}
	f, ok := t.Fields[name]
	if !ok || f.Offset > maxExtent {
		return f, fmt.Errorf("index member %s.%s absent or out of bounds", typ, name)
	}
	return f, nil
}

func kernelIndexRef(ref symbols.TypeRef) symbols.TypeRef {
	if ref.Name != "" && !strings.Contains(ref.Name, "!") {
		ref.Name = "nt_symbols!" + ref.Name
	}
	if ref.Subtype != nil {
		child := kernelIndexRef(*ref.Subtype)
		ref.Subtype = &child
	}
	if ref.BitType != nil {
		child := kernelIndexRef(*ref.BitType)
		ref.BitType = &child
	}
	return ref
}
