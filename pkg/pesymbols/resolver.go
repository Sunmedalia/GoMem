// Package pesymbols resolves exact PE symbols across ordered module instances.
// PDB identity acquisition is supplied by the engine's network/cache policy.
package pesymbols

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

var ErrUnavailable = errors.New("matching module PDB is unavailable")

type Module struct {
	Layer      memory.MemoryLayer
	Base, Size uint64
}
type PDB struct {
	Table        symbols.SymbolTable
	Identity     symbols.PDBIdentity
	SourceSHA256 string
}
type Provider func(context.Context, Module) (PDB, error)
type Request struct {
	Names     []string
	Addresses []uint64
}
type Match struct {
	Name                                string
	Address                             uint64
	Module                              int
	Method, SymbolsSHA256, SourceSHA256 string
}
type Attempt struct {
	Module                      int
	Method                      string
	Err                         error
	Unavailable                 bool
	SymbolsSHA256, SourceSHA256 string
}
type Read struct {
	Module int
	Method string
	pe.ExportRead
}
type Options struct {
	PDB        Provider
	Limits     pe.ExportLimits
	MaxSymbols uint64
	Observe    func(Read) error
}
type Result struct {
	Found          []Match
	Missing        Request
	Attempts       []Attempt
	StoppedOnGroup bool
}

type loaded struct {
	pdbDone, exportDone bool
	pdb                 PDB
	pdbErr              error
	table               *pe.ExportTable
	exportErr           error
	byName              map[string]uint64
	byAddress           map[uint64]string
}

// Resolver owns one analysis run's acquisitions. It must not be shared between
// concurrently executing tasks. Failed acquisitions retain their errors on reuse.
type Resolver struct {
	modules           []Module
	options           Options
	cache             []loaded
	stop              error
	acquired, indexed uint64
}

func New(modules []Module, options Options) (*Resolver, error) {
	if len(modules) > 10000 || options.MaxSymbols == 0 || options.MaxSymbols > 10000000 {
		return nil, fmt.Errorf("invalid PE module/symbol bounds")
	}
	l := options.Limits
	if l.MaxEntries == 0 || l.MaxEntries > 1000000 || l.MaxBytes == 0 || l.MaxBytes > 1<<30 || l.MaxString == 0 || l.MaxString > 65536 {
		return nil, fmt.Errorf("invalid PE acquisition bounds")
	}
	if l.Observe != nil {
		return nil, fmt.Errorf("use resolver Observe to retain module and method identity")
	}
	for _, m := range modules {
		if m.Layer == nil || m.Size == 0 || m.Size > pe.MaxImageSize || m.Size-1 > ^uint64(0)-m.Base {
			return nil, fmt.Errorf("invalid mapped PE module extent")
		}
	}
	return &Resolver{modules: append([]Module(nil), modules...), options: options, cache: make([]loaded, len(modules))}, nil
}

type traceLayer struct {
	memory.MemoryLayer
	read  func(pe.ExportRead) error
	guard func(context.Context, int, uint64) error
}

func (l traceLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := l.guard(ctx, len(p), at); err != nil {
		return 0, err
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n, err = 0, fmt.Errorf("invalid module PDB read count")
	}
	if err == nil && n != len(p) {
		err = fmt.Errorf("short module PDB read: %d/%d", n, len(p))
	}
	if cause := l.read(pe.ExportRead{Address: at, Requested: len(p), Raw: append([]byte(nil), p[:n]...), Err: err}); cause != nil {
		return n, cause
	}
	return n, err
}
func (r *Resolver) observe(ctx context.Context, index int, method string, read pe.ExportRead) error {
	r.acquired += uint64(len(read.Raw))
	if r.stop != nil {
		return r.stop
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.options.Observe != nil {
		r.stop = r.options.Observe(Read{index, method, read})
	}
	if r.stop != nil {
		return r.stop
	}
	return ctx.Err()
}
func (r *Resolver) loadPDB(ctx context.Context, index int) *loaded {
	c := &r.cache[index]
	if c.pdbDone {
		return c
	}
	c.pdbDone = true
	if r.options.PDB == nil {
		c.pdbErr = ErrUnavailable
		return c
	}
	m := r.modules[index]
	m.Layer = traceLayer{MemoryLayer: m.Layer, read: func(read pe.ExportRead) error { return r.observe(ctx, index, "pdb", read) }, guard: func(ctx context.Context, n int, at uint64) error {
		if r.stop != nil {
			return r.stop
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if uint64(n) > r.options.Limits.MaxBytes-r.acquired {
			return fmt.Errorf("module symbol acquisition byte limit exhausted")
		}
		if at < m.Base || at-m.Base > m.Size || uint64(n) > m.Size-(at-m.Base) {
			return fmt.Errorf("module PDB read outside collected extent")
		}
		return nil
	}}
	c.pdb, c.pdbErr = r.options.PDB(ctx, m)
	if c.pdbErr != nil {
		return c
	}
	if c.pdb.Table == nil {
		c.pdbErr = fmt.Errorf("PDB provider returned no table")
		return c
	}
	var metadata struct {
		PDB symbols.PDBIdentity `json:"pdb"`
	}
	if err := json.Unmarshal(c.pdb.Table.Metadata()["windows"], &metadata); err != nil || !metadata.PDB.Equal(c.pdb.Identity) {
		c.pdbErr = fmt.Errorf("PDB provider table identity mismatch")
		return c
	}
	guid, validGUID := hex.DecodeString(strings.ReplaceAll(c.pdb.Identity.GUID, "-", ""))
	if validGUID != nil || len(guid) != 16 || c.pdb.Identity.Database == "" || strings.ContainsAny(c.pdb.Identity.Database, "\x00/\\") {
		c.pdbErr = fmt.Errorf("invalid provider PDB identity")
		return c
	}
	names := c.pdb.Table.Names()
	if uint64(len(names)) > r.options.MaxSymbols-r.indexed {
		c.pdbErr = fmt.Errorf("module PDB symbol count limit exhausted")
		return c
	}
	r.indexed += uint64(len(names))
	sort.Strings(names)
	c.byName = map[string]uint64{}
	c.byAddress = map[uint64]string{}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			c.pdbErr = err
			return c
		}
		symbol, err := c.pdb.Table.Lookup(name)
		if err != nil {
			c.pdbErr = err
			return c
		}
		at, err := memory.Add(r.modules[index].Base, symbol.Address)
		if err != nil {
			c.pdbErr = err
			return c
		}
		c.byName[name] = at
		if _, exists := c.byAddress[at]; !exists {
			c.byAddress[at] = name
		}
	}
	return c
}
func (r *Resolver) loadExports(ctx context.Context, index int) *loaded {
	c := &r.cache[index]
	if c.exportDone {
		return c
	}
	c.exportDone = true
	if r.acquired >= r.options.Limits.MaxBytes {
		c.exportErr = fmt.Errorf("module symbol acquisition byte limit exhausted")
		return c
	}
	l := r.options.Limits
	l.MaxBytes -= r.acquired
	l.Observe = func(read pe.ExportRead) error { return r.observe(ctx, index, "exports", read) }
	m := r.modules[index]
	c.table, c.exportErr = pe.ReadExports(ctx, extentLayer{MemoryLayer: m.Layer, base: m.Base, size: m.Size}, m.Base, l)
	if c.exportErr == nil && c.table.ImageSize > r.modules[index].Size {
		c.exportErr = fmt.Errorf("PE image exceeds collected module extent")
	}
	return c
}

type extentLayer struct {
	memory.MemoryLayer
	base, size uint64
}

func (l extentLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at < l.base || at-l.base > l.size || uint64(len(p)) > l.size-(at-l.base) {
		return 0, fmt.Errorf("module export acquisition exceeds collected extent")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

// Resolve follows the pinned PDB-first, all-instances-before-exports ordering.
// Duplicate requests remain duplicates. Like the fixed helper, exhausting either
// a names or addresses group stops processing even if the other group remains.
// StoppedOnGroup and Missing expose that baseline behavior explicitly.
func (r *Resolver) Resolve(ctx context.Context, request Request) (result Result, err error) {
	result.Missing = Request{Names: append([]string(nil), request.Names...), Addresses: append([]uint64(nil), request.Addresses...)}
	if len(request.Names)+len(request.Addresses) == 0 || len(request.Names)+len(request.Addresses) > 1000000 {
		return result, fmt.Errorf("PE symbol request must contain 1..1000000 values")
	}
	for _, name := range request.Names {
		if name == "" || len(name) > 65536 {
			return result, fmt.Errorf("invalid requested PE symbol name")
		}
	}
	if r.stop != nil {
		return result, r.stop
	}
	var failures []error
	for _, method := range []string{"pdb", "exports"} {
		for index := range r.modules {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			var c *loaded
			var cause error
			if method == "pdb" {
				c = r.loadPDB(ctx, index)
				cause = c.pdbErr
			} else {
				c = r.loadExports(ctx, index)
				cause = c.exportErr
			}
			attempt := Attempt{Module: index, Method: method, Err: cause, Unavailable: errors.Is(cause, ErrUnavailable)}
			if method == "pdb" && c.pdb.Table != nil {
				attempt.SymbolsSHA256 = c.pdb.Table.Digest()
				attempt.SourceSHA256 = c.pdb.SourceSHA256
			}
			result.Attempts = append(result.Attempts, attempt)
			if r.stop != nil {
				return result, r.stop
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if cause != nil {
				if !attempt.Unavailable {
					failures = append(failures, cause)
				}
				continue
			}
			nameAt := func(address uint64) (string, error) {
				if method == "pdb" {
					return c.byAddress[address], nil
				}
				raw, ok := c.table.NameAt(address)
				if !ok {
					return "", nil
				}
				for _, b := range raw {
					if b >= 128 {
						return "", fmt.Errorf("export name is not ASCII")
					}
				}
				return string(raw), nil
			}
			addressFor := func(name string) uint64 {
				if method == "pdb" {
					return c.byName[name]
				}
				at, _ := c.table.AddressForName([]byte(name))
				return at
			}
			match := func(name string, at uint64) {
				result.Found = append(result.Found, Match{name, at, index, method, attempt.SymbolsSHA256, attempt.SourceSHA256})
			}
			if len(result.Missing.Names) > 0 {
				pending := make([]string, 0, len(result.Missing.Names))
				for _, name := range result.Missing.Names {
					if err := ctx.Err(); err != nil {
						return result, err
					}
					if at := addressFor(name); at != 0 {
						match(name, at)
					} else {
						pending = append(pending, name)
					}
				}
				result.Missing.Names = pending
				if len(pending) == 0 {
					result.StoppedOnGroup = true
					return result, errors.Join(failures...)
				}
			}
			if len(result.Missing.Addresses) > 0 {
				pending := make([]uint64, 0, len(result.Missing.Addresses))
				for _, at := range result.Missing.Addresses {
					if err := ctx.Err(); err != nil {
						return result, err
					}
					name, cause := nameAt(at)
					if cause != nil {
						failures = append(failures, cause)
						pending = append(pending, at)
						continue
					}
					if name != "" {
						match(name, at)
					} else {
						pending = append(pending, at)
					}
				}
				result.Missing.Addresses = pending
				if len(pending) == 0 {
					result.StoppedOnGroup = true
					return result, errors.Join(failures...)
				}
			}
		}
	}
	return result, errors.Join(failures...)
}
