package kallsyms

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

// ResolverLimits bounds the resident core index and the retained module index.
// NodesPerSource bounds each source search. Layer must capture acquisitions and
// enforce a shared byte budget across all sources, including initial Open.
type ResolverLimits struct {
	Core                          Limits
	NodesPerSource, ModuleSymbols int
}

type Resolution struct {
	Address        uint64
	Source, Module string
	Symbol         *Symbol
	Attempted      []string
	Unavailable    map[string]string
	ModuleSearch   *ModuleLookup
	BPF            *BPFMatch
	Ftrace         *FtraceMatch
}
type ResolverStats struct {
	Queries, Resolved, NoMatch, Failed uint64
	Core                               Stats
	CachedModules, CachedModuleSymbols uint64
}

// Resolver owns mutable core and module snapshot indices for one immutable
// acquisition/symbol table. Do not share it concurrently or replace its Layer.
// Configuration failures in later sources are deferred until that source is
// reached, so an unrelated missing source cannot invalidate a core match.
type Resolver struct {
	reader         object.Reader
	core           *Core
	mask           uint64
	module         ModuleConfig
	moduleErr      error
	modules        moduleCache
	bpf            BPFConfig
	bpfErr         error
	bpfUnavailable string
	ftrace         FtraceConfig
	ftraceErr      error
	stats          ResolverStats
}

func OpenResolver(ctx context.Context, r *object.Reader, slide, mask uint64, limits ResolverLimits) (*Resolver, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.Layer == nil || r.Symbols == nil || mask == 0 || limits.NodesPerSource < 1 || limits.NodesPerSource > 1000000 || limits.ModuleSymbols < 1 || limits.ModuleSymbols > 10000000 {
		return nil, fmt.Errorf("invalid symbol resolver configuration")
	}
	c, err := FromSymbols(r.Symbols, slide, mask)
	if err != nil {
		return nil, fmt.Errorf("core configuration: %w", err)
	}
	core, err := Open(ctx, r.Layer, c, limits.Core)
	if err != nil {
		return nil, fmt.Errorf("core index: %w", err)
	}
	s := &Resolver{reader: *r, core: core, mask: mask}
	s.module, s.moduleErr = ModuleFromSymbols(r.Symbols, slide, mask, limits.NodesPerSource, limits.ModuleSymbols)
	s.ftrace, s.ftraceErr = FtraceFromSymbols(r.Symbols, slide, mask, limits.NodesPerSource)
	s.bpf = BPFConfig{AddressMask: mask, MaxNodes: limits.NodesPerSource, Layout: "legacy"}
	if _, err := r.Symbols.Type("bpf_ksym"); err == nil {
		s.bpf.Layout = "modern"
	} else {
		if _, err := r.Symbols.Type("latch_tree_root"); err != nil {
			s.bpfUnavailable = "latch_tree_root type absent"
		} else {
			_, err := r.Field("bpf_prog_aux", "ksym_tnode")
			if errors.Is(err, object.ErrFieldAbsent) {
				s.bpfUnavailable = "legacy BPF latch node absent"
			} else if err != nil {
				s.bpfErr = err
			}
		}
	}
	if s.bpfUnavailable == "" && s.bpfErr == nil {
		found := false
		for _, name := range r.Symbols.Names() {
			if name == "bpf_tree" {
				found = true
				symbol, err := r.Symbols.Lookup(name)
				if err == nil {
					s.bpf.Root, err = memory.Add(symbol.Address, slide)
				}
				s.bpfErr = err
				break
			}
		}
		if !found {
			s.bpfUnavailable = "bpf_tree symbol absent"
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Resolver) Stats() ResolverStats {
	if s == nil || s.core == nil {
		return ResolverStats{}
	}
	v := s.stats
	v.Core = s.core.Stats()
	v.CachedModules = uint64(len(s.modules.tables))
	v.CachedModuleSymbols = s.modules.symbols
	return v
}

// Lookup applies the fixed core -> module -> BPF -> ftrace order and stops at
// the first match or error. Earlier no-match evidence remains in the result.
// Legacy BPF uses the independently validated native region primitive rather
// than reproducing the fixed missing get_addr_region method AttributeError.
func (s *Resolver) Lookup(ctx context.Context, address uint64) (out Resolution, err error) {
	if s == nil || s.core == nil {
		return out, fmt.Errorf("nil symbol resolver")
	}
	out.Address = address & s.mask
	s.stats.Queries++
	defer func() {
		if err != nil {
			out.Symbol = nil
			out.Source = ""
			out.Module = ""
			s.stats.Failed++
		} else if out.Symbol != nil {
			s.stats.Resolved++
		} else {
			s.stats.NoMatch++
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	out.Attempted = append(out.Attempted, "core")
	symbol, cause := s.core.Lookup(ctx, out.Address)
	if cause != nil {
		return out, fmt.Errorf("core lookup: %w", cause)
	}
	if symbol != nil {
		out.Symbol = symbol
		out.Source = "core"
		out.Module = "kernel"
		return out, ctx.Err()
	}
	out.Attempted = append(out.Attempted, "module")
	if s.moduleErr != nil {
		return out, fmt.Errorf("module configuration: %w", s.moduleErr)
	}
	m, cause := lookupModule(ctx, &s.reader, s.module, out.Address, nil, &s.modules)
	out.ModuleSearch = &m
	if cause != nil {
		return out, fmt.Errorf("module lookup: %w", cause)
	}
	if m.Match != nil {
		copy := m.Match.Symbol
		out.Symbol = &copy
		out.Source = "module"
		out.Module = m.Match.Module
		return out, ctx.Err()
	}
	out.Attempted = append(out.Attempted, "bpf")
	if s.bpfErr != nil {
		return out, fmt.Errorf("BPF configuration: %w", s.bpfErr)
	}
	if s.bpfUnavailable != "" {
		out.Unavailable = map[string]string{"bpf": s.bpfUnavailable}
	}
	out.BPF, cause = LookupBPF(ctx, &s.reader, s.bpf, out.Address)
	if cause != nil {
		return out, fmt.Errorf("BPF lookup: %w", cause)
	}
	if out.BPF != nil {
		copy := out.BPF.Symbol
		out.Symbol = &copy
		out.Source = "bpf"
		out.Module = "bpf"
		return out, ctx.Err()
	}
	out.Attempted = append(out.Attempted, "ftrace")
	if s.ftraceErr != nil {
		return out, fmt.Errorf("ftrace configuration: %w", s.ftraceErr)
	}
	out.Ftrace, cause = LookupFtrace(ctx, &s.reader, s.ftrace, out.Address)
	if cause != nil {
		return out, fmt.Errorf("ftrace lookup: %w", cause)
	}
	if out.Ftrace != nil {
		copy := out.Ftrace.Symbol
		out.Symbol = &copy
		out.Source = "ftrace"
		out.Module = out.Ftrace.Module
		return out, ctx.Err()
	}
	if !s.ftrace.HasMaps && !s.ftrace.HasTrampolines {
		if out.Unavailable == nil {
			out.Unavailable = map[string]string{}
		}
		out.Unavailable["ftrace"] = "optional types or roots absent"
	}
	return out, ctx.Err()
}
