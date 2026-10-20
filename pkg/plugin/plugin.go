// Package plugin is the compile-time extension interface. Plugins stream rows
// under caller cancellation and declare their parameters and prerequisites.
package plugin

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Parameter struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
}
type Spec struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Upstream     string            `json:"upstream,omitempty"`
	Platform     string            `json:"platform,omitempty"`
	Parameters   []Parameter       `json:"parameters,omitempty"`
	Columns      []evidence.Column `json:"columns"`
	NeedsKernel  bool              `json:"needs_kernel"`
	Dependencies []string          `json:"dependencies,omitempty"`
}
type Environment struct {
	Artifacts      evidence.ArtifactSink
	Physical       memory.MemoryLayer
	Kernel         memory.MemoryLayer
	Symbols        symbols.SymbolTable
	Objects        *object.Reader
	OS             string
	Architecture   string
	KernelBase     uint64
	KernelSlide    uint64
	ImageHash      string
	SymbolLocation string
}

func (e Environment) Symbol(name string) (uint64, error) {
	s, err := e.Symbols.Lookup(name)
	if err != nil {
		return 0, err
	}
	offset := e.KernelSlide
	if e.OS == "windows" {
		offset = e.KernelBase
	}
	return memory.Add(s.Address, offset)
}

type Emit func(evidence.Row) error
type Plugin interface {
	Spec() Spec
	Run(context.Context, Environment, map[string]string, Emit) error
}
type Registry struct{ entries map[string]Plugin }

func NewRegistry() *Registry { return &Registry{entries: make(map[string]Plugin)} }
func (r *Registry) Register(p Plugin) error {
	n := p.Spec().Name
	if n == "" {
		return fmt.Errorf("empty plugin name")
	}
	if _, ok := r.entries[n]; ok {
		return fmt.Errorf("duplicate plugin %s", n)
	}
	r.entries[n] = p
	return nil
}
func (r *Registry) Get(n string) (Plugin, error) {
	p, ok := r.entries[n]
	if !ok {
		return nil, fmt.Errorf("plugin %q is not implemented in this development preview; see docs/capabilities.json", n)
	}
	return p, nil
}
func (r *Registry) List() []Spec {
	out := make([]Spec, 0, len(r.entries))
	for _, p := range r.entries {
		out = append(out, p.Spec())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func Parameters(s Spec, in map[string]string) (map[string]string, error) {
	out := make(map[string]string)
	defs := make(map[string]Parameter)
	for _, d := range s.Parameters {
		defs[d.Name] = d
		out[d.Name] = d.Default
	}
	for k, v := range in {
		if _, ok := defs[k]; !ok {
			return nil, fmt.Errorf("unknown parameter %s for %s", k, s.Name)
		}
		out[k] = v
	}
	for k, v := range out {
		d := defs[k]
		switch d.Kind {
		case "uint":
			if _, e := strconv.ParseUint(v, 0, 64); e != nil {
				return nil, fmt.Errorf("%s: %w", k, e)
			}
		case "bool":
			if _, e := strconv.ParseBool(v); e != nil {
				return nil, fmt.Errorf("%s: %w", k, e)
			}
		case "string":
		default:
			return nil, fmt.Errorf("unknown parameter kind %s", d.Kind)
		}
	}
	return out, nil
}
