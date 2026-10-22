// Package wincallbacks reads Windows callback indexes using data-only callback
// layouts and a separate matching kernel symbol table. Pool recovery and
// module attribution are responsibilities of the caller.
package wincallbacks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Table keeps auxiliary and kernel types in distinct namespaces, including
// base types inside a referenced kernel aggregate. A same-named local base
// must never silently change a kernel field's width or signedness.
type Table struct {
	kernel symbols.SymbolTable
	local  *symbols.ISF
	digest string
}

func absentKernel(kernel symbols.SymbolTable) bool {
	if kernel == nil {
		return true
	}
	value := reflect.ValueOf(kernel)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func Parse(data []byte, kernel symbols.SymbolTable) (*Table, error) {
	if absentKernel(kernel) || len(data) == 0 || len(data) > 4<<20 {
		return nil, fmt.Errorf("callback layout requires kernel symbols and 1..4194304 bytes")
	}
	local, err := symbols.Parse(data)
	if err != nil {
		return nil, err
	}
	if local.PointerSize() != kernel.PointerSize() {
		return nil, fmt.Errorf("callback/kernel pointer width mismatch")
	}
	sum := sha256.Sum256([]byte(kernel.Digest() + ":" + local.Digest()))
	return &Table{kernel: kernel, local: local, digest: hex.EncodeToString(sum[:])}, nil
}

func qualify(ref symbols.TypeRef, namespace string) symbols.TypeRef {
	if ref.Name != "" && !strings.Contains(ref.Name, "!") {
		ref.Name = namespace + "!" + ref.Name
	}
	if ref.Subtype != nil {
		child := qualify(*ref.Subtype, namespace)
		ref.Subtype = &child
	}
	if ref.BitType != nil {
		child := qualify(*ref.BitType, namespace)
		ref.BitType = &child
	}
	return ref
}

func (t *Table) selectTable(name string) (symbols.SymbolTable, string, string, error) {
	namespace, bare, found := strings.Cut(name, "!")
	if !found {
		return t.kernel, name, "nt_symbols", nil
	}
	switch namespace {
	case "callbacks":
		return t.local, bare, namespace, nil
	case "nt_symbols":
		return t.kernel, bare, namespace, nil
	default:
		return nil, "", "", fmt.Errorf("unknown callback type namespace %q", namespace)
	}
}

func (t *Table) Type(name string) (symbols.Type, error) {
	table, bare, namespace, err := t.selectTable(name)
	if err != nil {
		return symbols.Type{}, err
	}
	typ, err := table.Type(bare)
	if err != nil {
		return typ, err
	}
	if typ.Fields != nil {
		fields := make(map[string]symbols.Field, len(typ.Fields))
		for key, value := range typ.Fields {
			value.Type = qualify(value.Type, namespace)
			fields[key] = value
		}
		typ.Fields = fields
	}
	return typ, nil
}
func (t *Table) Enumeration(name string) (symbols.Enumeration, error) {
	table, bare, namespace, err := t.selectTable(name)
	if err != nil {
		return symbols.Enumeration{}, err
	}
	enum, err := table.Enumeration(bare)
	if err == nil && !strings.Contains(enum.Base, "!") {
		enum.Base = namespace + "!" + enum.Base
	}
	return enum, err
}
func (t *Table) Lookup(name string) (symbols.Symbol, error) { return t.kernel.Lookup(name) }
func (t *Table) Names() []string                            { return t.kernel.Names() }
func (t *Table) Digest() string                             { return t.digest }
func (t *Table) Metadata() map[string]json.RawMessage       { return t.kernel.Metadata() }
func (t *Table) PointerSize() int                           { return t.kernel.PointerSize() }
func (t *Table) LayoutDigest() string                       { return t.local.Digest() }
