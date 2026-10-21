// Package symbols implements native ISF type and symbol access with bounded decompression.
package symbols

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz"
)

const MaxSymbolSize = 128 << 20

type TypeRef struct {
	Kind        string   `json:"kind"`
	Base        string   `json:"base,omitempty"`
	Name        string   `json:"name,omitempty"`
	Count       uint64   `json:"count,omitempty"`
	Subtype     *TypeRef `json:"subtype,omitempty"`
	BitType     *TypeRef `json:"type,omitempty"`
	Size        uint64   `json:"size,omitempty"`
	BitPosition uint64   `json:"bit_position,omitempty"`
	BitLength   uint64   `json:"bit_length,omitempty"`
}

func (t TypeRef) Underlying() *TypeRef {
	if t.Kind == "bitfield" && t.BitType != nil {
		return t.BitType
	}
	return t.Subtype
}
func (t TypeRef) MarshalJSON() ([]byte, error) {
	switch t.Kind {
	case "array":
		return json.Marshal(struct {
			Kind    string   `json:"kind"`
			Count   uint64   `json:"count"`
			Subtype *TypeRef `json:"subtype"`
		}{t.Kind, t.Count, t.Subtype})
	case "bitfield":
		return json.Marshal(struct {
			Kind     string   `json:"kind"`
			Position uint64   `json:"bit_position"`
			Length   uint64   `json:"bit_length"`
			Type     *TypeRef `json:"type"`
		}{t.Kind, t.BitPosition, t.BitLength, t.Underlying()})
	default:
		type alias TypeRef
		return json.Marshal(alias(t))
	}
}

type Field struct {
	Offset    uint64  `json:"offset"`
	Type      TypeRef `json:"type"`
	Anonymous bool    `json:"anonymous,omitempty"`
}
type Type struct {
	Kind          string           `json:"kind"`
	Size          uint64           `json:"size"`
	Fields        map[string]Field `json:"fields,omitempty"`
	FieldOrder    []string         `json:"-"`
	Endian        string           `json:"endian,omitempty"`
	Signed        bool             `json:"signed,omitempty"`
	SignedUnknown bool             `json:"-"`
}

func (t Type) MarshalJSON() ([]byte, error) {
	if t.Kind == "struct" || t.Kind == "union" || t.Kind == "class" {
		var fields bytes.Buffer
		fields.WriteByte('{')
		for i, name := range t.MemberNames() {
			if i > 0 {
				fields.WriteByte(',')
			}
			key, err := json.Marshal(name)
			if err != nil {
				return nil, err
			}
			value, err := json.Marshal(t.Fields[name])
			if err != nil {
				return nil, err
			}
			fields.Write(key)
			fields.WriteByte(':')
			fields.Write(value)
		}
		fields.WriteByte('}')
		return json.Marshal(struct {
			Kind   string          `json:"kind"`
			Size   uint64          `json:"size"`
			Fields json.RawMessage `json:"fields"`
		}{t.Kind, t.Size, fields.Bytes()})
	}
	return json.Marshal(struct {
		Kind   string `json:"kind"`
		Size   uint64 `json:"size"`
		Endian string `json:"endian"`
		Signed bool   `json:"signed"`
	}{t.Kind, t.Size, t.Endian, t.Signed})
}

// MemberNames retains declaration order from ISF/DWARF/PDB. Programmatically
// added fields without an order are appended lexicographically. Removed fields
// and duplicate order entries are ignored so callers can safely edit layouts.
func (t Type) MemberNames() []string {
	names := make([]string, 0, len(t.Fields))
	seen := map[string]bool{}
	for _, name := range t.FieldOrder {
		if _, ok := t.Fields[name]; ok && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	var extra []string
	for name := range t.Fields {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return append(names, extra...)
}

type orderedTypeFields struct {
	values map[string]Field
	names  []string
}

func (f *orderedTypeFields) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*f = orderedTypeFields{}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("type fields must be an object")
	}
	f.values = map[string]Field{}
	f.names = nil
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok {
			return fmt.Errorf("invalid field name")
		}
		var value Field
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if _, exists := f.values[name]; !exists {
			f.names = append(f.names, name)
		}
		f.values[name] = value
	}
	_, err = decoder.Token()
	return err
}
func (t *Type) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Kind   string            `json:"kind"`
		Size   uint64            `json:"size"`
		Fields orderedTypeFields `json:"fields"`
		Endian string            `json:"endian"`
		Signed bool              `json:"signed"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*t = Type{Kind: decoded.Kind, Size: decoded.Size, Fields: decoded.Fields.values, FieldOrder: decoded.Fields.names, Endian: decoded.Endian, Signed: decoded.Signed}
	return nil
}

type Symbol struct {
	Address      uint64   `json:"address"`
	LinkageName  string   `json:"linkage_name,omitempty"`
	Type         *TypeRef `json:"type,omitempty"`
	ConstantData string   `json:"constant_data,omitempty"`
}
type Enumeration struct {
	Base      string                 `json:"base"`
	Size      uint64                 `json:"size"`
	Constants map[string]json.Number `json:"constants"`
}

func (e Enumeration) Names(value uint64) []string {
	if e.Size == 0 {
		return nil
	}
	var names []string
	for name, n := range e.Constants {
		v, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil {
			signed, err := strconv.ParseInt(string(n), 10, 64)
			if err != nil {
				continue
			}
			v = uint64(signed)
		}
		if e.Size < 8 {
			mask := uint64(1)<<(e.Size*8) - 1
			v &= mask
			value &= mask
		}
		if v == value {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type SymbolTable interface {
	Lookup(string) (Symbol, error)
	Names() []string
	Type(string) (Type, error)
	Digest() string
	Metadata() map[string]json.RawMessage
	PointerSize() int
	Enumeration(string) (Enumeration, error)
}

// Names returns a stable snapshot for native symbol-index consumers/scanners.
func (t *ISF) Names() []string {
	names := make([]string, 0, len(t.Symbols))
	for name := range t.Symbols {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type ISF struct {
	Meta         map[string]json.RawMessage `json:"metadata"`
	Bases        map[string]Type            `json:"base_types"`
	Types        map[string]Type            `json:"user_types"`
	Symbols      map[string]Symbol          `json:"symbols"`
	Enums        map[string]Enumeration     `json:"enums"`
	digest       string
	architecture string
}

func (t *ISF) Lookup(n string) (Symbol, error) {
	s, ok := t.Symbols[n]
	if !ok {
		return s, fmt.Errorf("symbol %q is absent", n)
	}
	return s, nil
}
func (t *ISF) Type(n string) (Type, error) {
	v, ok := t.Types[n]
	if !ok {
		v, ok = t.Bases[n]
	}
	if !ok {
		if en, found := t.Enums[n]; found {
			base, exists := t.Bases[en.Base]
			if !exists {
				return v, fmt.Errorf("enum %s has no base %s", n, en.Base)
			}
			signed, unknown := base.Signed, base.Kind == "void"
			if unknown {
				for _, constant := range en.Constants {
					if strings.HasPrefix(string(constant), "-") && string(constant) != "-0" {
						signed, unknown = true, false
						break
					}
				}
			}
			return Type{Kind: "enum", Size: en.Size, Endian: base.Endian, Signed: signed, SignedUnknown: unknown}, nil
		}
	}
	if !ok {
		return v, fmt.Errorf("type %q is absent", n)
	}
	return v, nil
}
func (t *ISF) Enumeration(name string) (Enumeration, error) {
	e, ok := t.Enums[name]
	if !ok {
		return e, fmt.Errorf("enum %q is absent", name)
	}
	return e, nil
}
func (t *ISF) Digest() string                       { return t.digest }
func (t *ISF) Metadata() map[string]json.RawMessage { return t.Meta }
func (t *ISF) PointerSize() int {
	if p, ok := t.Bases["pointer"]; ok {
		return int(p.Size)
	}
	return 0
}
func (t *ISF) Architecture() string {
	if t.architecture != "" {
		return t.architecture
	}
	var zero struct {
		Architecture string `json:"architecture"`
	}
	if json.Unmarshal(t.Meta["zero"], &zero) == nil && zero.Architecture != "" {
		return zero.Architecture
	}
	var windows struct {
		PDB struct {
			Machine uint16 `json:"machine_type"`
		} `json:"pdb"`
	}
	if json.Unmarshal(t.Meta["windows"], &windows) == nil {
		switch windows.PDB.Machine {
		case 0x8664:
			return "x86_64"
		case 0x14c:
			return "i386"
		case 0xaa64:
			return "arm64"
		case 0x1c0, 0x1c4:
			return "arm"
		}
	}
	return ""
}
func (t *ISF) Banner() ([]byte, error) {
	for _, n := range []string{"linux_banner", "version"} {
		if s, ok := t.Symbols[n]; ok && s.ConstantData != "" {
			b, e := base64.StdEncoding.DecodeString(s.ConstantData)
			return bytes.TrimRight(b, "\x00"), e
		}
	}
	return nil, fmt.Errorf("symbol table lacks a kernel banner constant")
}
func (t *ISF) MatchPDB(database, guid string, age uint64) error {
	p, err := t.PDBIdentity()
	if err != nil {
		return err
	}
	if !p.Equal(PDBIdentity{Database: database, GUID: guid, Age: age}) {
		return fmt.Errorf("PDB identity mismatch: have %s %s/%d", p.Database, p.GUID, p.Age)
	}
	return nil
}
func limited(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxSymbolSize+1))
	if e != nil {
		return nil, e
	}
	if len(b) > MaxSymbolSize {
		return nil, fmt.Errorf("decompressed symbols exceed %d bytes", MaxSymbolSize)
	}
	return b, nil
}

// Load accepts JSON, gzip, xz, or ZIP archives with compressed ISF members.
// Ambiguous archives require path.zip#member; members never become output paths.
func Load(path string) (*ISF, error) { return LoadContext(context.Background(), path) }
func LoadContext(ctx context.Context, path string) (*ISF, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename, _, _ := strings.Cut(path, "#")
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	n, readErr := f.Read(magic[:])
	f.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, readErr
	}
	if n == 4 && nativeMagic(magic[:]) {
		table, _, err := ConvertDWARF(ctx, path, DWARFOptions{})
		return table, err
	}
	if n == 4 && string(magic[:]) == "Micr" {
		table, _, err := ConvertPDB(ctx, path, PDBOptions{})
		return table, err
	}
	return loadISF(ctx, path)
}
func loadISF(ctx context.Context, path string) (*ISF, error) {
	filename, member, _ := strings.Cut(path, "#")
	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		z, err := zip.OpenReader(filename)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		var chosen *zip.File
		for _, f := range z.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if member != "" && f.Name != member {
				continue
			}
			if member == "" && !isSymbolName(f.Name) {
				continue
			}
			if chosen != nil {
				return nil, fmt.Errorf("ambiguous symbol archive: specify #member")
			}
			chosen = f
		}
		if chosen == nil {
			return nil, fmt.Errorf("symbol archive member not found")
		}
		r, err := chosen.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		b, err := decode(contextReader{ctx, io.LimitReader(r, MaxSymbolSize+1)}, chosen.Name)
		if err != nil {
			return nil, err
		}
		return Parse(b)
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := decode(contextReader{ctx, io.LimitReader(f, MaxSymbolSize+1)}, filename)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}
func isSymbolName(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz") || strings.HasSuffix(name, ".json.xz")
}
func decode(r io.Reader, name string) ([]byte, error) {
	name = strings.ToLower(name)
	if strings.HasSuffix(name, ".gz") {
		g, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer g.Close()
		r = g
	}
	if strings.HasSuffix(name, ".xz") {
		x, err := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(r)
		if err != nil {
			return nil, err
		}
		r = x
	}
	return limited(r)
}

func Parse(data []byte) (*ISF, error) {
	if len(data) > MaxSymbolSize {
		return nil, fmt.Errorf("symbols exceed size limit")
	}
	var t ISF
	d := json.NewDecoder(bytes.NewReader(data))
	if e := d.Decode(&t); e != nil {
		return nil, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("trailing symbol data")
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	t.digest = hex.EncodeToString(sum[:])
	return &t, nil
}
func (t *ISF) validate() error {
	if len(t.Bases) == 0 || len(t.Types)+len(t.Enums)+len(t.Symbols) == 0 {
		return fmt.Errorf("ISF requires base types and at least one type, enum or symbol")
	}
	if t.PointerSize() != 4 && t.PointerSize() != 8 {
		return fmt.Errorf("ISF pointer size must be 4 or 8")
	}
	var format string
	if e := json.Unmarshal(t.Meta["format"], &format); e != nil || (!strings.HasPrefix(format, "6.") && !strings.HasPrefix(format, "4.") && !strings.HasPrefix(format, "5.")) {
		return fmt.Errorf("unsupported ISF metadata.format %q", format)
	}
	for n, typ := range t.Types {
		for f, v := range typ.Fields {
			if v.Offset > typ.Size {
				return fmt.Errorf("field %s.%s lies outside type", n, f)
			}
		}
	}
	for name, en := range t.Enums {
		base, ok := t.Bases[en.Base]
		if !ok || en.Size == 0 && (base.Kind != "void" || len(en.Constants) != 0) {
			return fmt.Errorf("invalid enum base or size for %s", name)
		}
		for constant, value := range en.Constants {
			if _, ok := new(big.Int).SetString(string(value), 10); !ok {
				return fmt.Errorf("invalid enum constant %s.%s", name, constant)
			}
		}
	}
	return nil
}
func (t *ISF) Encode() ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if len(b) > MaxSymbolSize {
		return nil, fmt.Errorf("encoded symbols exceed size limit")
	}
	return b, nil
}
func (t *ISF) finalize() error {
	b, err := t.Encode()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	t.digest = hex.EncodeToString(sum[:])
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// ValidateARM64 refuses geometries the native walker cannot interpret.
func (t *ISF) ValidateARM64() error {
	var config struct {
		PageShift int `json:"page_shift"`
		VABits    int `json:"va_bits"`
	}
	if err := json.Unmarshal(t.Meta["zero"], &config); err != nil {
		return fmt.Errorf("ARM64 requires symbol metadata.zero page_shift=12 and va_bits=48: %w", err)
	}
	if config.PageShift != 12 || config.VABits != 48 {
		return fmt.Errorf("unsupported ARM64 geometry: page_shift=%d va_bits=%d (requires 12/48)", config.PageShift, config.VABits)
	}
	if t.PointerSize() != 8 {
		return fmt.Errorf("ARM64 requires 64-bit symbols")
	}
	return nil
}
