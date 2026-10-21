// Package evidence defines lossless result cells and reproducible provenance.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Value struct {
	Kind   string `json:"kind"`
	Data   any    `json:"value,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

func Text(s string) Value    { return Value{Kind: "string", Data: s} }
func Number(n uint64) Value  { return Value{Kind: "uint64", Data: fmt.Sprint(n)} }
func Integer(n int64) Value  { return Value{Kind: "int64", Data: strconv.FormatInt(n, 10)} }
func Address(n uint64) Value { return Value{Kind: "address", Data: fmt.Sprintf("0x%016x", n)} }
func Bytes(b []byte) Value   { return Value{Kind: "bytes", Data: append([]byte(nil), b...)} }
func Missing(reason string, e error) Value {
	v := Value{Kind: "missing", Reason: reason}
	if e != nil {
		v.Error = e.Error()
	}
	return v
}
func Bool(b bool) Value { return Value{Kind: "bool", Data: b} }

func (v *Value) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Kind   string          `json:"kind"`
		Data   json.RawMessage `json:"value"`
		Reason string          `json:"reason"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	var data any
	if len(wire.Data) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(wire.Data))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err != nil {
			return err
		}
		// Bytes(nil) is an explicit null capture. Keep a typed nil slice so
		// omitempty does not turn that value into an absent key after paging.
		// An originally absent value remains absent for old evidence hashes.
		if wire.Kind == "bytes" && data == nil {
			data = []byte(nil)
		}
	}
	*v = Value{Kind: wire.Kind, Data: data, Reason: wire.Reason, Error: wire.Error}
	return nil
}

func (v Value) MarshalJSON() ([]byte, error) {
	type wire struct {
		Kind   string `json:"kind"`
		Data   any    `json:"value,omitempty"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	if text, ok := v.Data.(string); ok && v.Kind == "string" && text == "" && v.Reason == "" && v.Error == "" {
		return []byte(`{"kind":"string","value":""}`), nil
	}
	if v.Kind == "bool" && v.Reason == "" && v.Error == "" {
		b, ok := v.Data.(bool)
		if !ok {
			return nil, fmt.Errorf("bool evidence value is %T", v.Data)
		}
		if b {
			return []byte(`{"kind":"bool","value":true}`), nil
		}
		return []byte(`{"kind":"bool","value":false}`), nil
	}
	data := v.Data
	if v.Kind == "structure" || v.Kind == "artifact" {
		// Normalize nested typed Values to JSON objects before hashing. After
		// persistence these objects are generic maps with sorted keys; their
		// wire representation must be identical before and after that read.
		raw, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber() // Never round large integer metadata through float64.
		if err := decoder.Decode(&data); err != nil {
			return nil, err
		}
	}
	return json.Marshal(wire{Kind: v.Kind, Data: data, Reason: v.Reason, Error: v.Error})
}

func (v Value) String() string {
	if v.Kind == "missing" {
		if v.Error != "" {
			return "<" + v.Reason + ": " + v.Error + ">"
		}
		return "<" + v.Reason + ">"
	}
	return fmt.Sprint(v.Data)
}
func (v Value) Uint() (uint64, error) {
	if v.Kind == "address" {
		return strconv.ParseUint(strings.TrimPrefix(v.String(), "0x"), 16, 64)
	}
	if v.Kind == "uint64" {
		return strconv.ParseUint(v.String(), 10, 64)
	}
	return 0, fmt.Errorf("cell is %s, not an integer", v.Kind)
}
func (v Value) Int() (int64, error) {
	if v.Kind == "int64" {
		return strconv.ParseInt(v.String(), 10, 64)
	}
	return 0, fmt.Errorf("cell is %s, not a signed integer", v.Kind)
}

type Column struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type Provenance struct {
	ImageSHA256   string            `json:"image_sha256"`
	Engine        string            `json:"engine"`
	EngineBuild   string            `json:"engine_build"`
	SymbolsSHA256 string            `json:"symbols_sha256,omitempty"`
	Plugin        string            `json:"plugin"`
	Parameters    map[string]string `json:"parameters"`
	Layer         string            `json:"layer"`
	Offset        string            `json:"offset,omitempty"`
}
type Row struct {
	ID         string           `json:"id"`
	ParentID   string           `json:"parent_id,omitempty"`
	Cells      map[string]Value `json:"cells"`
	Provenance Provenance       `json:"provenance"`
}

func (r *Row) Seal() {
	r.ID = ""
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	r.ID = hex.EncodeToString(h[:])
}
func (r Row) Verify() error {
	want := r.ID
	if want == "" {
		return fmt.Errorf("evidence is not sealed")
	}
	r.ID = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != want {
		return fmt.Errorf("evidence content does not match ID %s", want)
	}
	return nil
}

type Task struct {
	ID         string     `json:"id"`
	CacheKey   string     `json:"cache_key"`
	Plugin     string     `json:"plugin"`
	State      string     `json:"state"`
	Error      string     `json:"error,omitempty"`
	Started    time.Time  `json:"started"`
	Finished   *time.Time `json:"finished,omitempty"`
	Rows       int64      `json:"rows"`
	Provenance Provenance `json:"provenance"`
}
type Query struct {
	TaskID        string
	Offset, Limit int
	Filter        string
	Desc          bool
}
type EvidenceStore interface {
	ArtifactPage(context.Context, string, int, int) ([]Artifact, error)
	VerifyTaskArtifacts(context.Context, string) error
	Begin(context.Context, string, string, Provenance) (Task, error)
	Append(context.Context, string, []Row) error
	Finish(context.Context, string, string, error) error
	Cached(context.Context, string) (Task, bool, error)
	Tasks(context.Context) ([]Task, error)
	Query(context.Context, Query) ([]Row, error)
	Close() error
}

// ProcessID includes the object address and available creation time. PIDs alone
// are never identities and cannot safely join separate enumerations.
func ProcessID(image, layer string, address, pid uint64, created string) string {
	b, _ := json.Marshal([]string{image, layer, fmt.Sprintf("%x", address), fmt.Sprint(pid), created})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ThreadID(image, layer string, address, tid uint64, created string) string {
	b, _ := json.Marshal([]string{"thread-v1", image, layer, fmt.Sprintf("%x", address), fmt.Sprint(tid), created})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
