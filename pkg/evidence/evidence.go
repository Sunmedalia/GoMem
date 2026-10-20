// Package evidence defines lossless result cells and reproducible provenance.
package evidence

import (
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
