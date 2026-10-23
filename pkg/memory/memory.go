// Package memory provides bounded, read-only access to physical and virtual memory.
package memory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

const MaxRead = 16 << 20

var ErrUnmapped = errors.New("unmapped memory")
var ErrUnsupported = errors.New("unsupported image format")

type ReadError struct {
	Address uint64
	Length  int
	Layer   string
	Cause   error
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("%s: read %#x (%d bytes): %v", e.Layer, e.Address, e.Length, e.Cause)
}
func (e *ReadError) Unwrap() error { return e.Cause }

type MemorySource interface {
	Name() string
	Size() uint64
	ReadAt(context.Context, []byte, uint64) (int, error)
	Close() error
}
type Range struct {
	Start      uint64 `json:"start"`
	Length     uint64 `json:"length"`
	FileOffset uint64 `json:"file_offset"`
	// Empty Encoding denotes a linear mapping with Length stored bytes. For
	// encoded regions FileOffset/StoredLength locate the encoded stream; adding
	// a physical displacement to that file offset is not a valid translation.
	StoredLength uint64 `json:"stored_length,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
}
type MemoryLayer interface {
	Name() string
	ReadAt(context.Context, []byte, uint64) (int, error)
	Ranges() []Range
}
type Translation struct {
	// PageSize is the hardware leaf mapping size, including large pages.
	// EntryAddress and Entry retain the final physical page-table entry.
	PageSize     uint64
	EntryAddress uint64
	Entry        uint64
	EntryWidth   uint8
	Dirty        bool
	DirtyKnown   bool
	Physical     uint64
	Available    uint64
	Writable     bool
	Executable   bool
	// Software transition entries do not carry hardware access permissions.
	PermissionsKnown bool
	Transition       bool
}
type Translator interface {
	Translate(context.Context, uint64) (Translation, error)
}

type FileSource struct {
	f    *os.File
	size uint64
}

func OpenFile(path string) (*FileSource, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() == 0 {
		f.Close()
		return nil, fmt.Errorf("source must be a nonempty regular file")
	}
	return &FileSource{f, uint64(s.Size())}, nil
}
func (f *FileSource) Name() string               { return f.f.Name() }
func (f *FileSource) Size() uint64               { return f.size }
func (f *FileSource) Close() error               { return f.f.Close() }
func (f *FileSource) Stat() (os.FileInfo, error) { return f.f.Stat() }
func (f *FileSource) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if len(p) > MaxRead {
		return 0, fmt.Errorf("read exceeds %d bytes", MaxRead)
	}
	if a > math.MaxInt64 {
		return 0, &ReadError{a, len(p), f.Name(), io.EOF}
	}
	n, e := f.f.ReadAt(p, int64(a))
	if e != nil {
		return n, &ReadError{a, len(p), f.Name(), e}
	}
	return n, nil
}
func Read(ctx context.Context, l MemoryLayer, a uint64, n int) ([]byte, error) {
	if n < 0 || n > MaxRead {
		return nil, fmt.Errorf("invalid read length %d", n)
	}
	p := make([]byte, n)
	k, e := l.ReadAt(ctx, p, a)
	if e != nil {
		return nil, e
	}
	if k != n {
		return nil, &ReadError{a, n, l.Name(), io.ErrUnexpectedEOF}
	}
	return p, nil
}
func Add(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, fmt.Errorf("address overflow: %#x + %#x", a, b)
	}
	return a + b, nil
}

type Mapped struct {
	source MemorySource
	name   string
	runs   []Range
}

func NewMapped(s MemorySource, name string, runs []Range) (*Mapped, error) {
	runs = append([]Range(nil), runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Start < runs[j].Start })
	var end uint64
	for i, r := range runs {
		if r.Encoding != "" || r.StoredLength != 0 && r.StoredLength != r.Length {
			return nil, fmt.Errorf("linear layer cannot map encoded segment %d", i)
		}
		a, e := Add(r.Start, r.Length)
		if e != nil || r.Length == 0 {
			return nil, fmt.Errorf("invalid segment %d", i)
		}
		if i > 0 && r.Start < end {
			return nil, fmt.Errorf("overlapping physical segments")
		}
		f, e := Add(r.FileOffset, r.Length)
		if e != nil || f > s.Size() {
			return nil, fmt.Errorf("truncated segment %d", i)
		}
		end = a
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("no memory segments")
	}
	return &Mapped{s, name, runs}, nil
}
func (m *Mapped) Name() string    { return m.name }
func (m *Mapped) Ranges() []Range { return append([]Range(nil), m.runs...) }
func (m *Mapped) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if len(p) > MaxRead {
		return 0, fmt.Errorf("read exceeds limit")
	}
	if _, e := Add(a, uint64(len(p))); e != nil {
		return 0, e
	}
	n := 0
	for n < len(p) {
		if e := ctx.Err(); e != nil {
			return n, e
		}
		x := a + uint64(n)
		i := sort.Search(len(m.runs), func(i int) bool { return m.runs[i].Start > x }) - 1
		if i < 0 || x-m.runs[i].Start >= m.runs[i].Length {
			return n, &ReadError{x, len(p) - n, m.name, ErrUnmapped}
		}
		r := m.runs[i]
		k := min(len(p)-n, int(min(r.Length-(x-r.Start), uint64(MaxRead))))
		got, e := m.source.ReadAt(ctx, p[n:n+k], r.FileOffset+x-r.Start)
		n += got
		if e != nil {
			return n, e
		}
		if got != k {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}

type Virtual struct {
	Physical   MemoryLayer
	Translator Translator
	ID         string
}

func (v *Virtual) Name() string    { return v.ID }
func (v *Virtual) Ranges() []Range { return nil } // Virtual ranges require an explicit page-table enumeration.
func (v *Virtual) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if len(p) > MaxRead {
		return 0, fmt.Errorf("read exceeds limit")
	}
	if _, e := Add(a, uint64(len(p))); e != nil {
		return 0, e
	}
	n := 0
	for n < len(p) {
		t, e := v.Resolve(ctx, a+uint64(n))
		if e != nil {
			return n, &ReadError{a + uint64(n), len(p) - n, v.ID, e}
		}
		if t.Available == 0 {
			return n, fmt.Errorf("translator returned zero extent")
		}
		k := min(len(p)-n, int(min(t.Available, uint64(MaxRead))))
		got, e := t.Layer.ReadAt(ctx, p[n:n+k], t.Offset)
		n += got
		if e != nil {
			return n, e
		}
		if got != k {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}
