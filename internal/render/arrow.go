package render

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

const arrowBatchRows = 1024
const arrowBatchBytes = 8 << 20
const ArrowMaxRowBytes = 64 << 20

// ArrowWriter emits bounded IPC stream batches. Projection columns are for
// analysis; _gomem_evidence holds the canonical complete evidence JSON.
type arrowOutput struct{ io.Writer }

func (w arrowOutput) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, fmt.Errorf("invalid Arrow output write count")
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

type ArrowWriter struct {
	cols    []evidence.Column
	builder *array.RecordBuilder
	writer  *ipc.Writer
	bytes   int
	err     error
	closed  bool
}

func arrowType(kind string) (arrow.DataType, error) {
	switch kind {
	case "string", "timestamp", "address":
		return arrow.BinaryTypes.String, nil
	case "uint64":
		return arrow.PrimitiveTypes.Uint64, nil
	case "int64", "integer":
		return arrow.PrimitiveTypes.Int64, nil
	case "bool":
		return arrow.FixedWidthTypes.Boolean, nil
	case "bytes", "structure", "artifact", "missing", "value":
		return arrow.BinaryTypes.Binary, nil
	default:
		return nil, fmt.Errorf("unsupported Arrow column kind %q", kind)
	}
}
func NewArrow(w io.Writer, cols []evidence.Column, metadata map[string]string) (*ArrowWriter, error) {
	return newArrow(w, cols, metadata, memory.DefaultAllocator)
}
func newArrow(w io.Writer, cols []evidence.Column, metadata map[string]string, allocator memory.Allocator) (*ArrowWriter, error) {
	if w == nil {
		return nil, fmt.Errorf("Arrow output writer is required")
	}
	if cols == nil {
		cols = []evidence.Column{}
	}
	if len(cols) > 4096 {
		return nil, fmt.Errorf("Arrow column budget exceeded")
	}
	fields := []arrow.Field{{Name: "_gomem_id", Type: arrow.BinaryTypes.String}, {Name: "_gomem_parent_id", Type: arrow.BinaryTypes.String, Nullable: true}, {Name: "_gomem_task_id", Type: arrow.BinaryTypes.String, Nullable: true}, {Name: "_gomem_evidence", Type: arrow.BinaryTypes.Binary}}
	seen := map[string]bool{}
	for _, f := range fields {
		seen[f.Name] = true
	}
	for _, col := range cols {
		if col.Name == "" || !utf8.ValidString(col.Name) || seen[col.Name] {
			return nil, fmt.Errorf("invalid or reserved Arrow column name %q", col.Name)
		}
		seen[col.Name] = true
		typ, err := arrowType(col.Kind)
		if err != nil {
			return nil, err
		}
		fields = append(fields, arrow.Field{Name: col.Name, Type: typ, Nullable: true, Metadata: arrow.MetadataFrom(map[string]string{"gomem.kind": col.Kind})})
	}
	values := map[string]string{}
	for k, v := range metadata {
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return nil, fmt.Errorf("invalid Arrow metadata UTF-8")
		}
		values[k] = v
	}
	values["gomem.schema"] = "gomem.arrow-evidence/v1"
	values["gomem.evidence.encoding"] = "canonical-evidence-json"
	encoded, err := json.Marshal(cols)
	if err != nil {
		return nil, err
	}
	values["gomem.columns"] = string(encoded)
	budget, err := json.Marshal(values)
	if err != nil || len(budget) > 8<<20 {
		return nil, fmt.Errorf("Arrow metadata budget exceeded")
	}
	meta := arrow.MetadataFrom(values)
	schema := arrow.NewSchema(fields, &meta)
	builder := array.NewRecordBuilder(allocator, schema)
	return &ArrowWriter{cols: append([]evidence.Column(nil), cols...), builder: builder, writer: ipc.NewWriter(arrowOutput{w}, ipc.WithSchema(schema), ipc.WithAllocator(allocator))}, nil
}
func arrowProjection(col evidence.Column, v evidence.Value, present bool) (any, error) {
	if !present || v.Kind == "missing" {
		return nil, nil
	}
	bad := func() (any, error) {
		return nil, fmt.Errorf("Arrow column %q (%s) cannot represent %s", col.Name, col.Kind, v.Kind)
	}
	switch col.Kind {
	case "string", "timestamp":
		if v.Kind != "string" && v.Kind != "timestamp" {
			return bad()
		}
		s, ok := v.Data.(string)
		if !ok || !utf8.ValidString(s) {
			return bad()
		}
		return s, nil
	case "address":
		if v.Kind != "address" {
			return bad()
		}
		if _, err := v.Uint(); err != nil {
			return bad()
		}
		return v.String(), nil
	case "uint64":
		if v.Kind != "uint64" {
			return bad()
		}
		n, err := v.Uint()
		if err != nil {
			return bad()
		}
		return n, nil
	case "int64", "integer":
		if v.Kind != "int64" && v.Kind != "uint64" {
			return bad()
		}
		n, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			return bad()
		}
		return n, nil
	case "bool":
		b, ok := v.Data.(bool)
		if v.Kind != "bool" || !ok {
			return bad()
		}
		return b, nil
	case "bytes":
		if v.Kind != "bytes" {
			return bad()
		}
		switch data := v.Data.(type) {
		case []byte:
			if data == nil {
				return nil, nil
			}
			return data, nil
		case string:
			b, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return bad()
			}
			return b, nil
		case nil:
			return nil, nil
		default:
			return bad()
		}
	case "structure", "artifact":
		if v.Kind != col.Kind {
			return bad()
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var wire struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		if len(wire.Value) == 0 || string(wire.Value) == "null" {
			return nil, nil
		}
		return []byte(wire.Value), nil
	case "value":
		return json.Marshal(v)
	default:
		return bad()
	}
}
func (w *ArrowWriter) Row(row evidence.Row) error { return w.RowForTask("", row) }
func (w *ArrowWriter) RowForTask(task string, row evidence.Row) error {
	if w.closed {
		return fmt.Errorf("Arrow writer is closed")
	}
	if w.err != nil {
		return w.err
	}
	if !utf8.ValidString(row.ID + row.ParentID + task) {
		w.err = fmt.Errorf("invalid Arrow identity UTF-8")
		return w.err
	}
	raw, err := json.Marshal(row)
	if err != nil {
		w.err = err
		return err
	}
	if len(raw) > ArrowMaxRowBytes {
		w.err = fmt.Errorf("Arrow evidence row exceeds %d byte budget", ArrowMaxRowBytes)
		return w.err
	}
	projected := make([]any, len(w.cols))
	for i, col := range w.cols {
		v, ok := row.Cells[col.Name]
		projected[i], err = arrowProjection(col, v, ok)
		if err != nil {
			w.err = err
			return err
		}
	}
	if w.bytes+len(raw) > arrowBatchBytes {
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.builder.Field(0).(*array.StringBuilder).Append(row.ID)
	if row.ParentID == "" {
		w.builder.Field(1).AppendNull()
	} else {
		w.builder.Field(1).(*array.StringBuilder).Append(row.ParentID)
	}
	if task == "" {
		w.builder.Field(2).AppendNull()
	} else {
		w.builder.Field(2).(*array.StringBuilder).Append(task)
	}
	w.builder.Field(3).(*array.BinaryBuilder).Append(raw)
	for i, v := range projected {
		b := w.builder.Field(i + 4)
		if v == nil {
			b.AppendNull()
			continue
		}
		switch b := b.(type) {
		case *array.StringBuilder:
			b.Append(v.(string))
		case *array.Uint64Builder:
			b.Append(v.(uint64))
		case *array.Int64Builder:
			b.Append(v.(int64))
		case *array.BooleanBuilder:
			b.Append(v.(bool))
		case *array.BinaryBuilder:
			b.Append(v.([]byte))
		}
	}
	w.bytes += len(raw)
	if w.builder.Field(0).Len() >= arrowBatchRows || w.bytes >= arrowBatchBytes {
		return w.flush()
	}
	return nil
}
func (w *ArrowWriter) flush() error {
	if w.err != nil {
		return w.err
	}
	if w.builder.Field(0).Len() == 0 {
		return nil
	}
	record := w.builder.NewRecordBatch()
	defer record.Release()
	w.bytes = 0
	w.err = w.writer.Write(record)
	return w.err
}
func (w *ArrowWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	defer w.builder.Release()
	err := w.flush()
	w.err = errors.Join(err, w.writer.Close())
	return w.err
}
