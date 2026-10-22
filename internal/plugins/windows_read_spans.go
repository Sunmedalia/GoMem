package plugins

import (
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// windowsReadSpans groups consecutive successful export acquisitions, without
// changing source reads or hiding their individual boundaries. Other rows and
// failed/partial reads are forwarded separately. It is local to one task.
type windowsSpanRead struct {
	Offset    string `json:"offset"`
	Requested uint64 `json:"requested"`
	Captured  uint64 `json:"captured"`
}
type windowsReadSpans struct {
	out     plugin.Emit
	pending *evidence.Row
	calls   []windowsSpanRead
	stop    error
}

func (s *windowsReadSpans) flush() error {
	if s.stop != nil {
		return s.stop
	}
	if s.pending == nil {
		return nil
	}
	row := *s.pending
	if len(s.calls) > 1 {
		row.Cells["Resolution"] = evidence.Value{Kind: "structure", Data: map[string]any{"method": "exports", "grouped": true, "acquisitions": s.calls}}
	}
	s.pending = nil
	s.calls = nil
	s.stop = s.out(row)
	return s.stop
}
func (s *windowsReadSpans) emit(row evidence.Row) error {
	if s.stop != nil {
		return s.stop
	}
	eligible := row.ID == "" && row.ParentID == "" && len(row.Cells) == 7 && row.Cells["RecordType"].String() == "memory_read" && row.Cells["Error"].Kind == "missing" && row.Cells["Error"].Reason == "no_error" && row.Cells["Error"].Error == ""
	detail, ok := row.Cells["Resolution"].Data.(map[string]any)
	eligible = eligible && ok && len(detail) == 1 && detail["method"] == "exports"
	raw, ok := row.Cells["Raw"].Data.([]byte)
	at, atErr := row.Cells["Offset"].Uint()
	requested, requestErr := row.Cells["Requested"].Uint()
	captured, captureErr := row.Cells["Captured"].Uint()
	eligible = eligible && row.Cells["Raw"].Kind == "bytes" && ok && atErr == nil && requestErr == nil && captureErr == nil && requested > 0 && requested == captured && captured == uint64(len(raw)) && len(raw) <= 4096
	if !eligible {
		if err := s.flush(); err != nil {
			return err
		}
		s.stop = s.out(row)
		return s.stop
	}
	if s.pending != nil {
		start, err := s.pending.Cells["Offset"].Uint()
		previous := s.pending.Cells["Raw"].Data.([]byte)
		if err != nil || uint64(len(previous)) > ^uint64(0)-start {
			return errors.New("invalid pending export span")
		}
		if s.pending.Provenance.Layer != row.Provenance.Layer || start+uint64(len(previous)) != at || len(previous)+len(raw) > 4096 || len(s.calls) >= 64 {
			if err := s.flush(); err != nil {
				return err
			}
		}
	}
	call := windowsSpanRead{Offset: evidence.Address(at).String(), Requested: requested, Captured: captured}
	if s.pending == nil {
		cells := make(map[string]evidence.Value, len(row.Cells))
		for key, value := range row.Cells {
			cells[key] = value
		}
		row.Cells = cells
		row.Cells["Raw"] = evidence.Bytes(raw)
		s.pending = &row
	} else {
		previous := s.pending.Cells["Raw"].Data.([]byte)
		combined := append(previous, raw...)
		s.pending.Cells["Raw"] = evidence.Bytes(combined)
		s.pending.Cells["Requested"] = evidence.Number(uint64(len(combined)))
		s.pending.Cells["Captured"] = evidence.Number(uint64(len(combined)))
	}
	s.calls = append(s.calls, call)
	if len(s.calls) > 64 {
		return fmt.Errorf("export span acquisition bound exceeded")
	}
	return nil
}
