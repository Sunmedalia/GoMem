package triage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// This evaluator spans SQLite pages. A sealed row proves integrity, not that
// its decoded flags or hardware dirty assertion agree with its captured bytes.
type malfindEvaluator struct {
	rule                                               Rule
	source                                             *evidence.Task
	proof                                              *evidence.Provenance
	rows, scans, probes, missing, diagnostics, invalid uint64
}

func malfindCapture(value evidence.Value) (uint64, []byte, error) {
	fields, err := pebEvidenceMap(value)
	if err != nil {
		return 0, nil, err
	}
	at, err := pebTypedUint(fields, "Address", "address")
	if err != nil {
		return 0, nil, err
	}
	raw, err := pebRaw(fields["Raw"])
	if err != nil {
		return 0, nil, err
	}
	want, e1 := pebTypedUint(fields, "RequestedBytes", "uint64")
	got, e2 := pebTypedUint(fields, "CapturedBytes", "uint64")
	complete, e3 := pebBool(fields["ReadComplete"])
	if e1 != nil || e2 != nil || e3 != nil || !complete || want == 0 || want != got || got != uint64(len(raw)) || fields["Error"].Error != "" {
		return 0, nil, fmt.Errorf("incomplete Malfind capture")
	}
	return at, raw, nil
}
func malfindScalar(value evidence.Value) (uint64, uint64, error) {
	at, raw, err := malfindCapture(value)
	if err != nil {
		return 0, 0, err
	}
	if len(raw) != 4 && len(raw) != 8 {
		return 0, 0, fmt.Errorf("invalid Malfind scalar width")
	}
	n := uint64(binary.LittleEndian.Uint32(raw))
	if len(raw) == 8 {
		n = binary.LittleEndian.Uint64(raw)
	}
	return at, n, nil
}
func (m *malfindEvaluator) consume(ctx context.Context, rows []evidence.Row, emit plugin.Emit) error {
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := row.Verify(); err != nil {
			return err
		}
		p := row.Provenance
		if p.Plugin != "linux.malfind" || p.ImageSHA256 == "" || p.Layer == "" || p.SymbolsSHA256 == "" {
			return fmt.Errorf("invalid Malfind provenance")
		}
		if m.proof == nil {
			copy := p
			m.proof = &copy
		}
		expected := *m.proof
		expected.Offset = p.Offset
		if !reflect.DeepEqual(expected, p) {
			return fmt.Errorf("mixed Malfind provenance")
		}
		if m.source != nil {
			expected = m.source.Provenance
			expected.Offset = p.Offset
			if m.source.Plugin != "linux.malfind" || !reflect.DeepEqual(expected, p) {
				return fmt.Errorf("Malfind row differs from source task")
			}
		}
		m.rows++
		switch row.Cells["RecordType"].String() {
		case "malfind_error":
			m.diagnostics++
			continue
		case "dirty_scan":
			fields, err := pebEvidenceMap(row.Cells["FieldEvidence"])
			if err != nil {
				m.invalid++
				continue
			}
			probes, e1 := pebTypedUint(fields, "Probes", "uint64")
			missing, e2 := pebTypedUint(fields, "MissingPages", "uint64")
			complete, e3 := pebBool(fields["Completed"])
			stopped, e4 := pebBool(fields["StoppedAfterFirstDirty"])
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || missing > probes {
				m.invalid++
				continue
			}
			m.scans++
			m.probes += probes
			m.missing += missing
			if !complete || stopped || row.Cells["Error"].Error != "" {
				m.diagnostics++
			}
			continue
		case "malfind_region":
		default:
			m.invalid++
			continue
		}
		hit, err := m.validate(row)
		if err != nil {
			m.invalid++
			continue
		}
		if row.Cells["Error"].Error != "" || row.Cells["Created"].Error != "" {
			m.diagnostics++
		}
		if hit {
			if err := emitFinding(ctx, m.rule, row, row.Cells["ProcessIdentity"].String(), []string{row.ID}, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *malfindEvaluator) validate(row evidence.Row) (bool, error) {
	fields, err := pebEvidenceMap(row.Cells["FieldEvidence"])
	if err != nil {
		return false, err
	}
	object, err := pebTypedUint(row.Cells, "Offset", "address")
	proof, e := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || e != nil || object != proof {
		return false, fmt.Errorf("VMA coordinates differ")
	}
	vma, raw, err := malfindCapture(fields["VMA"])
	if err != nil || vma != object {
		return false, fmt.Errorf("invalid VMA capture")
	}
	flagAt, flags, err := malfindScalar(fields["Flags"])
	if err != nil {
		return false, err
	}
	fileAt, file, err := malfindScalar(fields["File"])
	if err != nil {
		return false, err
	}
	for _, value := range []evidence.Value{fields["Flags"], fields["File"]} {
		at, data, e := malfindCapture(value)
		if e != nil || at < vma || at-vma > uint64(len(raw)) || uint64(len(data)) > uint64(len(raw))-(at-vma) || !bytes.Equal(data, raw[at-vma:at-vma+uint64(len(data))]) {
			return false, fmt.Errorf("field differs from VMA capture")
		}
	}
	if flagAt == fileAt {
		return false, fmt.Errorf("overlapping VMA fields")
	}
	identity := row.Cells["ProcessIdentity"]
	decoded, e := hex.DecodeString(identity.String())
	if identity.Kind != "string" || e != nil || len(decoded) != 32 {
		return false, fmt.Errorf("invalid process identity")
	}
	if _, err = pebTypedUint(row.Cells, "ProcessOffset", "address"); err != nil {
		return false, err
	}
	pid, err := pebTypedUint(row.Cells, "PID", "uint64")
	if err != nil {
		return false, err
	}
	process, _ := row.Cells["ProcessOffset"].Uint()
	created := row.Cells["Created"]
	stamp := ""
	if created.Kind != "missing" {
		if created.Kind != "uint64" {
			return false, fmt.Errorf("invalid creation time state")
		}
		if _, err := created.Uint(); err != nil {
			return false, err
		}
		stamp = created.String()
	}
	if identity.String() != evidence.ProcessID(row.Provenance.ImageSHA256, row.Provenance.Layer, process, pid, stamp) {
		return false, fmt.Errorf("process identity differs from coordinates")
	}
	processFields, err := pebEvidenceMap(fields["Process"])
	if err != nil {
		return false, err
	}
	for _, key := range []string{"MM", "PGD"} {
		_, value, e := malfindScalar(processFields[key])
		if e != nil || value == 0 {
			return false, fmt.Errorf("unreadable process address space")
		}
	}

	start, e1 := pebTypedUint(row.Cells, "Start", "address")
	end, e2 := pebTypedUint(row.Cells, "End", "address")
	region, e3 := pebTypedUint(row.Cells, "RegionStart", "address")
	size, e4 := pebTypedUint(row.Cells, "RegionSize", "uint64")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || end <= start || region < start || region >= end || size == 0 || size > ^uint64(0)-region {
		return false, fmt.Errorf("invalid region extent")
	}
	protection := []byte("---")
	for i, c := range []byte("rwx") {
		if flags&(1<<i) != 0 {
			protection[i] = c
		}
	}
	if row.Cells["Protection"].String() != string(protection) {
		return false, fmt.Errorf("protection differs from flags")
	}
	reason := row.Cells["Reason"].String()
	switch reason {
	case "RWX":
		if flags&7 != 7 || region != start || size != end-start {
			return false, fmt.Errorf("invalid RWX proof")
		}
	case "RX":
		if flags&7 != 5 || file != 0 || region != start || size != end-start {
			return false, fmt.Errorf("invalid RX proof")
		}
	case "X_DIRTY":
		if flags&4 == 0 || flags&7 == 7 || flags&7 == 5 && file == 0 {
			return false, fmt.Errorf("invalid dirty selection")
		}
		leaf, err := pebEvidenceMap(fields["DirtyLeaf"])
		if err != nil {
			return false, err
		}
		virtual, e1 := pebTypedUint(leaf, "Virtual", "address")
		page, e2 := pebTypedUint(leaf, "PageSize", "uint64")
		entry, e3 := pebTypedUint(leaf, "Entry", "address")
		dirty, e4 := pebBool(leaf["Dirty"])
		entryAt, actual, e5 := malfindScalar(leaf["Capture"])
		_, entryRaw, captureErr := malfindCapture(leaf["Capture"])
		validSize := page == 4096 || page == 1<<21 || page == 1<<22 || page == 1<<30
		validLeaf := captureErr == nil && len(entryRaw) > 0 && entryAt%uint64(len(entryRaw)) == 0 && (page == 4096 || entry&128 != 0)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || virtual != region || page != size || !validSize || !validLeaf || !dirty || entry&65 != 65 || actual != entry || leaf["Error"].Error != "" || leaf["Layer"].Kind != "string" || leaf["Layer"].String() == "" {
			return false, fmt.Errorf("invalid hardware dirty proof")
		}
	default:
		return false, fmt.Errorf("unknown Malfind selection")
	}
	return m.rule.ID == "anonymous-executable-region" && reason == "RX" || m.rule.ID == "executable-dirty-page" && reason == "X_DIRTY", nil
}
func (m *malfindEvaluator) finish() (map[string]string, error) {
	coverage := map[string]string{"rows": strconv.FormatUint(m.rows, 10), "dirty_scans": strconv.FormatUint(m.scans, 10), "probes": strconv.FormatUint(m.probes, 10), "missing_pages": strconv.FormatUint(m.missing, 10), "diagnostics": strconv.FormatUint(m.diagnostics, 10), "invalid_records": strconv.FormatUint(m.invalid, 10)}
	if m.source == nil {
		coverage["source_state"] = "unknown"
	} else {
		coverage["source_state"] = m.source.State
		if m.source.Error != "" {
			coverage["source_error"] = m.source.Error
		}
	}
	if m.source == nil || m.source.Plugin != "linux.malfind" || m.source.Provenance.ImageSHA256 == "" || m.source.Provenance.SymbolsSHA256 == "" || m.source.State != "completed" || m.source.Rows != int64(m.rows) || m.diagnostics > 0 || m.invalid > 0 || m.missing > 0 {
		return coverage, ErrIncomplete
	}
	return coverage, nil
}
