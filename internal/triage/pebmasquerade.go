package triage

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// Nested evidence has typed Value entries before persistence and JSON maps after
// SQLite paging. Decode both forms through the same wire format.
func pebEvidenceMap(value evidence.Value) (map[string]evidence.Value, error) {
	if value.Kind != "structure" {
		return nil, fmt.Errorf("PEB evidence is not a structure")
	}
	raw, err := json.Marshal(value.Data)
	if err != nil {
		return nil, err
	}
	var fields map[string]evidence.Value
	if err = json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("invalid PEB evidence map: %v", err)
	}
	return fields, nil
}
func pebTypedUint(fields map[string]evidence.Value, key, kind string) (uint64, error) {
	v, ok := fields[key]
	if !ok || v.Kind != kind {
		return 0, fmt.Errorf("PEB evidence lacks %s %s", kind, key)
	}
	return v.Uint()
}
func pebBool(value evidence.Value) (bool, error) {
	b, ok := value.Data.(bool)
	if value.Kind != "bool" || !ok {
		return false, fmt.Errorf("PEB evidence lacks typed boolean")
	}
	return b, nil
}
func pebRaw(value evidence.Value) ([]byte, error) {
	if value.Kind != "bytes" {
		return nil, fmt.Errorf("PEB string lacks raw bytes")
	}
	switch raw := value.Data.(type) {
	case []byte:
		return raw, nil
	case string:
		return base64.StdEncoding.DecodeString(raw)
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid PEB byte representation")
	}
}

func validatePebLength(row evidence.Row, textKey, detailKey, checkKey, compatibilityKey string) (checked, mismatch bool, err error) {
	text, exists := row.Cells[textKey]
	if !exists || text.Kind != "string" && (text.Kind != "missing" || text.Reason != "not_available" || text.Error != "") {
		return false, false, fmt.Errorf("PEB string has invalid state: %s", textKey)
	}
	if text.Kind == "string" {
		if value, ok := text.Data.(string); !ok || value == "" {
			return false, false, fmt.Errorf("PEB checked string must be nonempty")
		}
	}
	compatibility, err := pebBool(row.Cells[compatibilityKey])
	if err != nil {
		return false, false, err
	}
	check, exists := row.Cells[checkKey]
	if !exists {
		return false, false, fmt.Errorf("PEB evidence lacks %s", checkKey)
	}
	if check.Kind == "missing" {
		if check.Reason != "not_checked" || check.Error != "" || compatibility {
			return false, false, fmt.Errorf("unchecked PEB string has incompatible flags")
		}
		if text.Kind == "string" {
			details, err := pebEvidenceMap(row.Cells[detailKey])
			if err != nil || details["Error"].Error == "" {
				return false, false, fmt.Errorf("readable unchecked PEB string lacks comparison error")
			}
		}
		return false, false, nil
	}
	mismatch, err = pebBool(check)
	if err != nil || compatibility != mismatch || text.Kind != "string" {
		return false, false, fmt.Errorf("PEB string and comparison flags disagree")
	}
	details, err := pebEvidenceMap(row.Cells[detailKey])
	if err != nil {
		return false, false, err
	}
	for key, kind := range map[string]string{"Descriptor": "address", "Buffer": "address", "Length": "uint64", "MaximumLength": "uint64", "CapturedBytes": "uint64", "Codepoints": "uint64"} {
		if _, err = pebTypedUint(details, key, kind); err != nil {
			return false, false, err
		}
	}
	descriptor, _ := details["Descriptor"].Uint()
	parameters, err := pebTypedUint(row.Cells, "Parameters", "address")
	if err != nil || descriptor < parameters {
		return false, false, fmt.Errorf("PEB descriptor does not belong to process parameters")
	}
	if details["Layer"].Kind != "string" || details["Layer"].String() != row.Cells["ProcessLayer"].String() || row.Cells["ProcessLayer"].Kind != "string" || row.Cells["ProcessLayer"].String() == "" {
		return false, false, fmt.Errorf("PEB string layer differs from process layer")
	}
	if decoded := details["Decoded"]; decoded.Kind != "string" || decoded.String() != text.String() {
		return false, false, fmt.Errorf("PEB decoded text differs")
	}
	length, _ := details["Length"].Uint()
	maximum, _ := details["MaximumLength"].Uint()
	captured, _ := details["CapturedBytes"].Uint()
	points, _ := details["Codepoints"].Uint()
	raw, err := pebRaw(details["Raw"])
	if err != nil {
		return false, false, err
	}
	complete, err := pebBool(details["ReadComplete"])
	if err != nil || !complete || length > 65535 || maximum > 65535 || captured != length || uint64(len(raw)) != length || points != uint64(utf8.RuneCountInString(text.String())) || details["Error"].Error != "" {
		return false, false, fmt.Errorf("PEB length check lacks a complete matching string capture")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	decoded := string(utf16.Decode(units))
	if len(raw)%2 != 0 {
		decoded += "\ufffd"
	}
	decoded, _, _ = strings.Cut(decoded, "\x00")
	if decoded != text.String() {
		return false, false, fmt.Errorf("PEB text differs from captured UTF16 bytes")
	}
	expected := int64(length/2) != int64(points) || int64(maximum/2)-1 != int64(points)
	if expected != mismatch {
		return false, false, fmt.Errorf("PEB mismatch disagrees with raw lengths")
	}
	return true, mismatch, nil
}

func (n *nativeCheckEvaluator) consumePebMasquerade(ctx context.Context, row evidence.Row, emit plugin.Emit) error {
	identity, err := required(row, "ProcessIdentity")
	if err != nil || identity.Kind != "string" || identity.String() == "" {
		return fmt.Errorf("PEB evidence lacks process identity")
	}
	address, err := pebTypedUint(row.Cells, "ProcessOffset", "address")
	proof, proofErr := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || proofErr != nil || proof != address || row.Provenance.Layer == "" {
		return fmt.Errorf("PEB process coordinates differ from provenance")
	}
	if _, err = pebTypedUint(row.Cells, "PID", "uint64"); err != nil {
		return err
	}
	errorsCell, exists := row.Cells["Error"]
	if !exists {
		return fmt.Errorf("PEB evidence lacks error state")
	}
	if errorsCell.Kind == "structure" {
		issues, err := pebEvidenceMap(errorsCell)
		if err != nil || len(issues) == 0 {
			return fmt.Errorf("PEB error structure is empty or invalid")
		}
		for stage, value := range issues {
			if stage == "" || value.Kind != "missing" || value.Reason != stage || value.Error == "" {
				return fmt.Errorf("PEB error entry lacks cause")
			}
			n.diagnostics++
		}
	} else if errorsCell.Kind != "missing" || errorsCell.Reason != "not_applicable" || errorsCell.Error != "" {
		return fmt.Errorf("invalid PEB error state")
	}
	n.pebCounts[0]++
	anyMismatch := false
	for i, field := range []struct{ text, detail, check, compatibility string }{
		{"PEB_ImageFilePath", "ImagePathEvidence", "ImagePathLengthMismatch", "PEB_CommandLine_Spoofed"},
		{"PEB_CommandLine", "CommandLineEvidence", "CommandLineLengthMismatch", "PEB_ImageFilePath_Spoofed"},
	} {
		checked, mismatch, err := validatePebLength(row, field.text, field.detail, field.check, field.compatibility)
		if err != nil {
			return err
		}
		if checked {
			n.pebCounts[1+i]++
		}
		if mismatch {
			n.pebCounts[3+i]++
			anyMismatch = true
		}
	}
	if anyMismatch {
		if _, err = pebTypedUint(row.Cells, "PEB", "address"); err != nil {
			return err
		}
		n.findings++
		return emitFinding(ctx, n.rule, row, identity.String(), []string{row.ID}, emit)
	}
	return nil
}
func (n *nativeCheckEvaluator) finishPebMasquerade() (map[string]string, error) {
	keys := []string{"processes", "image_path_checked", "command_line_checked", "image_path_mismatches", "command_line_mismatches", "diagnostics"}
	for i, key := range keys {
		value, ok := n.coverage[key]
		expected := n.diagnostics
		if i < len(n.pebCounts) {
			expected = n.pebCounts[i]
		}
		if !ok || value != strconv.FormatUint(expected, 10) {
			return n.coverage, fmt.Errorf("PEB %s count differs from observed records", key)
		}
	}
	if n.diagnostics > 0 || n.pebCounts[1] < n.pebCounts[0] || n.pebCounts[2] < n.pebCounts[0] {
		return n.coverage, fmt.Errorf("%w: %d PEB diagnostics; path/command checks cover %d/%d of %d processes; length indicators remain informational", ErrIncomplete, n.diagnostics, n.pebCounts[1], n.pebCounts[2], n.pebCounts[0])
	}
	return n.coverage, nil
}
