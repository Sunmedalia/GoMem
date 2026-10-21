package triage

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type moduleCoordinate struct {
	layer, space string
	offset       uint64
}
type moduleResolver func(context.Context, evidence.Row) (moduleCoordinate, error)

// Keys describe the LDR object, not its name or the module's executable base.
// In the case workflow both virtual and legacy physical pool objects use the
// physical backing coordinate; original rows and evidence IDs stay unchanged.
func physicalModuleResolver(e plugin.Environment) moduleResolver {
	return func(ctx context.Context, row evidence.Row) (moduleCoordinate, error) {
		if err := ctx.Err(); err != nil {
			return moduleCoordinate{}, err
		}
		address, err := moduleObjectAddress(row)
		if err != nil {
			return moduleCoordinate{}, err
		}
		if e.Physical == nil || e.Kernel == nil {
			return moduleCoordinate{}, fmt.Errorf("module comparison requires kernel and physical layers")
		}
		result := moduleCoordinate{layer: e.Physical.Name(), space: "physical", offset: address}
		if row.Provenance.Layer == e.Physical.Name() {
			return result, nil
		}
		if row.Provenance.Layer != e.Kernel.Name() {
			return moduleCoordinate{}, fmt.Errorf("module object has an unknown source layer %q", row.Provenance.Layer)
		}
		virtual, ok := e.Kernel.(*memory.Virtual)
		if !ok || virtual.Translator == nil {
			return moduleCoordinate{}, fmt.Errorf("%w: no module object translator", ErrIncomplete)
		}
		mapping, err := virtual.Translator.Translate(ctx, address)
		if err != nil {
			if ctx.Err() != nil {
				return moduleCoordinate{}, ctx.Err()
			}
			return moduleCoordinate{}, fmt.Errorf("%w: module object translation: %v", ErrIncomplete, err)
		}
		result.offset = mapping.Physical
		return result, nil
	}
}

func moduleObjectAddress(row evidence.Row) (uint64, error) {
	value, err := required(row, "Offset")
	if err != nil || value.Kind != "address" || row.Provenance.Layer == "" {
		return 0, fmt.Errorf("module evidence lacks object coordinates")
	}
	address, err := value.Uint()
	proof, proofErr := strconv.ParseUint(row.Provenance.Offset, 0, 64)
	if err != nil || proofErr != nil || address != proof {
		return 0, fmt.Errorf("module object offset differs from provenance")
	}
	return address, nil
}

func rawModuleResolver(_ context.Context, row evidence.Row) (moduleCoordinate, error) {
	address, err := moduleObjectAddress(row)
	return moduleCoordinate{layer: row.Provenance.Layer, space: "source", offset: address}, err
}

type moduleViewEvaluator struct {
	rule              Rule
	resolve           moduleResolver
	active, scanned   map[moduleCoordinate]bool
	image, domain     string
	activeRows        uint64
	scannedRows       uint64
	matched           uint64
	mismatches        uint64
	activeUnresolved  uint64
	scannedUnresolved uint64
	coverage          map[string]string
	diagnostic        bool
	scanning          bool
	firstUnresolved   string
}

func (m *moduleViewEvaluator) consume(ctx context.Context, rows []evidence.Row, scanning bool, emit plugin.Emit) error {
	if !scanning && m.scanning {
		return fmt.Errorf("active modules received after the pool scan started")
	}
	m.scanning = scanning
	if m.resolve == nil {
		m.resolve = rawModuleResolver
	}
	if m.active == nil {
		m.active = map[moduleCoordinate]bool{}
		m.scanned = map[moduleCoordinate]bool{}
	}
	name := "windows.modules"
	if scanning {
		name = "windows.modscan"
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := row.Verify(); err != nil {
			return err
		}
		if row.Provenance.Plugin != name || row.Provenance.ImageSHA256 == "" || m.image != "" && m.image != row.Provenance.ImageSHA256 {
			return fmt.Errorf("module comparison received wrong plugin or mixed image evidence")
		}
		m.image = row.Provenance.ImageSHA256
		if m.coverage != nil {
			return fmt.Errorf("module comparison received rows after the scan summary")
		}
		if scanning {
			if row.Cells["RecordType"].Kind != "string" {
				return fmt.Errorf("module scan record type is not a string")
			}
			switch row.Cells["RecordType"].String() {
			case "summary":
				values, ok := row.Cells["Coverage"].Data.(map[string]any)
				if row.Cells["Coverage"].Kind != "structure" || !ok {
					return fmt.Errorf("module scan lacks structured coverage")
				}
				m.coverage = map[string]string{}
				for key, value := range values {
					text, ok := value.(string)
					if !ok {
						return fmt.Errorf("module scan coverage %s is not a string", key)
					}
					m.coverage[key] = text
				}
				if m.coverage["layer"] != row.Provenance.Layer {
					return fmt.Errorf("module scan coverage layer differs from provenance")
				}
				if row.Cells["Error"].Error != "" {
					m.diagnostic = true
				}
				continue
			case "diagnostic":
				if row.Cells["Error"].Error == "" {
					return fmt.Errorf("module scan diagnostic lacks a cause")
				}
				m.diagnostic = true
				continue
			case "module":
			default:
				return fmt.Errorf("unexpected module scan record type")
			}
			m.scannedRows++
		} else {
			if kind, ok := row.Cells["RecordType"]; ok && (kind.Kind != "string" || kind.String() != "module") {
				return fmt.Errorf("unexpected active module record type")
			}
			m.activeRows++
		}
		coordinate, err := m.resolve(ctx, row)
		if err != nil {
			if !errors.Is(err, ErrIncomplete) {
				return err
			}
			if scanning {
				m.scannedUnresolved++
			} else {
				m.activeUnresolved++
			}
			if m.firstUnresolved == "" {
				m.firstUnresolved = err.Error()
			}
			continue
		}
		domain := coordinate.layer + "\x00" + coordinate.space
		if m.domain != "" && m.domain != domain {
			return fmt.Errorf("module comparison cannot mix coordinate spaces")
		}
		m.domain = domain
		if !scanning {
			m.active[coordinate] = true
			if len(m.active) > 1000000 {
				return fmt.Errorf("active module index exceeds 1000000 objects")
			}
			continue
		}
		if m.scanned[coordinate] {
			continue
		}
		m.scanned[coordinate] = true
		if len(m.scanned) > 1000000 {
			return fmt.Errorf("scanned module index exceeds 1000000 objects")
		}
		if m.active[coordinate] {
			m.matched++
			continue
		}
		// A failed active translation could be this object. Do not manufacture a
		// mismatch from the incomplete active view; finish reports the lost coverage.
		if m.activeUnresolved > 0 || m.activeRows == 0 {
			continue
		}
		m.mismatches++
		key := fmt.Sprintf("%s:%s:%s:%x", m.image, coordinate.space, coordinate.layer, coordinate.offset)
		if err := emitFinding(ctx, m.rule, row, key, []string{row.ID}, func(f evidence.Row) error {
			f.Cells["ComparisonOffset"] = evidence.Address(coordinate.offset)
			f.Cells["ComparisonLayer"] = evidence.Text(coordinate.layer)
			f.Cells["ComparisonSpace"] = evidence.Text(coordinate.space)
			f.Seal()
			return emit(f)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *moduleViewEvaluator) finish() (map[string]string, error) {
	result := map[string]string{"active_modules": formatModuleCount(m.activeRows), "scanned_modules": formatModuleCount(m.scannedRows), "matched": formatModuleCount(m.matched), "mismatches": formatModuleCount(m.mismatches), "active_unresolved": formatModuleCount(m.activeUnresolved), "scanned_unresolved": formatModuleCount(m.scannedUnresolved)}
	if m.coverage == nil {
		return result, fmt.Errorf("%w: module scan lacks a final coverage summary", ErrIncomplete)
	}
	for key, value := range m.coverage {
		result["pool_"+key] = value
	}
	counts := map[string]uint64{}
	for _, key := range []string{"modules", "ranges", "scanned_bytes", "skipped_invalid", "skipped_type", "skipped_name", "read_failures"} {
		value, ok := m.coverage[key]
		if !ok {
			return result, fmt.Errorf("module scan coverage lacks %s", key)
		}
		count, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return result, fmt.Errorf("invalid module scan coverage %s: %w", key, err)
		}
		counts[key] = count
	}
	if counts["modules"] != m.scannedRows {
		return result, fmt.Errorf("module count differs from its scan summary")
	}
	if m.activeUnresolved > 0 || m.scannedUnresolved > 0 {
		return result, fmt.Errorf("%w: %d active and %d scanned module objects have unresolved coordinates: %s", ErrIncomplete, m.activeUnresolved, m.scannedUnresolved, m.firstUnresolved)
	}
	if m.activeRows == 0 || counts["ranges"] == 0 || counts["scanned_bytes"] == 0 || m.diagnostic || counts["read_failures"] > 0 || counts["skipped_invalid"] > 0 || counts["skipped_type"] > 0 || counts["skipped_name"] > 0 {
		return result, fmt.Errorf("%w: module list or pool read coverage is incomplete", ErrIncomplete)
	}
	return result, nil
}
func formatModuleCount(n uint64) string { return strconv.FormatUint(n, 10) }
