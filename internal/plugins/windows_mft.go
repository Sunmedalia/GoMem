package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/ntfs"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsMFTPlugins() []builtin {
	var result []builtin
	for _, item := range []struct{ name, upstream string }{{"windows.mftscan", "windows.mftscan.MFTScan"}, {"windows.ads", "windows.mftscan.ADS"}, {"windows.residentdata", "windows.mftscan.ResidentData"}} {
		name := item.name
		columns := []evidence.Column{}
		for _, column := range []struct{ name, kind string }{{"Offset", "address"}, {"RecordSignature", "string"}, {"RecordNumber", "uint64"}, {"LinkCount", "uint64"}, {"MFTType", "string"}, {"Permissions", "string"}, {"AttributeType", "string"}, {"Created", "string"}, {"Modified", "string"}, {"Updated", "string"}, {"Accessed", "string"}, {"Filename", "string"}, {"ADSFilename", "string"}, {"Hexdump", "bytes"}, {"RecordType", "string"}, {"RecordOffset", "address"}, {"FlagsRaw", "uint64"}, {"BaselineLevel", "uint64"}, {"TimesRaw", "structure"}, {"Attribute", "structure"}, {"ContentOffset", "address"}, {"ContentLength", "uint64"}, {"FilenameAvailable", "bool"}, {"Requested", "uint64"}, {"Captured", "uint64"}, {"Raw", "bytes"}, {"RawSHA256", "string"}, {"Error", "string"}, {"Coverage", "structure"}} {
			columns = append(columns, evidence.Column{Name: column.name, Kind: column.kind})
		}
		spec := plugin.Spec{Name: name, Upstream: item.upstream, Platform: "windows", Description: "Scan original physical MFT candidates and retain bounded attributes, resident bytes and source evidence", Columns: columns, Parameters: []plugin.Parameter{
			{Name: "max-records", Kind: "uint", Default: "100000", Description: "Scanned candidate bound, 1..1000000; overlap repeats count separately"},
			{Name: "max-attributes", Kind: "uint", Default: "1000000", Description: "Task attribute bound, 1..16777216"},
			{Name: "max-read-bytes", Kind: "uint", Default: "536870912", Description: "Task parsed acquisition bytes, 1..4294967296"},
			{Name: "max-scan-bytes", Kind: "uint", Default: "68719476736", Description: "Task actual scan read bytes including overlap, 1..1125899906842624"},
		}}
		result = append(result, builtin{spec, func(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
			return windowsMFT(ctx, e, p, out, name)
		}})
	}
	return result
}

type mftCoverage struct {
	Candidates, Attributes, Rows, Reads, Bytes, ScanReads, ScanBytes, Errors uint64
	Complete                                                                 bool
}
type mftAnalysis struct {
	ctx              context.Context
	out              plugin.Emit
	layer            memory.MemoryLayer
	maxRead, maxScan uint64
	coverage         mftCoverage
	stop             error
	failures         []error
	parent, lastRoot string
	mode             string
}

func (a *mftAnalysis) emit(row evidence.Row) error {
	if a.stop != nil {
		return a.stop
	}
	if err := a.ctx.Err(); err != nil {
		a.stop = err
		return err
	}
	a.stop = a.out(row)
	if a.stop == nil {
		a.stop = a.ctx.Err()
	}
	return a.stop
}
func (a *mftAnalysis) failure(err error) {
	if err == nil {
		return
	}
	a.coverage.Errors++
	if len(a.failures) < 64 {
		a.failures = append(a.failures, err)
	}
}

type mftRead struct {
	a    *mftAnalysis
	scan bool
}

func (l mftRead) Name() string           { return l.a.layer.Name() }
func (l mftRead) Ranges() []memory.Range { return l.a.layer.Ranges() }
func (l mftRead) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	a := l.a
	if a.stop != nil {
		return 0, a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	used, limit := a.coverage.Bytes, a.maxRead
	if l.scan {
		used, limit = a.coverage.ScanBytes, a.maxScan
	}
	if uint64(len(p)) > limit-used {
		a.stop = fmt.Errorf("MFT acquisition byte budget exhausted")
		return 0, a.stop
	}
	n, err := a.layer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid MFT read count")
	}
	if err == nil && n != len(p) {
		err = fmt.Errorf("short MFT read: %d/%d", n, len(p))
	}
	cell := evidence.Missing("no_error", nil)
	if err != nil {
		a.failure(err)
		cell = evidence.Text(err.Error())
	}
	row := evidence.Row{ParentID: a.parent, Cells: map[string]evidence.Value{"Offset": evidence.Address(at), "Requested": evidence.Number(uint64(len(p))), "Captured": evidence.Number(uint64(n)), "Error": cell}, Provenance: evidence.Provenance{Layer: l.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	if l.scan {
		a.coverage.ScanReads++
		a.coverage.ScanBytes += uint64(n)
		hash := sha256.Sum256(p[:n])
		row.ParentID = ""
		row.Cells["RecordType"] = evidence.Text("scan_read")
		row.Cells["RawSHA256"] = evidence.Text(hex.EncodeToString(hash[:]))
	} else {
		a.coverage.Reads++
		a.coverage.Bytes += uint64(n)
		row.Cells["RecordType"] = evidence.Text("memory_read")
		row.Cells["Raw"] = evidence.Bytes(p[:n])
	}
	if cause := a.emit(row); cause != nil {
		return n, cause
	}
	return n, err
}
func windowsMFT(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit, mode string) (err error) {
	if e.Physical == nil || e.OS != "windows" {
		return fmt.Errorf("Windows MFT scan requires a Windows physical image; kernel symbols are optional")
	}
	bounds := map[string]uint64{}
	for name, limit := range map[string]uint64{"max-records": 1000000, "max-attributes": 1 << 24, "max-read-bytes": 1 << 32, "max-scan-bytes": 1 << 50} {
		n, cause := strconv.ParseUint(p[name], 0, 64)
		if cause != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", name, limit)
		}
		bounds[name] = n
	}
	a := &mftAnalysis{ctx: ctx, out: out, layer: e.Physical, maxRead: bounds["max-read-bytes"], maxScan: bounds["max-scan-bytes"], mode: mode}
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: a.coverage}}, Provenance: evidence.Provenance{Layer: e.Physical.Name()}}))
	}()
	return ntfs.Scan(ctx, mftRead{a, true}, func(at uint64) error {
		if a.coverage.Candidates >= bounds["max-records"] {
			return fmt.Errorf("MFT candidate bound exhausted")
		}
		if a.coverage.Attributes >= bounds["max-attributes"] {
			return fmt.Errorf("MFT task attribute bound exhausted")
		}
		if a.coverage.Bytes >= a.maxRead {
			return fmt.Errorf("MFT task read bound exhausted")
		}
		a.coverage.Candidates++
		a.parent = fmt.Sprintf("mft-candidate:%d", a.coverage.Candidates)
		if err := a.emit(evidence.Row{ID: a.parent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("candidate"), "RecordOffset": evidence.Address(at)}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", at)}}); err != nil {
			return err
		}
		payloads := ntfs.FilenamePayload
		switch mode {
		case "windows.mftscan":
			payloads |= ntfs.StandardPayload
		case "windows.ads":
			payloads |= ntfs.AlternatePayload
		case "windows.residentdata":
			payloads |= ntfs.PrimaryPayload
		}
		record, cause := ntfs.ReadRecordPayloads(ctx, mftRead{a, false}, at, ntfs.Limits{MaxAttributes: min(bounds["max-attributes"]-a.coverage.Attributes, 1<<20), MaxBytes: a.maxRead - a.coverage.Bytes}, payloads)
		if a.stop != nil || ctx.Err() != nil {
			return errors.Join(a.stop, ctx.Err())
		}
		a.coverage.Attributes += uint64(len(record.Attributes))
		a.failure(cause)
		if cause != nil {
			if err := a.emit(evidence.Row{ParentID: a.parent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("diagnostic"), "RecordOffset": evidence.Address(at), "Error": evidence.Missing("mft_record_partial", cause)}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", at)}}); err != nil {
				return err
			}
		}
		for _, attr := range record.Attributes {
			detail := map[string]evidence.Value{"TypeRaw": evidence.Number(uint64(attr.TypeRaw)), "Length": evidence.Number(uint64(attr.Length)), "NonResident": evidence.Number(uint64(attr.NonResident)), "NameLength": evidence.Number(uint64(attr.NameLength)), "NameOffset": evidence.Number(uint64(attr.NameOffset)), "ContentLength": evidence.Number(uint64(attr.ContentLength)), "ContentOffset": evidence.Number(uint64(attr.ContentOffset))}
			errorCell := evidence.Missing("no_error", nil)
			if attr.Error != nil {
				errorCell = evidence.Missing("attribute_partial", attr.Error)
			}
			if err := a.emit(evidence.Row{ParentID: a.parent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("attribute"), "RecordOffset": evidence.Address(at), "Offset": evidence.Address(attr.Offset), "Attribute": {Kind: "structure", Data: detail}, "Error": errorCell}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", attr.Offset)}}); err != nil {
				return err
			}
		}
		return a.results(record)
	})
}
func mftTime(ticks uint64) evidence.Value {
	seconds := ticks / 10000000
	if seconds == 0 {
		return evidence.Missing("not_applicable", nil)
	}
	at := time.Unix(int64(seconds)-11644473600, 0).UTC()
	if at.Year() < 1 || at.Year() > 9999 {
		return evidence.Missing("unparsable_filetime", nil)
	}
	return evidence.Text(at.Format("2006-01-02T15:04:05-07:00"))
}
func (a *mftAnalysis) result(r ntfs.Record, offset uint64, level int, cells map[string]evidence.Value) error {
	a.coverage.Rows++
	row := evidence.Row{ID: fmt.Sprintf("mft-result:%d", a.coverage.Rows), Cells: cells, Provenance: evidence.Provenance{Layer: a.layer.Name(), Offset: fmt.Sprintf("0x%x", offset)}}
	cells["RecordType"] = evidence.Text("result")
	cells["Offset"] = evidence.Address(offset)
	cells["RecordOffset"] = evidence.Address(r.Offset)
	cells["RecordSignature"] = evidence.Text(r.Signature)
	cells["RecordNumber"] = evidence.Number(uint64(r.Number))
	cells["LinkCount"] = evidence.Number(uint64(r.Links))
	cells["MFTType"] = evidence.Text(r.Type())
	cells["FlagsRaw"] = evidence.Number(uint64(r.FlagsRaw))
	cells["BaselineLevel"] = evidence.Number(uint64(level))
	if a.mode == "windows.mftscan" {
		if level == 1 && a.lastRoot != "" {
			row.ParentID = a.lastRoot
		} else {
			a.lastRoot = row.ID
		}
	}
	return a.emit(row)
}
func mftTimes(cells map[string]evidence.Value, times [4]uint64) {
	raw := []evidence.Value{}
	for i, key := range []string{"Created", "Modified", "Updated", "Accessed"} {
		cells[key] = mftTime(times[i])
		raw = append(raw, evidence.Number(times[i]))
	}
	cells["TimesRaw"] = evidence.Value{Kind: "structure", Data: raw}
}
func (a *mftAnalysis) results(r ntfs.Record) error {
	if a.mode == "windows.mftscan" {
		for _, attr := range r.Attributes {
			if attr.Standard != nil {
				s := attr.Standard
				cells := map[string]evidence.Value{"AttributeType": evidence.Text("STANDARD_INFORMATION"), "Permissions": evidence.Missing("not_applicable", nil), "Filename": evidence.Missing("not_applicable", nil)}
				mftTimes(cells, s.Times)
				if err := a.result(r, s.Offset, 0, cells); err != nil {
					return err
				}
			}
		}
		for _, attr := range r.Attributes {
			if attr.Filename != nil {
				f := attr.Filename
				cells := map[string]evidence.Value{"AttributeType": evidence.Text("FILE_NAME"), "Permissions": evidence.Text(f.Permissions()), "Filename": evidence.Text(f.Name), "Attribute": {Kind: "structure", Data: map[string]evidence.Value{"PermissionsRaw": evidence.Number(uint64(f.PermissionsRaw))}}}
				mftTimes(cells, f.Times)
				if err := a.result(r, f.Offset, 1, cells); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, attr := range r.Attributes {
		if attr.Resident == nil || (a.mode == "windows.ads") != (attr.NameLength > 0) {
			continue
		}
		d := attr.Resident
		filename := r.LongestFilename()
		name := evidence.Text(filename)
		if filename == "" {
			if a.mode == "windows.ads" {
				name = evidence.Missing("not_available", nil)
			} else {
				name = evidence.Text("N/A")
			}
		}
		content := evidence.Bytes(d.Content)
		if len(d.Content) == 0 || d.ContentError != nil {
			content = evidence.Missing("not_available", d.ContentError)
		}
		cells := map[string]evidence.Value{"AttributeType": evidence.Text("DATA"), "Filename": name, "FilenameAvailable": evidence.Bool(filename != ""), "Hexdump": content, "ContentOffset": evidence.Address(d.Offset), "ContentLength": evidence.Number(uint64(attr.ContentLength))}
		if a.mode == "windows.ads" {
			stream := evidence.Text(d.Name)
			if d.Name == "" {
				stream = evidence.Missing("not_available", d.NameError)
			}
			cells["ADSFilename"] = stream
		}
		if err := a.result(r, attr.Offset+24, 0, cells); err != nil {
			return err
		}
		if a.mode == "windows.residentdata" {
			break
		}
	}
	return nil
}
