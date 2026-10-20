package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsAmcachePlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"string", "EntryType Path Company LastModifyTime LastModifyTime2 InstallTime CompileTime SHA1 Service ProductName ProductVersion RecordType Error"},
		{"uint64", "Depth"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.amcache", Upstream: "windows.registry.amcache.Amcache", Platform: "windows", NeedsKernel: true,
		Description: "Read executed-program inventory from the first Amcache hive",
		Columns:     columns,
	}, windowsAmcache}}
}

const (
	regNone uint32 = iota
	regSZ
	regExpandSZ
	regBinary
	regDWORD
	regDWORDBE
	regLink
	regMultiSZ
	regResourceList
	regFullResource
	regResourceRequirements
	regQWORD
)

type amRecord struct {
	kind                                          string
	id                                            evidence.Value
	path, company, sha, service, product, version evidence.Value
	last, last2, install, compile                 evidence.Value
	offset                                        uint64
	layer                                         string
}

type amPrograms struct {
	order []string
	items map[string]amRecord
}

func newAmPrograms() *amPrograms {
	return &amPrograms{items: map[string]amRecord{}}
}

func (p *amPrograms) put(id string, row amRecord) {
	if _, ok := p.items[id]; !ok {
		p.order = append(p.order, id)
	}
	p.items[id] = row
}

func (p *amPrograms) pop(id string) (amRecord, bool) {
	row, ok := p.items[id]
	if ok {
		delete(p.items, id)
	}
	return row, ok
}

type amState struct {
	seq int
}

func windowsAmcache(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return err
	}
	proc, _, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return err
	}
	var hive *registry.Hive
	var item listedHive
	for _, candidate := range hives {
		if !strings.Contains(strings.ToLower(candidate.Name), "amcache") {
			continue
		}
		opened, openErr := registry.Open(ctx, e.Kernel, proc, candidate.Address, candidate.Name, layout)
		if openErr != nil {
			continue
		}
		hive, item = opened, candidate
		break
	}
	if hive == nil {
		return out(amDiagnostic(e, "amcache_hive_not_found", fmt.Errorf("no readable hive name contains amcache")))
	}
	state := &amState{}
	if err := state.drivers(ctx, e, hive, out); err != nil {
		return err
	}
	if err := state.win8(ctx, e, hive, out); err != nil {
		return err
	}
	return state.win10(ctx, e, hive, item, out)
}

func (s *amState) drivers(ctx context.Context, e plugin.Environment, hive *registry.Hive, out plugin.Emit) error {
	key, ok, err := amSection(ctx, hive, `Root\InventoryDriverBinary`)
	if err != nil || !ok {
		return err
	}
	subs, subErr := hive.Subkeys(ctx, key)
	if subErr != nil && len(subs) == 0 {
		return nil
	}
	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		values, _ := amValues(ctx, hive, sub)
		name := sub.Name
		var path, sha evidence.Value
		if strings.Contains(name, "/") {
			path = evidence.Text(name)
			sha = amString(values, "DriverId")
		} else {
			sha = evidence.Text(name)
			path = amString(values, "DriverName")
		}
		sha = amStripHash(sha, true)
		row := amRecord{
			kind: "Driver", id: evidence.Missing("not_applicable", nil), path: path, sha: sha,
			company: amString(values, "DriverCompany"), product: amString(values, "Product"),
			service: amString(values, "Service"), last: amFiletime(sub.LastWrite),
			compile: amEpoch(values, "DriverTimeStamp"), offset: sub.Address, layer: amLayer(hive, sub.Address),
		}
		if err := s.emit(e, row, "", "", 0, out); err != nil {
			return err
		}
	}
	return nil
}

func (s *amState) win8(ctx context.Context, e plugin.Environment, hive *registry.Hive, out plugin.Emit) error {
	programs := newAmPrograms()
	if key, ok, err := amSection(ctx, hive, `Root\Programs`); err != nil {
		return err
	} else if ok {
		subs, subErr := hive.Subkeys(ctx, key)
		if subErr == nil || len(subs) > 0 {
			for _, sub := range subs {
				values, _ := amValues(ctx, hive, sub)
				id := amProgramKey(sub.Name)
				programs.put(id, amRecord{
					kind: "Program", id: evidence.Text(id), company: amString(values, "2"),
					last: amFiletime(sub.LastWrite), install: amEpoch(values, "a"),
					product: amString(values, "0"), version: amString(values, "1"),
					offset: sub.Address, layer: amLayer(hive, sub.Address),
				})
			}
		}
	}
	var files []amRecord
	if key, ok, err := amSection(ctx, hive, `Root\File`); err != nil {
		return err
	} else if ok {
		volumes, volErr := hive.Subkeys(ctx, key)
		if volErr == nil || len(volumes) > 0 {
			for _, volume := range volumes {
				entries, entErr := hive.Subkeys(ctx, volume)
				if entErr != nil && len(entries) == 0 {
					continue
				}
				for _, sub := range entries {
					values, _ := amValues(ctx, hive, sub)
					files = append(files, amRecord{
						kind: "File", id: amString(values, "100"), path: amString(values, "15"),
						company: amString(values, "1"), last: amFiletimeValue(values, "11"),
						last2: amFiletimeValue(values, "17"), install: amFiletimeValue(values, "12"),
						compile: amEpoch(values, "f"), sha: amStripHash(amString(values, "101"), false),
						product: amString(values, "0"), offset: sub.Address, layer: amLayer(hive, sub.Address),
					})
				}
			}
		}
	}
	return s.grouped(e, programs, files, out)
}

func (s *amState) win10(ctx context.Context, e plugin.Environment, hive *registry.Hive, _ listedHive, out plugin.Emit) error {
	programs := newAmPrograms()
	if key, ok, err := amSection(ctx, hive, `Root\InventoryApplication`); err != nil {
		return err
	} else if ok {
		subs, subErr := hive.Subkeys(ctx, key)
		if subErr == nil || len(subs) > 0 {
			for _, sub := range subs {
				values, _ := amValues(ctx, hive, sub)
				id := amProgramKey(sub.Name)
				name := amString(values, "Name")
				product := name
				if name.Kind != "string" {
					product = evidence.Text("UNKNOWN")
				}
				programs.put(id, amRecord{
					kind: "Program", id: evidence.Text(id), path: amString(values, "RootDirPath"),
					company: amString(values, "Publisher"), last: amFiletime(sub.LastWrite),
					install: amDateString(values, "InstallDate"), product: product,
					version: amString(values, "Version"), offset: sub.Address, layer: amLayer(hive, sub.Address),
				})
			}
		}
	}
	var files []amRecord
	if key, ok, err := amSection(ctx, hive, `Root\InventoryApplicationFile`); err != nil {
		return err
	} else if ok {
		subs, subErr := hive.Subkeys(ctx, key)
		if subErr == nil || len(subs) > 0 {
			for _, sub := range subs {
				values, _ := amValues(ctx, hive, sub)
				files = append(files, amRecord{
					kind: "File", id: amString(values, "ProgramId"), path: amString(values, "LowerCaseLongPath"),
					company: amString(values, "Publisher"), last: amFiletime(sub.LastWrite),
					compile: amDateString(values, "LinkDate"), sha: amStripHash(amString(values, "FileId"), false),
					product: amString(values, "ProductName"), version: amString(values, "ProductVersion"),
					offset: sub.Address, layer: amLayer(hive, sub.Address),
				})
			}
		}
	}
	return s.grouped(e, programs, files, out)
}

func (s *amState) grouped(e plugin.Environment, programs *amPrograms, files []amRecord, out plugin.Emit) error {
	sort.SliceStable(files, func(i, j int) bool {
		return amSortKey(files[i].id) < amSortKey(files[j].id)
	})
	for start := 0; start < len(files); {
		key := amSortKey(files[start].id)
		end := start + 1
		for end < len(files) && amSortKey(files[end].id) == key {
			end++
		}
		parent := ""
		depth := 0
		if program, ok := programs.pop(amProgramKey(key)); ok {
			parent = s.token()
			if err := s.emit(e, program, parent, "", 0, out); err != nil {
				return err
			}
			depth = 1
		}
		for _, file := range files[start:end] {
			if err := s.emit(e, file, "", parent, depth, out); err != nil {
				return err
			}
		}
		start = end
	}
	for _, id := range programs.order {
		program, ok := programs.items[id]
		if !ok {
			continue
		}
		if err := s.emit(e, program, "", "", 0, out); err != nil {
			return err
		}
	}
	return nil
}

func (s *amState) token() string {
	s.seq++
	return fmt.Sprintf("amcache-%d", s.seq)
}

func (s *amState) emit(e plugin.Environment, row amRecord, id, parent string, depth int, out plugin.Emit) error {
	outRow := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: row.layer, Offset: fmt.Sprintf("0x%x", row.offset)}}
	if outRow.Provenance.Layer == "" {
		outRow.Provenance.Layer = e.Kernel.Name()
	}
	for _, column := range windowsAmcachePlugins()[0].spec.Columns {
		outRow.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	outRow.Cells["RecordType"] = evidence.Text("entry")
	outRow.Cells["EntryType"] = evidence.Text(row.kind)
	outRow.Cells["Depth"] = evidence.Number(uint64(depth))
	set := func(name string, value evidence.Value) {
		if value.Kind != "" {
			outRow.Cells[name] = value
		}
	}
	set("Path", row.path)
	set("Company", row.company)
	set("LastModifyTime", row.last)
	set("LastModifyTime2", row.last2)
	set("InstallTime", row.install)
	set("CompileTime", row.compile)
	set("SHA1", row.sha)
	set("Service", row.service)
	set("ProductName", row.product)
	set("ProductVersion", row.version)
	if id != "" {
		outRow.ID = id
	}
	if parent != "" && depth > 0 {
		outRow.ParentID = parent
	}
	return out(outRow)
}

func amDiagnostic(e plugin.Environment, reason string, cause error) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	for _, column := range windowsAmcachePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["RecordType"] = evidence.Text("absent")
	row.Cells["Depth"] = evidence.Number(0)
	row.Cells["Error"] = evidence.Missing(reason, cause)
	return row
}

func amSection(ctx context.Context, hive *registry.Hive, path string) (registry.Key, bool, error) {
	keys, err := resolveRegistryKey(ctx, hive, path)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return registry.Key{}, false, nil
		}
		return registry.Key{}, false, err
	}
	return keys[len(keys)-1], true, nil
}

func amValues(ctx context.Context, hive *registry.Hive, key registry.Key) (map[string]registry.Value, error) {
	values, err := hive.Values(ctx, key)
	out := map[string]registry.Value{}
	for _, value := range values {
		out[value.Name] = value
	}
	return out, err
}

func amSortKey(id evidence.Value) string {
	if id.Kind == "string" {
		return id.String()
	}
	return ""
}

func amProgramKey(id string) string {
	return strings.Trim(strings.TrimSpace(id), "\x00")
}

func amLayer(hive *registry.Hive, address uint64) string {
	if name, ok := hive.LayerName(address); ok {
		return name
	}
	return ""
}

func amString(values map[string]registry.Value, name string) evidence.Value {
	value, ok := values[name]
	if !ok {
		return evidence.Missing("not_available", nil)
	}
	if value.DataErr != nil {
		return evidence.Missing("unparsable", value.DataErr)
	}
	switch value.Type {
	case regDWORD, regDWORDBE, regQWORD:
		return evidence.Missing("unparsable", nil)
	default:
		return evidence.Text(amUTF16(value.Data))
	}
}

func amFiletimeValue(values map[string]registry.Value, name string) evidence.Value {
	n, ok, value := amInt(values, name)
	if !ok {
		return value
	}
	return amFiletime(n)
}

func amEpoch(values map[string]registry.Value, name string) evidence.Value {
	n, ok, value := amInt(values, name)
	if !ok {
		return value
	}
	if n > uint64(1<<63-1) {
		return evidence.Missing("unparsable", nil)
	}
	stamp := int64(n)
	if stamp < 0 {
		return evidence.Missing("unparsable", nil)
	}
	// Match datetime.fromtimestamp: years outside 1..9999 are unparsable.
	if stamp > 253402300799 {
		return evidence.Missing("unparsable", nil)
	}
	return evidence.Text(time.Unix(stamp, 0).UTC().Format(time.RFC3339Nano))
}

func amDateString(values map[string]registry.Value, name string) evidence.Value {
	if _, ok := values[name]; !ok {
		return evidence.Missing("not_available", nil)
	}
	// The pinned helper rejects every decoded value before its string branch.
	return evidence.Missing("unparsable", nil)
}

func amInt(values map[string]registry.Value, name string) (uint64, bool, evidence.Value) {
	value, ok := values[name]
	if !ok {
		return 0, false, evidence.Missing("not_available", nil)
	}
	if value.DataErr != nil {
		return 0, false, evidence.Missing("unparsable", value.DataErr)
	}
	switch value.Type {
	case regDWORD:
		if len(value.Data) != 4 {
			return 0, false, evidence.Missing("unparsable", nil)
		}
		return uint64(binary.LittleEndian.Uint32(value.Data)), true, evidence.Value{}
	case regDWORDBE:
		if len(value.Data) != 4 {
			return 0, false, evidence.Missing("unparsable", nil)
		}
		return uint64(binary.BigEndian.Uint32(value.Data)), true, evidence.Value{}
	case regQWORD:
		if len(value.Data) != 8 {
			return 0, false, evidence.Missing("unparsable", nil)
		}
		return binary.LittleEndian.Uint64(value.Data), true, evidence.Value{}
	default:
		return 0, false, evidence.Missing("unparsable", nil)
	}
}

func amFiletime(raw uint64) evidence.Value {
	return windowsFiletime(raw)
}

func amStripHash(value evidence.Value, driver bool) evidence.Value {
	if value.Kind != "string" {
		return value
	}
	text := value.String()
	if driver && strings.HasPrefix(text, "0000") {
		text = text[4:]
	}
	return evidence.Text(strings.TrimLeft(text, "0"))
}

func amUTF16(data []byte) string {
	body := data
	var odd bool
	if len(body)%2 == 1 {
		odd = true
		body = body[:len(body)-1]
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[i*2:])
	}
	text := string(utf16.Decode(units))
	if odd {
		text += "\uFFFD"
	}
	return strings.TrimRight(text, "\x00")
}
