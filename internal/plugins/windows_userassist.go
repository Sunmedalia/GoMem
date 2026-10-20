package plugins

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

//go:embed userassist_folders.json
var userAssistFolderJSON []byte

// The pinned baseline ships this MSDN known-folder table beside the plugin.
// Names are matched after ROT-13, including the one lowercase GUID.
var userAssistFolders = loadUserAssistFolders()

func loadUserAssistFolders() map[string]string {
	var folders map[string]string
	if err := json.Unmarshal(userAssistFolderJSON, &folders); err != nil {
		panic("userassist folder map: " + err.Error())
	}
	return folders
}

func windowsUserAssistPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "HiveOffset"},
		{"string", "HiveName Path LastWriteTime Type Name TimeFocused LastUpdated RawData RecordType Error"},
		{"uint64", "ID Count FocusCount Depth RawLastWrite RawLastUpdated"},
		{"bytes", "RawBytes"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.userassist", Upstream: "windows.registry.userassist.UserAssist", Platform: "windows", NeedsKernel: true,
		Description: "Decode UserAssist execution counts from NTUSER.DAT hives",
		Parameters: []plugin.Parameter{
			{Name: "offset", Kind: "string", Description: "Optional hive virtual address; canonical high bits may be omitted"},
		},
		Columns: columns,
	}, windowsUserAssist}}
}

const userAssistKey = `software\microsoft\windows\currentversion\explorer\userassist`

func windowsUserAssist(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	var selected *uint64
	if strings.TrimSpace(p["offset"]) != "" {
		value, err := strconv.ParseUint(strings.TrimSpace(p["offset"]), 0, 64)
		if err != nil {
			return fmt.Errorf("offset: %w", err)
		}
		selected = &value
	}
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return err
	}
	proc, _, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return err
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	known, win7 := userAssistWin7(e.Symbols)
	state := &assistState{known: known, win7: win7}
	for _, hive := range hives {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.Contains(strings.ToLower(hive.Name), "ntuser.dat") {
			continue
		}
		if selected != nil && !hiveOffsetMatch(hive.Address, *selected, e.Symbols.PointerSize()) {
			continue
		}
		if err := state.oneHive(ctx, e, hive, layout, proc, out); err != nil {
			return err
		}
	}
	return nil
}

func userAssistWin7(table symbols.SymbolTable) (known, win7 bool) {
	if table == nil {
		return false, false
	}
	typ, err := table.Type("_KUSER_SHARED_DATA")
	if err != nil {
		return false, false
	}
	_, ok := typ.Fields["CookiePad"]
	return true, ok
}

type assistState struct {
	known bool
	win7  bool
	seq   int
}

func (s *assistState) oneHive(ctx context.Context, e plugin.Environment, item listedHive, layout registry.Offsets, proc memory.MemoryLayer, out plugin.Emit) error {
	h, err := registry.Open(ctx, e.Kernel, proc, item.Address, item.Name, layout)
	if err != nil {
		return s.unreadable(e, item, err, out)
	}
	path, err := resolveRegistryKey(ctx, h, userAssistKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return s.unreadable(e, item, err, out)
	}
	node := path[len(path)-1]
	guids, guidErr := h.Subkeys(ctx, node)
	if guidErr != nil && len(guids) == 0 {
		return s.unreadable(e, item, guidErr, out)
	}
	for _, guid := range guids {
		if err := ctx.Err(); err != nil {
			return err
		}
		counts, countErr := h.Subkeys(ctx, guid)
		if countErr != nil && len(counts) == 0 {
			if err := s.unreadable(e, item, countErr, out); err != nil {
				return err
			}
			continue
		}
		for _, count := range counts {
			if err := s.countKey(ctx, e, item, h, append(append([]registry.Key{}, path...), guid, count), out); err != nil {
				return err
			}
		}
		if countErr != nil {
			if err := s.unreadable(e, item, countErr, out); err != nil {
				return err
			}
		}
	}
	if guidErr != nil {
		return s.unreadable(e, item, guidErr, out)
	}
	return nil
}

func (s *assistState) countKey(ctx context.Context, e plugin.Environment, item listedHive, h *registry.Hive, path []registry.Key, out plugin.Emit) error {
	count := path[len(path)-1]
	keyPath := userAssistKeyPath(item.Name, path)
	token := fmt.Sprintf("userassist-%d", s.seq)
	s.seq++
	parent := s.blank(e, item, h)
	parent.ID = token
	parent.Cells["RecordType"] = evidence.Text("key")
	parent.Cells["Type"] = evidence.Text("Key")
	parent.Cells["Path"] = evidence.Text(keyPath)
	parent.Cells["Depth"] = evidence.Number(0)
	write, rawWrite := userAssistStamp(count.LastWrite)
	parent.Cells["LastWriteTime"] = write
	parent.Cells["RawLastWrite"] = rawWrite
	parent.Cells["RawData"] = evidence.Text("N/A")
	parent.Provenance.Offset = fmt.Sprintf("0x%x", count.Address)
	if name, ok := h.LayerName(count.Address); ok {
		parent.Provenance.Layer = name
	}
	if err := out(parent); err != nil {
		return err
	}
	subs, subErr := h.Subkeys(ctx, count)
	for _, child := range subs {
		row := s.child(e, item, h, token, keyPath, write, rawWrite)
		row.Cells["RecordType"] = evidence.Text("subkey")
		row.Cells["Type"] = evidence.Text("Subkey")
		row.Cells["Name"] = evidence.Text(child.Name)
		row.Cells["RawData"] = evidence.Text("N/A")
		row.Provenance.Offset = fmt.Sprintf("0x%x", child.Address)
		if err := out(row); err != nil {
			return err
		}
	}
	if subErr != nil {
		if err := s.unreadable(e, item, subErr, out); err != nil {
			return err
		}
	}
	values, valErr := h.Values(ctx, count)
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		row := s.child(e, item, h, token, keyPath, write, rawWrite)
		row.Cells["RecordType"] = evidence.Text("value")
		row.Cells["Type"] = evidence.Text("Value")
		row.Cells["Name"] = evidence.Text(userAssistValueName(value.Name, s.known && s.win7))
		parsed := parseUserAssist(value.Data, value.DataErr, s.known, s.win7)
		row.Cells["ID"] = parsed.id
		row.Cells["Count"] = parsed.count
		row.Cells["FocusCount"] = parsed.focus
		row.Cells["TimeFocused"] = parsed.focused
		row.Cells["LastUpdated"] = parsed.updated
		row.Cells["RawLastUpdated"] = parsed.updatedRaw
		row.Cells["RawData"] = parsed.raw
		if parsed.rawBytes.Kind == "bytes" {
			row.Cells["RawBytes"] = parsed.rawBytes
		}
		if parsed.cause.Kind == "missing" && parsed.cause.Reason != "" && parsed.cause.Reason != "not_applicable" {
			row.Cells["Error"] = parsed.cause
		}
		row.Provenance.Offset = fmt.Sprintf("0x%x", value.Address)
		if err := out(row); err != nil {
			return err
		}
	}
	if valErr != nil {
		return s.unreadable(e, item, valErr, out)
	}
	return nil
}

func (s *assistState) child(e plugin.Environment, item listedHive, h *registry.Hive, token, keyPath string, write, rawWrite evidence.Value) evidence.Row {
	row := s.blank(e, item, h)
	row.ParentID = token
	row.Cells["Path"] = evidence.Text(keyPath)
	row.Cells["Depth"] = evidence.Number(1)
	row.Cells["LastWriteTime"] = write
	row.Cells["RawLastWrite"] = rawWrite
	return row
}

func (s *assistState) unreadable(e plugin.Environment, item listedHive, cause error, out plugin.Emit) error {
	row := s.blank(e, item, nil)
	row.Cells["RecordType"] = evidence.Text("unreadable")
	row.Cells["Depth"] = evidence.Number(0)
	row.Cells["RawData"] = evidence.Text("N/A")
	for _, name := range []string{"Path", "LastWriteTime", "Type", "Name", "TimeFocused", "LastUpdated", "ID", "Count", "FocusCount", "RawLastWrite", "RawLastUpdated"} {
		row.Cells[name] = evidence.Missing("unreadable", nil)
	}
	row.Cells["Error"] = evidence.Missing("hive_unreadable", cause)
	return out(row)
}

func (s *assistState) blank(e plugin.Environment, item listedHive, h *registry.Hive) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", item.Address)}}
	for _, column := range windowsUserAssistPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["HiveOffset"] = evidence.Address(item.Address)
	name := item.Name
	if name == "" {
		name = "[NONAME]"
	}
	row.Cells["HiveName"] = evidence.Text(name)
	if h != nil {
		if layer, ok := h.LayerName(item.Address); ok && layer != "" {
			row.Provenance.Layer = layer
		}
	}
	return row
}

func userAssistKeyPath(hive string, path []registry.Key) string {
	base := hive
	if i := strings.LastIndex(base, `\`); i >= 0 {
		base = base[i+1:]
	}
	if base == "" {
		base = "[NONAME]"
	}
	parts := []string{base}
	for _, key := range path[1:] {
		parts = append(parts, key.Name)
	}
	return strings.Join(parts, `\`)
}

func userAssistValueName(name string, win7 bool) string {
	name = rot13(name)
	if !win7 || name == "" {
		return name
	}
	guid := name
	if i := strings.Index(name, `\`); i >= 0 {
		guid = name[:i]
	}
	if folder, ok := userAssistFolders[guid]; ok {
		name = strings.ReplaceAll(name, guid, folder)
	}
	return name
}

func rot13(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune('A' + (r-'A'+13)%26)
		case r >= 'a' && r <= 'z':
			b.WriteRune('a' + (r-'a'+13)%26)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type assistParsed struct {
	id, count, focus, focused, updated, updatedRaw, raw, rawBytes, cause evidence.Value
}

func parseUserAssist(data []byte, dataErr error, known, win7 bool) assistParsed {
	out := assistParsed{
		id:         evidence.Missing("unparsable", nil),
		count:      evidence.Missing("unparsable", nil),
		focus:      evidence.Missing("unparsable", nil),
		focused:    evidence.Missing("unparsable", nil),
		updated:    evidence.Missing("unparsable", nil),
		updatedRaw: evidence.Missing("unparsable", nil),
		raw:        evidence.Missing("unparsable", nil),
		cause:      evidence.Missing("not_applicable", nil),
	}
	if dataErr != nil {
		out.raw = evidence.Missing("registry_value_unreadable", nil)
		out.cause = evidence.Missing("registry_value_unreadable", dataErr)
		return out
	}
	out.raw = evidence.Text(spaceHex(data))
	out.rawBytes = evidence.Bytes(data)
	if !known {
		return out
	}
	size := 16
	if win7 {
		size = 72
	}
	if len(data) < size {
		return out
	}
	if win7 {
		out.id = evidence.Missing("not_applicable", nil)
		out.count = evidence.Number(uint64(binary.LittleEndian.Uint32(data[4:8])))
		out.focus = evidence.Number(uint64(binary.LittleEndian.Uint32(data[8:12])))
		out.focused = evidence.Text(focusDuration(binary.LittleEndian.Uint32(data[12:16])))
		raw := binary.LittleEndian.Uint64(data[60:68])
		out.updated = userAssistFiletime(int64(raw))
		out.updatedRaw = evidence.Number(raw)
		return out
	}
	count := binary.LittleEndian.Uint32(data[4:8])
	if count >= 5 {
		count -= 5
	}
	out.id = evidence.Number(uint64(binary.LittleEndian.Uint32(data[0:4])))
	out.count = evidence.Number(uint64(count))
	out.focus = evidence.Missing("not_applicable", nil)
	out.focused = evidence.Missing("not_applicable", nil)
	raw := binary.LittleEndian.Uint64(data[8:16])
	out.updated = userAssistFiletime(int64(raw))
	out.updatedRaw = evidence.Number(raw)
	return out
}

func userAssistStamp(raw uint64) (evidence.Value, evidence.Value) {
	return userAssistFiletime(int64(raw)), evidence.Number(raw)
}

func userAssistFiletime(raw int64) evidence.Value {
	// The 100 ns value is a signed QuadPart. Real UserAssist times fit in the
	// positive range; the high bit is not a second-resolution timestamp.
	return windowsFiletime(uint64(raw))
}

func focusDuration(focus uint32) string {
	return formatTimedelta(focusMicros(focus))
}

func focusMicros(focus uint32) int64 {
	seconds := float64(uint64(focus)+500) / 1000.0
	whole, frac := math.Modf(seconds)
	us := int64(whole) * 1000000
	if frac == 0 {
		return us
	}
	scaled := 1000000.0 * frac
	whole2, frac2 := math.Modf(scaled)
	us += int64(whole2)
	if frac2 == 0 {
		return us
	}
	wholeUS := pyRound(frac2)
	if math.Abs(wholeUS-frac2) == 0.5 {
		odd := 0.0
		if us&1 == 1 {
			odd = 1
		}
		wholeUS = 2*pyRound((frac2+odd)*0.5) - odd
	}
	return us + int64(wholeUS)
}

func pyRound(x float64) float64 {
	sign := 1.0
	if x < 0 {
		sign = -1
		x = -x
	}
	floor := math.Floor(x)
	diff := x - floor
	var rounded float64
	switch {
	case diff > 0.5:
		rounded = floor + 1
	case diff < 0.5:
		rounded = floor
	case int64(floor)%2 == 0:
		rounded = floor
	default:
		rounded = floor + 1
	}
	return sign * rounded
}

func formatTimedelta(us int64) string {
	sign := ""
	if us < 0 {
		sign = "-"
		us = -us
	}
	const usec = int64(1000000)
	days := us / (86400 * usec)
	rem := us % (86400 * usec)
	seconds := rem / usec
	micros := rem % usec
	body := fmt.Sprintf("%d:%02d:%02d", seconds/3600, (seconds%3600)/60, seconds%60)
	if micros != 0 {
		body += fmt.Sprintf(".%06d", micros)
	}
	if days == 0 {
		return sign + body
	}
	unit := "days"
	if days == 1 {
		unit = "day"
	}
	return fmt.Sprintf("%s%d %s, %s", sign, days, unit, body)
}

func spaceHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var buf strings.Builder
	buf.Grow(len(b)*3 - 1)
	for i, v := range b {
		if i > 0 {
			buf.WriteByte(' ')
		}
		fmt.Fprintf(&buf, "%02x", v)
	}
	return buf.String()
}
