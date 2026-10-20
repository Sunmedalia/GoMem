package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsPrintKeyPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "HiveOffset Cell RegistryProcess"},
		{"string", "Type Key Name Data LastWriteTime RecordType RootFrom"},
		{"bytes", "DataRaw"},
		{"bool", "Volatile"},
		{"uint64", "Depth"},
		{"string", "Error"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.printkey", Upstream: "windows.registry.printkey.PrintKey", Platform: "windows", NeedsKernel: true,
		Description: "List stable then volatile subkeys and values through the kernel HMAP and Registry process",
		Parameters: []plugin.Parameter{
			{Name: "offset", Kind: "string", Description: "Optional hive virtual address; canonical high bits may be omitted"},
			{Name: "key", Kind: "string", Description: "Registry path below the hive root, case-insensitive"},
			{Name: "recurse", Kind: "bool", Default: "false", Description: "Walk child keys"},
			{Name: "max-nodes", Kind: "uint", Default: "1000000", Description: "Emitted row bound, 1..1000000"},
		},
		Columns: columns,
	}, windowsPrintKey}}
}

type listedHive struct {
	Address uint64
	Name    string
}

func windowsPrintKey(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	recurse, err := strconv.ParseBool(p["recurse"])
	if err != nil {
		return err
	}
	max, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || max < 1 || max > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
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
	proc, procAddr, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return err
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	state := &printState{max: int(max), process: procAddr, hasProcess: proc != nil}
	for _, hive := range hives {
		if err := ctx.Err(); err != nil {
			return err
		}
		if selected != nil && !hiveOffsetMatch(hive.Address, *selected, e.Symbols.PointerSize()) {
			continue
		}
		if err := state.oneHive(ctx, e, hive, layout, proc, p["key"], recurse, out); err != nil {
			return err
		}
	}
	return nil
}

type printState struct {
	emitted    int
	max        int
	process    uint64
	hasProcess bool
}

func (s *printState) oneHive(ctx context.Context, e plugin.Environment, item listedHive, layout registry.Offsets, proc memory.MemoryLayer, key string, recurse bool, out plugin.Emit) error {
	h, err := registry.Open(ctx, e.Kernel, proc, item.Address, item.Name, layout)
	if err != nil {
		return s.unreadable(e, item, nil, key, err, out)
	}
	path, err := resolveRegistryKey(ctx, h, key)
	if err != nil {
		return s.unreadable(e, item, h, key, err, out)
	}
	return s.walk(ctx, e, item, h, path, 0, recurse, out)
}

func (s *printState) walk(ctx context.Context, e plugin.Environment, item listedHive, h *registry.Hive, path []registry.Key, depth int, recurse bool, out plugin.Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(path) == 0 {
		return fmt.Errorf("registry walk missing key")
	}
	node := path[len(path)-1]
	parent := registryPath(item.Name, path)
	subs, subErr := h.Subkeys(ctx, node)
	for _, child := range subs {
		if err := s.keyRow(e, item, h, parent, child, depth, out); err != nil {
			return err
		}
		if !recurse || indexSeen(path, child.Index) {
			continue
		}
		next := append(append([]registry.Key{}, path...), child)
		if err := s.walk(ctx, e, item, h, next, depth+1, true, out); err != nil {
			return err
		}
	}
	if subErr != nil {
		if err := s.diagnostic(e, item, h, parent, depth, subErr, out); err != nil {
			return err
		}
	}
	values, valErr := h.Values(ctx, node)
	for _, value := range values {
		if err := s.valueRow(e, item, h, parent, node, value, depth, out); err != nil {
			return err
		}
	}
	if valErr != nil {
		return s.diagnostic(e, item, h, parent, depth, valErr, out)
	}
	return nil
}

func (s *printState) keyRow(e plugin.Environment, item listedHive, h *registry.Hive, parent string, child registry.Key, depth int, out plugin.Emit) error {
	row := s.printRow(e, item, h)
	row.Cells["RecordType"] = evidence.Text("key")
	row.Cells["Type"] = evidence.Text("Key")
	row.Cells["Key"] = evidence.Text(parent)
	row.Cells["Name"] = evidence.Text(child.Name)
	row.Cells["Data"] = evidence.Text("")
	row.Cells["Volatile"] = boolValue(child.Volatile)
	row.Cells["LastWriteTime"] = windowsFiletime(child.LastWrite)
	row.Cells["Depth"] = evidence.Number(uint64(depth))
	row.Cells["Cell"] = evidence.Address(child.Address)
	row.Provenance.Offset = fmt.Sprintf("0x%x", child.Address)
	if name, ok := h.LayerName(child.Address); ok {
		row.Provenance.Layer = name
	}
	return s.emit(out, row)
}

func (s *printState) valueRow(e plugin.Environment, item listedHive, h *registry.Hive, parent string, node registry.Key, value registry.Value, depth int, out plugin.Emit) error {
	row := s.printRow(e, item, h)
	row.Cells["RecordType"] = evidence.Text("value")
	name := value.Name
	if name == "" {
		name = "(Default)"
	}
	row.Cells["Type"] = evidence.Text(registryTypeName(value.Type))
	row.Cells["Key"] = evidence.Text(parent)
	row.Cells["Name"] = evidence.Text(name)
	row.Cells["Data"], row.Cells["DataRaw"] = formatRegistryData(value)
	row.Cells["Volatile"] = boolValue(value.Volatile)
	row.Cells["LastWriteTime"] = windowsFiletime(node.LastWrite)
	row.Cells["Depth"] = evidence.Number(uint64(depth))
	row.Cells["Cell"] = evidence.Address(node.Address)
	if value.DataErr != nil {
		row.Cells["Error"] = evidence.Missing("registry_value_unreadable", value.DataErr)
	}
	return s.emit(out, row)
}

func (s *printState) unreadable(e plugin.Environment, item listedHive, h *registry.Hive, key string, cause error, out plugin.Emit) error {
	row := s.printRow(e, item, h)
	row.Cells["RecordType"] = evidence.Text("key")
	row.Cells["Type"] = evidence.Text("Key")
	row.Cells["Key"] = evidence.Text(item.Name + `\` + key)
	row.Cells["Name"] = evidence.Missing("unreadable", nil)
	row.Cells["Data"] = evidence.Text("")
	row.Cells["Volatile"] = evidence.Missing("unreadable", nil)
	row.Cells["LastWriteTime"] = evidence.Missing("unreadable", nil)
	row.Cells["Depth"] = evidence.Number(0)
	row.Cells["Error"] = evidence.Missing("hive_unreadable", cause)
	return s.emit(out, row)
}

func (s *printState) diagnostic(e plugin.Environment, item listedHive, h *registry.Hive, parent string, depth int, cause error, out plugin.Emit) error {
	row := s.printRow(e, item, h)
	row.Cells["RecordType"] = evidence.Text("diagnostic")
	row.Cells["Type"] = evidence.Text("Key")
	row.Cells["Key"] = evidence.Text(parent)
	row.Cells["Name"] = evidence.Missing("unreadable", nil)
	row.Cells["Volatile"] = evidence.Missing("unreadable", nil)
	row.Cells["LastWriteTime"] = evidence.Missing("unreadable", nil)
	row.Cells["Depth"] = evidence.Number(uint64(depth))
	row.Cells["Error"] = evidence.Missing("registry_walk_incomplete", cause)
	return s.emit(out, row)
}

func (s *printState) emit(out plugin.Emit, row evidence.Row) error {
	if s.emitted >= s.max {
		return fmt.Errorf("registry walk exceeded %d nodes", s.max)
	}
	s.emitted++
	return out(row)
}

func (s *printState) printRow(e plugin.Environment, item listedHive, h *registry.Hive) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", item.Address)}}
	for _, column := range windowsPrintKeyPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["HiveOffset"] = evidence.Address(item.Address)
	if h != nil && h.RootFrom != "" {
		row.Cells["RootFrom"] = evidence.Text(h.RootFrom)
	}
	if s.hasProcess {
		row.Cells["RegistryProcess"] = evidence.Address(s.process)
	} else {
		row.Cells["RegistryProcess"] = evidence.Missing("registry_process_absent", nil)
	}
	return row
}

func windowsHiveLayout(e plugin.Environment) (registry.Offsets, error) {
	base, err := e.Objects.Field("_CMHIVE", "Hive.BaseBlock")
	if err != nil {
		return registry.Offsets{}, err
	}
	storage, err := e.Objects.Field("_CMHIVE", "Hive.Storage")
	if err != nil {
		return registry.Offsets{}, err
	}
	version, err := e.Objects.Field("_CMHIVE", "Hive.Version")
	if err != nil {
		return registry.Offsets{}, err
	}
	dual, err := e.Symbols.Type("_DUAL")
	if err != nil {
		return registry.Offsets{}, err
	}
	length, err := e.Objects.Field("_DUAL", "Length")
	if err != nil {
		return registry.Offsets{}, err
	}
	dir, err := e.Objects.Field("_DUAL", "Map")
	if err != nil {
		return registry.Offsets{}, err
	}
	entry, err := e.Symbols.Type("_HMAP_ENTRY")
	if err != nil {
		return registry.Offsets{}, err
	}
	block, err := e.Objects.Field("_HMAP_ENTRY", "BlockOffset")
	if err != nil {
		return registry.Offsets{}, err
	}
	permanent, err := e.Objects.Field("_HMAP_ENTRY", "PermanentBinAddress")
	if err != nil {
		return registry.Offsets{}, err
	}
	blockWidth, err := e.Objects.Size(block.Type)
	if err != nil {
		return registry.Offsets{}, err
	}
	permanentWidth, err := e.Objects.Size(permanent.Type)
	if err != nil {
		return registry.Offsets{}, err
	}
	if blockWidth > 8 || permanentWidth > 8 || dual.Size == 0 || entry.Size == 0 {
		return registry.Offsets{}, fmt.Errorf("incomplete hive map layout")
	}
	return registry.Offsets{
		BaseBlock: base.Offset, Storage: storage.Offset, Version: version.Offset,
		DualSize: dual.Size, Length: length.Offset, Map: dir.Offset, EntrySize: entry.Size,
		BlockOffset: block.Offset, Permanent: permanent.Offset,
		BlockWidth: int(blockWidth), PermanentWidth: int(permanentWidth), PointerSize: e.Symbols.PointerSize(),
	}, nil
}

func windowsRegistryLayer(ctx context.Context, e plugin.Environment) (memory.MemoryLayer, uint64, error) {
	var found uint64
	var ok bool
	err := visitWindowsProcesses(ctx, e, 131072, nil, func(address, pid uint64, name string, created evidence.Value) error {
		if ok || name != "Registry" {
			return nil
		}
		parent, err := e.Objects.Uint(ctx, address, "_EPROCESS", "InheritedFromUniqueProcessId")
		if err != nil {
			return err
		}
		if parent != 4 {
			return nil
		}
		found = address
		ok = true
		return nil
	})
	if err != nil || !ok {
		return nil, 0, err
	}
	pid, err := e.Objects.Uint(ctx, found, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return nil, found, err
	}
	created, _ := windowsTime(ctx, e, found, "_EPROCESS", "CreateTime")
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	layer, err := processMemory(ctx, e, found, 0, evidence.ProcessID(e.ImageHash, e.Kernel.Name(), found, pid, stamp))
	return layer, found, err
}

func listPrintKeyHives(ctx context.Context, e plugin.Environment) ([]listedHive, error) {
	var out []listedHive
	err := windowsHiveList(ctx, e, map[string]string{"dump": "false", "filter": "", "max-nodes": "1024"}, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() != "hive" {
			return nil
		}
		address, err := row.Cells["Offset"].Uint()
		if err != nil {
			return err
		}
		item := listedHive{Address: address, Name: "[NONAME]"}
		if row.Cells["Name"].Kind == "string" && row.Cells["Name"].String() != "" {
			item.Name = row.Cells["Name"].String()
		}
		out = append(out, item)
		return nil
	})
	return out, err
}

func resolveRegistryKey(ctx context.Context, h *registry.Hive, key string) ([]registry.Key, error) {
	root, err := h.RootKey(ctx)
	if err != nil {
		return nil, err
	}
	path := []registry.Key{root}
	trimmed := strings.TrimRight(key, `\`)
	if trimmed == "" {
		return path, nil
	}
	for _, part := range strings.Split(trimmed, `\`) {
		subs, subErr := h.Subkeys(ctx, path[len(path)-1])
		var next *registry.Key
		for i := range subs {
			if strings.EqualFold(subs[i].Name, part) {
				next = &subs[i]
				break
			}
		}
		if next == nil {
			if subErr != nil {
				return nil, subErr
			}
			return nil, fmt.Errorf("key %q not found", part)
		}
		path = append(path, *next)
	}
	return path, nil
}

func registryPath(hive string, path []registry.Key) string {
	parts := []string{hive}
	for _, key := range path[1:] {
		parts = append(parts, key.Name)
	}
	return strings.Join(parts, `\`)
}

func indexSeen(path []registry.Key, index uint32) bool {
	for _, key := range path {
		if key.Index == index {
			return true
		}
	}
	return false
}

func hiveOffsetMatch(address, want uint64, pointerSize int) bool {
	if address == want {
		return true
	}
	if pointerSize == 8 {
		const mask = 0x0000ffffffffffff
		return address&mask == want&mask
	}
	return false
}

func boolValue(v bool) evidence.Value { return evidence.Value{Kind: "bool", Data: v} }

func registryTypeName(typ uint32) string {
	names := []string{"REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD"}
	if int(typ) < len(names) {
		return names[typ]
	}
	return "REG_UNKNOWN"
}

func formatRegistryData(v registry.Value) (evidence.Value, evidence.Value) {
	if v.DataErr != nil {
		miss := evidence.Missing("registry_value_unreadable", v.DataErr)
		return miss, miss
	}
	raw := evidence.Bytes(v.Data)
	switch v.Type {
	case 0:
		return evidence.Text(""), raw
	case 4:
		if len(v.Data) != 4 {
			return evidence.Missing("registry_value_size", fmt.Errorf("REG_DWORD is %d bytes", len(v.Data))), raw
		}
		return evidence.Text(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(v.Data)), 10)), raw
	case 5:
		if len(v.Data) != 4 {
			return evidence.Missing("registry_value_size", fmt.Errorf("REG_DWORD_BIG_ENDIAN is %d bytes", len(v.Data))), raw
		}
		return evidence.Text(strconv.FormatUint(uint64(binary.BigEndian.Uint32(v.Data)), 10)), raw
	case 11:
		if len(v.Data) != 8 {
			return evidence.Missing("registry_value_size", fmt.Errorf("REG_QWORD is %d bytes", len(v.Data))), raw
		}
		return evidence.Text(strconv.FormatUint(binary.LittleEndian.Uint64(v.Data), 10)), raw
	case 1, 2, 6:
		text, err := registryString(v.Data, false)
		if err != nil {
			return evidence.Missing("registry_value_encoding", err), raw
		}
		return evidence.Text(text), raw
	case 7:
		text, err := registryString(v.Data, true)
		if err != nil {
			return evidence.Missing("registry_value_encoding", err), raw
		}
		return evidence.Text(text), raw
	default:
		return evidence.Text(hex.EncodeToString(v.Data)), raw
	}
}

func registryString(raw []byte, multi bool) (string, error) {
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("utf-16 registry value has odd length %d", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	decoded := string(utf16.Decode(units))
	if !multi {
		if i := strings.IndexRune(decoded, 0); i >= 0 {
			if strings.TrimRight(decoded[i:], "\x00") != "" {
				return hex.EncodeToString(raw), nil
			}
			return decoded[:i], nil
		}
		return decoded, nil
	}
	parts := strings.Split(decoded, "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "\n"), nil
}
