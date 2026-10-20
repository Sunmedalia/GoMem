package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsGetSIDPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.getsids", Upstream: "windows.getsids.GetSIDs", Platform: "windows", NeedsKernel: true,
		Description: "List SIDs for each active process token and resolve names from the pinned tables and SOFTWARE ProfileList",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "SID", Kind: "string"},
			{Name: "Name", Kind: "string"},
			{Name: "Token", Kind: "address"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsGetSIDs}}
}

var errSidStop = errors.New("sid list stopped")

var windowsSIDRegexes = compileSIDPatterns()

func compileSIDPatterns() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(windowsSIDPatterns))
	for i, item := range windowsSIDPatterns {
		out[i] = regexp.MustCompile(item.Pattern)
	}
	return out
}

func windowsGetSIDs(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.getsids requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	if _, err = e.Objects.Field("_EPROCESS", "Token.Object"); err != nil {
		return fmt.Errorf("windows.getsids requires _EPROCESS.Token as _EX_FAST_REF: %w", err)
	}
	for _, name := range []string{"UserAndGroupCount", "UserAndGroups"} {
		if _, err = e.Objects.Field("_TOKEN", name); err != nil {
			return fmt.Errorf("windows.getsids requires _TOKEN.%s: %w", name, err)
		}
	}
	users, hiveSkips, hiveErr := profileUsers(ctx, e)
	if hiveErr != nil && users == nil {
		return hiveErr
	}
	var processes, rowsOut, unreadable, stopped int
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		raw, readErr := e.Objects.Uint(ctx, process, "_EPROCESS", "Token.Object")
		if readErr != nil {
			unreadable++
			return out(sidRow(e, process, pid, name, created, 0, "Token unreadable", "", true))
		}
		token := maskFastRef(raw, e.Symbols.PointerSize())
		sids, stop, cause := tokenSIDs(ctx, e, token)
		if cause != nil {
			return cause
		}
		if stop {
			stopped++
		}
		if len(sids) == 0 && !stop {
			return nil
		}
		for _, sid := range sids {
			display, ok := sidDisplayName(sid, users)
			rowsOut++
			if err := out(sidRow(e, process, pid, name, created, token, sid, display, ok)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := sidBase(e, 0, 0, "", evidence.Missing("not_applicable", nil))
	summary.Provenance.Offset = "0x0"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"processes":  strconv.Itoa(processes),
		"rows":       strconv.Itoa(rowsOut),
		"unreadable": strconv.Itoa(unreadable),
		"stopped":    strconv.Itoa(stopped),
		"users":      strconv.Itoa(len(users)),
		"hive_skips": strconv.Itoa(hiveSkips),
	}}
	return out(summary)
}

func tokenSIDs(ctx context.Context, e plugin.Environment, token uint64) ([]string, bool, error) {
	count, err := e.Objects.Uint(ctx, token, "_TOKEN", "UserAndGroupCount")
	if err != nil {
		return nil, false, err
	}
	if count >= 0xFFFF {
		return nil, false, nil
	}
	target, err := e.Objects.Uint(ctx, token, "_TOKEN", "UserAndGroups")
	if err != nil {
		return nil, false, err
	}
	size, err := e.Objects.Size(symbols.TypeRef{Kind: "struct", Name: "_SID_AND_ATTRIBUTES"})
	if err != nil || size == 0 {
		return nil, false, fmt.Errorf("windows.getsids requires _SID_AND_ATTRIBUTES: %w", err)
	}
	sidField, err := e.Objects.Field("_SID_AND_ATTRIBUTES", "Sid")
	if err != nil {
		return nil, false, err
	}
	var sids []string
	for i := uint64(0); i < count; i++ {
		element, err := memory.Add(target, i*size)
		if err != nil {
			return nil, false, err
		}
		pointer, err := memory.Add(element, sidField.Offset)
		if err != nil {
			return nil, false, err
		}
		sidAddress, err := readPointer(ctx, e, pointer)
		if err != nil {
			continue
		}
		text, err := formatSID(ctx, e, sidAddress)
		if errors.Is(err, errSidStop) {
			return sids, true, nil
		}
		if err != nil {
			continue
		}
		sids = append(sids, text)
	}
	return sids, false, nil
}

func formatSID(ctx context.Context, e plugin.Environment, address uint64) (string, error) {
	header, err := memory.Read(ctx, e.Kernel, address, 8)
	if err != nil {
		return "", err
	}
	revision := header[0]
	subCount := header[1]
	if revision&0xF != 1 || subCount > 15 {
		return "", errSidStop
	}
	authority := header[7]
	parts := []string{"S", strconv.Itoa(int(revision)), strconv.Itoa(int(authority))}
	if subCount > 0 {
		raw, err := memory.Read(ctx, e.Kernel, address+8, int(subCount)*4)
		if err != nil {
			return "", err
		}
		for i := 0; i < int(subCount); i++ {
			parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[i*4:])), 10))
		}
	}
	return strings.Join(parts, "-"), nil
}

func readPointer(ctx context.Context, e plugin.Environment, address uint64) (uint64, error) {
	width := e.Symbols.PointerSize()
	if width < 1 || width > 8 {
		return 0, fmt.Errorf("invalid pointer width %d", width)
	}
	raw, err := memory.Read(ctx, e.Kernel, address, width)
	if err != nil {
		return 0, err
	}
	var value uint64
	for i, b := range raw {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func sidDisplayName(sid string, users map[string]string) (string, bool) {
	if name, ok := windowsWellKnownSIDs[sid]; ok {
		return name, true
	}
	if name, ok := windowsServiceSIDs[sid]; ok {
		return name, true
	}
	if name, ok := users[sid]; ok {
		return name, true
	}
	for i, pattern := range windowsSIDRegexes {
		if pattern.MatchString(sid) {
			return windowsSIDPatterns[i].Name, true
		}
	}
	return "", false
}

func profileUsers(ctx context.Context, e plugin.Environment) (map[string]string, int, error) {
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil && len(hives) == 0 {
		return nil, 0, err
	}
	layout, layoutErr := windowsHiveLayout(e)
	if layoutErr != nil {
		return map[string]string{}, 0, nil
	}
	proc, _, _ := windowsRegistryLayer(ctx, e)
	users := map[string]string{}
	skipped := 0
	const filter = `config\software`
	const key = `Microsoft\Windows NT\CurrentVersion\ProfileList`
	for _, hive := range hives {
		if !strings.Contains(strings.ToLower(hive.Name), filter) {
			continue
		}
		opened, openErr := registry.Open(ctx, e.Kernel, proc, hive.Address, hive.Name, layout)
		if openErr != nil {
			skipped++
			continue
		}
		path, keyErr := resolveRegistryKey(ctx, opened, key)
		if keyErr != nil || len(path) == 0 {
			skipped++
			continue
		}
		subs, _ := opened.Subkeys(ctx, path[len(path)-1])
		for _, sub := range subs {
			if sub.Name == "" {
				continue
			}
			values, _ := opened.Values(ctx, sub)
			var raw []byte
			found := false
			for _, value := range values {
				if value.Name != "ProfileImagePath" || value.DataErr != nil {
					continue
				}
				encoded, ok := profileImageBytes(value)
				if !ok {
					continue
				}
				raw, found = encoded, true
			}
			if !found {
				continue
			}
			users[sub.Name] = profileBasename(raw)
		}
	}
	return users, skipped, nil
}

func profileImageBytes(value registry.Value) ([]byte, bool) {
	switch value.Type {
	case 4:
		if len(value.Data) != 4 {
			return nil, false
		}
		return sidUTF16Bytes(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(value.Data)), 10)), true
	case 5:
		if len(value.Data) != 4 {
			return nil, false
		}
		return sidUTF16Bytes(strconv.FormatUint(uint64(binary.BigEndian.Uint32(value.Data)), 10)), true
	case 11:
		if len(value.Data) != 8 {
			return nil, false
		}
		return sidUTF16Bytes(strconv.FormatUint(binary.LittleEndian.Uint64(value.Data), 10)), true
	default:
		return value.Data, true
	}
}

func sidUTF16Bytes(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[i*2:], unit)
	}
	return out
}

func profileBasename(raw []byte) string {
	text := pythonBytesRepr(raw)
	text = strings.ReplaceAll(text, `\x00`, "")
	if text != "" {
		text = text[:len(text)-1]
	}
	text = strings.ReplaceAll(text, "/", `\`)
	if i := strings.LastIndex(text, `\`); i >= 0 {
		return text[i+1:]
	}
	return text
}

func pythonBytesRepr(raw []byte) string {
	quote := byte('\'')
	if bytesContains(raw, '\'') && !bytesContains(raw, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte('b')
	b.WriteByte(quote)
	for _, c := range raw {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case quote:
			b.WriteByte('\\')
			b.WriteByte(quote)
		default:
			if c < 32 || c >= 127 {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte(quote)
	return b.String()
}

func bytesContains(raw []byte, c byte) bool {
	for _, v := range raw {
		if v == c {
			return true
		}
	}
	return false
}

func sidRow(e plugin.Environment, process, pid uint64, name string, created evidence.Value, token uint64, sid, display string, named bool) evidence.Row {
	row := sidBase(e, process, pid, name, created)
	row.Cells["RecordType"] = evidence.Text("sid")
	row.Cells["SID"] = evidence.Text(sid)
	if named {
		row.Cells["Name"] = evidence.Text(display)
	}
	if token != 0 {
		row.Cells["Token"] = evidence.Address(token)
		row.Provenance.Offset = fmt.Sprintf("0x%x", token)
	}
	return row
}

func sidBase(e plugin.Environment, process, pid uint64, name string, created evidence.Value) evidence.Row {
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	layer := ""
	if e.Kernel != nil {
		layer = e.Kernel.Name()
	}
	return evidence.Row{Cells: map[string]evidence.Value{
		"PID": evidence.Number(pid), "Process": evidence.Text(name),
		"SID": evidence.Missing("not_applicable", nil), "Name": evidence.Missing("not_available", nil),
		"Token": evidence.Missing("not_applicable", nil), "ProcessOffset": evidence.Address(process),
		"ProcessIdentity": evidence.Text(evidence.ProcessID(e.ImageHash, layer, process, pid, stamp)),
		"RecordType":      evidence.Missing("not_applicable", nil),
		"Error":           evidence.Missing("not_applicable", nil),
		"Coverage":        evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", process)}}
}
