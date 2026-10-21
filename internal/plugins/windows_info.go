package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsInfoPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.info", Upstream: "windows.info.Info", Platform: "windows", NeedsKernel: true,
		Description: "Report kernel identity, version, KUSER shared data and the kernel PE header",
		Columns: []evidence.Column{
			{Name: "Variable", Kind: "string"},
			{Name: "Value", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsInfo}}
}

// Offsets come from the pinned volatility3 windows/kdbg.json _KDDEBUGGER_DATA64.
const (
	kdbgOwnerTagOffset   = 16
	kdbgNtBuildLabOffset = 520
	kdbgCSDVersionOffset = 616
	kdbgOwnerTag         = 0x4742444B
)

func windowsInfo(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil || e.Physical == nil {
		return fmt.Errorf("windows.info requires physical and kernel layers and symbols")
	}
	bits := 32
	if e.Symbols.PointerSize() == 8 {
		bits = 64
	} else if e.Symbols.PointerSize() != 4 {
		return fmt.Errorf("windows.info unsupported pointer size %d", e.Symbols.PointerSize())
	}
	virtual, ok := e.Kernel.(*memory.Virtual)
	if !ok || virtual.Translator == nil {
		return fmt.Errorf("windows.info requires an Intel kernel layer")
	}
	intel, ok := virtual.Translator.(*memory.Intel)
	if !ok {
		return fmt.Errorf("windows.info requires an Intel kernel layer")
	}
	rows := [][2]string{
		{"Kernel Base", volHex(e.KernelBase, bits)},
		{"DTB", volHex(intel.Root(), bits)},
		{"Symbols", volatilitySymbolURL(e.SymbolLocation)},
		{"Is64Bit", pythonBool(bits == 64)},
		{"IsPAE", pythonBool(e.Architecture == "pae")},
	}
	layers, err := windowsInfoLayers(e)
	if err != nil {
		return err
	}
	rows = append(rows, layers...)
	kdbg, err := e.Symbol("KdDebuggerDataBlock")
	if err != nil {
		return err
	}
	tag, err := readUintAt(ctx, e.Kernel, kdbg+kdbgOwnerTagOffset, 4)
	if err != nil {
		return fmt.Errorf("windows.info cannot read KDBG owner tag: %w", err)
	}
	if tag == kdbgOwnerTag {
		labAddr, err := readUintAt(ctx, e.Kernel, kdbg+kdbgNtBuildLabOffset, e.Symbols.PointerSize())
		if err != nil {
			return fmt.Errorf("windows.info cannot read NtBuildLab: %w", err)
		}
		lab, err := readCString(ctx, e.Kernel, labAddr, 32)
		if err != nil {
			return fmt.Errorf("windows.info cannot read NTBuildLab string: %w", err)
		}
		csdAddr, err := readUintAt(ctx, e.Kernel, kdbg+kdbgCSDVersionOffset, e.Symbols.PointerSize())
		if err != nil {
			return fmt.Errorf("windows.info cannot read CmNtCSDVersion: %w", err)
		}
		csd, err := readUintAt(ctx, e.Kernel, csdAddr, 4)
		if err != nil {
			return fmt.Errorf("windows.info cannot read CSDVersion: %w", err)
		}
		rows = append(rows,
			[2]string{"KdDebuggerDataBlock", volHex(kdbg, bits)},
			[2]string{"NTBuildLab", lab},
			[2]string{"CSDVersion", strconv.FormatUint((csd>>8)&0xffffffff, 10)},
		)
	}
	vers, err := e.Symbol("KdVersionBlock")
	if err != nil {
		return err
	}
	major, err := e.Objects.Uint(ctx, vers, "_DBGKD_GET_VERSION64", "MajorVersion")
	if err != nil {
		return fmt.Errorf("windows.info cannot read KdVersionBlock.MajorVersion: %w", err)
	}
	minor, err := e.Objects.Uint(ctx, vers, "_DBGKD_GET_VERSION64", "MinorVersion")
	if err != nil {
		return fmt.Errorf("windows.info cannot read KdVersionBlock.MinorVersion: %w", err)
	}
	machine, err := e.Objects.Uint(ctx, vers, "_DBGKD_GET_VERSION64", "MachineType")
	if err != nil {
		return fmt.Errorf("windows.info cannot read KdVersionBlock.MachineType: %w", err)
	}
	rows = append(rows,
		[2]string{"KdVersionBlock", volHex(vers, bits)},
		[2]string{"Major/Minor", fmt.Sprintf("%d.%d", major, minor)},
		[2]string{"MachineType", strconv.FormatUint(machine, 10)},
	)
	cpuAddr, err := e.Symbol("KeNumberProcessors")
	if err != nil {
		return err
	}
	cpus, err := readUnsignedInt(ctx, e, cpuAddr)
	if err != nil {
		return fmt.Errorf("windows.info cannot read KeNumberProcessors: %w", err)
	}
	rows = append(rows, [2]string{"KeNumberProcessors", strconv.FormatUint(cpus, 10)})
	kuser := uint64(0xFFDF0000)
	if bits == 64 {
		kuser = 0xFFFFF78000000000
	}
	shared, err := readKUser(ctx, e, kuser)
	if err != nil {
		return err
	}
	rows = append(rows, shared...)
	peRows, err := readKernelInfoPE(ctx, e, e.KernelBase)
	if err != nil {
		return err
	}
	rows = append(rows, peRows...)
	for _, item := range rows {
		row := infoBase()
		row.Cells["RecordType"] = evidence.Text("info")
		row.Cells["Variable"] = evidence.Text(item[0])
		row.Cells["Value"] = evidence.Text(item[1])
		if err := out(row); err != nil {
			return err
		}
	}
	summary := infoBase()
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{"rows": strconv.Itoa(len(rows))}}
	return out(summary)
}

func windowsInfoLayers(e plugin.Environment) ([][2]string, error) {
	intel := "WindowsIntel"
	switch e.Architecture {
	case "x64":
		intel = "WindowsIntel32e"
	case "pae":
		intel = "WindowsIntelPAE"
	case "x86":
		intel = "WindowsIntel"
	default:
		return nil, fmt.Errorf("windows.info unsupported architecture %q", e.Architecture)
	}
	header, crash := crashHeaderOf(e.Physical)
	if !crash {
		return [][2]string{{"layer_name", "0 " + intel}}, nil
	}
	crashName := "WindowsCrashDump32Layer"
	if header.Bits == 64 {
		crashName = "WindowsCrashDump64Layer"
	}
	return [][2]string{
		{"layer_name", "0 " + intel},
		{"memory_layer", "1 " + crashName},
		{"base_layer", "2 FileLayer"},
	}, nil
}

func crashHeaderOf(layer memory.MemoryLayer) (memory.CrashHeader, bool) {
	source, ok := layer.(interface{ CrashHeader() memory.CrashHeader })
	if !ok {
		return memory.CrashHeader{}, false
	}
	return source.CrashHeader(), true
}

func readKUser(ctx context.Context, e plugin.Environment, base uint64) ([][2]string, error) {
	clock, err := e.Objects.Field("_KUSER_SHARED_DATA", "SystemTime")
	if err != nil {
		return nil, err
	}
	lowField, err := e.Objects.Field("_KSYSTEM_TIME", "LowPart")
	if err != nil {
		return nil, err
	}
	highField, err := e.Objects.Field("_KSYSTEM_TIME", "High1Time")
	if err != nil {
		return nil, err
	}
	clockAddr, err := memory.Add(base, clock.Offset)
	if err != nil {
		return nil, err
	}
	lowAddr, err := memory.Add(clockAddr, lowField.Offset)
	if err != nil {
		return nil, err
	}
	highAddr, err := memory.Add(clockAddr, highField.Offset)
	if err != nil {
		return nil, err
	}
	low, err := readUintAt(ctx, e.Kernel, lowAddr, 4)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read KUSER SystemTime: %w", err)
	}
	high, err := readUintAt(ctx, e.Kernel, highAddr, 4)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read KUSER SystemTime: %w", err)
	}
	rootField, err := e.Objects.Field("_KUSER_SHARED_DATA", "NtSystemRoot")
	if err != nil {
		return nil, err
	}
	rootAddr, err := memory.Add(base, rootField.Offset)
	if err != nil {
		return nil, err
	}
	root, err := readUTF16Limited(ctx, e.Kernel, rootAddr, 260)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read NtSystemRoot: %w", err)
	}
	productField, err := e.Objects.Field("_KUSER_SHARED_DATA", "NtProductType")
	if err != nil {
		return nil, err
	}
	productAddr, err := memory.Add(base, productField.Offset)
	if err != nil {
		return nil, err
	}
	productRaw, err := readUintAt(ctx, e.Kernel, productAddr, 4)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read NtProductType: %w", err)
	}
	product := strconv.FormatUint(productRaw, 10)
	if enumeration, err := e.Symbols.Enumeration(productField.Type.Name); err == nil {
		if names := enumeration.Names(productRaw); len(names) == 1 {
			product = names[0]
		}
	}
	major, err := e.Objects.Uint(ctx, base, "_KUSER_SHARED_DATA", "NtMajorVersion")
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read NtMajorVersion: %w", err)
	}
	minor, err := e.Objects.Uint(ctx, base, "_KUSER_SHARED_DATA", "NtMinorVersion")
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read NtMinorVersion: %w", err)
	}
	return [][2]string{
		{"SystemTime", ksystemTimeText((high << 32) | low)},
		{"NtSystemRoot", root},
		{"NtProductType", product},
		{"NtMajorVersion", strconv.FormatUint(major, 10)},
		{"NtMinorVersion", strconv.FormatUint(minor, 10)},
	}, nil
}

func readKernelInfoPE(ctx context.Context, e plugin.Environment, base uint64) ([][2]string, error) {
	dos, err := readAt(ctx, e.Kernel, base, 64)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read kernel DOS header: %w", err)
	}
	if string(dos[:2]) != "MZ" {
		return nil, fmt.Errorf("windows.info kernel base lacks a DOS signature")
	}
	peOff := uint64(binary.LittleEndian.Uint32(dos[60:]))
	file, err := readAt(ctx, e.Kernel, base+peOff, 24+44)
	if err != nil {
		return nil, fmt.Errorf("windows.info cannot read kernel NT header: %w", err)
	}
	if string(file[:4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("windows.info kernel base lacks an NT signature")
	}
	machine := binary.LittleEndian.Uint16(file[4:6])
	stamp := binary.LittleEndian.Uint32(file[8:12])
	optional := file[24:]
	major := binary.LittleEndian.Uint16(optional[40:42])
	minor := binary.LittleEndian.Uint16(optional[42:44])
	return [][2]string{
		{"PE MajorOperatingSystemVersion", strconv.Itoa(int(major))},
		{"PE MinorOperatingSystemVersion", strconv.Itoa(int(minor))},
		{"PE Machine", strconv.Itoa(int(machine))},
		{"PE TimeDateStamp", time.Unix(int64(stamp), 0).UTC().Format("Mon Jan _2 15:04:05 2006")},
	}, nil
}

func readUTF16Limited(ctx context.Context, layer memory.MemoryLayer, address uint64, maxBytes int) (string, error) {
	raw, err := readAt(ctx, layer, address, maxBytes)
	if err != nil {
		return "", err
	}
	if len(raw)%2 != 0 {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
		if units[i] == 0 {
			units = units[:i]
			break
		}
	}
	return string(utf16.Decode(units)), nil
}

func readCString(ctx context.Context, layer memory.MemoryLayer, address uint64, max int) (string, error) {
	raw, err := readAt(ctx, layer, address, max)
	if err != nil {
		return "", err
	}
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToValidUTF8(string(raw), "\uFFFD"), nil
}

func readAt(ctx context.Context, layer memory.MemoryLayer, address uint64, n int) ([]byte, error) {
	return memory.Read(ctx, layer, address, n)
}

func readUintAt(ctx context.Context, layer memory.MemoryLayer, address uint64, size int) (uint64, error) {
	raw, err := readAt(ctx, layer, address, size)
	if err != nil {
		return 0, err
	}
	var value uint64
	for i, b := range raw {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func ksystemTimeText(ticks uint64) string {
	seconds := ticks / 10000000
	if seconds == 0 || seconds < 11644473600 {
		return "-"
	}
	when := time.Unix(int64(seconds-11644473600), 0).UTC()
	if when.Year() < 1 || when.Year() > 9999 {
		return "-"
	}
	return when.Format("2006-01-02 15:04:05-07:00")
}

func volHex(value uint64, bits int) string {
	if bits == 64 {
		value &= 0x0000ffffffffffff
	} else {
		value &= 0xffffffff
	}
	return fmt.Sprintf("0x%x", value)
}

func volatilitySymbolURL(location string) string {
	if strings.HasPrefix(location, "jar:file:") {
		return location
	}
	file, member, ok := strings.Cut(location, "#")
	if !ok {
		return location
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	// file: URLs use slash-separated paths, including on Windows. A drive
	// letter needs a leading slash; preserve UNC's existing // prefix.
	abs = filepath.ToSlash(abs)
	if filepath.VolumeName(abs) != "" && !strings.HasPrefix(abs, "/") {
		abs = "/" + abs
	}
	path := (&url.URL{Path: abs}).EscapedPath()
	return "jar:file:" + path + "!" + member
}

func pythonBool(value bool) string {
	if value {
		return "True"
	}
	return "False"
}

func infoBase() evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{
		"Variable": evidence.Missing("not_applicable", nil), "Value": evidence.Missing("not_applicable", nil),
		"RecordType": evidence.Missing("not_applicable", nil), "Coverage": evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Offset: "0x0"}}
}
