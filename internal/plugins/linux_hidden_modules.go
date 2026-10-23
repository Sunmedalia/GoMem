package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxHiddenModulePlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"}, {Name: "Module Name", Kind: "string"},
		{Name: "Code Size", Kind: "address"}, {Name: "Taints", Kind: "string"},
		{Name: "Load Arguments", Kind: "string"}, {Name: "File Output", Kind: "artifact"},
		{Name: "DumpEvidence", Kind: "structure"}, {Name: "FieldEvidence", Kind: "structure"},
		{Name: "RecordType", Kind: "string"}, {Name: "Source", Kind: "string"},
		{Name: "Status", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "missing"},
	}
	return []builtin{{plugin.Spec{
		Name: "linux.hidden_modules", Upstream: "linux.malware.hidden_modules.Hidden_modules", Platform: "linux", NeedsKernel: true,
		Description: "Scan module allocation memory for valid modules absent from the active list",
		Parameters: []plugin.Parameter{
			{Name: "plain-taints", Kind: "bool", Default: "false", Description: "Display pinned plain taint characters instead of descriptions"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-list and emitted-module bound, 1..1000000"},
			{Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"},
			linuxModuleDumpParameters()[0], linuxModuleDumpParameters()[1],
		},
		Columns: columns,
	}, linuxHiddenModules}}
}

func linuxHiddenScanStep(pointer uint64, addresses []uint64) uint64 {
	if pointer == 0 {
		return 1
	}
	for _, address := range addresses {
		if address%pointer != 0 {
			return 1
		}
	}
	return pointer
}

func linuxDwarf2JSONSupported(table symbols.SymbolTable) error {
	const required = "0.8.0"
	raw, ok := table.Metadata()["producer"]
	if !ok {
		return fmt.Errorf("symbol table has no producer metadata; dwarf2json >= %s is required", required)
	}
	var producer struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &producer); err != nil {
		return fmt.Errorf("symbol producer metadata: %w", err)
	}
	if producer.Name != "dwarf2json" {
		return fmt.Errorf("symbol producer %q is not dwarf2json >= %s", producer.Name, required)
	}
	got, err := splitSymbolVersion(producer.Version)
	if err != nil || versionLess(got, []int{0, 8, 0}) {
		return fmt.Errorf("dwarf2json %q is below %s", producer.Version, required)
	}
	return nil
}

func splitSymbolVersion(value string) ([]int, error) {
	if value == "" {
		return nil, fmt.Errorf("empty version")
	}
	parts := strings.Split(value, ".")
	out := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid version %q", value)
		}
		out[i] = n
	}
	return out, nil
}

func versionLess(got, required []int) bool {
	n := len(got)
	if len(required) > n {
		n = len(required)
	}
	for i := 0; i < n; i++ {
		var left, right int
		if i < len(got) {
			left = got[i]
		}
		if i < len(required) {
			right = required[i]
		}
		if left != right {
			return left < right
		}
	}
	return false
}

func linuxHiddenModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.hidden_modules requires kernel memory and symbols")
	}
	if err := linuxDwarf2JSONSupported(e.Symbols); err != nil {
		return err
	}
	if _, err := linuxModuleAddressMask(e); err != nil {
		return err
	}
	maxNodes, _, err := limits(p)
	if err != nil {
		return err
	}
	span, err := strconv.ParseUint(p["max-scan-bytes"], 0, 64)
	if err != nil || span < 1 || span > 8<<30 {
		return fmt.Errorf("max-scan-bytes must be 1..8589934592")
	}
	plain, err := strconv.ParseBool(p["plain-taints"])
	if err != nil {
		return err
	}
	dump, maxBytes, err := linuxModuleDumpOptions(p)
	if err != nil {
		return err
	}
	if _, err = e.Objects.Field("module", "mkobj.mod"); err != nil {
		return fmt.Errorf("hidden module scan requires module.mkobj.mod: %w", err)
	}
	hasExtent := false
	for _, name := range []string{"mem", "core_layout", "core_size"} {
		if _, fieldErr := e.Objects.Field("module", name); fieldErr == nil {
			hasExtent = true
			break
		}
	}
	if !hasExtent {
		return fmt.Errorf("hidden module scan requires module size metadata")
	}
	head, err := e.Symbol("modules")
	if err != nil {
		return err
	}
	link, err := e.Objects.Field("module", "list")
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	exclude := map[uint64]bool{}
	var known []uint64
	err = e.Objects.WalkList(ctx, head, link.Offset, maxNodes, func(address uint64) error {
		if len(known) >= maxNodes {
			return fmt.Errorf("active modules exceed max-nodes %d", maxNodes)
		}
		if !exclude[address] {
			exclude[address] = true
			known = append(known, address)
		}
		return nil
	})
	if err != nil {
		return err
	}
	step := linuxHiddenScanStep(uint64(e.Symbols.PointerSize()), known)
	s := &linuxModuleSources{ctx: ctx, e: e, emit: out, maxNodes: maxNodes, maxScan: span, quietBounds: true}
	low, high, err := s.boundaries()
	if err != nil {
		return err
	}
	hidden, excluded, unreadable, rejected, selfMatches, err := s.scanHiddenModules(low, high, step, exclude, plain, dump, maxBytes)
	if err != nil {
		return err
	}
	summary := linuxModuleRow(e, low, "hidden_scan_summary", "Scanner")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{
		"known_modules": evidence.Number(uint64(len(known))), "excluded": evidence.Number(excluded),
		"positions": evidence.Number(s.positions), "unreadable": evidence.Number(unreadable),
		"self_matches": evidence.Number(selfMatches), "rejected": evidence.Number(rejected),
		"hidden": evidence.Number(hidden), "step": evidence.Number(step),
		"low": evidence.Address(low), "high": evidence.Address(high),
	}}
	summary.Cells["Status"] = evidence.Text("scan_summary")
	summary.Provenance.Offset = "hidden_modules"
	if err = s.out(summary); err != nil {
		return err
	}
	return s.failures.err("Linux hidden module scan")
}

func (s *linuxModuleSources) scanHiddenModules(low, high, step uint64, exclude map[uint64]bool, plain, dump bool, maxBytes uint64) (hidden, excluded, unreadable, rejected, selfMatches uint64, err error) {
	self, err := s.e.Objects.Field("module", "mkobj.mod")
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if self.Type.Kind != "pointer" {
		return 0, 0, 0, 0, 0, fmt.Errorf("module.mkobj.mod must be a pointer")
	}
	width, err := s.e.Objects.Size(self.Type)
	if err != nil || width < 1 || width > 8 {
		return 0, 0, 0, 0, 0, fmt.Errorf("invalid module self-pointer extent %d: %v", width, err)
	}
	pointerType, err := s.e.Symbols.Type("pointer")
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if step < 1 {
		return 0, 0, 0, 0, 0, fmt.Errorf("invalid hidden-module scan step")
	}
	reader := linuxPagePointer{ctx: s.ctx, layer: s.e.Kernel, width: int(width), big: pointerType.Endian == "big"}
	for address := low; address < high; {
		if err = s.ctx.Err(); err != nil {
			return hidden, excluded, unreadable, rejected, selfMatches, err
		}
		s.positions++
		if exclude[address] {
			excluded++
		} else {
			at, addErr := memory.Add(address, self.Offset)
			if addErr != nil {
				return hidden, excluded, unreadable, rejected, selfMatches, addErr
			}
			value, ok := reader.at(at)
			if !ok {
				unreadable++
			} else if value == address {
				selfMatches++
				if !s.hiddenModuleValid(address) {
					rejected++
				} else {
					if err = s.visit(); err != nil {
						return hidden, excluded, unreadable, rejected, selfMatches, err
					}
					row, rowErr := linuxModuleDisplayRow(s, linuxModuleInfo{offset: address, source: "Scanner"}, plain)
					if rowErr != nil {
						return hidden, excluded, unreadable, rejected, selfMatches, rowErr
					}
					row.Cells["RecordType"] = evidence.Text("hidden_module")
					row.Cells["Source"] = evidence.Text("Scanner")
					row.Cells["Status"] = evidence.Text("hidden")
					if dump {
						linuxDumpModule(s, &row, address, maxBytes)
					}
					if err = s.out(row); err != nil {
						return hidden, excluded, unreadable, rejected, selfMatches, err
					}
					hidden++
				}
			}
		}
		if high-address <= step {
			break
		}
		address, err = memory.Add(address, step)
		if err != nil {
			return hidden, excluded, unreadable, rejected, selfMatches, err
		}
	}
	return hidden, excluded, unreadable, rejected, selfMatches, nil
}

func (s *linuxModuleSources) hiddenModuleValid(address uint64) bool {
	scratch := pluginFailures{}
	n := &linuxModuleRead{ctx: s.ctx, e: s.e, fields: map[string]evidence.Value{}, failures: &scratch}
	_, wholeErr := n.capture(address, "module", "")
	core, coreErr := n.layout(address, "core")
	text, textErr := n.layout(address, "text")
	init, initErr := n.layout(address, "init")
	pointer, pointerErr := n.uint(address, "module", "mkobj.mod")
	return linuxModuleCandidateValid(core, text, init, pointer, address, wholeErr == nil && coreErr == nil && textErr == nil && initErr == nil && pointerErr == nil)
}

type linuxPagePointer struct {
	ctx      context.Context
	layer    memory.MemoryLayer
	width    int
	big      bool
	pageBase uint64
	page     []byte
	set      bool
}

func (p *linuxPagePointer) at(address uint64) (uint64, bool) {
	base := address &^ uint64(4095)
	offset := address - base
	if !p.set || p.pageBase != base {
		buf := make([]byte, 4096)
		got, err := p.layer.ReadAt(p.ctx, buf, base)
		if got < 0 || got > len(buf) {
			got = 0
		}
		if err == nil && got != len(buf) {
			err = io.ErrUnexpectedEOF
		}
		_ = err
		p.page = buf[:got]
		p.pageBase = base
		p.set = true
	}
	var raw []byte
	if offset+uint64(p.width) <= uint64(len(p.page)) {
		raw = p.page[offset : offset+uint64(p.width)]
	} else if offset+uint64(p.width) > 4096 {
		data, err := memory.Read(p.ctx, p.layer, address, p.width)
		if err != nil {
			return 0, false
		}
		raw = data
	} else {
		return 0, false
	}
	var value uint64
	if p.big {
		for _, b := range raw {
			value = value<<8 | uint64(b)
		}
	} else {
		for i, b := range raw {
			value |= uint64(b) << uint(i*8)
		}
	}
	return value, true
}
