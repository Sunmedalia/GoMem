package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type builtin struct {
	spec plugin.Spec
	run  func(context.Context, plugin.Environment, map[string]string, plugin.Emit) error
}

func (b builtin) Spec() plugin.Spec { return b.spec }
func (b builtin) Run(c context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	return b.run(c, e, p, out)
}
func Register(r *plugin.Registry) error {
	specs := []builtin{
		{plugin.Spec{Name: "generic.info", Description: "Physical memory segments and explicit linear/encoded storage metadata", Columns: []evidence.Column{{Name: "Start", Kind: "address"}, {Name: "Length", Kind: "uint64"}, {Name: "FileOffset", Kind: "address"}, {Name: "StoredLength", Kind: "uint64"}, {Name: "Encoding", Kind: "string"}}}, info},
		{plugin.Spec{Name: "banners", Upstream: "banners.Banners", Description: "Scan validated Linux/Darwin banners and Windows kernel PDB identities", Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Banner", Kind: "string"}}}, banners},
		{plugin.Spec{Name: "generic.strings", Description: "Bounded printable ASCII strings with physical offsets", Parameters: []plugin.Parameter{{Name: "min", Kind: "uint", Default: "8", Description: "Minimum length, 1..4096"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Text", Kind: "string"}, {Name: "Truncated", Kind: "string"}}}, ascii},
		{plugin.Spec{Name: "generic.ioc", Description: "Exact literal byte search; overlap-safe, no regex or YARA", Parameters: []plugin.Parameter{{Name: "needle", Kind: "string", Description: "Nonempty UTF-8 literal, at most 4096 bytes"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Match", Kind: "bytes"}}}, ioc},
	}
	specs = append(specs, regexPlugins()...)
	specs = append(specs, linuxVMARegexPlugins()...)
	specs = append(specs, windowsVADRegexPlugins()...)
	specs = append(specs, windowsPoolScannerPlugins()...)
	specs = append(specs, windowsNetScanPlugins()...)
	specs = append(specs, windowsNetStatPlugins()...)
	specs = append(specs, windowsCallbackPlugins()...)
	specs = append(specs, processPlugins()...)
	specs = append(specs, modulePlugins()...)
	specs = append(specs, linuxModuleExtractPlugins()...)
	specs = append(specs, linuxHiddenModulePlugins()...)
	specs = append(specs, linuxNetfilterPlugins()...)
	specs = append(specs, threadPlugins()...)
	specs = append(specs, windowsSuspendedThreadPlugins()...)
	specs = append(specs, windowsDebugRegisterPlugins()...)
	specs = append(specs, windowsETWPatchPlugins()...)
	specs = append(specs, windowsIATPlugins()...)
	specs = append(specs, windowsMalfindPlugins()...)
	specs = append(specs, windowsStringsPlugins()...)
	specs = append(specs, windowsMFTPlugins()...)
	specs = append(specs, windowsPESymbolPlugins()...)
	specs = append(specs, vadPlugins()...)
	specs = append(specs, linuxMapPlugins()...)
	specs = append(specs, linuxMalfindPlugins()...)
	specs = append(specs, dllPlugins()...)
	specs = append(specs, pePlugins()...)
	specs = append(specs, cmdlinePlugins()...)
	specs = append(specs, windowsEnvarPlugins()...)
	specs = append(specs, windowsSessionPlugins()...)
	specs = append(specs, windowsCrashInfoPlugins()...)
	specs = append(specs, windowsPrivilegePlugins()...)
	specs = append(specs, windowsGetSIDPlugins()...)
	specs = append(specs, windowsGetServiceSIDPlugins()...)
	specs = append(specs, windowsKPCRPlugins()...)
	specs = append(specs, windowsVadWalkPlugins()...)
	specs = append(specs, windowsInfoPlugins()...)
	specs = append(specs, windowsPsTreePlugins()...)
	specs = append(specs, windowsJobLinkPlugins()...)
	specs = append(specs, linuxPsauxPlugins()...)
	specs = append(specs, linuxEnvarPlugins()...)
	specs = append(specs, linuxProcessSpoofingPlugins()...)
	specs = append(specs, linuxCapabilityPlugins()...)
	specs = append(specs, linuxCheckCredsPlugins()...)
	specs = append(specs, linuxBoottimePlugins()...)
	specs = append(specs, linuxIOMemPlugins()...)
	specs = append(specs, linuxIPPlugins()...)
	specs = append(specs, linuxVMCoreInfoPlugins()...)
	specs = append(specs, linuxModxviewPlugins()...)
	specs = append(specs, linuxKthreadsPlugins()...)
	specs = append(specs, linuxPsCallStackPlugins()...)
	specs = append(specs, linuxSockscanPlugins()...)
	specs = append(specs, linuxAFInfoPlugins()...)
	specs = append(specs, linuxIDTPlugins()...)
	specs = append(specs, linuxSyscallPlugins()...)
	specs = append(specs, linuxKeyboardPlugins()...)
	specs = append(specs, linuxTTYPlugins()...)
	specs = append(specs, linuxMountInfoPlugins()...)
	specs = append(specs, linuxCheckModulesPlugins()...)
	specs = append(specs, linuxBashPlugins()...)
	specs = append(specs, linuxPtracePlugins()...)
	specs = append(specs, linuxPsTreePlugins()...)
	specs = append(specs, windowsHivePlugins()...)
	specs = append(specs, windowsPrintKeyPlugins()...)
	specs = append(specs, windowsUserAssistPlugins()...)
	specs = append(specs, windowsGetCellRoutinePlugins()...)
	specs = append(specs, windowsAmcachePlugins()...)
	specs = append(specs, windowsScheduledTaskPlugins()...)
	specs = append(specs, windowsHashdumpPlugins()...)
	specs = append(specs, windowsCredentialPlugins()...)
	specs = append(specs, windowsHiveScanPlugins()...)
	specs = append(specs, windowsBigPoolPlugins()...)
	specs = append(specs, windowsUnloadedModulePlugins()...)
	specs = append(specs, windowsFileScanPlugins()...)
	specs = append(specs, windowsPsScanPlugins()...)
	specs = append(specs, windowsThrdScanPlugins()...)
	specs = append(specs, windowsMutantScanPlugins()...)
	specs = append(specs, windowsDriverScanPlugins()...)
	specs = append(specs, windowsDeviceTreePlugins()...)
	specs = append(specs, windowsHandlePlugins()...)
	specs = append(specs, windowsSSDTPlugins()...)
	specs = append(specs, windowsDriverIRPPlugins()...)
	specs = append(specs, windowsDriverModulePlugins()...)
	specs = append(specs, windowsTimerPlugins()...)
	specs = append(specs, windowsVirtMapPlugins()...)
	specs = append(specs, windowsOrphanKernelThreadPlugins()...)
	specs = append(specs, windowsMemmapPlugins()...)
	specs = append(specs, windowsMBRScanPlugins()...)
	specs = append(specs, windowsTrueCryptPlugins()...)
	specs = append(specs, windowsVerInfoPlugins()...)
	specs = append(specs, windowsLdrModulesPlugins()...)
	specs = append(specs, windowsSvcScanPlugins()...)
	specs = append(specs, windowsSuspiciousThreadPlugins()...)
	specs = append(specs, windowsHollowProcessPlugins()...)
	specs = append(specs, windowsProcessGhostingPlugins()...)
	specs = append(specs, windowsPebMasqueradePlugins()...)
	specs = append(specs, windowsPsXViewPlugins()...)
	specs = append(specs, windowsSymlinkScanPlugins()...)
	specs = append(specs, windowsModScanPlugins()...)
	specs = append(specs, linuxELFPlugins()...)
	specs = append(specs, linuxLibraryListPlugins()...)
	specs = append(specs, linuxEBPFPlugins()...)
	specs = append(specs, linuxPIDHashPlugins()...)
	specs = append(specs, linuxKmsgPlugins()...)
	specs = append(specs, linuxPerfEventsPlugins()...)
	specs = append(specs, linuxFbdevPlugins()...)
	specs = append(specs, linuxFtracePlugins()...)
	specs = append(specs, linuxTracepointsPlugins()...)
	specs = append(specs, linuxKallsymsPlugins()...)
	specs = append(specs, linuxScanPlugins()...)
	specs = append(specs, linuxLsofPlugins()...)
	specs = append(specs, linuxSocketPlugins()...)
	specs = append(specs, linuxPageCachePlugins()...)
	specs = append(specs, linuxFilesPlugins()...)
	specs = append(specs, linuxRecoverPlugins()...)
	for _, b := range specs {
		if err := r.Register(b); err != nil {
			return err
		}
	}
	return nil
}
func info(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	for _, r := range e.Physical.Ranges() {
		if err := ctx.Err(); err != nil {
			return err
		}
		encoding, stored := r.Encoding, r.StoredLength
		if encoding == "" {
			encoding, stored = "linear", r.Length
		}
		if err := out(evidence.Row{Cells: map[string]evidence.Value{"Start": evidence.Address(r.Start), "Length": evidence.Number(r.Length), "FileOffset": evidence.Address(r.FileOffset), "StoredLength": evidence.Number(stored), "Encoding": evidence.Text(encoding)}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", r.Start)}}); err != nil {
			return err
		}
	}
	return nil
}

// scanASCII carries a bounded string across read boundaries and never joins
// strings across holes. Adjacent physical ranges continue the same string even
// when their container records or compression streams differ.
func scanASCII(ctx context.Context, l memory.MemoryLayer, minLen int, emit func(uint64, string, bool) error) error {
	if minLen < 1 || minLen > 4096 {
		return fmt.Errorf("minimum string length must be 1..4096")
	}
	buf := make([]byte, 1<<20)
	var start, previousEnd uint64
	word := make([]byte, 0, 256)
	long := false
	flush := func() error {
		if len(word) >= minLen {
			if err := emit(start, string(word), long); err != nil {
				return err
			}
		}
		word = word[:0]
		long = false
		return nil
	}
	for index, r := range l.Ranges() {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || index > 0 && r.Start < previousEnd {
			return fmt.Errorf("invalid ASCII scan ranges")
		}
		if index > 0 && r.Start != previousEnd {
			if err := flush(); err != nil {
				return err
			}
		}
		for off := uint64(0); off < r.Length; {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := int(min(uint64(len(buf)), r.Length-off))
			got, err := l.ReadAt(ctx, buf[:n], r.Start+off)
			if err != nil {
				return err
			}
			if got != n {
				return fmt.Errorf("short scan read")
			}
			for j, b := range buf[:n] {
				if b >= 32 && b <= 126 || b == 9 {
					if len(word) == 0 {
						start = r.Start + off + uint64(j)
					}
					if len(word) < 4096 {
						word = append(word, b)
					} else {
						long = true
					}
				} else {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			off += uint64(n)
		}
		previousEnd = end
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return flush()
}

var bannerVersion = regexp.MustCompile(`(?:Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+`)

func banners(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	err := scanASCII(ctx, e.Physical, 12, func(a uint64, s string, long bool) error {
		if loc := bannerVersion.FindStringIndex(s); loc != nil {
			i := loc[0]
			a += uint64(i)
			n := uint64(4095)
			ranges := e.Physical.Ranges()
			for index, run := range ranges {
				if a >= run.Start && a-run.Start < run.Length {
					end := run.Start + run.Length
					for next := index + 1; next < len(ranges) && ranges[next].Start == end && end-a < n; next++ {
						var err error
						end, err = memory.Add(end, ranges[next].Length)
						if err != nil {
							return err
						}
					}
					n = min(n, end-a)
					break
				}
			}
			data, err := memory.Read(ctx, e.Physical, a, int(n))
			if err != nil {
				return err
			}
			end := bytes.IndexByte(data, 0)
			if end < 0 {
				return nil
			}
			data = bytes.TrimSpace(data[:end])
			const allowed = " #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
			for _, b := range data {
				if !strings.ContainsRune(allowed, rune(b)) {
					return nil
				}
			}
			return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Banner": evidence.Text(string(data))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return pdbBanners(ctx, e, out)
}

func pdbBanners(ctx context.Context, e plugin.Environment, out plugin.Emit) error {
	names := map[string]bool{"ntoskrnl.pdb": true, "ntkrnlmp.pdb": true, "ntkrnlpa.pdb": true, "ntkrpamp.pdb": true}
	buf := make([]byte, 1<<20)
	var tail []byte
	var previousEnd uint64
	for index, r := range e.Physical.Ranges() {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || index > 0 && r.Start < previousEnd {
			return fmt.Errorf("invalid PDB scan ranges")
		}
		if index == 0 || r.Start != previousEnd {
			tail = nil
		}
		for off := uint64(0); off < r.Length; {
			n := int(min(uint64(len(buf)), r.Length-off))
			got, err := e.Physical.ReadAt(ctx, buf[:n], r.Start+off)
			if err != nil {
				return err
			}
			if got != n {
				return fmt.Errorf("short PDB signature read")
			}
			window := append(append(make([]byte, 0, len(tail)+n), tail...), buf[:n]...)
			base := r.Start + off - uint64(len(tail))
			for from := 0; from < len(window); {
				idx := bytes.Index(window[from:], []byte("RSDS"))
				if idx < 0 {
					break
				}
				idx += from
				from = idx + 4
				if idx+25 > len(window) {
					continue
				}
				cv := window[idx:]
				end := bytes.IndexByte(cv[24:min(len(cv), 24+512)], 0)
				if end < 0 {
					continue
				}
				end += 24
				if base+uint64(idx+end+1) <= r.Start+off {
					continue
				}
				name := string(cv[24:end])
				if j := strings.LastIndexAny(name, "/\\"); j >= 0 {
					name = name[j+1:]
				}
				if !names[strings.ToLower(name)] {
					continue
				}
				g := cv[4:20]
				guid := fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:])
				age := binary.LittleEndian.Uint32(cv[20:])
				a := base + uint64(idx)
				if err := out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Banner": evidence.Text(fmt.Sprintf("%s|%s|%d", name, guid, age))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}}); err != nil {
					return err
				}
			}
			keep := min(4096, len(window))
			tail = append(tail[:0], window[len(window)-keep:]...)
			off += uint64(n)
		}
		previousEnd = end
	}
	return ctx.Err()
}
func ascii(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	n, err := strconv.ParseUint(p["min"], 0, 64)
	if err != nil || n < 1 || n > 4096 {
		return fmt.Errorf("minimum string length must be 1..4096")
	}
	return scanASCII(ctx, e.Physical, int(n), func(a uint64, s string, long bool) error {
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Text": evidence.Text(s), "Truncated": evidence.Text(strconv.FormatBool(long))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
func ioc(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	needle := p["needle"]
	if len(needle) < 1 || len(needle) > 4096 {
		return fmt.Errorf("needle must be 1..4096 bytes")
	}
	return memory.Scan(ctx, e.Physical, []byte(needle), func(a uint64) error {
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Match": evidence.Bytes([]byte(needle))}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
