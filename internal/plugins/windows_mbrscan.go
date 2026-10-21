package plugins

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const (
	mbrLength          = 0x200
	mbrSignatureOffset = 0x1FE
	mbrBootcodeLength  = 0x1B8
	mbrDiskSignature   = 440
	mbrPartitionBase   = 446
	mbrPartitionSize   = 16
)

func windowsMBRScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "DiskSignature", Kind: "string"},
		{Name: "BootcodeMD5", Kind: "string"},
		{Name: "FullMBRMD5", Kind: "string"},
		{Name: "PartitionIndex", Kind: "uint64"},
		{Name: "Bootable", Kind: "bool"},
		{Name: "PartitionType", Kind: "string"},
		{Name: "SectorInSize", Kind: "uint64"},
		{Name: "Disasm", Kind: "string"},
		{Name: "BootFlag", Kind: "uint64"},
		{Name: "PartitionTypeRaw", Kind: "uint64"},
		{Name: "StartingLBA", Kind: "uint64"},
		{Name: "StartingCylinder", Kind: "uint64"},
		{Name: "StartingCHS", Kind: "uint64"},
		{Name: "StartingSector", Kind: "uint64"},
		{Name: "EndingCylinder", Kind: "uint64"},
		{Name: "EndingCHS", Kind: "uint64"},
		{Name: "EndingSector", Kind: "uint64"},
		{Name: "Bootcode", Kind: "string"},
		{Name: "Depth", Kind: "uint64"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.mbrscan", Upstream: "windows.mbrscan.MBRScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan physical memory for Master Boot Records and list the four partition entries",
		Parameters: []plugin.Parameter{
			{Name: "full", Kind: "bool", Default: "false", Description: "Include CHS, LBA, raw type and the bootcode hex dump"},
		},
		Columns: columns,
	}, windowsMBRScan}}
}

type mbrStats struct {
	signatures, zeroBootcode, rows uint64
}

func windowsMBRScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Physical == nil {
		return fmt.Errorf("windows.mbrscan requires a physical layer")
	}
	if p == nil {
		p = map[string]string{}
	}
	if p["full"] == "" {
		p["full"] = "false"
	}
	full, err := strconv.ParseBool(p["full"])
	if err != nil {
		return fmt.Errorf("full: %w", err)
	}
	arch, err := mbrDisasmArchitecture(e)
	if err != nil {
		return err
	}
	stats := mbrStats{}
	err = memory.Scan(ctx, e.Physical, []byte{0x55, 0xaa}, func(offset uint64) error {
		stats.signatures++
		start, err := mbrWindowStart(offset)
		if err != nil {
			return err
		}
		data, present, err := readPaddedPhysical(ctx, e.Physical, start, mbrLength)
		if err != nil {
			return err
		}
		if isAllZero(data[:mbrBootcodeLength]) {
			stats.zeroBootcode++
			return nil
		}
		if missing := firstUnmappedMBRField(present); missing >= 0 {
			return fmt.Errorf("windows.mbrscan: MBR at physical %#x has unmapped field byte at physical %#x", offset, start+int64(missing))
		}
		rows := mbrEvidence(e.Physical.Name(), offset, data, full)
		for _, row := range rows {
			if err = out(row); err != nil {
				return err
			}
		}
		sum, err := memory.Add(stats.rows, uint64(len(rows)))
		if err != nil {
			return err
		}
		stats.rows = sum
		return nil
	})
	if err != nil {
		return err
	}
	row := mbrBaseRow(e.Physical.Name(), 0)
	row.Provenance.Offset = ""
	row.Cells["Offset"] = evidence.Missing("not_applicable", nil)
	row.Cells["RecordType"] = evidence.Text("summary")
	row.Cells["Coverage"] = poolCoverage(map[string]string{
		"signatures":    formatCount(stats.signatures),
		"zero_bootcode": formatCount(stats.zeroBootcode),
		"rows":          formatCount(stats.rows),
		"architecture":  arch,
		"full":          strconv.FormatBool(full),
	})
	return out(row)
}

func mbrDisasmArchitecture(e plugin.Environment) (string, error) {
	if e.Symbols != nil {
		switch e.Symbols.PointerSize() {
		case 8:
			return "intel64", nil
		case 4:
			return "intel", nil
		case 0:
		default:
			return "", fmt.Errorf("windows.mbrscan: pointer size %d is not 4 or 8", e.Symbols.PointerSize())
		}
	}
	switch e.Architecture {
	case "", "x64":
		return "intel64", nil
	case "x86", "pae":
		return "intel", nil
	default:
		return "", fmt.Errorf("windows.mbrscan requires an Intel architecture, not %s", e.Architecture)
	}
}

func mbrWindowStart(signature uint64) (int64, error) {
	if signature > uint64(math.MaxInt64) {
		return 0, fmt.Errorf("windows.mbrscan: signature %#x does not fit a signed physical offset", signature)
	}
	return int64(signature) - mbrSignatureOffset, nil
}

func readPaddedPhysical(ctx context.Context, layer memory.MemoryLayer, start int64, n int) ([]byte, []bool, error) {
	if n < 0 || n > memory.MaxRead {
		return nil, nil, fmt.Errorf("padded physical read length %d is outside 0..%d", n, memory.MaxRead)
	}
	buf := make([]byte, n)
	present := make([]bool, n)
	if n == 0 {
		return buf, present, nil
	}
	index := 0
	addr := uint64(0)
	if start < 0 {
		index = int(-start)
		if index > n {
			return buf, present, nil
		}
	} else {
		addr = uint64(start)
	}
	remain := n - index
	if remain == 0 {
		return buf, present, nil
	}
	limit, err := memory.Add(addr, uint64(remain))
	if err != nil {
		return nil, nil, err
	}
	for _, r := range layer.Ranges() {
		rend, err := memory.Add(r.Start, r.Length)
		if err != nil {
			return nil, nil, err
		}
		if rend <= addr {
			continue
		}
		if r.Start >= limit {
			break
		}
		from := addr
		if r.Start > from {
			from = r.Start
		}
		to := limit
		if rend < to {
			to = rend
		}
		off := index + int(from-addr)
		length := int(to - from)
		if _, err = layer.ReadAt(ctx, buf[off:off+length], from); err != nil {
			return nil, nil, err
		}
		for i := 0; i < length; i++ {
			present[off+i] = true
		}
	}
	return buf, present, nil
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func firstUnmappedMBRField(present []bool) int {
	if len(present) < mbrLength {
		return 0
	}
	for _, span := range [][2]int{{mbrDiskSignature, 4}, {mbrPartitionBase, mbrPartitionSize * 4}} {
		for i := span[0]; i < span[0]+span[1]; i++ {
			if !present[i] {
				return i
			}
		}
	}
	return -1
}

func mbrEvidence(layer string, signature uint64, data []byte, full bool) []evidence.Row {
	boot := data[:mbrBootcodeLength]
	signatureText := diskSignature(data[mbrDiskSignature : mbrDiskSignature+4])
	bootHash := md5Hex(boot)
	fullHash := md5Hex(data)
	disasm := quotedHex(boot)
	bootHex := hexSpaces(boot)
	token := "mbr-" + strconv.FormatUint(signature, 16)
	parent := mbrBaseRow(layer, signature)
	parent.ID = token
	parent.Cells["DiskSignature"] = evidence.Text(signatureText)
	parent.Cells["BootcodeMD5"] = evidence.Text(bootHash)
	parent.Cells["FullMBRMD5"] = evidence.Text(fullHash)
	parent.Cells["Disasm"] = evidence.Text(disasm)
	parent.Cells["Depth"] = evidence.Number(0)
	parent.Cells["RecordType"] = evidence.Text("mbr")
	if full {
		parent.Cells["Bootcode"] = evidence.Text(bootHex)
	}
	rows := []evidence.Row{parent}
	for index := 0; index < 4; index++ {
		entry := data[mbrPartitionBase+index*mbrPartitionSize : mbrPartitionBase+(index+1)*mbrPartitionSize]
		startHead, startSector, startCylinder := decodeCHS(entry[1:4])
		endHead, endSector, endCylinder := decodeCHS(entry[5:8])
		child := mbrBaseRow(layer, signature)
		child.ParentID = token
		child.Cells["DiskSignature"] = evidence.Text(signatureText)
		child.Cells["BootcodeMD5"] = evidence.Text(bootHash)
		child.Cells["FullMBRMD5"] = evidence.Text(fullHash)
		child.Cells["PartitionIndex"] = evidence.Number(uint64(index + 1))
		child.Cells["Bootable"] = evidence.Bool(entry[0] == 0x80)
		child.Cells["PartitionType"] = evidence.Text(mbrPartitionName(entry[4]))
		child.Cells["SectorInSize"] = evidence.Number(uint64(binary.LittleEndian.Uint32(entry[12:16])))
		child.Cells["Disasm"] = evidence.Text("")
		child.Cells["Depth"] = evidence.Number(1)
		child.Cells["RecordType"] = evidence.Text("partition")
		if full {
			child.Cells["BootFlag"] = evidence.Number(uint64(entry[0]))
			child.Cells["PartitionTypeRaw"] = evidence.Number(uint64(entry[4]))
			child.Cells["StartingLBA"] = evidence.Number(uint64(binary.LittleEndian.Uint32(entry[8:12])))
			child.Cells["StartingCylinder"] = evidence.Number(startCylinder)
			child.Cells["StartingCHS"] = evidence.Number(startHead)
			child.Cells["StartingSector"] = evidence.Number(startSector)
			child.Cells["EndingCylinder"] = evidence.Number(endCylinder)
			child.Cells["EndingCHS"] = evidence.Number(endHead)
			child.Cells["EndingSector"] = evidence.Number(endSector)
			child.Cells["Bootcode"] = evidence.Text("N/A")
		}
		rows = append(rows, child)
	}
	return rows
}

func mbrBaseRow(layer string, signature uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", signature)}}
	for _, column := range windowsMBRScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(signature)
	return row
}

func diskSignature(b []byte) string {
	return fmt.Sprintf("%02x-%02x-%02x-%02x", b[0], b[1], b[2], b[3])
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func hexSpaces(b []byte) string {
	const digits = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, len(b)*3-1)
	for i, v := range b {
		out[i*3] = digits[v>>4]
		out[i*3+1] = digits[v&0x0f]
		if i*3+2 < len(out) {
			out[i*3+2] = ' '
		}
	}
	return string(out)
}

func quotedHex(b []byte) string { return `"` + hexSpaces(b) + `"` }

func decodeCHS(b []byte) (head, sector, cylinder uint64) {
	head = uint64(b[0])
	sector = uint64(b[1] % 64)
	cylinder = (uint64(b[1])-sector)*4 + uint64(b[2])
	return head, sector, cylinder
}

func mbrPartitionName(value byte) string {
	if name, ok := mbrPartitionTypes[value]; ok {
		return name
	}
	return "Not Defined PartitionType"
}

// mbrPartitionTypes is the pinned windows/mbr.json PartitionTypes table.
// Values are unique, so the first-name rule for duplicate enumerations does not apply.
var mbrPartitionTypes = map[byte]string{
	0:   "Empty",
	1:   "FAT12,CHS",
	4:   "FAT16 16-32MB,CHS",
	5:   "Microsoft Extended",
	6:   "FAT16 32MB,CHS",
	7:   "NTFS",
	11:  "FAT32,CHS",
	12:  "FAT32,LBA",
	14:  "FAT16, 32MB-2GB,LBA",
	15:  "Microsoft Extended, LBA",
	17:  "Hidden FAT12,CHS",
	20:  "Hidden FAT16,16-32MB,CHS",
	22:  "Hidden FAT16,32MB-2GB,CHS",
	24:  "AST SmartSleep Partition",
	27:  "Hidden FAT32,CHS",
	28:  "Hidden FAT32,LBA",
	30:  "Hidden FAT16,32MB-2GB,LBA",
	39:  "PQservice",
	57:  "Plan 9 partition",
	60:  "PartitionMagic recovery partition",
	66:  "Microsoft MBR,Dynamic Disk",
	68:  "GoBack partition",
	81:  "Novell",
	82:  "CP/M",
	99:  "Unix System V",
	100: "PC-ARMOUR protected partition",
	130: "Solaris x86 or Linux Swap",
	131: "Linux",
	161: "Hibernation",
	133: "Linux Extended",
	135: "NTFS Volume Set",
	159: "BSD/OS",
	165: "FreeBSD",
	166: "OpenBSD",
	168: "Mac OSX",
	169: "NetBSD",
	171: "Mac OSX Boot",
	175: "MacOS X HFS",
	183: "BSDI",
	184: "BSDI Swap",
	187: "Boot Wizard hidden",
	190: "Solaris 8 boot partition",
	216: "CP/M-86",
	222: "Dell PowerEdge Server utilities (FAT fs)",
	223: "DG/UX virtual disk manager partition",
	235: "BeOS BFS",
	238: "EFI GPT Disk",
	239: "EFI System Partition",
	251: "VMWare File System",
	252: "VMWare Swap",
}
