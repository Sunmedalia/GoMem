package symbols

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type PDBOptions struct {
	Database   string
	MaxBytes   uint64
	MaxRecords int
}

// ConvertPDB converts MSF 7.0 / CodeView symbols directly to canonical ISF.
// Addresses remain image-relative RVAs; kernel relocation is the engine's job.
func ConvertPDB(ctx context.Context, path string, options PDBOptions) (*ISF, Conversion, error) {
	var report Conversion
	if options.MaxBytes == 0 {
		options.MaxBytes = 512 << 20
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = 2000000
	}
	if options.MaxBytes < 1024 || options.MaxBytes > 2<<30 || options.MaxRecords < 1 || options.MaxRecords > 10000000 {
		return nil, report, fmt.Errorf("invalid PDB resource bounds")
	}
	if options.Database == "" {
		options.Database = filepath.Base(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, report, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("PDB input must be a regular file")
		}
		return nil, report, err
	}
	msf, err := openMSF(ctx, f, uint64(before.Size()), options.MaxBytes)
	if err != nil {
		return nil, report, err
	}
	info, err := msf.stream(1)
	if err != nil || len(info) < 28 {
		return nil, report, fmt.Errorf("PDB information header is unavailable: %w", errOrEOF(err))
	}
	guid := info[12:28]
	identity := PDBIdentity{Database: options.Database, Age: uint64(binary.LittleEndian.Uint32(info[8:])),
		GUID: fmt.Sprintf("%08X%04X%04X%X", binary.LittleEndian.Uint32(guid), binary.LittleEndian.Uint16(guid[4:]), binary.LittleEndian.Uint16(guid[6:]), guid[8:])}
	if err = identity.validate(); err != nil {
		return nil, report, err
	}
	dbi, err := msf.stream(3)
	if err != nil || len(dbi) < 64 {
		return nil, report, fmt.Errorf("DBI header is unavailable: %w", errOrEOF(err))
	}
	if binary.LittleEndian.Uint32(dbi) != 0xffffffff || binary.LittleEndian.Uint32(dbi[4:]) != 19990903 {
		return nil, report, fmt.Errorf("unsupported DBI version")
	}
	var warnings []string
	if age := uint64(binary.LittleEndian.Uint32(dbi[8:])); age != identity.Age {
		warnings = append(warnings, fmt.Sprintf("PDB info age %d differs from DBI image age %d; image identity uses DBI age", identity.Age, age))
		identity.Age = age
	}
	machine := binary.LittleEndian.Uint16(dbi[58:])
	var pointer int
	var arch string
	switch machine {
	case 0x8664:
		pointer, arch = 8, "x86_64"
	case 0x14c:
		pointer, arch = 4, "i386"
	case 0xaa64:
		pointer, arch = 8, "arm64"
	case 0x1c0, 0x1c4:
		pointer, arch = 4, "arm"
	default:
		return nil, report, fmt.Errorf("unsupported PDB machine %#x", machine)
	}
	metadata, err := json.Marshal(map[string]any{"pdb": map[string]any{"database": identity.Database, "GUID": identity.GUID, "age": identity.Age, "machine_type": machine}})
	if err != nil {
		return nil, report, err
	}
	table := &ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`), "windows": metadata, "producer": json.RawMessage(`{"name":"gomem-pdb","version":"1"}`)},
		Bases: map[string]Type{"pointer": {Kind: "int", Size: uint64(pointer), Endian: "little"}, "void": {Kind: "void", Endian: "little"}},
		Types: map[string]Type{}, Enums: map[string]Enumeration{}, Symbols: map[string]Symbol{}, architecture: arch}
	tpi, err := msf.stream(2)
	if err != nil {
		return nil, report, err
	}
	builder, err := newCodeView(ctx, tpi, table, options.MaxRecords)
	if err != nil {
		return nil, report, err
	}
	if err = builder.convert(); err != nil {
		return nil, report, err
	}
	if err = builder.symbols(msf, dbi); err != nil {
		return nil, report, err
	}
	if err = builder.validateLayouts(); err != nil {
		return nil, report, err
	}
	hash := sha256.New()
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, report, err
	}
	if _, err = io.CopyBuffer(hash, contextReader{ctx, f}, make([]byte, 1<<20)); err != nil {
		return nil, report, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, report, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, report, fmt.Errorf("PDB input changed while converting")
	}
	if err = table.finalize(); err != nil {
		return nil, report, err
	}
	report = Conversion{Format: "pdb-msf7", Architecture: arch, BuildID: fmt.Sprintf("%s/%d", identity.GUID, identity.Age), Entries: builder.entries,
		Types: len(table.Types), Symbols: len(table.Symbols), Enums: len(table.Enums),
		Sources: []SymbolSource{{Name: filepath.Base(path), Kind: "pdb", SHA256: hex.EncodeToString(hash.Sum(nil))}}}
	report.Warnings = warnings
	report.AbsoluteSymbols = builder.absolute
	report.RemovedSymbols = builder.removed
	if builder.variants > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d earlier same-name type definitions preserved as NAME@0xINDEX; canonical names use the final definition", builder.variants))
	}
	if builder.collisions > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d symbol-name collisions retained as NAME@0xRVA; canonical aliases use the final record", builder.collisions))
	}
	return table, report, nil
}
func errOrEOF(err error) error {
	if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
