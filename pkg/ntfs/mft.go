// Package ntfs reads bounded NTFS record candidates from memory without fixups
// or filesystem reconstruction. Coordinates always refer to original bytes.
package ntfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type Payloads uint8

const (
	StandardPayload Payloads = 1 << iota
	FilenamePayload
	PrimaryPayload
	AlternatePayload
	AllPayloads = StandardPayload | FilenamePayload | PrimaryPayload | AlternatePayload
)

type Limits struct{ MaxAttributes, MaxBytes uint64 }
type Record struct {
	Offset          uint64
	Signature       string
	Number          uint32
	Links, FlagsRaw uint16
	FirstAttribute  uint16
	Attributes      []Attribute
}
type Attribute struct {
	Offset                    uint64
	TypeRaw, Length           uint32
	NonResident, NameLength   uint8
	NameOffset, ContentOffset uint16
	ContentLength             uint32
	Standard                  *StandardInformation
	Filename                  *FileName
	Resident                  *ResidentData
	Error                     error
}
type StandardInformation struct {
	Offset uint64
	Times  [4]uint64
}
type FileName struct {
	Offset         uint64
	Times          [4]uint64
	PermissionsRaw uint32
	Name           string
}
type ResidentData struct {
	Offset                  uint64
	Name                    string
	Content                 []byte
	NameError, ContentError error
}

func (a Attribute) Kind() uint8 { return uint8(a.TypeRaw) }
func (r Record) Type() string {
	switch uint8(r.FlagsRaw) {
	case 0:
		return "Removed"
	case 1:
		return "File"
	case 2:
		return "Directory"
	case 3:
		return "DirInUse"
	}
	return fmt.Sprintf("0x%x", uint8(r.FlagsRaw))
}
func (r Record) LongestFilename() string {
	longest := ""
	count := -1
	for _, a := range r.Attributes {
		if a.Filename != nil {
			n := utf8.RuneCountInString(a.Filename.Name)
			if n > count {
				longest = a.Filename.Name
				count = n
			}
		}
	}
	return longest
}
func (f FileName) Permissions() string {
	names := map[uint8]string{1: "ReadOnly", 2: "Hidden", 4: "System", 32: "Archive", 34: "ArchiveHidden", 36: "ArchiveSystem", 38: "ArchiveHiddenSystem", 60: "Device", 128: "Normal"}
	// The locked MFT ISF declares this enum as one byte, including constants
	// outside that range. Preserve that interpretation and retain the full word.
	if name, ok := names[uint8(f.PermissionsRaw)]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", uint8(f.PermissionsRaw))
}

type reader struct {
	ctx         context.Context
	layer       memory.MemoryLayer
	limit, used uint64
	payloads    Payloads
	primarySeen bool
}

func (r *reader) read(at, n uint64) ([]byte, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if n > memory.MaxRead || n > r.limit-r.used {
		return nil, fmt.Errorf("MFT read budget exhausted")
	}
	if _, err := memory.Add(at, n); err != nil {
		return nil, err
	}
	r.used += n
	return memory.Read(r.ctx, r.layer, at, int(n))
}
func validKind(kind uint8) bool {
	switch kind {
	case 16, 32, 48, 64, 80, 96, 112, 128, 114, 160, 176, 192, 208, 224, 240:
		return true
	}
	return false
}

// ReadRecord follows the pinned attribute-chain semantics: byte-width enums,
// fixed +24 SI/FILENAME payloads, declared resident DATA offsets, and first
// zero-length attribute inclusion. Errors retain already parsed candidates.
// The caller can wrap layer to record every actual acquisition.
func ReadRecord(ctx context.Context, layer memory.MemoryLayer, at uint64, limits Limits) (Record, error) {
	return ReadRecordPayloads(ctx, layer, at, limits, AllPayloads)
}

// ReadRecordPayloads acquires only the payloads used by a command. Primary DATA
// means the first resident unnamed stream, even when its content is unavailable.
func ReadRecordPayloads(ctx context.Context, layer memory.MemoryLayer, at uint64, limits Limits, payloads Payloads) (record Record, err error) {
	record.Offset = at
	if layer == nil || limits.MaxAttributes == 0 || limits.MaxAttributes > 1<<20 || limits.MaxBytes == 0 || limits.MaxBytes > 1<<32 {
		return record, fmt.Errorf("invalid MFT reader or limits")
	}
	r := reader{ctx: ctx, layer: layer, limit: limits.MaxBytes, payloads: payloads}
	raw, err := r.read(at, 48)
	if err != nil {
		return record, err
	}
	record.Signature = string(raw[:4])
	record.Links = binary.LittleEndian.Uint16(raw[18:])
	record.FirstAttribute = binary.LittleEndian.Uint16(raw[20:])
	record.FlagsRaw = binary.LittleEndian.Uint16(raw[22:])
	record.Number = binary.LittleEndian.Uint32(raw[44:])
	if record.Signature != "FILE" && record.Signature != "BAAD" {
		return record, fmt.Errorf("unrecognized MFT candidate signature")
	}
	cursor, cause := memory.Add(at, uint64(record.FirstAttribute))
	if cause != nil {
		return record, cause
	}
	var failures []error
	for {
		if err = ctx.Err(); err != nil {
			return record, errors.Join(append(failures, err)...)
		}
		kind, cause := r.read(cursor, 1)
		if cause != nil {
			return record, errors.Join(append(failures, cause)...)
		}
		if !validKind(kind[0]) {
			return record, errors.Join(failures...)
		}
		if uint64(len(record.Attributes)) >= limits.MaxAttributes {
			return record, errors.Join(append(failures, fmt.Errorf("MFT attribute limit exhausted"))...)
		}
		raw, cause := r.read(cursor, 24)
		if cause != nil {
			return record, errors.Join(append(failures, cause)...)
		}
		a := Attribute{Offset: cursor, TypeRaw: binary.LittleEndian.Uint32(raw), Length: binary.LittleEndian.Uint32(raw[4:]), NonResident: raw[8], NameLength: raw[9], NameOffset: binary.LittleEndian.Uint16(raw[10:]), ContentLength: binary.LittleEndian.Uint32(raw[16:]), ContentOffset: binary.LittleEndian.Uint16(raw[20:])}
		a.Error = readAttribute(&r, &a)
		record.Attributes = append(record.Attributes, a)
		if a.Error != nil {
			failures = append(failures, fmt.Errorf("attribute %#x: %w", cursor, a.Error))
		}
		if ctx.Err() != nil {
			return record, errors.Join(append(failures, ctx.Err())...)
		}
		if a.Length == 0 {
			return record, errors.Join(append(failures, fmt.Errorf("zero-length MFT attribute at %#x", cursor))...)
		}
		cursor, cause = memory.Add(cursor, uint64(a.Length))
		if cause != nil {
			return record, errors.Join(append(failures, cause)...)
		}
	}
}
func readAttribute(r *reader, a *Attribute) error {
	at, err := memory.Add(a.Offset, 24)
	if err != nil {
		return err
	}
	switch a.Kind() {
	case 16:
		if r.payloads&StandardPayload == 0 {
			return nil
		}
		raw, err := r.read(at, 32)
		if err != nil {
			return err
		}
		s := &StandardInformation{Offset: at}
		for i := range s.Times {
			s.Times[i] = binary.LittleEndian.Uint64(raw[i*8:])
		}
		a.Standard = s
	case 48:
		if r.payloads&FilenamePayload == 0 {
			return nil
		}
		raw, err := r.read(at, 66)
		if err != nil {
			return err
		}
		f := &FileName{Offset: at, PermissionsRaw: binary.LittleEndian.Uint32(raw[56:])}
		for i := range f.Times {
			f.Times[i] = binary.LittleEndian.Uint64(raw[8+i*8:])
		}
		name, err := memory.Add(at, 66)
		if err != nil {
			return err
		}
		data, err := r.read(name, uint64(raw[64])*2)
		if err != nil {
			return err
		}
		f.Name = decodeUTF16(data)
		a.Filename = f
	case 128:
		if a.NonResident != 0 {
			return nil
		}
		if a.NameLength == 0 {
			if r.payloads&PrimaryPayload == 0 || r.primarySeen {
				return nil
			}
			r.primarySeen = true
		} else if r.payloads&AlternatePayload == 0 {
			return nil
		}
		d := &ResidentData{}
		a.Resident = d
		if a.NameLength != 0 {
			name, err := memory.Add(a.Offset, uint64(a.NameOffset))
			if err == nil {
				var raw []byte
				raw, err = r.read(name, uint64(a.NameLength)*2)
				if err == nil {
					d.Name = decodeUTF16(raw)
				}
			}
			d.NameError = err
		}
		d.Offset, err = memory.Add(a.Offset, uint64(a.ContentOffset))
		if err == nil && a.ContentLength > 0x400000 {
			err = fmt.Errorf("resident content exceeds pinned 4 MiB limit")
		}
		if err == nil && a.ContentLength != 0 {
			d.Content, err = r.read(d.Offset, uint64(a.ContentLength))
		}
		d.ContentError = err
		return errors.Join(d.NameError, d.ContentError)
	}
	return nil
}
func decodeUTF16(raw []byte) string {
	var order binary.ByteOrder = binary.LittleEndian
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		} else if raw[0] == 0xfe && raw[1] == 0xff {
			order = binary.BigEndian
			raw = raw[2:]
		}
	}
	words := make([]uint16, 0, len(raw)/2)
	for len(raw) >= 2 {
		words = append(words, order.Uint16(raw))
		raw = raw[2:]
	}
	text := string(utf16.Decode(words))
	if len(raw) != 0 {
		text += "\ufffd"
	}
	if at := strings.IndexByte(text, 0); at >= 0 {
		text = text[:at]
	}
	return text
}
