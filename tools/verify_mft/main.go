// Command verify_mft checks saved MFT evidence against original image bytes and
// the pinned upstream ISF, independently of the raw NTFS candidate parser.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const layoutDigest = "12b8ede2f1c5c43ba2af1f7c550153bd3afd8bac90d36014c05155c51534da36"

type sourceRecord struct {
	attributes   map[uint64]uint64
	firstPrimary uint64
	longest      string
}
type verifier struct {
	ctx     context.Context
	objects *object.Reader
	layout  *symbols.ISF
	records map[uint64]sourceRecord
	plugin  string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	image := flag.String("image", "", "Original image")
	stream := flag.String("jsonl", "", "Saved MFT evidence stream")
	layout := flag.String("layout", "", "Locked upstream windows/mft.json")
	name := flag.String("plugin", "windows.mftscan", "windows.mftscan, windows.ads or windows.residentdata")
	flag.Parse()
	if *image == "" || *stream == "" || *layout == "" {
		return fmt.Errorf("image, jsonl and layout are required")
	}
	if *name != "windows.mftscan" && *name != "windows.ads" && *name != "windows.residentdata" {
		return fmt.Errorf("unexpected command")
	}
	raw, err := os.ReadFile(*layout)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != layoutDigest {
		return fmt.Errorf("requires exact locked MFT ISF")
	}
	// This locked auxiliary ISF has no pointer base or pointer fields. Read
	// its exact definitions without inventing a kernel pointer architecture.
	var table symbols.ISF
	err = json.Unmarshal(raw, &table)
	if err != nil {
		return err
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: *image, OS: "windows", Offline: true})
	if err != nil {
		return err
	}
	defer e.Close()
	v := verifier{ctx: ctx, objects: &object.Reader{Layer: e.Env.Physical, Symbols: &table}, layout: &table, records: map[uint64]sourceRecord{}, plugin: *name}
	f, err := os.Open(*stream)
	if err != nil {
		return err
	}
	defer f.Close()
	digest := sha256.New()
	decoder := json.NewDecoder(bufio.NewReaderSize(io.TeeReader(f, digest), 64<<10))
	parents := map[string]bool{}
	counts := map[string]uint64{}
	var readBytes, scanBytes uint64
	lastRoot := ""
	var summary map[string]json.RawMessage
	for {
		var row evidence.Row
		if err = decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if err = row.Verify(); err != nil {
			return err
		}
		if len(summary) > 0 {
			return fmt.Errorf("records follow terminal summary")
		}
		if row.Provenance.ImageSHA256 != e.Hash || row.Provenance.Plugin != *name || row.Provenance.Layer != e.Env.Physical.Name() {
			return fmt.Errorf("original provenance differs")
		}
		kind := row.Cells["RecordType"].String()
		counts[kind]++
		switch kind {
		case "candidate":
			at, cause := row.Cells["RecordOffset"].Uint()
			if cause != nil {
				return cause
			}
			raw, cause := memory.Read(ctx, e.Env.Physical, at, 4)
			if cause != nil {
				return cause
			}
			if string(raw) != "FILE" && string(raw) != "BAAD" {
				return fmt.Errorf("candidate signature absent")
			}
			if string(raw) == "FILE" {
				tail, cause := memory.Read(ctx, e.Env.Physical, at+4, 1)
				if cause != nil || (tail[0] != '0' && tail[0] != '*') {
					return fmt.Errorf("FILE signature suffix absent")
				}
			}
			parents[row.ID] = true
		case "memory_read", "scan_read":
			if kind == "memory_read" && !parents[row.ParentID] {
				return fmt.Errorf("capture candidate parent absent")
			}
			at, cause := row.Cells["Offset"].Uint()
			if cause != nil {
				return cause
			}
			requested, cause := row.Cells["Requested"].Uint()
			if cause != nil || requested > memory.MaxRead {
				return fmt.Errorf("invalid read span")
			}
			captured, cause := row.Cells["Captured"].Uint()
			if cause != nil || captured > requested {
				return fmt.Errorf("invalid captured length")
			}
			raw := make([]byte, requested)
			n, fault := e.Env.Physical.ReadAt(ctx, raw, at)
			if uint64(n) != captured || (fault == nil) != (row.Cells["Error"].Kind == "missing") {
				return fmt.Errorf("source acquisition differs at %#x", at)
			}
			if kind == "memory_read" {
				original, cause := cellBytes(row.Cells["Raw"])
				if cause != nil || !bytes.Equal(original, raw[:n]) {
					return fmt.Errorf("original raw bytes differ")
				}
				readBytes += captured
			} else {
				hash := sha256.Sum256(raw[:n])
				if row.Cells["RawSHA256"].String() != hex.EncodeToString(hash[:]) {
					return fmt.Errorf("original scan digest differs")
				}
				scanBytes += captured
			}
		case "attribute", "diagnostic":
			if !parents[row.ParentID] {
				return fmt.Errorf("candidate parent absent")
			}
		case "result":
			if err = v.result(row); err != nil {
				return fmt.Errorf("result %#v: %w", row.Cells["Offset"], err)
			}
			level, cause := row.Cells["BaselineLevel"].Uint()
			if cause != nil {
				return cause
			}
			parent := ""
			if *name == "windows.mftscan" {
				if level == 1 && lastRoot != "" {
					parent = lastRoot
				} else {
					lastRoot = row.ID
				}
			}
			if row.ParentID != parent {
				return fmt.Errorf("baseline result hierarchy differs")
			}
		case "summary":
			data, _ := json.Marshal(row.Cells["Coverage"].Data)
			if err = json.Unmarshal(data, &summary); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unrecognized record type %q", kind)
		}
	}
	if len(summary) == 0 {
		return fmt.Errorf("terminal summary absent")
	}
	for key, want := range map[string]uint64{"Candidates": counts["candidate"], "Attributes": counts["attribute"], "Rows": counts["result"], "Reads": counts["memory_read"], "Bytes": readBytes, "ScanReads": counts["scan_read"], "ScanBytes": scanBytes} {
		var got uint64
		if json.Unmarshal(summary[key], &got) != nil || got != want {
			return fmt.Errorf("summary count differs: %s", key)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"scope": "original captures, resident payloads, typed result fields and hierarchy; not exhaustive filesystem reconstruction", "plugin": *name, "image_sha256": e.Hash, "jsonl_sha256": hex.EncodeToString(digest.Sum(nil)), "layout_sha256": layoutDigest, "records": counts, "captured_bytes": readBytes, "scanned_bytes": scanBytes, "all_seals_and_provenance_verified": true, "all_captures_independently_reread": true, "baseline_result_fields_and_resident_bytes_verified": true})
}
func cellBytes(v evidence.Value) ([]byte, error) {
	if v.Kind != "bytes" {
		return nil, fmt.Errorf("expected bytes")
	}
	switch raw := v.Data.(type) {
	case nil:
		return nil, nil
	case []byte:
		return raw, nil
	case string:
		return base64.StdEncoding.DecodeString(raw)
	}
	return nil, fmt.Errorf("invalid byte cell")
}
func (v *verifier) scalar(at uint64, typ, path string) (uint64, error) {
	return v.objects.Uint(v.ctx, at, typ, path)
}
func (v *verifier) enum(name string, value uint64) string {
	e, _ := v.layout.Enumeration(name)
	for name, n := range e.Constants {
		number, err := strconv.ParseUint(n.String(), 10, 64)
		if err == nil && number == value {
			return name
		}
	}
	return fmt.Sprintf("0x%x", value)
}
func (v *verifier) source(at uint64) (sourceRecord, error) {
	if r, ok := v.records[at]; ok {
		return r, nil
	}
	r := sourceRecord{attributes: map[uint64]uint64{}}
	first, err := v.scalar(at, "MFT_ENTRY", "FirstAttrOffset")
	if err != nil {
		return r, err
	}
	cursor, err := memory.Add(at, first)
	if err != nil {
		return r, err
	}
	for n := 0; n < 1<<20; n++ {
		kind, err := v.scalar(cursor, "ATTR_HEADER", "AttrType")
		if err != nil {
			break
		}
		name := v.enum("AttrTypeEnum", kind)
		if strings.HasPrefix(name, "0x") {
			break
		}
		r.attributes[cursor+24] = kind
		if kind == 48 {
			name, err := v.filename(cursor + 24)
			if err == nil && utf8.RuneCountInString(name) > utf8.RuneCountInString(r.longest) {
				r.longest = name
			}
		}
		if kind == 128 && r.firstPrimary == 0 {
			resident, err := v.scalar(cursor, "ATTR_HEADER", "NonResidentFlag")
			if err != nil {
				return r, err
			}
			length, err := v.scalar(cursor, "ATTR_HEADER", "NameLength")
			if err != nil {
				return r, err
			}
			if resident == 0 && length == 0 {
				r.firstPrimary = cursor + 24
			}
		}
		length, err := v.scalar(cursor, "ATTR_HEADER", "Length")
		if err != nil || length == 0 {
			break
		}
		cursor, err = memory.Add(cursor, length)
		if err != nil {
			return r, err
		}
	}
	v.records[at] = r
	return r, nil
}
func (v *verifier) wide(at, n uint64) (string, error) {
	if n > 1024 {
		return "", fmt.Errorf("invalid string bound")
	}
	raw, err := memory.Read(v.ctx, v.objects.Layer, at, int(n))
	if err != nil {
		return "", err
	}
	var order binary.ByteOrder = binary.LittleEndian
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		} else if raw[0] == 0xfe && raw[1] == 0xff {
			order = binary.BigEndian
			raw = raw[2:]
		}
	}
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = order.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(words))
	if len(raw)%2 != 0 {
		text += "\ufffd"
	}
	return strings.SplitN(text, "\x00", 2)[0], nil
}
func (v *verifier) filename(at uint64) (string, error) {
	n, err := v.scalar(at, "FILE_NAME_ENTRY", "NameLength")
	if err != nil {
		return "", err
	}
	field, err := v.objects.Field("FILE_NAME_ENTRY", "Name")
	if err != nil {
		return "", err
	}
	return v.wide(at+field.Offset, n*2)
}
func verifyUint(cell evidence.Value, want uint64) error {
	got, err := cell.Uint()
	if err != nil || got != want {
		return fmt.Errorf("integer differs: %v != %#x", cell, want)
	}
	return nil
}
func (v *verifier) result(row evidence.Row) error {
	record, err := row.Cells["RecordOffset"].Uint()
	if err != nil {
		return err
	}
	at, err := row.Cells["Offset"].Uint()
	if err != nil {
		return err
	}
	r, err := v.source(record)
	if err != nil {
		return err
	}
	kind, ok := r.attributes[at]
	if !ok {
		return fmt.Errorf("result is not an original attribute")
	}
	for key, path := range map[string]string{"RecordNumber": "RecordNumber", "LinkCount": "LinkCount"} {
		want, err := v.scalar(record, "MFT_ENTRY", path)
		if err != nil {
			return err
		}
		if err = verifyUint(row.Cells[key], want); err != nil {
			return err
		}
	}
	signature, err := memory.Read(v.ctx, v.objects.Layer, record, 4)
	if err != nil || row.Cells["RecordSignature"].String() != string(signature) {
		return fmt.Errorf("record signature differs")
	}
	flags, err := v.scalar(record, "MFT_ENTRY", "Flags")
	if err != nil || row.Cells["MFTType"].String() != v.enum("MFTFlagsEnum", flags) {
		return fmt.Errorf("record flag differs")
	}
	if row.Cells["AttributeType"].String() != v.enum("AttrTypeEnum", kind) {
		return fmt.Errorf("attribute type differs")
	}
	if kind == 16 || kind == 48 {
		if v.plugin != "windows.mftscan" {
			return fmt.Errorf("unexpected metadata result")
		}
		typ := "STANDARD_INFORMATION_ENTRY"
		if kind == 48 {
			typ = "FILE_NAME_ENTRY"
			name, err := v.filename(at)
			if err != nil || row.Cells["Filename"].String() != name {
				return fmt.Errorf("filename differs")
			}
			permission, err := v.scalar(at, typ, "Flags")
			if err != nil || row.Cells["Permissions"].String() != v.enum("PermissionFlagEnum", permission) {
				return fmt.Errorf("permission differs")
			}
		} else if row.Cells["Filename"].Reason != "not_applicable" || row.Cells["Permissions"].Reason != "not_applicable" {
			return fmt.Errorf("SI missing fields differ")
		}
		for key, path := range map[string]string{"Created": "CreationTime", "Modified": "ModifiedTime", "Updated": "UpdatedTime", "Accessed": "AccessedTime"} {
			ticks, err := v.scalar(at, typ, path)
			if err != nil {
				return err
			}
			seconds := ticks / 10000000
			stamp := time.Unix(int64(seconds)-11644473600, 0).UTC()
			cell := row.Cells[key]
			if seconds == 0 {
				if cell.Reason != "not_applicable" {
					return fmt.Errorf("zero filetime differs")
				}
			} else if stamp.Year() < 1 || stamp.Year() > 9999 {
				if cell.Reason != "unparsable_filetime" {
					return fmt.Errorf("overflow filetime differs")
				}
			} else if cell.String() != stamp.Format("2006-01-02T15:04:05-07:00") {
				return fmt.Errorf("source filetime differs")
			}
		}
		return nil
	}
	if kind != 128 || v.plugin == "windows.mftscan" {
		return fmt.Errorf("unexpected data result")
	}
	header := at - 24
	nonresident, err := v.scalar(header, "ATTR_HEADER", "NonResidentFlag")
	if err != nil || nonresident != 0 {
		return fmt.Errorf("data is not resident")
	}
	nameLength, err := v.scalar(header, "ATTR_HEADER", "NameLength")
	if err != nil {
		return err
	}
	if (v.plugin == "windows.ads") != (nameLength > 0) || v.plugin == "windows.residentdata" && r.firstPrimary != at {
		return fmt.Errorf("wrong resident stream")
	}
	filename := row.Cells["Filename"]
	if r.longest != "" {
		if filename.String() != r.longest {
			return fmt.Errorf("longest original filename differs")
		}
	} else if v.plugin == "windows.ads" {
		if filename.Reason != "not_available" {
			return fmt.Errorf("absent filename differs")
		}
	} else if filename.String() != "N/A" {
		return fmt.Errorf("resident absent filename differs")
	}
	if v.plugin == "windows.ads" {
		offset, err := v.scalar(header, "ATTR_HEADER", "NameOffset")
		if err != nil {
			return err
		}
		name, cause := v.wide(header+offset, nameLength*2)
		cell := row.Cells["ADSFilename"]
		if cause == nil && name != "" {
			if cell.String() != name {
				return fmt.Errorf("original stream name differs")
			}
		} else if cell.Reason != "not_available" {
			return fmt.Errorf("unavailable stream name differs")
		}
	}
	length, err := v.scalar(header, "ATTR_HEADER", "ContentLength")
	if err != nil {
		return err
	}
	offset, err := v.scalar(header, "ATTR_HEADER", "ContentOffset")
	if err != nil {
		return err
	}
	if err = verifyUint(row.Cells["ContentLength"], length); err != nil {
		return err
	}
	if err = verifyUint(row.Cells["ContentOffset"], header+offset); err != nil {
		return err
	}
	cell := row.Cells["Hexdump"]
	if length == 0 || length > 0x400000 {
		if cell.Reason != "not_available" {
			return fmt.Errorf("empty/oversized content differs")
		}
		return nil
	}
	raw, cause := memory.Read(v.ctx, v.objects.Layer, header+offset, int(length))
	if cause != nil {
		if cell.Reason != "not_available" || cell.Error == "" {
			return fmt.Errorf("missing content lacks source error")
		}
		return nil
	}
	captured, err := cellBytes(cell)
	if err != nil || !bytes.Equal(captured, raw) {
		return fmt.Errorf("original resident bytes differ")
	}
	return nil
}
