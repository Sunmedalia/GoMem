package memory

import (
	"context"
	"debug/elf"
	"fmt"
	"math"
)

// XenHeader describes the mapping actually used, including baseline-compatible
// headerless 4KiB dumps. Counts include invalid entries, which remain unmapped.
type XenHeader struct {
	Layout        string `json:"layout"`
	PageSize      uint64 `json:"page_size"`
	Pages         uint64 `json:"pages"`
	MappedPages   uint64 `json:"mapped_pages"`
	InvalidPages  uint64 `json:"invalid_pages"`
	HasNotes      bool   `json:"has_notes"`
	Magic         uint64 `json:"magic,omitempty"`
	VCPUs         uint64 `json:"vcpus,omitempty"`
	FormatVersion uint64 `json:"format_version,omitempty"`
}
type XenLayer struct {
	*Mapped
	header XenHeader
}

func (x *XenLayer) XenHeader() XenHeader { return x.header }

// xenImage returns matched=true on any Xen-specific section, so malformed Xen
// cannot fall back to an unrelated PT_LOAD mapping or a raw-file view.
func xenImage(ctx context.Context, source MemorySource, file *elf.File) (MemoryLayer, bool, error) {
	sections := map[string]*elf.Section{}
	matched := false
	for _, section := range file.Sections {
		switch section.Name {
		case ".xen_pages", ".xen_pfn", ".xen_p2m", ".note.Xen":
			matched = true
			if sections[section.Name] != nil {
				return nil, true, fmt.Errorf("duplicate Xen section %s", section.Name)
			}
			if section.Flags&elf.SHF_COMPRESSED != 0 {
				return nil, true, fmt.Errorf("%w: compressed Xen section", ErrUnsupported)
			}
			expectedType := elf.SHT_PROGBITS
			if section.Name == ".note.Xen" {
				expectedType = elf.SHT_NOTE
			}
			if section.Type != expectedType {
				return nil, true, fmt.Errorf("invalid Xen section type for %s", section.Name)
			}
			end, err := Add(section.Offset, section.Size)
			if err != nil || end > source.Size() {
				return nil, true, fmt.Errorf("truncated Xen section %s", section.Name)
			}
			sections[section.Name] = section
		}
	}
	if !matched {
		return nil, false, nil
	}
	if file.Class != elf.ELFCLASS64 {
		return nil, true, fmt.Errorf("%w: Xen requires ELF64", ErrUnsupported)
	}
	pages, pfn, p2m := sections[".xen_pages"], sections[".xen_pfn"], sections[".xen_p2m"]
	if pages == nil || (pfn == nil) == (p2m == nil) {
		return nil, true, fmt.Errorf("Xen requires pages and exactly one PFN/P2M index")
	}
	header := XenHeader{PageSize: 4096, Layout: "pfn"}
	if notes := sections[".note.Xen"]; notes != nil {
		if err := xenNotes(ctx, source, file, notes, &header); err != nil {
			return nil, true, err
		}
	}
	index, stride := pfn, uint64(8)
	if p2m != nil {
		index, stride = p2m, 16
		header.Layout = "p2m"
	}
	if index.Size == 0 || index.Size%stride != 0 || index.Size/stride > 1<<24 {
		return nil, true, fmt.Errorf("invalid Xen index length or page budget (16777216)")
	}
	count := index.Size / stride
	if header.HasNotes && header.Pages != count {
		return nil, true, fmt.Errorf("Xen note and index page counts disagree")
	}
	header.Pages = count
	if count > math.MaxUint64/header.PageSize || pages.Size != count*header.PageSize {
		return nil, true, fmt.Errorf("Xen pages section does not match index")
	}
	var runs []Range
	block := make([]byte, 64<<10)
	for position := uint64(0); position < index.Size; {
		if err := ctx.Err(); err != nil {
			return nil, true, err
		}
		length := min(uint64(len(block)), index.Size-position)
		got, err := source.ReadAt(ctx, block[:int(length)], index.Offset+position)
		if err != nil {
			return nil, true, fmt.Errorf("Xen index: %w", err)
		}
		if uint64(got) != length {
			return nil, true, fmt.Errorf("short Xen index read")
		}
		for offset := uint64(0); offset < length; offset += stride {
			frame := file.ByteOrder.Uint64(block[offset:])
			invalid := frame == math.MaxUint64 || (!header.HasNotes && frame == 0xffffffff)
			if p2m != nil {
				machineFrame := file.ByteOrder.Uint64(block[offset+8:])
				if (frame == math.MaxUint64) != (machineFrame == math.MaxUint64) {
					return nil, true, fmt.Errorf("inconsistent invalid Xen P2M pair")
				}
			}
			if invalid {
				header.InvalidPages++
				continue
			}
			if frame > math.MaxUint64/header.PageSize {
				return nil, true, fmt.Errorf("Xen physical frame overflows")
			}
			address := frame * header.PageSize
			if _, err := Add(address, header.PageSize); err != nil {
				return nil, true, err
			}
			stored := pages.Offset + (position+offset)/stride*header.PageSize
			if len(runs) > 0 {
				previous := &runs[len(runs)-1]
				if previous.Start+previous.Length == address && previous.FileOffset+previous.Length == stored {
					previous.Length += header.PageSize
					header.MappedPages++
					continue
				}
			}
			if len(runs) >= 1<<20 {
				return nil, true, fmt.Errorf("Xen fragmented range budget exceeded (1048576)")
			}
			runs = append(runs, Range{Start: address, Length: header.PageSize, FileOffset: stored})
			header.MappedPages++
		}
		position += length
	}
	if err := ctx.Err(); err != nil {
		return nil, true, err
	}
	mapped, err := NewMapped(source, "physical:xen", runs)
	if err != nil {
		return nil, true, fmt.Errorf("Xen mapping: %w", err)
	}
	return &XenLayer{Mapped: mapped, header: header}, true, nil
}

func xenNotes(ctx context.Context, source MemorySource, file *elf.File, notes *elf.Section, header *XenHeader) error {
	if notes.Size == 0 || notes.Size > 1<<20 {
		return fmt.Errorf("Xen notes exceed 1MiB budget or are empty")
	}
	data := make([]byte, int(notes.Size))
	n, err := source.ReadAt(ctx, data, notes.Offset)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("short Xen notes")
	}
	seen := map[uint32]bool{}
	for offset := uint64(0); offset < uint64(len(data)); {
		if err := ctx.Err(); err != nil {
			return err
		}
		if uint64(len(data))-offset < 12 {
			return fmt.Errorf("truncated Xen note header")
		}
		nameSize, descSize, kind := uint64(file.ByteOrder.Uint32(data[offset:])), uint64(file.ByteOrder.Uint32(data[offset+4:])), file.ByteOrder.Uint32(data[offset+8:])
		nameStart := offset + 12
		descStart := nameStart + (nameSize+3)&^uint64(3)
		next := descStart + (descSize+3)&^uint64(3)
		if next > uint64(len(data)) {
			return fmt.Errorf("truncated Xen note payload")
		}
		if nameSize == 4 && string(data[nameStart:nameStart+4]) == "Xen\x00" {
			if seen[kind] {
				return fmt.Errorf("duplicate Xen note %#x", kind)
			}
			seen[kind] = true
			desc := data[descStart : descStart+descSize]
			switch kind {
			case 0x2000000:
				if len(desc) != 0 {
					return fmt.Errorf("invalid Xen NONE note")
				}
			case 0x2000001:
				if len(desc) != 32 {
					return fmt.Errorf("invalid Xen header note")
				}
				header.Magic = file.ByteOrder.Uint64(desc)
				header.VCPUs = file.ByteOrder.Uint64(desc[8:])
				header.Pages = file.ByteOrder.Uint64(desc[16:])
				header.PageSize = file.ByteOrder.Uint64(desc[24:])
				if header.Magic != 0xf00febed && header.Magic != 0xf00febee {
					return fmt.Errorf("invalid Xen core magic")
				}
				if header.PageSize < 4096 || header.PageSize > 2<<20 || header.PageSize&(header.PageSize-1) != 0 {
					return fmt.Errorf("%w: Xen page size", ErrUnsupported)
				}
			case 0x2000003:
				if len(desc) != 8 {
					return fmt.Errorf("invalid Xen version note")
				}
				header.FormatVersion = file.ByteOrder.Uint64(desc)
				if header.FormatVersion != 1 {
					return fmt.Errorf("%w: Xen format version %#x", ErrUnsupported, header.FormatVersion)
				}
			}
		}
		offset = next
	}
	if !seen[0x2000000] || !seen[0x2000001] || !seen[0x2000003] {
		return fmt.Errorf("Xen notes lack required identity/header/version")
	}
	header.HasNotes = true
	return nil
}
