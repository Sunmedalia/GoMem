package symbols

import "fmt"

// BitfieldSpan returns the bytes that contain a bitfield, relative to the
// declared storage type, and the shift after decoding those bytes. Keeping the
// declared type allows packed members to retain their C type without reading
// adjacent bytes or requiring a whole allocation unit to be resident.
func BitfieldSpan(t TypeRef, storage uint64, endian string) (offset, size, shift uint64, err error) {
	base := t.Underlying()
	if t.Kind != "bitfield" || base == nil || base.Kind != "base" && base.Kind != "enum" ||
		storage == 0 || storage > 8 || t.BitLength == 0 || t.BitLength > storage*8 ||
		t.BitPosition > storage*8-t.BitLength {
		return 0, 0, 0, fmt.Errorf("invalid bitfield storage or range")
	}
	low, high := t.BitPosition/8, (t.BitPosition+t.BitLength+7)/8
	offset = low
	if endian == "big" {
		offset = storage - high
	} else if endian != "little" && endian != "" {
		return 0, 0, 0, fmt.Errorf("invalid bitfield byte order %q", endian)
	}
	return offset, high - low, t.BitPosition % 8, nil
}
