package memoryscan

import (
	"strings"
	"unicode/utf8"
)

// DisplayUTF8 reproduces Python bytes.decode("utf-8", errors="replace").
// A truncated valid sequence prefix becomes one replacement, while invalid
// leading bytes and constrained second-byte failures consume one byte each.
// Original evidence must retain its bytes independently of this display text.
func DisplayUTF8(data []byte) string {
	var out strings.Builder
	out.Grow(len(data))
	for at := 0; at < len(data); {
		lead := data[at]
		if lead < 0x80 {
			out.WriteByte(lead)
			at++
			continue
		}
		width := 0
		switch {
		case lead >= 0xc2 && lead <= 0xdf:
			width = 2
		case lead >= 0xe0 && lead <= 0xef:
			width = 3
		case lead >= 0xf0 && lead <= 0xf4:
			width = 4
		}
		if width == 0 {
			out.WriteRune(utf8.RuneError)
			at++
			continue
		}
		valid := 1
		for valid < width && at+valid < len(data) {
			next := data[at+valid]
			if next < 0x80 || next > 0xbf {
				break
			}
			if valid == 1 && (lead == 0xe0 && next < 0xa0 || lead == 0xed && next > 0x9f || lead == 0xf0 && next < 0x90 || lead == 0xf4 && next > 0x8f) {
				break
			}
			valid++
		}
		if valid == width {
			out.Write(data[at : at+width])
		} else {
			out.WriteRune(utf8.RuneError)
		}
		at += valid
	}
	return out.String()
}
