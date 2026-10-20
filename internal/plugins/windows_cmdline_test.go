package plugins

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func FuzzWindowsCommandLineUTF16(f *testing.F) {
	for _, seed := range [][]byte{{}, {'a', 0}, {0, 0xd8, 0, 0xdc}, {0, 0xd8, 'x'}, {255, 254, 0, 0}, {'a', 0, 0, 0, 'b', 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			t.Skip()
		}
		before := append([]byte(nil), raw...)
		decoded, warnings := decodeWindowsUTF16(raw)
		if !bytes.Equal(before, raw) || !utf8.ValidString(decoded) || utf8.RuneCountInString(decoded) > (len(raw)+1)/2 {
			t.Fatal("decoding altered evidence or exceeded Unicode bounds")
		}
		seen := map[string]bool{}
		for _, warning := range warnings {
			if seen[warning] {
				t.Fatal("duplicate validation warning")
			}
			seen[warning] = true
			switch warning {
			case "odd_byte_length", "unpaired_surrogate", "leading_bom":
			default:
				t.Fatal("unknown validation warning")
			}
		}
		if seen["odd_byte_length"] != (len(raw)%2 != 0) {
			t.Fatal("incomplete code unit was not identified")
		}
	})
}
