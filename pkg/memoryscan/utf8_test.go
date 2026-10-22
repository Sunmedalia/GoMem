package memoryscan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"unicode/utf8"
)

func TestDisplayUTF8AgainstPythonReplacementOracle(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Decoding struct {
			Cases  int
			SHA256 string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	count := 0
	check := func(data []byte) {
		decoded := DisplayUTF8(data)
		if !utf8.ValidString(decoded) {
			t.Fatalf("invalid decoded text for %x", data)
		}
		if utf8.Valid(data) && decoded != string(data) {
			t.Fatalf("changed valid UTF-8 %x", data)
		}
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(decoded)))
		hash.Write(size[:])
		hash.Write([]byte(decoded))
		count++
	}
	check(nil)
	for first := 0; first < 256; first++ {
		check([]byte{byte(first)})
		for second := 0; second < 256; second++ {
			check([]byte{byte(first), byte(second)})
		}
	}
	edges := []byte{0, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff}
	for _, first := range []byte{0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xed, 0xef, 0xf0, 0xf1, 0xf4, 0xf5, 0xff} {
		for _, second := range edges {
			for _, third := range edges {
				check([]byte{first, second, third})
				for _, fourth := range edges {
					check([]byte{first, second, third, fourth})
				}
			}
		}
	}
	if count != 80093 || fixture.Decoding.Cases != count || hex.EncodeToString(hash.Sum(nil)) != fixture.Decoding.SHA256 {
		t.Fatal("Python replacement decoding mismatch", count, hex.EncodeToString(hash.Sum(nil)), fixture.Decoding)
	}
}

func TestDisplayUTF8MalformedPrefixes(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte{0xe1, 0x80}, "\ufffd"},
		{[]byte{0xe1, 0x80, 'A'}, "\ufffdA"},
		{[]byte{0xe0, 0x80, 0x80}, "\ufffd\ufffd\ufffd"},
		{[]byte{0xed, 0xa0, 0x80}, "\ufffd\ufffd\ufffd"},
		{[]byte{0xf0, 0x90, 0x80}, "\ufffd"},
		{[]byte{0xf4, 0x90, 0x80, 0x80}, "\ufffd\ufffd\ufffd\ufffd"},
		{[]byte{0xff, 0xff}, "\ufffd\ufffd"},
	} {
		if got := DisplayUTF8(c.in); got != c.want {
			t.Fatalf("%x: %q want %q", c.in, got, c.want)
		}
	}
}
