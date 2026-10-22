package memoryscan

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
)

func TestExtractAgainstActualGenerators(t *testing.T) {
	raw, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	type write struct {
		Offset int
		Data   string
	}
	type row struct{ Values []json.RawMessage }
	var fixture struct {
		Cases []struct {
			Name, Pattern string
			Padded        struct {
				Size    int
				Writes  []write
				Results []struct {
					Maxsize int
					Rows    []row
				}
			} `json:"padded_generic"`
		}
		VMAs []struct {
			Name, Pattern string
			Size          int
			Writes        []write
			Rows          []row
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	checked := 0
	materialize := func(size int, writes []write) []byte {
		data := make([]byte, size)
		for _, w := range writes {
			b, e := hex.DecodeString(w.Data)
			if e != nil {
				t.Fatal(e)
			}
			copy(data[w.Offset:], b)
		}
		return data
	}
	check := func(t *testing.T, pattern string, data []byte, size int, rows []row, anchored bool) {
		re, e := byteregex.Compile(pattern, false)
		if e != nil {
			if len(rows) > 0 {
				t.Fatal(e)
			}
			return
		}
		for _, row := range rows {
			checked++
			index := 0
			if anchored {
				index = 2
			}
			var at uint64
			var text, hexBytes string
			if e = json.Unmarshal(row.Values[index], &at); e != nil {
				t.Fatal(e)
			}
			if e = json.Unmarshal(row.Values[index+1], &text); e != nil {
				t.Fatal(e)
			}
			if e = json.Unmarshal(row.Values[index+2], &hexBytes); e != nil {
				t.Fatal(e)
			}
			if at > uint64(len(data)) || uint64(size) > uint64(len(data))-at {
				t.Fatal("reference context crosses fixture end")
			}
			contextBytes := data[at : at+uint64(size)]
			got, e := Extract(context.Background(), re, contextBytes, anchored, byteregex.Limits{})
			if e != nil {
				t.Fatal(e)
			}
			want, e := hex.DecodeString(hexBytes)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(contextBytes[got.Start:got.End], want) || got.Text != text {
				t.Fatalf("result bytes=%x text=%q; want %x %q", contextBytes[got.Start:got.End], got.Text, want, text)
			}
		}
	}
	for _, c := range fixture.Cases {
		for _, r := range c.Padded.Results {
			t.Run("generic/"+c.Name, func(t *testing.T) {
				check(t, c.Pattern, materialize(c.Padded.Size, c.Padded.Writes), r.Maxsize, r.Rows, false)
			})
		}
	}
	for _, c := range fixture.VMAs {
		t.Run("vma/"+c.Name, func(t *testing.T) { check(t, c.Pattern, materialize(c.Size, c.Writes), 128, c.Rows, true) })
	}
	if checked != 2581 {
		t.Fatal("result-context reference drift", checked)
	}
}

func TestExtractPreservesSearchAndAnchorDifference(t *testing.T) {
	re, _ := byteregex.Compile("MATCH", false)
	data := []byte("xxMATCH")
	search, err := Extract(context.Background(), re, data, false, byteregex.Limits{})
	if err != nil || !search.Matched || search.Start != 2 || search.Text != "MATCH" {
		t.Fatal(search, err)
	}
	anchored, err := Extract(context.Background(), re, data, true, byteregex.Limits{})
	if err != nil || anchored.Matched || anchored.Start != 0 || anchored.End != len(data) || anchored.Text != "xxMATCH" {
		t.Fatal(anchored, err)
	}
}
