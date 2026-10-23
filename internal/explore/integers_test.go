package explore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestIntegerDisplaysActualPinnedVolshell(t *testing.T) {
	data, err := os.ReadFile("testdata/shell-integers-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Width       int
			Order       string
			Address     uint64
			Data        []byte
			Text, Error string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 288 {
		t.Fatal("incomplete actual volshell controls")
	}
	for n, tc := range fixture.Cases {
		t.Run(fmt.Sprintf("%d-width%d-%s", n, tc.Width, tc.Order), func(t *testing.T) {
			var order binary.ByteOrder = binary.LittleEndian
			if tc.Order == ">" {
				order = binary.BigEndian
			}
			var out bytes.Buffer
			if err := writeIntegerLines(context.Background(), &out, tc.Address, tc.Data, tc.Width, order); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.Text {
				t.Fatalf("actual fixed volshell text differs\ngot  %q\nwant %q", out.String(), tc.Text)
			}
			if tc.Error != "" && (len(tc.Data) != 0 || tc.Address != 0 || tc.Error != "InvalidAddressException") {
				t.Fatal("unexplained baseline read error", tc)
			}
		})
	}
}
