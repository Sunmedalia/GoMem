package plugins

import (
	"bytes"
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestLinuxMountNumericFailedCaptureRetained(t *testing.T) {
	for _, signed := range []bool{false, true} {
		data, n := moduleParamFixture(8, "little", "ops", false)
		data[len(data)-2], data[len(data)-1] = 0xab, 0xcd
		if signed {
			table := n.e.Symbols.(*symbols.ISF)
			f := table.Types["module"].Fields["num_kp"]
			f.Type = symbols.TypeRef{Kind: "base", Name: "int"}
			table.Types["module"].Fields["num_kp"] = f
		}
		fields := map[string]evidence.Value{}
		var err error
		if signed {
			_, _, err = linuxSignedField(context.Background(), n.e, uint64(len(data)-10), "module", "num_kp", fields, "Value")
		} else {
			_, _, err = linuxUnsignedField(context.Background(), n.e, uint64(len(data)-10), "module", "num_kp", fields, "Value")
		}
		if err == nil {
			t.Fatal("partial scalar succeeded")
		}
		proof, ok := fields["Value"].Data.(map[string]evidence.Value)
		if !ok {
			t.Fatal("failed proof discarded", fields)
		}
		raw, ok := proof["Raw"].Data.([]byte)
		if !ok || !bytes.Equal(raw, []byte{0xab, 0xcd}) || proof["ReadComplete"].Data != false || proof["Error"].Error == "" {
			t.Fatal(proof)
		}
		requested, _ := proof["RequestedBytes"].Uint()
		captured, _ := proof["CapturedBytes"].Uint()
		if requested != 4 || captured != 2 {
			t.Fatal(proof)
		}
		// A missing layout also retains its explicit missing cause in the field map.
		fields = map[string]evidence.Value{}
		if _, _, err = linuxUnsignedField(context.Background(), n.e, 0, "module", "absent", fields, "Value"); err == nil || fields["Value"].Reason != "field_unavailable" {
			t.Fatal(fields, err)
		}
	}
}
