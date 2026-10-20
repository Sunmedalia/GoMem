package plugins

import (
	"math/big"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestLinuxClockFractionalEpochAndZeroCounter(t *testing.T) {
	clock := linuxBootClock{nanos: big.NewInt(500000000), source: "fixture"}
	display, exact, _, _ := clock.apply(evidence.Number(0))
	if display.String() != "1970-01-01T00:00:00Z" || exact.String() != "1970-01-01T00:00:00.5Z" {
		t.Fatal(display, exact)
	}
	clock.nanos.SetInt64(0)
	if display, _, _, _ := clock.apply(evidence.Number(1)); display.Reason != "invalid_boot_clock" || display.Error == "" {
		t.Fatal("uninitialized clock became a real boot epoch", display)
	}
}

func FuzzLinuxClockArithmetic(f *testing.F) {
	f.Add(int64(1403605353), int64(691776031), uint64(16000956))
	f.Add(int64(1700000000), int64(123456789), uint64(1001234567))
	f.Add(int64(-1), int64(1), ^uint64(0))
	f.Fuzz(func(t *testing.T, seconds, nanos int64, counter uint64) {
		if nanos < 0 || nanos >= nanosPerSecond {
			t.Skip()
		}
		boot := new(big.Int).Mul(big.NewInt(seconds), big.NewInt(nanosPerSecond))
		boot.Add(boot, big.NewInt(nanos))
		before := boot.String()
		clock := linuxBootClock{nanos: boot, source: "fuzz", base: 0x1000}
		display, exact, _, proof := clock.apply(evidence.Number(counter))
		if boot.String() != before || proof.Kind != "structure" {
			t.Fatal("clock input or provenance was modified")
		}
		for i, value := range []evidence.Value{display, exact} {
			if value.Kind == "missing" {
				if value.Error == "" {
					t.Fatal("invalid timestamp lost its reason")
				}
				continue
			}
			parsed, err := time.Parse(time.RFC3339Nano, value.String())
			if err != nil {
				t.Fatal(err)
			}
			got := new(big.Int).Mul(big.NewInt(parsed.Unix()), big.NewInt(nanosPerSecond))
			got.Add(got, big.NewInt(int64(parsed.Nanosecond())))
			want := new(big.Int).Set(boot)
			if i == 0 {
				want.Div(want, big.NewInt(nanosPerSecond)).Mul(want, big.NewInt(nanosPerSecond))
			}
			want.Add(want, new(big.Int).SetUint64(counter))
			if got.Cmp(want) != 0 {
				t.Fatal("timestamp overflow or precision loss")
			}
		}
	})
}
