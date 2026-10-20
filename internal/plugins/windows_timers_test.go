package plugins

import "testing"

func TestTimerDecodeAndDueTime(t *testing.T) {
	if rol64(0x0123456789abcdef, 8) != 0x23456789abcdef01 || rol64(0xffffffffffffffff, 0) != 0xffffffffffffffff || rol64(1, 63) != 0x8000000000000000 {
		t.Fatalf("%x %x %x", rol64(0x0123456789abcdef, 8), rol64(0xffffffffffffffff, 0), rol64(1, 63))
	}
	if bswap64(0x0123456789abcdef) != 0xefcdab8967452301 {
		t.Fatalf("%x", bswap64(0x0123456789abcdef))
	}
	if got := decodeTimerDPC(0x1122334455667788, 0x0102030405060708, 0xAABBCCDDEEFF0011, 0xFFFFF8043601F000); got != 0xbacbbd8bba47cfce {
		t.Fatalf("%x", got)
	}
	if pythonHex010(0) != "0x00000000" || pythonHex010(0x3c8efdec) != "0x3c8efdec" || pythonHex010(2) != "0x00000002" || pythonHex010(-1) != "-0x0000001" || pythonHex010(-2147483648) != "-0x80000000" {
		t.Fatalf("%s %s %s %s %s", pythonHex010(0), pythonHex010(0x3c8efdec), pythonHex010(2), pythonHex010(-1), pythonHex010(-2147483648))
	}
}
