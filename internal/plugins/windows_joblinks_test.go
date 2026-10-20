package plugins

import "testing"

func TestFollowForwardLinksStopsAtCycleAndInvalidObject(t *testing.T) {
	// Head 0x1000, links at offset 0x10. 0x1010 -> object 0x1000 is invalid.
	// 0x2010 -> object 0x2000, then 0x3010 -> object 0x3000, then back to head.
	next := map[uint64]uint64{0x1000: 0x2010, 0x2010: 0x3010, 0x3010: 0x1000, 0x4010: 0x4010}
	got := followForwardLinks(0x1000, 0x10, 10, func(address uint64) (uint64, bool) {
		value, ok := next[address]
		return value, ok
	}, func(address uint64) bool {
		return address == 0x2000 || address == 0x3000
	})
	if len(got) != 2 || got[0] != 0x2000 || got[1] != 0x3000 {
		t.Fatalf("%#x", got)
	}
	stopped := followForwardLinks(0x4000, 0x10, 10, func(address uint64) (uint64, bool) {
		if address == 0x4000 {
			return 0x5010, true
		}
		return 0, false
	}, func(uint64) bool { return true })
	if len(stopped) != 1 || stopped[0] != 0x5000 {
		t.Fatalf("stop %#x", stopped)
	}
	invalid := followForwardLinks(0x1000, 0x10, 10, func(address uint64) (uint64, bool) {
		return next[address], true
	}, func(address uint64) bool { return address != 0x2000 && address != 0x3000 })
	if len(invalid) != 0 {
		t.Fatalf("invalid %#x", invalid)
	}
}
