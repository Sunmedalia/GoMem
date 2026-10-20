package plugins

import (
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"testing"
)

func TestWindowsFiletimeBoundaries(t *testing.T) {
	if got := windowsFiletime(116444736001234567); got.String() != "1970-01-01T00:00:00.1234567Z" {
		t.Fatal(got)
	}
	for _, stamp := range []uint64{0, 1, 9999999} {
		if got := windowsFiletime(stamp); got.Reason != "not_set" {
			t.Fatal(got)
		}
	}
	if got := windowsFiletime(^uint64(0)); got.Reason != "invalid_filetime" {
		t.Fatal(got)
	}
	if got := windowsFiletime(2650467743999999999); got.String() != "9999-12-31T23:59:59.9999999Z" {
		t.Fatal(got)
	}
	if evidence.ThreadID("image", "kernel", 0x1000, 4, "a") == evidence.ThreadID("image", "kernel", 0x1000, 4, "b") {
		t.Fatal("TID reuse conflated")
	}
	if evidence.ThreadID("image", "kernel", 0x1000, 4, "a") == evidence.ProcessID("image", "kernel", 0x1000, 4, "a") {
		t.Fatal("process and thread identity namespaces collide")
	}
}
