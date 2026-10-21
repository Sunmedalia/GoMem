package plugins

import "testing"

func TestOrphanKernelPointerMask(t *testing.T) {
	if pointerIdentity(0xfffff8043601f000, 8) != 0xf8043601f000 {
		t.Fatal(pointerIdentity(0xfffff8043601f000, 8))
	}
	if pointerIdentity(4, 8) != 4 || pointerIdentity(0x80000000, 4) != 0x80000000 {
		t.Fatal("pid mask")
	}
	kernel := uint64(0x800000000000)
	if pointerIdentity(0xfffff8043601f000, 8) < kernel {
		t.Fatal("kernel start should stay in kernel space")
	}
	if !(uint64(0x7ffe0000) < kernel) {
		t.Fatal("user address")
	}
}
