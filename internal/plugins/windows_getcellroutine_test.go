package plugins

import "testing"

func TestModuleStemAndRange(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"ntoskrnl.exe", "ntoskrnl"},
		{"ntkrnlmp.exe", "ntkrnlmp"},
		{"hook.sys", "hook"},
		{"a.b.c", "a.b"},
		{".hidden", ".hidden"},
		{"nodot", "nodot"},
		{"foo.", "foo"},
		{"NTOSKRNL.EXE", "NTOSKRNL"},
	} {
		if got := moduleStem(tc.in); got != tc.out {
			t.Fatalf("%s -> %s, want %s", tc.in, got, tc.out)
		}
	}
	if !kernelModuleStems[moduleStem("ntoskrnl.exe")] || kernelModuleStems[moduleStem("NTOSKRNL.EXE")] || kernelModuleStems["hook"] {
		t.Fatal("kernel stem set")
	}
	base, size := uint64(0x1000), uint64(0x1000)
	for _, addr := range []uint64{0x1000, 0x1fff, 0x2000} {
		if !addressInModule(base, size, addr) {
			t.Fatal(addr)
		}
	}
	if addressInModule(base, size, 0xfff) || addressInModule(base, size, 0x2001) || addressInModule(base, 0, 0x1001) {
		t.Fatal("range")
	}
	if !addressInModule(^uint64(0)-8, 16, ^uint64(0)) || addressInModule(^uint64(0)-8, 16, 1) {
		t.Fatal("overflow")
	}
}
