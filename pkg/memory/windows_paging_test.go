package memory

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestWindowsResidentTransitionPages(t *testing.T) {
	for _, mode := range []string{"x64", "pae", "x86"} {
		for _, scenario := range []string{"leaf", "intermediate", "prototype", "swap", "absent-frame"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				b := make([]byte, 0x10000)
				width := 8
				entries := []uint64{0x1000, 0x2000, 0x3000, 0x4000}
				if mode == "pae" {
					entries = entries[:3]
				} else if mode == "x86" {
					width, entries = 4, entries[:2]
				}
				put := func(a, v uint64) {
					if width == 4 {
						binary.LittleEndian.PutUint32(b[a:], uint32(v))
					} else {
						binary.LittleEndian.PutUint64(b[a:], v)
					}
				}
				for n, address := range entries {
					next := uint64(0x8000)
					if n+1 < len(entries) {
						next = entries[n+1]
					}
					flags := uint64(3)
					if n == len(entries)-1 || scenario == "intermediate" && n == len(entries)-2 {
						flags = 2048 | 128 // Transition plus software protection bits.
						if mode == "x64" {
							flags |= 1 << 45 // Windows software PFN metadata, not RAM.
						}
					}
					if n == len(entries)-1 {
						switch scenario {
						case "prototype":
							flags |= 1024
						case "swap":
							flags &^= 2048
						case "absent-frame":
							next = 0x20000
						}
					}
					put(address, next|flags)
				}
				copy(b[0x8123:], "resident")
				p := raw(t, b)
				for _, os := range []string{"", "linux", "windows"} {
					tr, err := NewIntelForOS(p, 0x1000, mode, os, 4)
					if err != nil {
						t.Fatal(err)
					}
					v, err := tr.Translate(context.Background(), 0x123)
					if os != "windows" || scenario == "prototype" || scenario == "swap" {
						if !errors.Is(err, ErrUnmapped) {
							t.Fatal("software entry incorrectly accepted", os, v, err)
						}
						continue
					}
					if err != nil || !v.Transition || v.PermissionsKnown || v.DirtyKnown || v.Dirty || v.Writable || v.Executable {
						t.Fatal("transition metadata/permission uncertainty lost", v, err)
					}
					layer := &Virtual{Physical: p, Translator: tr, ID: "windows-transition"}
					got, err := Read(context.Background(), layer, 0x123, 8)
					if scenario == "absent-frame" {
						if err == nil {
							t.Fatal("missing resident frame became successful bytes")
						}
					} else if err != nil || v.Physical != 0x8123 || string(got) != "resident" {
						t.Fatal(v, string(got), err)
					}
				}
			})
		}
	}
}
