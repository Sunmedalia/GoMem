package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestServiceListSelectsFirstExecutableVAD(t *testing.T) {
	regions := []windowsVADPath{
		{start: 0x4000, file: evidence.Text(`C:\services.exe.bak`)},
		{start: 0x9000, file: evidence.Text(`C:\Windows\System32\SERVICES.EXE`)},
		{start: 0x1000, file: evidence.Text(`C:\services.exe`)},
	}
	got, ok := serviceExecutableRegion(regions)
	if !ok || got.start != 0x9000 {
		t.Fatal(got, ok)
	}
	if _, ok = serviceExecutableRegion(regions[:1]); ok {
		t.Fatal("suffix mismatch accepted")
	}
}

func TestServiceListPatternAndRepeatedWalk(t *testing.T) {
	mem := make(flatMemory, 0x3000)
	copy(mem[0x100:], "Sc27")
	copy(mem[0x200:], "serH")
	copy(mem[4094:], "Sc27") // scanner must retain a tag split over pages
	putU64(mem, 0x110, 0x400)
	putService(mem, 0x400, 0, 1, 2, 32, 4, 0x800, 0xA00, 0xC00)
	putUTF16(mem, 0x800, "listed")
	putUTF16(mem, 0xA00, "Listed service")
	putU64(mem, 0xC00+svcProcBinary, 0xE00)
	putU32(mem, 0xC00+svcProcPID, 112)
	putUTF16(mem, 0xE00, "service.exe")
	var hits []uint64
	err := scanServicePattern(context.Background(), mem, 0, uint64(len(mem)), []byte("Sc27"), func(a uint64) error { hits = append(hits, a); return nil })
	if err != nil || len(hits) != 2 || hits[0] != 0x100 || hits[1] != 4094 {
		t.Fatal(hits, err)
	}
	binaries := map[string]svcBinary{"listed": {pathOK: true, path: "service.exe"}}
	stats := svcStats{}
	var rows []evidence.Row
	for i := 0; i < 2; i++ {
		err = walkServiceHeader(context.Background(), mem, 0x100, binaries, nil, &stats, func(row evidence.Row) error { rows = append(rows, row); return nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(rows) != 2 || stats.records != 2 || rows[0].Cells["PID"].String() != "112" {
		t.Fatal(rows, stats)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = scanServicePattern(ctx, mem, 0, 4096, []byte("Sc27"), func(uint64) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	failure := errors.New("output failed")
	if err = scanServicePattern(context.Background(), mem, 0, 4096, []byte("Sc27"), func(uint64) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestServiceDiffKeepsLastScannedRecordAndExactNames(t *testing.T) {
	records := map[string]evidence.Row{}
	row := func(name, path string) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text(name), "Binary": evidence.Text(path)}}
	}
	for _, r := range []evidence.Row{row("normal", "a"), row("hidden", "old"), row("hidden", "last"), row("Normal", "case")} {
		if err := rememberScannedService(records, r); err != nil {
			t.Fatal(err)
		}
	}
	listed := map[string]bool{"normal": true}
	var rows []evidence.Row
	emit := func(r evidence.Row) error { rows = append(rows, r); return nil }
	if err := emitServiceDifference(context.Background(), records, listed, emit); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Cells["Name"].String() != "Normal" || rows[1].Cells["Binary"].String() != "last" {
		t.Fatal(rows)
	}
	if err := rememberScannedService(records, evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Missing("unreadable", nil)}}); err == nil {
		t.Fatal("unknown name compared as a service")
	}
	failure := errors.New("output failed")
	if err := emitServiceDifference(context.Background(), records, listed, func(evidence.Row) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := emitServiceDifference(ctx, records, listed, emit); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestServiceListVersionAndRegistration(t *testing.T) {
	table := &symbols.ISF{Meta: map[string]json.RawMessage{}}
	env := plugin.Environment{Symbols: table}
	for _, c := range []struct {
		version string
		want    bool
	}{
		{`{"pe":{"major":10,"minor":0,"revision":15062}}`, false},
		{`{"pe":{"major":10,"minor":0,"revision":15063}}`, true},
		{`{"pe":{"major":10,"minor":0,"revision":19041}}`, true},
		{`{"pe":{"major":6,"minor":3,"revision":9600}}`, false},
	} {
		table.Meta["windows"] = json.RawMessage(c.version)
		if got := serviceListSupported(env); got != c.want {
			t.Fatal(c, got)
		}
	}
	reg := plugin.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"windows.svclist", "windows.svcdiff"} {
		if _, err := reg.Get(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceListCycleFailsAndKeepsOutput(t *testing.T) {
	mem := make(flatMemory, 0x1000)
	putService(mem, 0x100, 0x100, 1, 3, 16, 1, 0x600, 0x800, 0)
	putUTF16(mem, 0x600, "cycle")
	putUTF16(mem, 0x800, "Cycle service")
	count := 0
	err := walkServiceRecord(context.Background(), mem, 0x100, 0x100, nil, nil, &svcStats{}, func(evidence.Row) error { count++; return nil })
	if err == nil || count != 1 {
		t.Fatal(count, err)
	}
}
