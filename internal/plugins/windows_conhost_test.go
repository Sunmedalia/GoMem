package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestConhostScanSectionsPinnedScopes(t *testing.T) {
	vads := []windowsVADPath{
		{start: 0x8000, end: 0x8fff, file: evidence.Text("other.dll")},
		{start: 0x4000, end: 0x5fff, file: evidence.Text(`C:\Windows\CONHOST.EXE`)},
		{start: 0x1000, end: 0x1fff, file: evidence.Text("conhost.exe")},
		{start: 0x100000000, end: 0x13fffffff}, // exactly 1 GiB: excluded from CmdScan
	}
	for _, tc := range []struct {
		scope conhostScanScope
		want  []memory.Range
	}{
		{conhostHistoryVADs, []memory.Range{{Start: 0x1000, Length: 0x1000}, {Start: 0x4000, Length: 0x2000}, {Start: 0x8000, Length: 0x1000}}},
		{conhostExecutableVAD, []memory.Range{{Start: 0x4000, Length: 0x2000}}},
	} {
		base, sections, err := conhostScanSections(vads, tc.scope)
		if err != nil || base != 0x4000 || !reflect.DeepEqual(sections, tc.want) {
			t.Fatal(tc.scope, base, sections, err)
		}
	}
	// The original Consoles scan has no CmdScan 1 GiB cutoff.
	large := []windowsVADPath{{start: 0x1000, end: 0x40000fff, file: evidence.Text("conhost.exe")}}
	_, sections, err := conhostScanSections(large, conhostExecutableVAD)
	if err != nil || len(sections) != 1 || sections[0].Length != 0x40000000 {
		t.Fatal(sections, err)
	}
	for _, invalid := range []windowsVADPath{{start: 2, end: 1}, {start: 0, end: ^uint64(0)}} {
		input := []windowsVADPath{{start: 0x1000, end: 0x1fff, file: evidence.Text("conhost.exe")}, invalid}
		if _, _, err := conhostScanSections(input, conhostHistoryVADs); err == nil {
			t.Fatal("invalid history VAD accepted", invalid)
		}
	}
	if _, _, err := conhostScanSections([]windowsVADPath{{start: 2, end: 1, file: evidence.Text("conhost.exe")}}, conhostExecutableVAD); err == nil {
		t.Fatal("reversed executable VAD accepted")
	}

	if _, _, err := conhostScanSections(vads, conhostScanScope(99)); err == nil {
		t.Fatal("invalid scope accepted")
	}
	base, sections, err := conhostScanSections(vads[:1], conhostExecutableVAD)
	if err != nil || base != 0 || len(sections) != 0 {
		t.Fatal(base, sections, err)
	}
}

func TestConhostAcquisitionLimitsScanToSelectedVADs(t *testing.T) {
	c := cmdControls(t)[0]
	for _, scope := range []conhostScanScope{conhostHistoryVADs, conhostExecutableVAD} {
		env, data := cmdEnvironment(t, c)
		// Add a second, genuinely mapped VAD, also named conhost.exe. Discovery
		// order must keep the original root as the selected executable mapping.
		binary.LittleEndian.PutUint64(data[0x1000:], 0x1200)
		copy(data[0x1200-12:], []byte("Vadl"))
		binary.LittleEndian.PutUint64(data[0x1210:], 0x1000)
		binary.LittleEndian.PutUint32(data[0x1218:], 0x104)
		binary.LittleEndian.PutUint32(data[0x121c:], 0x105)
		binary.LittleEndian.PutUint64(data[0x1228:], 0x2000)
		needle := []byte("outside-first-conhost-vad")
		copy(data[0x104123:], needle)
		a := &poolScannerAnalysis{ctx: context.Background(), maxBytes: 1 << 30, maxReads: 100000, maxRows: 100000, out: func(evidence.Row) error { return nil }}
		s := &cmdScan{a: a, maxNodes: 64, maxRegions: 64, maxTables: 1024, maxEntries: 1 << 20}
		var err error
		s.env, err = s.environment(env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.acquireConhost(context.Background(), 0x400, "test-conhost", scope)
		if err != nil || got == nil || got.Scan == nil {
			t.Fatal(got, err)
		}
		want := []memory.Range{{Start: 0x100000, Length: 0x4000}}
		if scope == conhostHistoryVADs {
			want[0].Length = 0x6000
		}
		if !reflect.DeepEqual(got.Scan.Ranges(), want) {
			t.Fatal(scope, got.Scan.Ranges(), want)
		}
		matches := []uint64{}
		err = memory.Scan(context.Background(), got.Scan, needle, func(at uint64) error { matches = append(matches, at); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if scope == conhostHistoryVADs && !reflect.DeepEqual(matches, []uint64{0x104123}) {
			t.Fatal(matches)
		}
		if scope == conhostExecutableVAD && len(matches) != 0 {
			t.Fatal("scan escaped first executable VAD", matches)
		}
		sentinel := errors.New("scan stopped")
		a.out = func(evidence.Row) error { return sentinel }
		err = memory.Scan(context.Background(), got.Scan, needle, func(uint64) error { return nil })
		if !errors.Is(err, sentinel) {
			t.Fatal("read capture output failure lost", err)
		}
	}
}

func TestConhostAcquisitionPreservesHolesAndCancellation(t *testing.T) {
	c := cmdControls(t)[0]
	env, data := cmdEnvironment(t, c)
	binary.LittleEndian.PutUint64(data[0xb000+0x102*8:], 0)
	a := &poolScannerAnalysis{ctx: context.Background(), maxBytes: 1 << 30, maxReads: 100000, maxRows: 100000}
	diagnostics := 0
	a.out = func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "vad_acquisition_incomplete" {
			diagnostics++
		}
		return nil
	}
	s := &cmdScan{a: a, maxNodes: 64, maxRegions: 64, maxTables: 1024, maxEntries: 1 << 20}
	var err error
	s.env, err = s.environment(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.acquireConhost(context.Background(), 0x400, "hole-test", conhostExecutableVAD)
	if err != nil || got == nil || got.Scan == nil {
		t.Fatal(got, err)
	}
	want := []memory.Range{{Start: 0x100000, Length: 0x2000}, {Start: 0x103000, Length: 0x1000}}
	if !reflect.DeepEqual(got.Scan.Ranges(), want) || diagnostics != 1 || a.failures.err("coverage") == nil {
		t.Fatal("missing page hidden or joined", got.Scan.Ranges(), diagnostics)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.acquireConhost(ctx, 0x400, "cancel-test", conhostExecutableVAD); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
