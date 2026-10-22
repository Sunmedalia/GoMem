package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
)

func scanTestRecord(name string, value byte) []byte {
	raw := append([]byte("RSDS"), bytes.Repeat([]byte{value}, 16)...)
	raw = binary.LittleEndian.AppendUint32(raw, 7)
	return append(append(raw, name...), 0)
}

func TestModuleRSDSBoundsOrderAndFirstIdentity(t *testing.T) {
	for _, at := range []int{0, 4090, 4096, 8192 - 30, 8192 - 29} {
		data := make([]byte, 8193)
		record := scanTestRecord("x.pdb", 0x12)
		copy(data[at:], record)
		m := pesymbols.Module{Layer: moduleTestLayer{0x1000, data}, Base: 0x1000, Size: 8192, PDBNames: []string{"x.pdb"}}
		got, err := scanModulePDB(context.Background(), m)
		want := 1
		if at+len(record) > 8192 {
			want = 0
		}
		if err != nil || len(got) != want {
			t.Fatal(at, got, err)
		}
		if want == 1 && (got[0].Age != 7 || got[0].GUID != strings.Repeat("12", 16)) {
			t.Fatal(got)
		}
	}
	data := make([]byte, 8192)
	copy(data[100:], scanTestRecord("second.pdb", 0x22))
	copy(data[4000:], scanTestRecord("first.pdb", 0x11))
	copy(data[5000:], scanTestRecord("first.pdb", 0x33))
	m := pesymbols.Module{Layer: moduleTestLayer{0, data}, Size: uint64(len(data)), PDBNames: []string{"first.pdb", "second.pdb"}}
	got, err := scanModulePDB(context.Background(), m)
	if err != nil || len(got) != 2 || got[0].GUID != strings.Repeat("11", 16) || got[1].GUID != strings.Repeat("22", 16) {
		t.Fatal(got, err)
	}
}

type scanFaultLayer struct {
	memory.MemoryLayer
	reads  *int
	stop   error
	cancel context.CancelFunc
}

func (l scanFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	*l.reads++
	if *l.reads == 2 {
		return 0, l.stop
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if l.cancel != nil {
		l.cancel()
	}
	return n, err
}

func TestModuleRSDSReadErrorsCancellationAndBounds(t *testing.T) {
	data := make([]byte, 8192)
	copy(data, scanTestRecord("x.pdb", 1))
	base := moduleTestLayer{0, data}
	reads := 0
	m := pesymbols.Module{Layer: scanFaultLayer{MemoryLayer: base, reads: &reads, stop: io.ErrUnexpectedEOF}, Size: 8192, PDBNames: []string{"x.pdb"}}
	if _, err := scanModulePDB(context.Background(), m); !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reads = 0
	m.Layer = scanFaultLayer{MemoryLayer: base, reads: &reads, cancel: cancel}
	if _, err := scanModulePDB(ctx, m); !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatal(err, reads)
	}
	for _, name := range []string{"", "a/b.pdb", "a\\b.pdb", "中文.pdb", "x\x00.pdb", strings.Repeat("x", 257)} {
		m.Layer = base
		m.PDBNames = []string{name}
		if _, err := scanModulePDB(context.Background(), m); err == nil {
			t.Fatal("invalid candidate accepted", name)
		}
	}
	m.PDBNames = []string{"é.pdb"}
	copy(data, scanTestRecord(string([]byte{0xe9})+".pdb", 1))
	if _, err := scanModulePDB(context.Background(), m); err == nil {
		t.Fatal("baseline UTF-8 decode failure hidden")
	}
	m.PDBNames = []string{"x.pdb"}
	m.Base = ^uint64(0) - 3
	if _, err := scanModulePDB(context.Background(), m); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestModuleRSDSObserverFailureAndByteBudget(t *testing.T) {
	m, table, _ := nativeModuleFixture(t, "x64")
	id, _ := table.PDBIdentity()
	m.PDBNames = []string{id.Database}
	e := &Engine{Config: Config{Offline: true, SymbolCache: t.TempDir()}, Build: strings.Repeat("ab", 32)}
	e.Env.Symbols = table
	stop := errors.New("evidence output stopped")
	reads := 0
	opts := pesymbols.Options{PDB: e.modulePDBProvider(), Limits: pe.DefaultExportLimits(), MaxSymbols: 1000000, Observe: func(r pesymbols.Read) error { reads++; return stop }}
	r, err := pesymbols.New([]pesymbols.Module{m}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Resolve(context.Background(), pesymbols.Request{Names: []string{"entry"}}); !errors.Is(err, stop) || reads != 1 {
		t.Fatal(err, reads)
	}
	opts.Observe = nil
	opts.Limits.MaxBytes = 4095
	r, err = pesymbols.New([]pesymbols.Module{m}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Resolve(context.Background(), pesymbols.Request{Names: []string{"entry"}}); err == nil || errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal("scan budget failure hidden", err)
	}
}

func TestModuleRSDSAcquisitionCandidatePriority(t *testing.T) {
	m, table, _ := nativeModuleFixture(t, "x64")
	id, _ := table.PDBIdentity()
	resident := m.Layer.(moduleTestLayer).data
	at := bytes.Index(resident, []byte("RSDS"))
	if at < 0 {
		t.Fatal("fixture lacks RSDS")
	}
	record := append([]byte(nil), resident[at:at+25+len(id.Database)]...)
	data := make([]byte, len(resident))
	copy(data[100:], scanTestRecord("missing.pdb", 0x33))
	copy(data[4090:], record)
	m.Layer = moduleTestLayer{m.Base, data}
	m.PDBNames = []string{"missing.pdb", id.Database}
	e := &Engine{Config: Config{Offline: true, SymbolCache: t.TempDir()}, Build: strings.Repeat("ab", 32)}
	e.Env.Symbols = table
	if got, err := e.modulePDBProvider()(context.Background(), m); err != nil || !got.Identity.Equal(id) {
		t.Fatal(got, err)
	}
	// A second identity with the same candidate name must not rescue the first.
	wrong := append([]byte(nil), record...)
	wrong[4] ^= 0xff
	copy(data[100:], wrong)
	m.PDBNames = []string{id.Database}
	if _, err := e.modulePDBProvider()(context.Background(), m); !errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal("second identity tried", err)
	}
}

func FuzzModuleRSDS(f *testing.F) {
	f.Add(scanTestRecord("x.pdb", 0x12), uint16(4090))
	f.Add([]byte("RSDS"), uint16(0))
	f.Fuzz(func(t *testing.T, record []byte, offset uint16) {
		if len(record) > 16384 {
			return
		}
		data := make([]byte, 16384)
		copy(data[int(offset)%len(data):], record)
		m := pesymbols.Module{Layer: moduleTestLayer{0x1000, data}, Base: 0x1000, Size: uint64(len(data)), PDBNames: []string{"x.pdb", "X.pdb"}}
		got, err := scanModulePDB(context.Background(), m)
		if err != nil || len(got) > 2 {
			t.Fatal(got, err)
		}
		for _, id := range got {
			if id.Database != "x.pdb" && id.Database != "X.pdb" {
				t.Fatal(id)
			}
		}
		// Independent whole-buffer regex mirrors the actual upstream scanner;
		// unlike production, this small fuzz oracle can materialize all matches.
		want := 0
		// Go regex operates on Unicode characters, unlike Python bytes regex.
		// Map every byte to one Latin-1 rune so arbitrary GUID bytes count once.
		latin := make([]rune, len(data))
		for i, b := range data {
			latin[i] = rune(b)
		}
		for _, name := range m.PDBNames {
			pattern := regexp.MustCompile(`(?s)RSDS.{20}` + regexp.QuoteMeta(name) + "\x00")
			matched := pattern.FindString(string(latin))
			if matched == "" {
				continue
			}
			var match []byte
			for _, r := range matched {
				match = append(match, byte(r))
			}
			if want >= len(got) || got[want].Database != name || got[want].Age != uint64(binary.LittleEndian.Uint32(match[20:24])) {
				t.Fatal(got, name)
			}
			want++
		}
		if len(got) != want {
			t.Fatal("scan completeness", got, want)
		}
	})
}
