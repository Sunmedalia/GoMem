package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type mftTestMemory struct {
	data  []byte
	reads int
	short bool
}

func (m *mftTestMemory) Name() string { return "physical" }
func (m *mftTestMemory) Ranges() []memory.Range {
	return []memory.Range{{Start: 0, Length: uint64(len(m.data))}}
}
func (m *mftTestMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	m.reads++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at >= uint64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[at:])
	if m.short && n > 0 {
		return n - 1, nil
	}
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func mftTestFixture(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/windows-mft-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name   string
			Size   int
			Writes []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		if c.Name == "FILE-normal" {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				raw, _ := hex.DecodeString(w.Data)
				copy(data[w.Offset:], raw)
			}
			return data
		}
	}
	t.Fatal("missing fixture")
	return nil
}
func mftTestParams(t testing.TB, mode string, overrides map[string]string) (builtin, map[string]string) {
	t.Helper()
	for _, p := range windowsMFTPlugins() {
		if p.Spec().Name == mode {
			params, err := plugin.Parameters(p.Spec(), overrides)
			if err != nil {
				t.Fatal(err)
			}
			return p, params
		}
	}
	t.Fatal("missing plugin")
	return builtin{}, nil
}
func TestMFTPipelineBoundsOutputCancellationAndSourceFault(t *testing.T) {
	original := mftTestFixture(t)
	copy(original[0x3000:0x3400], original[0x1000:0x1400])
	for _, mode := range []string{"windows.mftscan", "windows.ads", "windows.residentdata"} {
		for _, kind := range []string{"scan_read", "candidate", "memory_read", "attribute", "result", "summary"} {
			for _, cancelled := range []bool{false, true} {
				t.Run(mode+"/"+kind+map[bool]string{false: "/output", true: "/cancel"}[cancelled], func(t *testing.T) {
					layer := &mftTestMemory{data: original}
					p, params := mftTestParams(t, mode, nil)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					stop := errors.New("output stopped")
					failed := false
					readCount := 0
					err := p.Run(ctx, plugin.Environment{Physical: layer, OS: "windows"}, params, func(row evidence.Row) error {
						if failed {
							t.Fatal("output after failure")
						}
						if row.Cells["RecordType"].String() == kind {
							failed = true
							readCount = layer.reads
							if cancelled {
								cancel()
								return nil
							}
							return stop
						}
						return nil
					})
					expected := stop
					if cancelled {
						expected = context.Canceled
					}
					if !failed || !errors.Is(err, expected) || layer.reads != readCount {
						t.Fatal("failed boundary", err, failed, layer.reads, readCount)
					}
				})
			}
		}
		for _, limit := range []string{"max-records", "max-attributes", "max-read-bytes", "max-scan-bytes"} {
			t.Run(mode+"/"+limit, func(t *testing.T) {
				layer := &mftTestMemory{data: original}
				p, params := mftTestParams(t, mode, map[string]string{limit: "1"})
				errFlag := false
				err := p.Run(context.Background(), plugin.Environment{Physical: layer, OS: "windows"}, params, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "summary" {
						raw, _ := json.Marshal(row.Cells["Coverage"].Data)
						var coverage mftCoverage
						json.Unmarshal(raw, &coverage)
						errFlag = !coverage.Complete
					}
					return nil
				})
				if err == nil || (!errFlag && limit != "max-scan-bytes") {
					t.Fatal(limit, err, errFlag)
				}
			})
		}
	}
	layer := &mftTestMemory{data: original, short: true}
	p, params := mftTestParams(t, "windows.mftscan", nil)
	results := 0
	err := p.Run(context.Background(), plugin.Environment{Physical: layer, OS: "windows"}, params, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "result" {
			results++
		}
		return nil
	})
	if err == nil || results != 0 || layer.reads != 1 {
		t.Fatal("short scan", err, results, layer.reads)
	}
}
func FuzzMFTPipeline(f *testing.F) {
	fixture := mftTestFixture(f)
	f.Add([]byte{}, uint16(56), uint8(0))
	f.Add([]byte("BAAD"), uint16(0), uint8(5))
	f.Fuzz(func(t *testing.T, raw []byte, first uint16, cut uint8) {
		if len(raw) > 4096 {
			return
		}
		data := append([]byte(nil), fixture...)
		copy(data[0x1000:], raw)
		data[0x1014] = byte(first)
		data[0x1015] = byte(first >> 8)
		layer := &mftTestMemory{data: data}
		p, params := mftTestParams(t, "windows.mftscan", map[string]string{"max-records": "16", "max-attributes": "32", "max-read-bytes": "65536", "max-scan-bytes": "65536"})
		count, stopped, reads := 0, false, 0
		p.Run(context.Background(), plugin.Environment{Physical: layer, OS: "windows"}, params, func(row evidence.Row) error {
			if stopped {
				t.Fatal("post-error output")
			}
			count++
			if cut > 0 && count == int(cut) {
				stopped = true
				reads = layer.reads
				return io.ErrClosedPipe
			}
			return nil
		})
		if stopped && layer.reads != reads {
			t.Fatal("post-error acquisition")
		}
	})
}
