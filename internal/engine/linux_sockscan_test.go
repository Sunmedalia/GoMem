package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type engineSockscanCase struct {
	Width, Size int
	Scenario    string
	ISF         json.RawMessage
	Writes      [][]json.RawMessage
	Rows        [][]any
	NativeRows  [][]any `json:"native_rows"`
}

func engineSockscanCases(t testing.TB) []engineSockscanCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-sockscan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []engineSockscanCase
	}
	if err = json.Unmarshal(raw, &f); err != nil || f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" {
		t.Fatal(err)
	}
	return f.Cases
}
func sockscanEngine(t *testing.T, c engineSockscanCase, arch string) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		var at int
		var encoded string
		json.Unmarshal(w[0], &at)
		json.Unmarshal(w[1], &encoded)
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	dtb := uint64(0x70000)
	if arch == "pae" {
		dtb = 0x75000
		binary.LittleEndian.PutUint64(data[0x75000:], 0x76001)
		binary.LittleEndian.PutUint64(data[0x76000:], 0x77003)
		for page := 0; page < 128; page++ {
			value := uint64(binary.LittleEndian.Uint32(data[0x73000+page*4:]))
			binary.LittleEndian.PutUint64(data[0x77000+page*8:], value)
		}
	}
	image, symbols := filepath.Join(dir, "image.raw"), filepath.Join(dir, "kernel.json")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symbols, c.ISF, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbols, Arch: arch, DTB: fmt.Sprintf("0x%x", dtb), OS: "linux", Offline: true, CaseDir: filepath.Join(dir, "case")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func verifySocketScanCapture(t *testing.T, e *engine.Engine, row evidence.Row) {
	t.Helper()
	proof := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
	if row.Cells["RecordType"].String() == "socket_scan_read" {
		// Scan row provenance addresses are physical, independent of object reads.
		var location uint64
		if _, err := fmt.Sscanf(row.Provenance.Offset, "0x%x", &location); err != nil {
			t.Fatal(err)
		}
		captured, _ := proof["CapturedBytes"].Uint()
		raw := make([]byte, captured)
		n, err := e.Env.Physical.ReadAt(context.Background(), raw, location)
		if err != nil || n != len(raw) {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if proof["SHA256"].String() != fmt.Sprintf("%x", digest) {
			t.Fatal("scan digest mismatch")
		}
		return
	}
	at, _ := proof["Address"].Uint()
	want, _ := proof["RequestedBytes"].Uint()
	capture, _ := proof["CapturedBytes"].Uint()
	layer := e.Env.Kernel
	if row.Provenance.Layer == e.Env.Physical.Name() {
		layer = e.Env.Physical
	}
	raw := make([]byte, want)
	n, cause := layer.ReadAt(context.Background(), raw, at)
	if n < 0 || n > len(raw) {
		t.Fatal("invalid control read")
	}
	if uint64(n) != capture || !bytes.Equal(raw[:n], proof["Raw"].Data.([]byte)) || (cause == nil && n == len(raw)) != (proof["ReadComplete"].Data == true) {
		t.Fatal("independent socket capture mismatch", at, cause, capture)
	}
}
func verifySocketScanStore(t *testing.T, e *engine.Engine, id string, total int64) {
	t.Helper()
	for offset := 0; offset < int(total); {
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: id, Offset: offset, Limit: 1000})
		if err != nil || len(rows) == 0 {
			t.Fatal(err)
		}
		for _, row := range rows {
			if err := row.Verify(); err != nil {
				t.Fatal(err)
			}
		}
		offset += len(rows)
	}
}
func TestLinuxSockscanPinnedStoreAndCache(t *testing.T) {
	for _, c := range engineSockscanCases(t) {
		archs := []string{"x64"}
		if c.Width == 4 {
			archs = []string{"x86", "pae"}
		}
		for _, arch := range archs {
			t.Run(arch+"/"+c.Scenario, func(t *testing.T) {
				e := sockscanEngine(t, c, arch)
				var fresh, cached bytes.Buffer
				selected := []evidence.Row{}
				reads := 0
				result, err := e.Run(context.Background(), "linux.sockscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "socket_read", "socket_scan_read":
						reads++
						verifySocketScanCapture(t, e, row)
					case "socket":
						selected = append(selected, row)
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if c.Scenario == "missing-symbols" {
					if err == nil {
						t.Fatal("missing symbols accepted")
					}
					again, err := e.Run(context.Background(), "linux.sockscan", nil, engine.RunOptions{})
					if err == nil || again.Reused {
						t.Fatal("failed task reused", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(selected) != len(c.NativeRows) || reads == 0 {
					t.Fatal(len(selected), len(c.NativeRows), reads)
				}
				verifySocketScanStore(t, e, result.Task.ID, result.Task.Rows)
				again, err := e.Run(context.Background(), "linux.sockscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal("socket cache mismatch", err, again.Reused)
				}
				if c.Scenario == "ipv6" {
					baseline, er := e.Run(context.Background(), "linux.sockscan", map[string]string{"baseline-ipv6": "true"}, engine.RunOptions{})
					if er != nil || baseline.Reused || baseline.Task.ID == result.Task.ID {
						t.Fatal("IPv6 compatibility parameter lost from cache key", er)
					}
					nativeAgain, er := e.Run(context.Background(), "linux.sockscan", nil, engine.RunOptions{})
					if er != nil || !nativeAgain.Reused || nativeAgain.Task.ID != result.Task.ID {
						t.Fatal("native IPv6 cache was replaced", er)
					}
				}

			})
		}
	}
}
