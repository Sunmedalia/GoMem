package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

func socketScanSelected(c map[string]evidence.Value) []any {
	keys := []string{"Offset", "Family", "Type", "Proto", "Source", "SourcePort", "Destination", "DestinationPort", "State", "Filter"}
	row := make([]any, len(keys))
	for i, key := range keys {
		v := c[key]
		if v.Kind == "missing" {
			continue
		}
		if i == 0 {
			n, _ := v.Uint()
			row[i] = n
		} else {
			row[i] = v.String()
		}
	}
	return row
}
func verifySocketScanNativeIPv6(t *testing.T, e *engine.Engine, c map[string]evidence.Value) {
	t.Helper()
	at, err := c["Offset"].Uint()
	if err != nil {
		t.Fatal(err)
	}
	r := &object.Reader{Layer: e.Env.Physical, Symbols: e.Env.Symbols}
	pointer, err := r.Uint(context.Background(), at, "inet_sock", "pinet6")
	if err != nil {
		t.Fatal(err)
	}
	field, err := r.Field("inet_sock", "pinet6")
	if err != nil || field.Type.Subtype == nil {
		t.Fatal(err)
	}
	info := field.Type.Subtype.Name
	for _, endpoint := range []struct{ key, path, common string }{{"Source", "saddr", "sk.__sk_common.skc_v6_rcv_saddr"}, {"Destination", "daddr", "sk.__sk_common.skc_v6_daddr"}} {
		f, err := r.Field(info, endpoint.path)
		layer := e.Env.Kernel
		address := uint64(0)
		if errors.Is(err, object.ErrFieldAbsent) {
			f, err = r.Field("inet_sock", endpoint.common)
			layer = e.Env.Physical
			address = at
		} else {
			address = pointer
		}
		if err != nil {
			t.Fatal(err)
		}
		address, err = memory.Add(address, f.Offset)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := memory.Read(context.Background(), layer, address, 16)
		if err != nil {
			t.Fatal(err)
		}
		expected := netip.AddrFrom16([16]byte(raw)).String()
		if c[endpoint.key].String() != expected {
			t.Fatal("native IPv6 layer mismatch", address, c[endpoint.key], expected)
		}
	}
}
func TestOfficialLinuxSockscan(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_SOCKSCAN_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional Debian corpus and pinned Linux sockscan reference; not acceptance")
	}
	manifest, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Baseline   struct{ Commit string }
		Plugin     string
		Parameters []string
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
	}
	if err = json.Unmarshal(manifest, &m); err != nil || m.Plugin != "linux.sockscan" || m.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(m.Parameters) != 0 {
		t.Fatal(m, err)
	}
	raw, err := os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != m.Output {
		t.Fatal("reference digest")
	}
	var reference []map[string]any
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 404 {
		t.Fatal(err, len(reference))
	}
	keys := []string{"Sock Offset", "Family", "Type", "Proto", "Source Addr", "Source Port", "Destination Addr", "Destination Port", "State", "Filter"}
	expected := [][]any{}
	refOffsets := map[uint64]bool{}
	for _, r := range reference {
		selected := make([]any, len(keys))
		for i, key := range keys {
			selected[i] = r[key]
		}
		at := uint64(r["Sock Offset"].(float64))
		selected[0] = at
		refOffsets[at] = true
		expected = append(expected, selected)
	}
	for _, baseline := range []bool{true, false} {
		t.Run(fmt.Sprintf("baseline=%t", baseline), func(t *testing.T) {
			e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.Hash != m.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
				t.Fatal("corpus hash")
			}
			p := map[string]string{"baseline-ipv6": strconv.FormatBool(baseline)}
			got := [][]any{}
			readErrors, reads, scans, additional, v6 := 0, 0, 0, 0, 0
			result, err := e.Run(context.Background(), "linux.sockscan", p, engine.RunOptions{Emit: func(r evidence.Row) error {
				if err := r.Verify(); err != nil {
					t.Fatal(err)
				}
				switch r.Cells["RecordType"].String() {
				case "socket_read", "socket_scan_read":
					verifySocketScanCapture(t, e, r)
					if r.Cells["RecordType"].String() == "socket_read" {
						reads++
						if r.Cells["Error"].Error != "" {
							readErrors++
						}
					} else {
						scans++
					}
				case "socket":
					got = append(got, socketScanSelected(r.Cells))
					if !baseline && r.Cells["Family"].String() == "AF_INET6" {
						v6++
						verifySocketScanNativeIPv6(t, e, r.Cells)
						at, _ := r.Cells["Offset"].Uint()
						if !refOffsets[at] {
							additional++
						}
					}
				case "socket_scan_summary":
					proof := r.Cells["Coverage"].Data.(map[string]evidence.Value)
					if proof["PhysicalScanComplete"].Data != true || proof["Completed"].Data != false {
						t.Fatal("coverage hides candidate read failures", proof)
					}
				}
				return nil
			}})
			if err == nil || result.Task.State != "failed" || reads == 0 || scans == 0 || readErrors == 0 {
				t.Fatal("candidate faults became successful scan", result, err, reads, readErrors)
			}
			if baseline {
				if !reflect.DeepEqual(got, expected) {
					t.Fatal("ten-column ordered reference mismatch", len(got), len(expected))
				}
			} else {
				if len(got) != 478 || additional != 74 || v6 != 86 {
					t.Fatal("native IPv6 coverage", len(got), additional, v6)
				}
				common := [][]any{}
				for _, r := range got {
					if !refOffsets[r[0].(uint64)] {
						continue
					}
					copy := append([]any(nil), r...)
					if copy[1] == "AF_INET6" {
						copy[4], copy[6] = nil, nil
					}
					common = append(common, copy)
				}
				if !reflect.DeepEqual(common, expected) {
					t.Fatal("unexplained difference outside corrected IPv6 addresses")
				}
			}
			verifySocketScanStore(t, e, result.Task.ID, result.Task.Rows)
			retryRows := [][]any{}
			retry, err := e.Run(context.Background(), "linux.sockscan", p, engine.RunOptions{Emit: func(r evidence.Row) error {
				if r.Cells["RecordType"].String() == "socket" {
					retryRows = append(retryRows, socketScanSelected(r.Cells))
				}
				return nil
			}})
			if err == nil || retry.Reused || !reflect.DeepEqual(retryRows, got) {
				t.Fatal("failed scan cache/retry mismatch", retry.Reused, err)
			}
			t.Logf("%d ten-field socket rows, %d object reads, %d scan chunks, %d explicit read failures, %d additional IPv6 rows; seals and uncached retry verified", len(got), reads, scans, readErrors, additional)
		})
	}
}
