// Command bench records page-query percentiles on a fixed, generated case.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func main() {
	rows := flag.Int("rows", 100000, "Generated result rows")
	samples := flag.Int("samples", 200, "Page queries")
	flag.Parse()
	if *rows < 100 || *rows > 10000000 || *samples < 20 || *samples > 10000 {
		fmt.Fprintln(os.Stderr, "invalid rows/samples")
		os.Exit(1)
	}
	if err := run(*rows, *samples); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(total, samples int) error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "gomem-benchmark-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	s, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	task, err := s.Begin(ctx, "bench", "bench", evidence.Provenance{})
	if err != nil {
		return err
	}
	for offset := 0; offset < total; offset += 500 {
		var batch []evidence.Row
		for i := offset; i < min(offset+500, total); i++ {
			r := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(uint64(i)), "Name": evidence.Text(fmt.Sprintf("process-%d", i)), "Offset": evidence.Address(uint64(i) * 4096)}}
			r.Seal()
			batch = append(batch, r)
		}
		if err = s.Append(ctx, task.ID, batch); err != nil {
			return err
		}
	}
	if err = s.Finish(ctx, task.ID, "completed", nil); err != nil {
		return err
	}
	latencies := make([]float64, 0, samples)
	for i := 0; i < samples; i++ {
		offset := (i * 7919) % (total - 100)
		start := time.Now()
		page, err := s.Query(ctx, evidence.Query{TaskID: task.ID, Offset: offset, Limit: 100})
		if err != nil {
			return err
		}
		if len(page) != 100 {
			return fmt.Errorf("short benchmark page")
		}
		latencies = append(latencies, float64(time.Since(start).Nanoseconds())/1e6)
	}
	sort.Float64s(latencies)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"engine": version.Version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "rows": total, "page_size": 100, "samples": samples, "p50_ms": latencies[len(latencies)/2], "p95_ms": latencies[(len(latencies)*95-1)/100], "p99_ms": latencies[(len(latencies)*99-1)/100], "runtime_peak_heap_sys_bytes": mem.HeapSys, "scope": "warm unfiltered SQLite OFFSET pages; cold startup, filtering and real-image peak RSS measured separately"})
}
