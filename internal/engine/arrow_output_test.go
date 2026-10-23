package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
)

func TestOfficialArrowStreamingResults(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("set GOMEM_CORPUS_DIR for real Windows/Linux Arrow output")
	}
	for _, tc := range []struct {
		platform, image, symbols, dtb string
		base                          uint64
		count                         int
	}{{"linux", "linux-sample-1.bin", "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", "23089152", 0, 133}, {"windows", "win-10_19041-2025_03.dmp", "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json", "7159808", 0xfffff8043601f000, 120}} {
		t.Run(tc.platform, func(t *testing.T) {
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, tc.image), Symbols: filepath.Join(dir, tc.symbols), DTB: tc.dtb, OS: tc.platform, Arch: "x64", KernelBase: tc.base, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			plugin, err := e.Registry.Get(tc.platform + ".pslist")
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			w, err := render.New(&output, "arrow", plugin.Spec().Columns)
			if err != nil {
				t.Fatal(err)
			}
			expected := [][]byte{}
			result, err := e.Run(ctx, tc.platform+".pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				raw, err := json.Marshal(row)
				if err != nil {
					return err
				}
				expected = append(expected, raw)
				return w.Row(row)
			}})
			if err != nil {
				w.Close()
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if len(expected) != tc.count {
				t.Fatal(len(expected))
			}
			reader, err := ipc.NewReader(&output)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Release()
			index := 0
			for reader.Next() {
				record := reader.RecordBatch()
				for i := 0; i < int(record.NumRows()); i++ {
					raw := record.Column(3).(*array.Binary).Value(i)
					if index >= len(expected) || !bytes.Equal(raw, expected[index]) {
						t.Fatal("evidence JSON changed")
					}
					var restored evidence.Row
					if err := json.Unmarshal(raw, &restored); err != nil {
						t.Fatal(err)
					}
					if err := restored.Verify(); err != nil {
						t.Fatal(err)
					}
					index++
				}
			}
			if reader.Err() != nil || index != tc.count {
				t.Fatal(index, reader.Err())
			}
			cached, err := e.Run(ctx, tc.platform+".pslist", nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			verification, err := e.Store.VerifyCase(ctx, "")
			if err != nil || !verification.Verified {
				t.Fatal(verification, err)
			}
		})
	}
}
