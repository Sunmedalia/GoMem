package kallsyms_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type checkedLayer struct {
	memory.MemoryLayer
	t            *testing.T
	reads, bytes uint64
}

func (l *checkedLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if err != nil {
		return n, err
	}
	actual := make([]byte, len(p))
	m, cause := l.MemoryLayer.ReadAt(ctx, actual, at)
	if cause != nil || m != n || !bytes.Equal(actual[:m], p[:n]) {
		l.t.Fatal("independent reread differs", at, m, n, cause)
	}
	l.reads++
	l.bytes += uint64(n)
	return n, err
}

// A skipped optional corpus check is not core-symbol or plugin acceptance.
func TestOfficialDebianCoreSymbols(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_KALLSYMS_CORE_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned --core reference")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline   struct{ Commit string }
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
		Plugin     string
		Parameters []string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.kallsyms" || !reflect.DeepEqual(manifest.Parameters, []string{"--core"}) {
		t.Fatal(manifest, err)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != manifest.Output {
		t.Fatal("reference digest")
	}
	var reference []struct {
		Addr                                    uint64
		SymbolName, Type, ModuleName, SubSystem string
		Size                                    *uint64
		Exported                                *bool
	}
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 24648 {
		t.Fatal(err, len(reference))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	config, err := kallsyms.FromSymbols(e.Env.Symbols, e.Env.KernelSlide, 0x0000ffffffffffff)
	if err != nil {
		t.Fatal(err)
	}
	layer := &checkedLayer{MemoryLayer: e.Env.Kernel, t: t}
	core, err := kallsyms.Open(context.Background(), layer, config, kallsyms.Limits{Symbols: 1000000, Bytes: 512 << 20, TokenBytes: 4096, NameBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	err = core.Stream(context.Background(), func(s kallsyms.Symbol) error {
		if count >= len(reference) {
			t.Fatal("extra symbol")
		}
		r := reference[count]
		var size *uint64
		if s.SizeAvailable {
			v := s.Size
			size = &v
		}
		if s.Address != r.Addr || s.Name != r.SymbolName || s.Type != r.Type || !reflect.DeepEqual(s.Exported, r.Exported) || !reflect.DeepEqual(size, r.Size) || r.ModuleName != "kernel" || r.SubSystem != "core" {
			t.Fatalf("index %d: native %+v reference %+v", count, s, r)
		}
		count++
		return nil
	})
	if err != nil || count != len(reference) || core.Stats().ReadCalls != layer.reads || core.Stats().AcquiredBytes != layer.bytes {
		t.Fatal(count, err, core.Stats(), layer.reads, layer.bytes)
	}
	t.Logf("matched %d core symbols; independently reread %d acquisitions (%d bytes)", count, layer.reads, layer.bytes)
}
