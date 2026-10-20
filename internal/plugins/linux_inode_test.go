package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestLinuxPOSIXModesMatchIndependentPythonStat(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-inode-mode-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Cases  int
		SHA256 string
	}
	if err = json.Unmarshal(raw, &record); err != nil || record.Cases != 32768 {
		t.Fatal(record, err)
	}
	hash := sha256.New()
	for mode := uint64(0); mode < 65536; mode++ {
		switch mode & 0170000 {
		case 0, 0010000, 0020000, 0040000, 0060000, 0100000, 0120000, 0140000:
		default:
			continue
		}
		kind, text := linuxMode(mode)
		fmt.Fprintf(hash, "%d\t%s\t%s\n", mode, kind, text)
	}
	if hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
		t.Fatal("POSIX mode rendering differs from independent Python stat oracle")
	}
}

type inodeTimeLayer []byte

func (l inodeTimeLayer) Name() string           { return "inode-time-fixture" }
func (l inodeTimeLayer) Ranges() []memory.Range { return nil }
func (l inodeTimeLayer) ReadAt(ctx context.Context, b []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a > uint64(len(l)) {
		return 0, io.EOF
	}
	n := copy(b, l[a:])
	if n < len(b) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func FuzzLinuxInodeTimestamp(f *testing.F) {
	f.Add(int64(0), uint64(0), false)
	f.Add(int64(-1), uint64(999999999), true)
	f.Add(int64(1700000000), uint64(123456789), false)
	f.Add(int64(253402300799), uint64(1000000000), true)
	f.Fuzz(func(t *testing.T, seconds int64, nanos uint64, split bool) {
		data := make(inodeTimeLayer, 16)
		binary.LittleEndian.PutUint64(data, uint64(seconds))
		binary.LittleEndian.PutUint64(data[8:], nanos)
		base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
		fields := map[string]symbols.Field{"tv_sec": {Offset: 0, Type: base("i64")}, "tv_nsec": {Offset: 8, Type: base("u64")}}
		inode := symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"i_ctime": {Type: symbols.TypeRef{Kind: "struct", Name: "timespec"}}}}
		if split {
			inode.Fields = map[string]symbols.Field{"i_ctime_sec": {Type: base("i64")}, "i_ctime_nsec": {Offset: 8, Type: base("u64")}}
		}
		table := &symbols.ISF{Bases: map[string]symbols.Type{"i64": {Size: 8, Endian: "little", Signed: true}, "u64": {Size: 8, Endian: "little"}}, Types: map[string]symbols.Type{"inode": inode, "timespec": {Kind: "struct", Size: 16, Fields: fields}}}
		env := plugin.Environment{Kernel: data, Objects: &object.Reader{Layer: data, Symbols: table}, Symbols: table}
		value, proof, err := linuxInodeTimestamp(context.Background(), env, 0, "i_ctime")
		valid := seconds >= -62135596800 && seconds <= 253402300799 && nanos < 1000000000
		if (err == nil) != valid || proof.Kind != "structure" {
			t.Fatal(seconds, nanos, value, proof, err)
		}
		raw := proof.Data.(map[string]string)
		if raw["seconds"] != strconv.FormatInt(seconds, 10) || raw["nanoseconds"] != strconv.FormatUint(nanos, 10) {
			t.Fatal(raw)
		}
		if valid {
			parsed, err := time.Parse(time.RFC3339Nano, value.String())
			if err != nil || parsed.Unix() != seconds || uint64(parsed.Nanosecond()) != nanos {
				t.Fatal(value, err)
			}
		} else if value.Kind != "missing" || value.Error == "" {
			t.Fatal(value)
		}
	})
}
