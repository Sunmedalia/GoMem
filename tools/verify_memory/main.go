// verify_memory compares complete physical coverage and bytes independently of
// container segmentation. It is a development verifier, not a forensic plugin.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"math/rand"
	"os"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type interval struct {
	Start, End uint64
}

func coverage(layer memory.MemoryLayer) ([]interval, error) {
	var out []interval
	for _, r := range layer.Ranges() {
		end, err := memory.Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || len(out) > 0 && r.Start < out[len(out)-1].End {
			return nil, fmt.Errorf("invalid physical coverage")
		}
		if len(out) > 0 && r.Start == out[len(out)-1].End {
			out[len(out)-1].End = end
		} else {
			out = append(out, interval{r.Start, end})
		}
	}
	return out, nil
}

func digest(ctx context.Context, source memory.MemorySource) (string, error) {
	h := sha256.New()
	buffer := make([]byte, 1<<20)
	for offset := uint64(0); offset < source.Size(); {
		n := min(uint64(len(buffer)), source.Size()-offset)
		got, err := source.ReadAt(ctx, buffer[:n], offset)
		if err != nil || uint64(got) != n {
			return "", fmt.Errorf("source digest read at %#x: %v", offset, err)
		}
		h.Write(buffer[:n])
		offset += n
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func run(image, reference string, randomReads int) (map[string]any, error) {
	ctx := context.Background()
	var sources [2]*memory.FileSource
	var layers [2]memory.MemoryLayer
	var hashes [2]string
	var formats [2]string
	for i, path := range []string{image, reference} {
		source, err := memory.OpenFile(path)
		if err != nil {
			return nil, err
		}
		defer source.Close()
		sources[i] = source
		hashes[i], err = digest(ctx, source)
		if err != nil {
			return nil, err
		}
		layers[i], formats[i], err = memory.Detect(ctx, source)
		if err != nil {
			return nil, err
		}
	}
	ranges, err := coverage(layers[0])
	if err != nil {
		return nil, err
	}
	other, err := coverage(layers[1])
	if err != nil || len(ranges) != len(other) {
		return nil, fmt.Errorf("physical coverage differs: %v", err)
	}
	for i := range ranges {
		if ranges[i] != other[i] {
			return nil, fmt.Errorf("physical coverage differs at interval %d", i)
		}
	}
	buffers := [2][]byte{make([]byte, 1<<20), make([]byte, 1<<20)}
	h := sha256.New()
	var total uint64
	compare := func(address uint64, n int, output hash.Hash) error {
		for i, layer := range layers {
			got, err := layer.ReadAt(ctx, buffers[i][:n], address)
			if err != nil || got != n {
				return fmt.Errorf("physical read at %#x (%d bytes), input %d: %v", address, n, i, err)
			}
		}
		if !bytes.Equal(buffers[0][:n], buffers[1][:n]) {
			return fmt.Errorf("physical bytes differ at block starting %#x", address)
		}
		if output != nil {
			output.Write(buffers[0][:n])
		}
		return nil
	}
	var normalized []map[string]string
	for _, r := range ranges {
		normalized = append(normalized, map[string]string{"start": fmt.Sprintf("0x%x", r.Start), "end_exclusive": fmt.Sprintf("0x%x", r.End)})
		for address := r.Start; address < r.End; {
			n := int(min(uint64(len(buffers[0])), r.End-address))
			if err := compare(address, n, h); err != nil {
				return nil, err
			}
			address += uint64(n)
			if uint64(n) > ^uint64(0)-total {
				return nil, fmt.Errorf("physical byte count overflow")
			}
			total += uint64(n)
		}
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no physical bytes verified")
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < randomReads; i++ {
		r := ranges[rng.Intn(len(ranges))]
		address := r.Start + rng.Uint64()%(r.End-r.Start)
		if err := compare(address, int(min(8192, r.End-address)), nil); err != nil {
			return nil, err
		}
	}
	for i, source := range sources {
		stat, err := source.Stat()
		if err != nil || stat.Size() < 0 || uint64(stat.Size()) != source.Size() {
			return nil, fmt.Errorf("input %d size changed during verification: %v", i, err)
		}
		current, err := digest(ctx, source)
		if err != nil || current != hashes[i] {
			return nil, fmt.Errorf("input %d changed during verification: %v", i, err)
		}
	}
	return map[string]any{"schema": "gomem.physical-byte-comparison/v1", "matched": true, "formats": formats, "source_sha256": hashes, "physical_bytes": fmt.Sprint(total), "coverage": normalized, "physical_sha256": hex.EncodeToString(h.Sum(nil)), "random_reads": randomReads, "scope": "Exact complete mapped physical coverage and bytes for these containers; not full format or plugin acceptance"}, nil
}

func main() {
	image := flag.String("image", "", "First local image")
	reference := flag.String("reference", "", "Independent reference image")
	randomReads := flag.Int("random-reads", 1024, "Additional deterministic random reads, 0..1000000")
	flag.Parse()
	if *image == "" || *reference == "" || *randomReads < 0 || *randomReads > 1000000 {
		fmt.Fprintln(os.Stderr, "image/reference required; random-reads must be 0..1000000")
		os.Exit(2)
	}
	start := time.Now()
	result, err := run(*image, *reference, *randomReads)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result["duration_ms"] = time.Since(start).Milliseconds()
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
