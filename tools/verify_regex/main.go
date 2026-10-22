// Development verifier: reread sealed regex evidence from the original image.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type audit struct {
	ctx                                                                                    context.Context
	engine                                                                                 *engine.Engine
	roots                                                                                  map[string]uint64
	Reads, Chunks, Matches, ContextParts, HardwareProofs, Disagreements, UnavailableProofs uint64
}

func structure(v evidence.Value) (map[string]evidence.Value, error) {
	var m map[string]evidence.Value
	b, e := json.Marshal(v.Data)
	if e == nil {
		e = json.Unmarshal(b, &m)
	}
	return m, e
}
func parts(v evidence.Value) ([]map[string]evidence.Value, error) {
	var m []map[string]evidence.Value
	b, e := json.Marshal(v.Data)
	if e == nil {
		e = json.Unmarshal(b, &m)
	}
	return m, e
}
func raw(v evidence.Value) ([]byte, error) {
	if v.Kind != "bytes" {
		return nil, fmt.Errorf("expected bytes, got %s", v.Kind)
	}
	switch x := v.Data.(type) {
	case []byte:
		return x, nil
	case string:
		return base64.StdEncoding.DecodeString(x)
	default:
		return nil, fmt.Errorf("invalid bytes representation")
	}
}
func number(v evidence.Value) uint64 {
	n, e := v.Uint()
	if e != nil {
		panic(fmt.Errorf("invalid numeric evidence: %w", e))
	}
	return n
}
func truth(v evidence.Value) bool {
	b, ok := v.Data.(bool)
	if v.Kind != "bool" || !ok {
		panic(fmt.Errorf("invalid bool evidence"))
	}
	return b
}
func (a *audit) read(at, n uint64) ([]byte, error) {
	if n > memory.MaxRead {
		return nil, fmt.Errorf("audit read exceeds bound")
	}
	return memory.Read(a.ctx, a.engine.Env.Physical, at, int(n))
}
func (a *audit) hashRange(h hash.Hash, at, n uint64) error {
	if _, e := memory.Add(at, n); e != nil {
		return e
	}
	for n > 0 {
		size := min(n, uint64(memory.MaxRead))
		b, e := a.read(at, size)
		if e != nil {
			return e
		}
		h.Write(b)
		at += size
		n -= size
	}
	return nil
}
func (a *audit) verify(row evidence.Row) error {
	if err := row.Verify(); err != nil {
		return err
	}
	if row.Provenance.ImageSHA256 != a.engine.Hash {
		return fmt.Errorf("image hash differs from sealed provenance")
	}
	kind := row.Cells["RecordType"].String()
	switch kind {
	case "address_space":
		m, e := structure(row.Cells["Mapping"])
		if e != nil {
			return e
		}
		if _, ok := a.roots[row.ID]; ok {
			return fmt.Errorf("duplicate address-space evidence identity")
		}
		a.roots[row.ID] = number(m["Root"])
	case "scan_chunk":
		root, ok := a.roots[row.ParentID]
		if !ok {
			return fmt.Errorf("missing address-space parent")
		}
		if _, ok = a.roots[row.ID]; ok {
			return fmt.Errorf("duplicate scan-chunk evidence identity")
		}
		a.roots[row.ID] = root
		m, e := structure(row.Cells["Mapping"])
		if e != nil {
			return e
		}
		ps, e := parts(m["Parts"])
		if e != nil {
			return e
		}
		combined := sha256.New()
		var captured uint64
		for _, p := range ps {
			at, n, want := number(p["Physical"]), number(p["Captured"]), number(p["Requested"])
			if n > want {
				return fmt.Errorf("captured prefix exceeds request")
			}
			h := sha256.New()
			if e = a.hashRange(h, at, n); e != nil {
				return e
			}
			if hex.EncodeToString(h.Sum(nil)) != p["SHA256"].String() {
				return fmt.Errorf("original scan-part digest differs")
			}
			if truth(p["ReadComplete"]) {
				if n != want || number(p["BufferOffset"]) != captured {
					return fmt.Errorf("successful part bounds differ")
				}
				if e = a.hashRange(combined, at, n); e != nil {
					return e
				}
				captured += n
			}
		}
		if captured != number(row.Cells["Captured"]) || hex.EncodeToString(combined.Sum(nil)) != row.Cells["SHA256"].String() {
			return fmt.Errorf("original scan-buffer digest differs")
		}
		if captured > number(m["End"]) || number(row.Cells["Offset"]) != number(m["End"])-captured {
			return fmt.Errorf("scan coordinate differs from acquired bytes")
		}
		a.Chunks++
	case "regex_match":
		root, ok := a.roots[row.ParentID]
		if !ok {
			return fmt.Errorf("missing scan-chunk parent")
		}
		source, e := structure(row.Cells["Source"])
		if e != nil {
			return e
		}
		ps, e := parts(source["Parts"])
		if e != nil {
			return e
		}
		matchBytes, e := raw(row.Cells["MatchRaw"])
		if e != nil {
			return e
		}
		combined := sha256.New()
		var length uint64
		native, e := memory.NewIntelForOS(a.engine.Env.Physical, root, a.engine.Env.Architecture, a.engine.Env.OS, 1024)
		if e != nil {
			return e
		}
		same := len(ps) > 0
		for _, p := range ps {
			at, size := number(p["Physical"]), number(p["Length"])
			if number(p["BufferOffset"]) != length {
				return fmt.Errorf("match source has gap or overlap")
			}
			if e = a.hashRange(combined, at, size); e != nil {
				return e
			}
			virtual := number(p["Virtual"])
			reported := number(row.Cells["Offset"]) + number(p["BufferOffset"])
			if a.engine.Env.Architecture == "x64" {
				virtual &= 0x0000ffffffffffff
				reported &= 0x0000ffffffffffff
			}
			if virtual != reported {
				same = false
			}
			if size == 0 {
				return fmt.Errorf("empty source part")
			}
			proofs, e := parts(p["Translation"])
			if e != nil {
				return e
			}
			var proved uint64
			unavailable := false
			for _, proof := range proofs {
				if number(proof["Virtual"]) != number(p["Virtual"])+proved {
					return fmt.Errorf("translation proof has gap or overlap")
				}
				tr, err := native.Translate(a.ctx, number(proof["Virtual"]))
				if _, failed := proof["Error"]; failed && proof["Physical"].Kind == "" {
					if err == nil {
						return fmt.Errorf("unavailable translation became readable")
					}
					if row.Cells["Error"].Error == "" {
						return fmt.Errorf("unavailable proof lacks row failure")
					}
					a.UnavailableProofs++
					unavailable = true
					break
				}
				if err != nil || tr.Physical != number(proof["Physical"]) || tr.EntryAddress != number(proof["EntryAddress"]) || tr.Entry != number(proof["Entry"]) {
					return fmt.Errorf("independent hardware translation differs: %v", err)
				}
				if number(proof["Length"]) == 0 || number(proof["Length"]) > size-proved || number(proof["Length"]) > tr.Available {
					return fmt.Errorf("translation proof extent differs")
				}
				proved += number(proof["Length"])
				delta := number(proof["Virtual"]) - number(p["Virtual"])
				equal := delta <= size && tr.Physical == at+delta
				if truth(proof["MatchesAcquisition"]) != equal {
					return fmt.Errorf("hardware correspondence claim differs")
				}
				if !equal {
					if proof["Error"].Reason != "mapping_translation_disagreement" || row.Cells["Error"].Error == "" {
						return fmt.Errorf("hardware disagreement lacks explicit failure")
					}
					a.Disagreements++
				}
				a.HardwareProofs++
			}
			if proved != size && !unavailable {
				return fmt.Errorf("source lacks complete translation evidence")
			}
			length += size
		}
		sum := sha256.Sum256(matchBytes)
		if length != uint64(len(matchBytes)) || length != number(row.Cells["MatchLength"]) || !bytes.Equal(sum[:], combined.Sum(nil)) || same != truth(source["CoordinatesMatchSource"]) {
			return fmt.Errorf("original match bytes or coordinates differ")
		}
		contextProof, e := structure(row.Cells["Context"])
		if e != nil {
			return e
		}
		buffer, e := raw(contextProof["Raw"])
		if e != nil {
			return e
		}
		start := number(contextProof["Address"])
		contextParts, e := parts(contextProof["Parts"])
		if e != nil {
			return e
		}
		var covered uint64
		for _, p := range contextParts {
			offset := number(p["Virtual"]) - start
			n, requested := uint64(0), uint64(0)
			if _, padded := p["Length"]; padded {
				requested = number(p["Length"])
				if !truth(p["Padded"]) || p["Error"].Kind != "missing" {
					return fmt.Errorf("unmapped context lacks explicit padding provenance")
				}
			} else {
				requested = number(p["Requested"])
				n = number(p["Captured"])
				b, e := raw(p["Raw"])
				if e != nil {
					return e
				}
				actual, e := a.read(number(p["Physical"]), n)
				if e != nil || !bytes.Equal(b, actual) || uint64(len(b)) != n {
					return fmt.Errorf("original context capture differs")
				}
				if offset > uint64(len(buffer)) || n > uint64(len(buffer))-offset || !bytes.Equal(b, buffer[offset:offset+n]) {
					return fmt.Errorf("context capture placement differs")
				}
			}
			if offset != covered || offset > uint64(len(buffer)) || requested > uint64(len(buffer))-offset || n > requested {
				return fmt.Errorf("context part outside buffer")
			}
			if !bytes.Equal(buffer[offset+n:offset+requested], make([]byte, requested-n)) {
				return fmt.Errorf("padded context contains invented bytes")
			}
			covered += requested
			a.ContextParts++
		}
		if covered != uint64(len(buffer)) {
			return fmt.Errorf("context provenance omits bytes")
		}
		a.Matches++
	}
	if value, ok := row.Cells["Raw"]; ok {
		data, e := raw(value)
		if e != nil {
			return e
		}
		at := number(row.Cells["Offset"])
		layer := a.engine.Env.Physical
		if row.Provenance.Layer == a.engine.Env.Kernel.Name() {
			layer = a.engine.Env.Kernel
		} else if row.Provenance.Layer != a.engine.Env.Physical.Name() {
			return fmt.Errorf("unknown captured source layer %s", row.Provenance.Layer)
		}
		actual, e := memory.Read(a.ctx, layer, at, len(data))
		if e != nil || !bytes.Equal(data, actual) || uint64(len(data)) != number(row.Cells["Captured"]) {
			return fmt.Errorf("original raw metadata/table capture differs")
		}
		a.Reads++
	}
	return nil
}
func run() error {
	image := flag.String("image", "", "Original image")
	input := flag.String("rows", "", "Sealed native JSONL")
	dtb := flag.String("dtb", "", "Kernel physical page root")
	arch := flag.String("arch", "x64", "Intel architecture")
	osName := flag.String("os", "linux", "Image OS")
	flag.Parse()
	if *image == "" || *input == "" || *dtb == "" {
		return fmt.Errorf("--image, --rows and --dtb are required")
	}
	directory, e := os.MkdirTemp("", "gomem-regex-audit-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(directory)
	ctx := context.Background()
	eng, e := engine.Open(ctx, engine.Config{Image: *image, CaseDir: directory, DTB: *dtb, Arch: *arch, OS: *osName, Offline: true})
	if e != nil {
		return e
	}
	defer eng.Close()
	file, e := os.Open(*input)
	if e != nil {
		return e
	}
	defer file.Close()
	audit := audit{ctx: ctx, engine: eng, roots: map[string]uint64{}}
	decoder := json.NewDecoder(file)
	for index := 0; ; index++ {
		var row evidence.Row
		e = decoder.Decode(&row)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if e = audit.verify(row); e != nil {
			return fmt.Errorf("row %d (%s): %w", index, row.Cells["RecordType"].String(), e)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(audit)
}
func main() {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintln(os.Stderr, p)
			os.Exit(1)
		}
	}()
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
