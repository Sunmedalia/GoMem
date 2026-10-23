package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type pagefileMember struct {
	Number uint8  `json:"number"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}
type pagefileInputs struct {
	files     []*memory.FileSource
	info      []os.FileInfo
	layers    map[uint8]memory.MemoryLayer
	members   []pagefileMember
	closeOnce sync.Once
	closeErr  error
}

// Validate on each external byte read as well as task boundaries. Shell hex and
// object inspection do not necessarily create a task, so task checks alone
// would allow them to expose changed pagefile bytes under an old identity.
type capturedPagefile struct {
	*memory.FileSource
	info   os.FileInfo
	number uint8
}

func (f *capturedPagefile) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != f.info.Size() || !info.ModTime().Equal(f.info.ModTime()) {
		return fmt.Errorf("pagefile %d changed since hashing; results cannot be reused", f.number)
	}
	return nil
}
func (f *capturedPagefile) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	if err := f.validate(ctx); err != nil {
		return 0, err
	}
	n, err := f.FileSource.ReadAt(ctx, p, offset)
	if err != nil {
		return n, err
	}
	return n, f.validate(ctx)
}

func parsePagefiles(values []string) (map[uint8]string, error) {
	if len(values) > 16 {
		return nil, fmt.Errorf("at most 16 pagefiles can be supplied")
	}
	paths := make(map[uint8]string, len(values))
	for _, value := range values {
		number, path, ok := strings.Cut(value, "=")
		n, err := strconv.ParseUint(number, 10, 4)
		if !ok || err != nil || path == "" {
			return nil, fmt.Errorf("pagefile requires NUMBER=LOCAL_PATH with NUMBER 0..15")
		}
		if _, exists := paths[uint8(n)]; exists {
			return nil, fmt.Errorf("duplicate pagefile number %d", n)
		}
		paths[uint8(n)] = path
	}
	return paths, nil
}

func openPagefiles(ctx context.Context, paths map[uint8]string) (inputs *pagefileInputs, err error) {
	inputs = &pagefileInputs{layers: make(map[uint8]memory.MemoryLayer)}
	defer func() {
		if err != nil {
			inputs.close()
		}
	}()
	for number := uint8(0); number < 16; number++ {
		path, ok := paths[number]
		if !ok {
			continue
		}
		file, e := memory.OpenFile(path)
		if e != nil {
			return inputs, fmt.Errorf("open pagefile %d: %w", number, e)
		}
		inputs.files = append(inputs.files, file)
		info, e := file.Stat()
		if e != nil {
			return inputs, e
		}
		if info.Size() < 0 || uint64(info.Size()) != file.Size() {
			return inputs, fmt.Errorf("pagefile %d changed while opening", number)
		}
		inputs.info = append(inputs.info, info)
		digest, e := Hash(ctx, file)
		if e != nil {
			return inputs, fmt.Errorf("hash pagefile %d: %w", number, e)
		}
		capture := &capturedPagefile{FileSource: file, info: info, number: number}
		layer, e := memory.NewMapped(capture, fmt.Sprintf("pagefile:%d", number), []memory.Range{{Length: file.Size()}})
		if e != nil {
			return inputs, e
		}
		inputs.layers[number] = layer
		inputs.members = append(inputs.members, pagefileMember{Number: number, Size: file.Size(), SHA256: digest})
	}
	return inputs, inputs.validate(ctx)
}

func (p *pagefileInputs) close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		var errs []error
		for _, file := range p.files {
			errs = append(errs, file.Close())
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}
func (p *pagefileInputs) validate(ctx context.Context) error {
	if p == nil {
		return nil
	}
	for n, file := range p.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Size() != p.info[n].Size() || !info.ModTime().Equal(p.info[n].ModTime()) {
			return fmt.Errorf("pagefile %d changed since hashing; results cannot be reused", p.members[n].Number)
		}
	}
	return nil
}
func (p *pagefileInputs) identity(base string) string {
	if p == nil || len(p.members) == 0 {
		return base
	}
	manifest := struct {
		Schema  string           `json:"schema"`
		Base    string           `json:"base_sha256"`
		Members []pagefileMember `json:"pagefiles"`
	}{"gomem.pagefile-acquisition/v1", base, p.members}
	b, _ := json.Marshal(manifest)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
