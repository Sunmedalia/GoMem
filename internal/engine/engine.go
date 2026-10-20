package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Sunmedalia/GoMem/internal/plugins"
	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Config struct {
	Image, CaseDir, Symbols, OS, Arch, DTB string
	SymbolIndex                            string
	SymbolCache, SymbolServer              string
	KernelBase, KernelSlide                uint64
	Offline                                bool
}
type Engine struct {
	Config                Config
	Source                memory.MemorySource
	Format                string
	Hash                  string
	Build                 string
	Env                   plugin.Environment
	Store                 *store.Store
	Registry              *plugin.Registry
	CrashHeader           *memory.CrashHeader
	WindowsDiscovery      *WindowsDiscovery
	WindowsDiscoveryError error
	Discovery             *LinuxDiscovery
	SymbolResolution      *symbols.PDBResolution
	mu                    sync.Mutex
	closing               bool
	wg                    sync.WaitGroup
	stop                  context.CancelFunc
	life                  context.Context
	closeOnce             sync.Once
	closeErr              error
	imageInfo             os.FileInfo
}

func Open(ctx context.Context, c Config) (eng *Engine, err error) {
	if c.Image == "" {
		return nil, fmt.Errorf("--image is required")
	}
	autoArch := c.Arch == "" || c.Arch == "auto"
	if autoArch {
		c.Arch = "x64"
	}
	if c.OS != "" && c.OS != "linux" && c.OS != "windows" && c.OS != "mac" {
		return nil, fmt.Errorf("--os must be linux, windows or mac")
	}
	src, err := memory.OpenFile(c.Image)
	if err != nil {
		return nil, err
	}
	initialStat, err := src.Stat()
	if err != nil {
		src.Close()
		return nil, err
	}
	var st *store.Store
	defer func() {
		if err != nil {
			src.Close()
			if st != nil {
				st.Close()
			}
		}
	}()
	physical, format, err := memory.Detect(ctx, src)
	if err != nil {
		return nil, err
	}
	var crashHeader *memory.CrashHeader
	if layer, ok := physical.(interface{ CrashHeader() memory.CrashHeader }); ok {
		header := layer.CrashHeader()
		crashHeader = &header
		if autoArch && header.Architecture != "" {
			c.Arch = header.Architecture
		}
		if c.OS == "" {
			c.OS = "windows"
		}
		if c.DTB == "" && c.OS == "windows" && header.Architecture != "" && header.DirectoryTableBase != 0 {
			c.DTB = fmt.Sprintf("0x%x", header.DirectoryTableBase)
		}
	}
	if c.Arch != "x64" && c.Arch != "x86" && c.Arch != "pae" {
		return nil, fmt.Errorf("unsupported architecture %q", c.Arch)
	}
	hash, err := Hash(ctx, src)
	if err != nil {
		return nil, err
	}
	finalStat, err := src.Stat()
	if err != nil {
		return nil, err
	}
	if initialStat.Size() != finalStat.Size() || !initialStat.ModTime().Equal(finalStat.ModTime()) {
		return nil, fmt.Errorf("image changed while hashing; use an immutable acquisition")
	}
	if c.CaseDir != "" {
		for _, name := range []string{"case.db", "case.db-wal", "case.db-shm", "case.db-journal", "case.lock"} {
			info, statErr := os.Stat(filepath.Join(c.CaseDir, name))
			if statErr == nil && os.SameFile(initialStat, info) {
				return nil, fmt.Errorf("case database or journal aliases the input image: %s", name)
			}
			if statErr != nil && !os.IsNotExist(statErr) {
				return nil, statErr
			}
		}
	}
	st, err = store.Open(c.CaseDir)
	if err != nil {
		return nil, err
	}
	r := plugin.NewRegistry()
	if err = plugins.Register(r); err != nil {
		return nil, err
	}
	eng = &Engine{CrashHeader: crashHeader, Config: c, Source: src, Format: format, Hash: hash, Store: st, Registry: r}
	eng.Build, err = version.Identity()
	if err != nil {
		return nil, err
	}
	eng.imageInfo = initialStat
	eng.Env = plugin.Environment{Physical: physical, OS: c.OS, KernelBase: c.KernelBase, KernelSlide: c.KernelSlide, ImageHash: hash}
	if c.DTB != "" {
		root, e := strconv.ParseUint(c.DTB, 0, 64)
		if e != nil {
			return nil, fmt.Errorf("--dtb: %w", e)
		}
		tr, e := memory.NewIntel(physical, root, c.Arch, 1024)
		if e != nil {
			return nil, e
		}
		root = tr.Root()
		eng.Env.Kernel = &memory.Virtual{Physical: physical, Translator: tr, ID: fmt.Sprintf("kernel:%s:dtb=%#x", c.Arch, root)}
		eng.Config.DTB = fmt.Sprintf("0x%x", root)
	}
	if c.Symbols != "" {
		table, e := symbols.LoadContext(ctx, c.Symbols)
		if e != nil {
			return nil, fmt.Errorf("symbols: %w", e)
		}
		eng.Env.Symbols = table
		if eng.Env.OS == "" {
			if _, ok := table.Meta["windows"]; ok {
				eng.Env.OS = "windows"
			} else if _, ok := table.Meta["linux"]; ok {
				eng.Env.OS = "linux"
			} else if _, ok := table.Meta["mac"]; ok {
				eng.Env.OS = "mac"
			}
		}
	}
	if crashHeader != nil && eng.Env.OS == "windows" && eng.Config.KernelBase == 0 {
		if eng.Env.Kernel == nil {
			eng.WindowsDiscoveryError = fmt.Errorf("crash header does not provide a supported, nonzero page-table root; provide --arch and --dtb")
		} else {
			eng.WindowsDiscoveryError = eng.discoverWindows(ctx, *crashHeader)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	c = eng.Config
	if c.Symbols == "" && eng.WindowsDiscoveryError == nil {
		indexPath := c.SymbolIndex
		if indexPath == "" && c.CaseDir != "" && c.DTB != "" {
			candidate := filepath.Join(c.CaseDir, "symbols", "index.json")
			if _, statErr := os.Stat(candidate); statErr == nil {
				indexPath = candidate
			} else if !os.IsNotExist(statErr) {
				return nil, statErr
			}
		}
		if indexPath != "" {
			table, selected, e := eng.selectSymbols(ctx, indexPath)
			if e != nil {
				if c.SymbolIndex != "" || !errors.Is(e, ErrNoMatchingSymbols) || eng.Env.Kernel == nil || c.KernelBase == 0 || c.OS != "" && c.OS != "windows" {
					return nil, e
				}
			} else {
				eng.Env.Symbols, eng.Env.OS = table, selected.OS
				eng.Config.SymbolIndex, eng.Config.Symbols = indexPath, selected.Location
			}
		}
	}
	if eng.Env.Kernel == nil && eng.Env.Symbols != nil {
		kernel, proof, discoverErr := eng.discoverLinux(ctx)
		if discoverErr != nil {
			return nil, discoverErr
		}
		if proof != nil {
			eng.Env.Kernel, eng.Discovery, eng.Config.DTB = kernel, proof, proof.DTB
		}
	}
	if eng.Env.Symbols == nil && eng.Env.Kernel != nil && c.KernelBase != 0 && (c.OS == "" || c.OS == "windows") {
		identity, e := readKernelPDB(ctx, eng.Env.Kernel, c.KernelBase)
		if e != nil {
			return nil, fmt.Errorf("read Windows kernel identity for symbol acquisition: %w", e)
		}
		table, resolution, e := eng.resolveWindowsIdentity(ctx, identity)
		if e != nil {
			return nil, fmt.Errorf("Windows symbols: %w", e)
		}
		eng.Env.Symbols, eng.Env.OS = table, "windows"
		eng.Config.Symbols = resolution.TablePath
		eng.SymbolResolution = resolution
	}
	if eng.Env.Kernel != nil && eng.Env.Symbols != nil {
		eng.Env.Objects = &object.Reader{Layer: eng.Env.Kernel, Symbols: eng.Env.Symbols}
	}
	if err = eng.unchanged(); err != nil {
		return nil, err
	}
	imagePath, err := filepath.Abs(c.Image)
	if err != nil {
		return nil, err
	}
	if err = eng.Store.RecordImage(ctx, hash, imagePath, format, src.Size()); err != nil {
		return nil, err
	}
	eng.life, eng.stop = context.WithCancel(ctx)
	return eng, nil
}
func Hash(ctx context.Context, s memory.MemorySource) (string, error) {
	h := sha256.New()
	b := make([]byte, 4<<20)
	for off := uint64(0); off < s.Size(); {
		n := int(min(uint64(len(b)), s.Size()-off))
		got, e := s.ReadAt(ctx, b[:n], off)
		if e != nil {
			return "", e
		}
		if got != n {
			return "", io.ErrUnexpectedEOF
		}
		h.Write(b[:n])
		off += uint64(n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closing = true
		e.stop()
		e.mu.Unlock()
		e.wg.Wait()
		e.closeErr = errors.Join(e.Source.Close(), e.Store.Close())
	})
	return e.closeErr
}
func (e *Engine) Check(ctx context.Context, s plugin.Spec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.unchanged(); err != nil {
		return err
	}
	if !s.NeedsKernel {
		return nil
	}
	if e.WindowsDiscoveryError != nil {
		return fmt.Errorf("Windows automatic configuration: %w", e.WindowsDiscoveryError)
	}
	if e.Env.Symbols == nil {
		mode := "supply matching --symbols/local index; Windows crash discovery can also use verified PDB sources"
		if e.Config.Offline {
			mode = "offline mode"
		}
		return fmt.Errorf("%s needs --symbols with an exact matching ISF (%s)", s.Name, mode)
	}
	if e.Env.Kernel == nil {
		return fmt.Errorf("%s needs --dtb (physical page-table root)", s.Name)
	}
	if s.Platform != e.Env.OS {
		return fmt.Errorf("%s needs %s symbols, selected OS is %q", s.Name, s.Platform, e.Env.OS)
	}
	ptr := e.Env.Symbols.PointerSize()
	if native, ok := e.Env.Symbols.(interface{ Architecture() string }); ok {
		arch := native.Architecture()
		if arch != "" && arch != "EM_X86_64" && arch != "EM_386" && arch != "x86_64" && arch != "i386" {
			return fmt.Errorf("native debug architecture %s has no %s translator", arch, e.Config.Arch)
		}
	}
	if pointer, err := e.Env.Symbols.Type("pointer"); err != nil {
		return err
	} else if pointer.Endian != "" && pointer.Endian != "little" {
		return fmt.Errorf("Intel translation requires little-endian symbols")
	}
	if (e.Config.Arch == "x64") != (ptr == 8) {
		return fmt.Errorf("architecture and symbol pointer size disagree")
	}
	return e.verifySymbols(ctx)
}

type RunOptions struct {
	Fresh   bool
	Emit    plugin.Emit
	OnStart func(evidence.Task)
}
type Result struct {
	Task   evidence.Task
	Reused bool
}

func (e *Engine) Run(ctx context.Context, name string, in map[string]string, opts RunOptions) (Result, error) {
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return Result{}, fmt.Errorf("engine is closed")
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.life, cancel)
	defer stop()
	defer cancel()
	if err := e.unchanged(); err != nil {
		return Result{}, err
	}
	return e.run(ctx, name, in, opts, make(map[string]bool))
}
func (e *Engine) unchanged() error {
	f, ok := e.Source.(*memory.FileSource)
	if !ok {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != e.imageInfo.Size() || !info.ModTime().Equal(e.imageInfo.ModTime()) {
		return fmt.Errorf("image changed since hashing; results cannot be reused")
	}
	return nil
}
func (e *Engine) run(ctx context.Context, name string, in map[string]string, opts RunOptions, stack map[string]bool) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if stack[name] {
		return result, fmt.Errorf("plugin dependency cycle at %s", name)
	}
	stack[name] = true
	defer delete(stack, name)
	p, err := e.Registry.Get(name)
	if err != nil {
		return result, err
	}
	spec := p.Spec()
	params, err := plugin.Parameters(spec, in)
	if err != nil {
		return result, err
	}
	if err = e.Check(ctx, spec); err != nil {
		return result, err
	}
	for _, dep := range spec.Dependencies {
		if _, err = e.run(ctx, dep, nil, RunOptions{Fresh: opts.Fresh}, stack); err != nil {
			return result, fmt.Errorf("dependency %s: %w", dep, err)
		}
	}
	provenance := evidence.Provenance{ImageSHA256: e.Hash, Engine: version.Version, Plugin: name, Parameters: make(map[string]string), Layer: e.Env.Physical.Name()}
	provenance.EngineBuild = e.Build
	for k, v := range params {
		provenance.Parameters[k] = v
	}
	for k, v := range map[string]string{"arch": e.Config.Arch, "dtb": e.Config.DTB, "kernel-base": fmt.Sprintf("%#x", e.Config.KernelBase), "kernel-slide": fmt.Sprintf("%#x", e.Config.KernelSlide), "os": e.Env.OS} {
		provenance.Parameters["engine."+k] = v
	}
	if spec.NeedsKernel {
		provenance.Layer = e.Env.Kernel.Name()
	}
	if e.Env.Symbols != nil {
		provenance.SymbolsSHA256 = e.Env.Symbols.Digest()
	}
	b, err := json.Marshal(provenance)
	if err != nil {
		return result, err
	}
	keySum := sha256.Sum256(b)
	key := hex.EncodeToString(keySum[:])
	if !opts.Fresh {
		t, ok, err := e.Store.Cached(ctx, key)
		if err != nil {
			return result, err
		}
		if ok {
			result = Result{t, true}
			if opts.OnStart != nil {
				opts.OnStart(t)
			}
			if opts.Emit != nil {
				for off := 0; ; off += 1000 {
					rows, err := e.Store.Query(ctx, evidence.Query{TaskID: t.ID, Offset: off, Limit: 1000})
					if err != nil {
						return result, err
					}
					for _, r := range rows {
						if err = opts.Emit(r); err != nil {
							return result, err
						}
					}
					if len(rows) < 1000 {
						break
					}
				}
			}
			return result, nil
		}
	}
	task, err := e.Store.Begin(ctx, key, name, provenance)
	if err != nil {
		return result, err
	}
	result.Task = task
	if opts.OnStart != nil {
		opts.OnStart(task)
	}
	batch := make([]evidence.Row, 0, 128)
	var count int64
	flush := func(c context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		if err := e.Store.Append(c, task.ID, batch); err != nil {
			return err
		}
		count += int64(len(batch))
		batch = batch[:0]
		return nil
	}
	err = p.Run(ctx, e.Env, params, func(row evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		row.Provenance.ImageSHA256 = provenance.ImageSHA256
		row.Provenance.Engine = provenance.Engine
		row.Provenance.EngineBuild = provenance.EngineBuild
		row.Provenance.SymbolsSHA256 = provenance.SymbolsSHA256
		row.Provenance.Plugin = name
		row.Provenance.Parameters = provenance.Parameters
		if row.Provenance.Layer == "" {
			row.Provenance.Layer = provenance.Layer
		}
		row.Seal()
		batch = append(batch, row)
		if len(batch) == cap(batch) {
			if err := flush(ctx); err != nil {
				return err
			}
		}
		if opts.Emit != nil {
			return opts.Emit(row)
		}
		return nil
	})
	err = errors.Join(err, ctx.Err(), e.unchanged())
	// Commit partial evidence and terminal state even after user cancellation.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err = errors.Join(err, flush(cleanup))
	state := "completed"
	if err != nil {
		state = "failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			state = "canceled"
		}
	}
	err = errors.Join(err, e.Store.Finish(cleanup, task.ID, state, err))
	result.Task.State = state
	result.Task.Rows = count
	finished := time.Now().UTC()
	result.Task.Finished = &finished
	if err != nil {
		result.Task.Error = err.Error()
	}
	return result, err
}
