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
	Pagefiles                              []string
	CapstoneLibrary                        string
	LeechCore                              memory.LeechCoreOptions
	GCS                                    memory.GCSOptions
	S3                                     memory.S3Options
	VMwareMetadata                         string
	Image, CaseDir, Symbols, OS, Arch, DTB string
	SymbolIndex                            string
	SymbolCache, SymbolServer              string
	KernelBase, KernelSlide                uint64
	Offline                                bool
}
type Engine struct {
	pagefiles             *pagefileInputs
	baseAcquisitionHash   string
	VMwareAcquisition     *memory.VMwareAcquisition
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
	rootFromCrash         bool
}

func Open(ctx context.Context, c Config) (eng *Engine, err error) {
	pagefilePaths, err := parsePagefiles(c.Pagefiles)
	if err != nil {
		return nil, err
	}
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
	snapshotDirectory := ""
	if c.CaseDir != "" {
		snapshotDirectory = filepath.Join(c.CaseDir, "sources")
	}
	src, err := memory.OpenImageSource(ctx, c.Image, memory.ImageSourceOptions{Offline: c.Offline, VMwareMetadata: c.VMwareMetadata, SnapshotDirectory: snapshotDirectory, S3: c.S3, GCS: c.GCS, LeechCore: c.LeechCore})
	if err != nil {
		return nil, err
	}
	var initialStat os.FileInfo
	if file, ok := src.(*memory.FileSource); ok {
		initialStat, err = file.Stat()
		if err != nil {
			src.Close()
			return nil, err
		}
	}
	var st *store.Store
	var pagefiles *pagefileInputs
	defer func() {
		if err != nil {
			pagefiles.close()
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
	rootFromCrash := false
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
			rootFromCrash = true
		}
	}
	if c.Arch != "x64" && c.Arch != "x86" && c.Arch != "pae" && c.Arch != "arm64" {
		return nil, fmt.Errorf("unsupported architecture %q", c.Arch)
	}
	if len(pagefilePaths) != 0 && (c.OS != "windows" || c.Arch == "arm64") {
		return nil, fmt.Errorf("pagefiles currently require Intel Windows; supply --os windows")
	}
	hash, err := Hash(ctx, src)
	if err != nil {
		return nil, err
	}
	if file, ok := src.(*memory.FileSource); ok {
		finalStat, statErr := file.Stat()
		if statErr != nil {
			return nil, statErr
		}
		if initialStat.Size() != finalStat.Size() || !initialStat.ModTime().Equal(finalStat.ModTime()) {
			return nil, fmt.Errorf("image changed while hashing; use an immutable acquisition")
		}
	}
	if snapshot, ok := src.(interface {
		SnapshotInfo() memory.RemoteSnapshotInfo
	}); ok {
		if hash != snapshot.SnapshotInfo().SHA256 {
			return nil, fmt.Errorf("acquired snapshot hash changed before analysis")
		}
	}
	var acquisition *memory.VMwareAcquisition
	if vmware, ok := src.(*memory.VMwareSource); ok {
		var manifest memory.VMwareAcquisition
		hash, manifest, err = vmware.AcquisitionIdentity(ctx, hash)
		if err != nil {
			return nil, err
		}
		acquisition = &manifest
	}
	var inputFiles []os.FileInfo
	baseAcquisitionHash := hash
	if len(pagefilePaths) != 0 {
		pagefiles, err = openPagefiles(ctx, pagefilePaths)
		if err != nil {
			return nil, err
		}
		physical, err = memory.WithPagefiles(physical, pagefiles.layers)
		if err != nil {
			return nil, err
		}
		hash = pagefiles.identity(hash)
		inputFiles = append(inputFiles, pagefiles.info...)
	}
	if initialStat != nil {
		inputFiles = append(inputFiles, initialStat)
	}
	if members, ok := src.(interface{ FileInfos() []os.FileInfo }); ok {
		inputFiles = append(inputFiles, members.FileInfos()...)
	}
	if c.CaseDir != "" {
		for _, name := range []string{"case.db", "case.db-wal", "case.db-shm", "case.db-journal", "case.lock"} {
			info, statErr := os.Stat(filepath.Join(c.CaseDir, name))
			if statErr == nil {
				for _, member := range inputFiles {
					if os.SameFile(member, info) {
						return nil, fmt.Errorf("case database or journal aliases an acquisition member: %s", name)
					}
				}
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
	eng = &Engine{pagefiles: pagefiles, baseAcquisitionHash: baseAcquisitionHash, VMwareAcquisition: acquisition, rootFromCrash: rootFromCrash, CrashHeader: crashHeader, Config: c, Source: src, Format: format, Hash: hash, Store: st, Registry: r}
	eng.Build, err = version.Identity()
	if err != nil {
		return nil, err
	}
	eng.imageInfo = initialStat
	eng.Env = plugin.Environment{Offline: c.Offline, SymbolCache: c.SymbolCache, Physical: physical, OS: c.OS, Architecture: c.Arch, KernelBase: c.KernelBase, KernelSlide: c.KernelSlide, ImageHash: hash}
	eng.Env.PointerMask = enginePointerMask(c.Arch, c.OS)
	if c.Symbols != "" {
		table, e := symbols.LoadContext(ctx, c.Symbols)
		if e != nil {
			return nil, fmt.Errorf("symbols: %w", e)
		}
		if arch := table.Architecture(); arch == "aarch64" || arch == "arm64" || arch == "EM_AARCH64" {
			if autoArch {
				c.Arch = "arm64"
				eng.Config.Arch = c.Arch
				eng.Env.Architecture = c.Arch
			} else if c.Arch != "arm64" {
				return nil, fmt.Errorf("ARM64 symbols disagree with --arch %s", c.Arch)
			}
		}
		if c.Arch == "arm64" {
			if !architectureMatches(table.Architecture(), c.Arch) {
				return nil, fmt.Errorf("symbol architecture %s disagrees with ARM64", table.Architecture())
			}
			if err := table.ValidateARM64(); err != nil {
				return nil, err
			}
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
	kernelOS := eng.Env.OS
	if c.DTB != "" {
		root, e := strconv.ParseUint(c.DTB, 0, 64)
		if e != nil {
			return nil, fmt.Errorf("--dtb: %w", e)
		}
		tr, e := memory.NewTranslatorForOS(physical, root, c.Arch, eng.Env.OS, 1024)
		if e != nil {
			return nil, e
		}
		root = tr.Root()
		eng.Env.Kernel = &memory.Virtual{Physical: physical, Translator: tr, ID: fmt.Sprintf("kernel:%s:dtb=%#x", c.Arch, root)}
		eng.Config.DTB = fmt.Sprintf("0x%x", root)
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
		// An index or automatic PDB acquisition can identify Windows after
		// the bootstrap layer was created. Apply software paging semantics
		// before any plugin receives an object reader.
		if eng.Env.OS == "windows" && kernelOS != "windows" {
			if layer, ok := eng.Env.Kernel.(*memory.Virtual); ok {
				if initial, ok := layer.Translator.(*memory.Intel); ok {
					tr, e := memory.NewIntelForOS(physical, initial.Root(), c.Arch, "windows", 1024)
					if e != nil {
						return nil, e
					}
					layer.Translator = tr
				}
			}
		}
		eng.Env.Objects = &object.Reader{Layer: eng.Env.Kernel, Symbols: eng.Env.Symbols}
		// Symbol/PDB discovery may identify Windows after the bootstrap layer
		// was created. Recompute the native pointer mask from the final OS.
		eng.Env.PointerMask = enginePointerMask(c.Arch, eng.Env.OS)
		if eng.rootFromCrash && eng.Env.OS == "windows" && eng.Config.KernelBase != 0 && eng.WindowsDiscoveryError == nil {
			if e := eng.preferWindowsSystemRoot(ctx); e != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if eng.WindowsDiscovery != nil {
					eng.WindowsDiscovery.SystemRootError = e.Error()
				}
			}
		}
	}
	if err = eng.unchanged(ctx); err != nil {
		return nil, err
	}
	imagePath := src.Name()
	if initialStat != nil {
		imagePath, err = filepath.Abs(c.Image)
		if err != nil {
			return nil, err
		}
	}
	if err = eng.Store.RecordImage(ctx, hash, imagePath, format, src.Size()); err != nil {
		return nil, err
	}
	eng.life, eng.stop = context.WithCancel(ctx)
	eng.Env.SymbolLocation = eng.Config.Symbols
	if eng.Env.OS == "windows" {
		eng.Env.ModulePDB = eng.modulePDBProvider()
	}
	return eng, nil
}

func enginePointerMask(arch, os string) uint64 {
	switch arch {
	case "x86", "pae":
		return 0xffffffff
	case "x64":
		if os == "windows" {
			return 0x0000ffffffffffff
		}
	}
	return ^uint64(0)
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
		e.closeErr = errors.Join(e.Source.Close(), e.pagefiles.close(), e.Store.Close())
	})
	return e.closeErr
}
func (e *Engine) Check(ctx context.Context, s plugin.Spec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.unchanged(ctx); err != nil {
		return err
	}
	if !s.NeedsKernel {
		if s.NeedsTranslation && e.Env.Kernel == nil {
			return fmt.Errorf("%s needs --dtb or a discovered translation layer", s.Name)
		}
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
		if !architectureMatches(arch, e.Config.Arch) {
			return fmt.Errorf("native debug architecture %s has no %s translator", arch, e.Config.Arch)
		}
	}
	if pointer, err := e.Env.Symbols.Type("pointer"); err != nil {
		return err
	} else if pointer.Endian != "" && pointer.Endian != "little" {
		return fmt.Errorf("translation requires little-endian symbols")
	}
	if (e.Config.Arch == "x64" || e.Config.Arch == "arm64") != (ptr == 8) {
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
	if err := e.unchanged(ctx); err != nil {
		return Result{}, err
	}
	return e.run(ctx, name, in, opts, make(map[string]bool))
}

// DeprecatedPluginAliases maps locked upstream class names to implemented commands.
// The requested name remains the cache and provenance identity.
var DeprecatedPluginAliases = map[string]string{
	"linux.check_afinfo.Check_afinfo":              "linux.check_afinfo",
	"linux.check_creds.Check_creds":                "linux.check_creds",
	"linux.check_idt.Check_idt":                    "linux.check_idt",
	"linux.check_modules.Check_modules":            "linux.check_modules",
	"linux.check_syscall.Check_syscall":            "linux.check_syscall",
	"linux.hidden_modules.Hidden_modules":          "linux.hidden_modules",
	"linux.keyboard_notifiers.Keyboard_notifiers":  "linux.keyboard_notifiers",
	"linux.modxview.Modxview":                      "linux.modxview",
	"linux.malfind.Malfind":                        "linux.malfind",
	"linux.netfilter.Netfilter":                    "linux.netfilter",
	"linux.tty_check.tty_check":                    "linux.tty_check",
	"windows.amcache.Amcache":                      "windows.amcache",
	"windows.cachedump.Cachedump":                  "windows.cachedump",
	"windows.drivermodule.DriverModule":            "windows.drivermodule",
	"windows.hashdump.Hashdump":                    "windows.hashdump",
	"windows.hollowprocesses.HollowProcesses":      "windows.hollowprocesses",
	"windows.malfind.Malfind":                      "windows.malfind",
	"windows.ldrmodules.LdrModules":                "windows.ldrmodules",
	"windows.lsadump.Lsadump":                      "windows.lsadump",
	"windows.processghosting.ProcessGhosting":      "windows.processghosting",
	"windows.psxview.PsXView":                      "windows.psxview",
	"windows.scheduled_tasks.ScheduledTasks":       "windows.scheduledtasks",
	"windows.suspicious_threads.SuspiciousThreads": "windows.suspicious_threads",
	"windows.svcdiff.SvcDiff":                      "windows.svcdiff",
}

// ValidateSource checks that the open acquisition still matches its hashed identity.
// It performs no analysis and may issue a conditional read for a remote source.
func (e *Engine) ValidateSource(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.unchanged(ctx)
}

func (e *Engine) unchanged(ctx context.Context) error {
	if err := e.pagefiles.validate(ctx); err != nil {
		return err
	}
	if remote, ok := e.Source.(interface{ Validate(context.Context) error }); ok {
		return remote.Validate(ctx)
	}
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
	requested := name
	if alias, ok := DeprecatedPluginAliases[name]; ok {
		name = alias
	}
	p, err := e.Registry.Get(name)
	if err != nil {
		return result, err
	}
	spec := p.Spec()
	if requested != name {
		spec.Name = requested
	}
	params, err := plugin.Parameters(spec, in)
	if err != nil {
		return result, err
	}
	if err = e.Check(ctx, spec); err != nil {
		return result, err
	}
	inputs, releaseInputs, err := snapshotInputs(ctx, spec, params)
	if err != nil {
		return result, err
	}
	defer releaseInputs()
	for _, dep := range spec.Dependencies {
		if _, err = e.run(ctx, dep, nil, RunOptions{Fresh: opts.Fresh}, stack); err != nil {
			return result, fmt.Errorf("dependency %s: %w", dep, err)
		}
	}
	provenance := evidence.Provenance{ImageSHA256: e.Hash, Engine: version.Version, Plugin: requested, Parameters: make(map[string]string), Layer: e.Env.Physical.Name()}
	provenance.EngineBuild = e.Build
	if e.pagefiles != nil {
		provenance.Parameters["engine.pagefiles.schema"] = "gomem.pagefile-acquisition/v1"
		provenance.Parameters["engine.pagefiles.base-acquisition.sha256"] = e.baseAcquisitionHash
		for _, member := range e.pagefiles.members {
			prefix := fmt.Sprintf("engine.pagefiles.%d.", member.Number)
			provenance.Parameters[prefix+"sha256"] = member.SHA256
			provenance.Parameters[prefix+"size"] = strconv.FormatUint(member.Size, 10)
		}
	}
	if e.VMwareAcquisition != nil {
		members := e.VMwareAcquisition
		provenance.Parameters["engine.acquisition.schema"] = members.Schema
		provenance.Parameters["engine.acquisition.memory.sha256"] = members.MemorySHA256
		provenance.Parameters["engine.acquisition.metadata.sha256"] = members.MetadataSHA256
		provenance.Parameters["engine.acquisition.memory.size"] = strconv.FormatUint(members.MemorySize, 10)
		provenance.Parameters["engine.acquisition.metadata.size"] = strconv.FormatUint(members.MetadataSize, 10)
	}
	if snapshot, ok := e.Source.(interface {
		SnapshotInfo() memory.RemoteSnapshotInfo
	}); ok {
		info := snapshot.SnapshotInfo()
		provenance.Parameters["engine.source.schema"] = info.Schema
		provenance.Parameters["engine.source.protocol"] = info.Protocol
		provenance.Parameters["engine.source.sha256"] = info.SHA256
		provenance.Parameters["engine.source.size"] = strconv.FormatUint(info.Size, 10)
		if info.RemoteSize != nil {
			provenance.Parameters["engine.source.remote.size"] = strconv.FormatUint(*info.RemoteSize, 10)
		}
		if info.RemoteModified != "" {
			provenance.Parameters["engine.source.remote.modified"] = info.RemoteModified
		}
	}
	if object, ok := e.Source.(interface{ CloudObjectInfo() memory.CloudObjectInfo }); ok {
		info := object.CloudObjectInfo()
		provenance.Parameters["engine.source.schema"] = info.Schema
		provenance.Parameters["engine.source.protocol"] = info.Protocol
		provenance.Parameters["engine.source.region"] = info.Region
		provenance.Parameters["engine.source.endpoint"] = info.Endpoint
		provenance.Parameters["engine.source.bucket"] = info.Bucket
		provenance.Parameters["engine.source.key"] = info.Key
		provenance.Parameters["engine.source.version"] = info.Version
		if info.Metageneration != "" {
			provenance.Parameters["engine.source.metageneration"] = info.Metageneration
		}
		provenance.Parameters["engine.source.etag"] = info.ETag
		provenance.Parameters["engine.source.size"] = strconv.FormatUint(info.Size, 10)
	}
	for k, v := range params {
		provenance.Parameters[k] = v
	}
	for key, input := range inputs {
		provenance.Parameters["engine.input."+key+".sha256"] = input.SHA256
		provenance.Parameters["engine.input."+key+".size"] = strconv.FormatInt(input.Size, 10)
	}
	for k, v := range map[string]string{"arch": e.Config.Arch, "dtb": e.Config.DTB, "kernel-base": fmt.Sprintf("%#x", e.Config.KernelBase), "kernel-slide": fmt.Sprintf("%#x", e.Config.KernelSlide), "os": e.Env.OS} {
		provenance.Parameters["engine."+k] = v
	}
	if spec.NeedsKernel || spec.NeedsTranslation {
		provenance.Layer = e.Env.Kernel.Name()
	}
	if e.Env.Symbols != nil {
		provenance.SymbolsSHA256 = e.Env.Symbols.Digest()
	}
	if spec.ExternalSymbols {
		provenance.Parameters["engine.symbols-offline"] = strconv.FormatBool(e.Config.Offline)
		server := sha256.Sum256([]byte(e.Config.SymbolServer))
		provenance.Parameters["engine.symbol-server-sha256"] = hex.EncodeToString(server[:])
		provenance.Parameters["engine.symbol-cache-policy"] = "fresh-runtime-dependencies"
	}
	b, err := json.Marshal(provenance)
	if err != nil {
		return result, err
	}
	keySum := sha256.Sum256(b)
	key := hex.EncodeToString(keySum[:])
	if !opts.Fresh && !spec.ExternalSymbols {
		t, ok, err := e.Store.Cached(ctx, key)
		if err != nil {
			return result, err
		}
		if ok {
			if err = e.Store.VerifyTaskArtifacts(ctx, t.ID); err != nil {
				return Result{t, true}, fmt.Errorf("cached extraction integrity check failed for task %s: %w", t.ID, err)
			}
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
			return result, e.unchanged(ctx)
		}
	}
	task, err := e.Store.Begin(ctx, key, requested, provenance)
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
	env := e.Env
	env.Inputs = inputs
	artifacts := e.Store.TaskArtifacts(task)
	env.Artifacts = artifacts
	// A plugin may set ID to a local token and ParentID to its parent's token.
	// Tokens are not hashed. The sealed parent ID is written before Seal.
	parents := map[string]string{}
	err = p.Run(ctx, env, params, func(row evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, parentToken := row.ID, row.ParentID
		row.ID = ""
		row.ParentID = ""
		if parentToken != "" {
			parent, ok := parents[parentToken]
			if !ok {
				return fmt.Errorf("parent evidence %s has not been emitted", parentToken)
			}
			row.ParentID = parent
		}
		row.Provenance.ImageSHA256 = provenance.ImageSHA256
		row.Provenance.Engine = provenance.Engine
		row.Provenance.EngineBuild = provenance.EngineBuild
		row.Provenance.SymbolsSHA256 = provenance.SymbolsSHA256
		row.Provenance.Plugin = requested
		if requested != name {
			if row.Cells == nil {
				row.Cells = map[string]evidence.Value{}
			}
			row.Cells["RequestedPlugin"] = evidence.Text(requested)
			row.Cells["ImplementedPlugin"] = evidence.Text(name)
		}
		row.Provenance.Parameters = provenance.Parameters
		if row.Provenance.Layer == "" {
			row.Provenance.Layer = provenance.Layer
		}
		row.Seal()
		if token != "" {
			if _, exists := parents[token]; exists {
				return fmt.Errorf("duplicate evidence token %s", token)
			}
			parents[token] = row.ID
		}
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
	err = errors.Join(err, ctx.Err(), e.unchanged(ctx))
	// Commit partial evidence and terminal state even after user cancellation.
	// Slow case storage (notably Windows with filesystem scanning) must not
	// exhaust a tiny shared deadline before the terminal-state write starts.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	err = errors.Join(err, artifacts.Finalize(cleanup))
	err = errors.Join(err, flush(cleanup))
	state := "completed"
	if err != nil {
		state = "failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			state = "canceled"
		}
	}
	finishContext, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer finishCancel()
	if finishErr := e.Store.Finish(finishContext, task.ID, state, err); finishErr != nil {
		err = errors.Join(err, fmt.Errorf("persist terminal task state: %w", finishErr))
		// A failed terminal write is not a successfully completed task, even
		// if the plugin and evidence flush themselves succeeded.
		state = "failed"
	}
	result.Task.State = state
	result.Task.Rows = count
	finished := time.Now().UTC()
	result.Task.Finished = &finished
	if err != nil {
		result.Task.Error = err.Error()
	}
	return result, err
}
