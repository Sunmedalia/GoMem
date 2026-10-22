package wingui

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// SessionReader discovers the first process address space for each session.
// Kernel and Physical may be recording wrappers; the resulting process layers
// read page tables and data through the supplied physical layer as well.
type SessionReader struct {
	Kernel     *object.Reader
	Physical   memory.MemoryLayer
	KernelBase uint64
}
type SessionOptions struct {
	MaxProcesses, MaxSessions uint64
	PIDs                      []uint64
}
type SessionSpace struct {
	SessionID, Process, PID, SessionPointer uint64
	RawCR3, CR3                             uint64
	Method                                  string
	Layer                                   memory.MemoryLayer
}
type sessionFailures struct {
	count uint64
	first error
}

func (f *sessionFailures) add(err error) {
	if err != nil {
		f.count++
		if f.first == nil {
			f.first = err
		}
	}
}
func (f sessionFailures) err() error {
	if f.count == 0 {
		return nil
	}
	return fmt.Errorf("GUI session acquisition: %d failures; first: %w", f.count, f.first)
}

// Visit retains process order from the pinned PsList's forward then backward
// passes, globally deduplicates object addresses, and keeps the first layer per
// session. Session IDs are read in the kernel layer, even though the original
// source's comment says process layer. Image names and timestamps are not read.
func (r SessionReader) Visit(ctx context.Context, options SessionOptions, emit func(SessionSpace) error) error {
	if options.MaxProcesses == 0 || options.MaxProcesses > 1000000 || options.MaxSessions == 0 || options.MaxSessions > 1000000 || emit == nil {
		return fmt.Errorf("GUI session discovery requires emitter and bounds 1..1000000")
	}
	if r.Kernel == nil || r.Kernel.Layer == nil || r.Kernel.Symbols == nil || r.Physical == nil || r.KernelBase == 0 || r.Kernel.Symbols.PointerSize() != 8 {
		return fmt.Errorf("GUI sessions require x64 kernel symbols, base, kernel layer and physical memory")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var failures sessionFailures
	seenSessions := map[uint64]bool{}
	pids := map[uint64]bool{}
	for _, pid := range options.PIDs {
		pids[pid] = true
	}
	err := r.processes(ctx, options.MaxProcesses, &failures, func(process uint64) error {
		pid, err, fatal := r.field(ctx, process, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			if fatal {
				return err
			}
			failures.add(err)
			return ctx.Err()
		}
		if len(pids) > 0 && !pids[pid] {
			return nil
		}
		candidate, err, fatal := r.space(ctx, process, pid)
		if err != nil {
			if fatal {
				return err
			}
			failures.add(err)
			return ctx.Err()
		}
		if seenSessions[candidate.SessionID] {
			return nil
		}
		if uint64(len(seenSessions)) >= options.MaxSessions {
			return fmt.Errorf("GUI session bound exhausted")
		}
		seenSessions[candidate.SessionID] = true
		return emit(candidate)
	})
	return errors.Join(failures.err(), err, ctx.Err())
}

// field distinguishes symbol/schema errors (not swallowed by the original)
// from per-process memory failures, after which later processes may be useful.
func (r SessionReader) field(ctx context.Context, at uint64, typ, name string) (uint64, error, bool) {
	field, err := r.Kernel.Field(typ, name)
	if err != nil {
		return 0, err, true
	}
	address, err := memory.Add(at, field.Offset)
	if err != nil {
		return 0, err, false
	}
	value, err := r.Kernel.Scalar(ctx, address, field.Type)
	return value, err, false
}
func (r SessionReader) space(ctx context.Context, process, pid uint64) (SessionSpace, error, bool) {
	result := SessionSpace{Process: process, PID: pid}
	f, err := r.Kernel.Field("_EPROCESS", "Pcb.DirectoryTableBase")
	if err != nil {
		return result, err, true
	}
	address, err := memory.Add(process, f.Offset)
	if err != nil {
		return result, err, false
	}
	if f.Type.Kind == "array" {
		// EPROCESS.add_process_layer casts the array to unsigned long long;
		// reading its first element loses the high half of a u32[2] CR3.
		raw, readErr := memory.Read(ctx, r.Kernel.Layer, address, 8)
		if readErr != nil {
			return result, readErr, false
		}
		result.RawCR3 = binary.LittleEndian.Uint64(raw)
	} else {
		result.RawCR3, err = r.Kernel.Scalar(ctx, address, f.Type)
		if err != nil {
			return result, err, false
		}
	}
	translator, err := memory.NewIntelForOS(r.Physical, result.RawCR3, "x64", "windows", 1024)
	if err != nil {
		return result, err, true
	}
	result.CR3 = translator.Root()
	// Constructing a layer does not establish that its root or session pages
	// are readable. Do not silently substitute the kernel CR3, even for zero.
	result.Layer = &memory.Virtual{Physical: r.Physical, Translator: translator, ID: fmt.Sprintf("gui-session:%s:0x%x:%d", r.Kernel.Layer.Name(), process, pid)}
	var fatal bool
	result.SessionPointer, err, fatal = r.field(ctx, process, "_EPROCESS", "Session")
	if err != nil {
		return result, err, fatal
	}
	if _, typeErr := r.Kernel.Symbols.Type("_MM_SESSION_SPACE"); typeErr == nil {
		result.Method = "typed"
		var fatal bool
		result.SessionID, err, fatal = r.field(ctx, result.SessionPointer, "_MM_SESSION_SPACE", "SessionId")
		return result, err, fatal
	}
	// The pinned Windows 11 opaque-type fallback is only for a missing type.
	// A present _MM_SESSION_SPACE with no SessionId raises AttributeError;
	// that must not be mistaken for permission to guess a member offset.
	result.Method = "opaque-offset-8"
	address, err = memory.Add(result.SessionPointer, 8)
	if err != nil {
		return result, err, false
	}
	base, err := r.Kernel.Symbols.Type("unsigned long")
	if err != nil || base.Kind != "int" || base.Size != 4 || base.Signed || base.Endian != "little" {
		return result, fmt.Errorf("opaque GUI session fallback requires unsigned little-endian 32-bit unsigned long"), true
	}
	result.SessionID, err = r.Kernel.Scalar(ctx, address, symbols.TypeRef{Kind: "base", Name: "unsigned long"})
	return result, err, false
}

func (r SessionReader) processes(ctx context.Context, max uint64, failures *sessionFailures, emit func(uint64) error) error {
	symbol, err := r.Kernel.Symbols.Lookup("PsActiveProcessHead")
	if err != nil {
		return err
	}
	head, err := memory.Add(r.KernelBase, symbol.Address)
	if err != nil {
		return err
	}
	link, err := r.Kernel.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	size, err := r.Kernel.Size(symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"})
	if err != nil || size != 16 {
		return fmt.Errorf("GUI sessions require x64 kernel LIST_ENTRY")
	}
	global := map[uint64]bool{}
	for _, direction := range []string{"Flink", "Blink"} {
		if _, err := memory.Read(ctx, r.Kernel.Layer, head, 1); err != nil {
			return err
		}
		seen := map[uint64]bool{head: true}
		current := head
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			next, err := r.Kernel.Uint(ctx, current, "_LIST_ENTRY", direction)
			// A pointer-value read exception escapes the original iterator;
			// an unreadable pointer target ends only that directional walk.
			if err != nil {
				return err
			}
			if next == 0 {
				failures.add(fmt.Errorf("null GUI process %s at 0x%x", direction, current))
				break
			}
			if _, err := memory.Read(ctx, r.Kernel.Layer, next, 16); err != nil {
				failures.add(err)
				break
			}
			if seen[next] {
				if next != head {
					failures.add(fmt.Errorf("GUI process %s cycle at 0x%x", direction, next))
				}
				break
			}
			if uint64(len(seen)-1) >= max {
				return fmt.Errorf("GUI process directional bound exhausted")
			}
			if next < link.Offset {
				failures.add(fmt.Errorf("GUI process container underflow"))
				break
			}
			process := next - link.Offset
			if _, err := memory.Read(ctx, r.Kernel.Layer, process, 1); err != nil {
				failures.add(err)
				break
			}
			seen[next] = true
			current = next
			if global[process] {
				continue
			}
			if uint64(len(global)) >= max {
				return fmt.Errorf("GUI process bound exhausted")
			}
			global[process] = true
			if err := emit(process); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
