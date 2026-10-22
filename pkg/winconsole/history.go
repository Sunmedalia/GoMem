// Package winconsole reads conhost command structures using explicit symbol layouts.
// It does not discover processes or infer a conhost version from kernel symbols.
package winconsole

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Reader struct{ Objects *object.Reader }

type Command struct {
	Address, Length, Allocated uint64
}

func (c Command) Valid() bool {
	return c.Length >= 1 && c.Length <= 1024 && c.Allocated >= 1 && c.Allocated <= 1024
}

func (r Reader) Command(ctx context.Context, at uint64) (Command, error) {
	c := Command{Address: at}
	var err error
	c.Length, err = r.Objects.Uint(ctx, at, "_COMMAND", "Length")
	if err != nil {
		return c, err
	}
	c.Allocated, err = r.Objects.Uint(ctx, at, "_COMMAND", "Allocated")
	return c, err
}

// ValidCommand preserves the extension's short circuit: an empty command does
// not require readable allocation metadata. Command itself reads both fields.
func (r Reader) ValidCommand(ctx context.Context, at uint64) (bool, error) {
	n, err := r.Objects.Uint(ctx, at, "_COMMAND", "Length")
	if err != nil || n == 0 {
		return false, err
	}
	a, err := r.Objects.Uint(ctx, at, "_COMMAND", "Allocated")
	if err != nil {
		return false, err
	}
	return (Command{Length: n, Allocated: a}).Valid(), nil
}

// Text preserves the original bytes. A nil string with no error is the pinned
// extension's None result for Length >= 1024, including valid Length == 1024.
// Text deliberately does not require Command.Valid, matching direct method calls.
func (r Reader) Text(ctx context.Context, at uint64) (*string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	n, err := r.Objects.Uint(ctx, at, "_COMMAND", "Length")
	if err != nil {
		return nil, nil, err
	}
	if n >= 1024 {
		return nil, nil, nil
	}
	var address uint64
	if n < 8 {
		f, err := r.Objects.Field("_COMMAND", "Chars")
		if err != nil {
			return nil, nil, err
		}
		address, err = memory.Add(at, f.Offset)
		if err != nil {
			return nil, nil, err
		}
	} else {
		address, err = r.Objects.Uint(ctx, at, "_COMMAND", "Pointer")
		if err != nil {
			return nil, nil, err
		}
	}
	raw, err := memory.Read(ctx, r.Objects.Layer, address, int(n*2))
	if err != nil {
		return nil, raw, err
	}
	// Python's utf-16 codec consumes an optional BOM and otherwise uses the
	// native little endian order on the Windows baseline's supported hosts.
	var order binary.ByteOrder = binary.LittleEndian
	data := raw
	if len(data) >= 2 {
		if data[0] == 0xff && data[1] == 0xfe {
			data = data[2:]
		} else if data[0] == 0xfe && data[1] == 0xff {
			order = binary.BigEndian
			data = data[2:]
		}
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = order.Uint16(data[i*2:])
	}
	text := string(utf16.Decode(units))
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	return &text, raw, nil
}

type History struct {
	Address, Begin, End, Capacity, Maximum, Handle uint64
	Count, LastDisplayed                           int64
}

func (h History) Valid(maxHistory int64) bool {
	return h.Count >= 0 && h.Count <= maxHistory && h.LastDisplayed >= -1 && h.LastDisplayed <= maxHistory && h.Handle > 0 && h.Handle <= 0xffff && h.Handle%4 == 0
}

func (r Reader) commandSize() (uint64, error) {
	n, err := r.Objects.Size(symbols.TypeRef{Kind: "struct", Name: "_COMMAND"})
	if err == nil && (n == 0 || n > memory.MaxRead) {
		err = fmt.Errorf("invalid command size %d", n)
	}
	return n, err
}

func commandCount(begin, end, size uint64) (int64, error) {
	delta, sign := end-begin, float64(1)
	if end < begin {
		delta, sign = begin-end, -1
	}
	count := sign * (float64(delta) / float64(size))
	if count >= math.Exp2(63) || count < -math.Exp2(63) {
		return 0, fmt.Errorf("command count overflows int64")
	}
	return int64(count), nil
}

func (r Reader) CommandCount(ctx context.Context, at uint64) (int64, error) {
	begin, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "CommandBucket.Begin")
	if err != nil {
		return 0, err
	}
	end, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "CommandBucket.End")
	if err != nil {
		return 0, err
	}
	n, err := r.commandSize()
	if err != nil {
		return 0, err
	}
	return commandCount(begin, end, n)
}

func (r Reader) ProcessHandle(ctx context.Context, at uint64) (uint64, error) {
	p, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", "ConsoleProcessHandle")
	if err != nil {
		return 0, err
	}
	return r.Objects.Uint(ctx, p, "_CONSOLE_PROCESS_HANDLE", "ProcessHandle")
}

// ValidHistory does not read unused capacity or application metadata, and
// preserves validation short circuits before dereferencing the process handle.
func (r Reader) ValidHistory(ctx context.Context, at uint64, maxHistory int64) (bool, error) {
	count, err := r.CommandCount(ctx, at)
	if err != nil || count < 0 || count > maxHistory {
		return false, err
	}
	last, err := r.Objects.Int(ctx, at, "_COMMAND_HISTORY", "LastDisplayed")
	if err != nil || last < -1 || last > maxHistory {
		return false, err
	}
	handle, err := r.ProcessHandle(ctx, at)
	if err != nil {
		return false, err
	}
	return (History{Count: count, LastDisplayed: last, Handle: handle}).Valid(maxHistory), nil
}

func (r Reader) History(ctx context.Context, at uint64) (History, error) {
	h := History{Address: at}
	for _, f := range []struct {
		name string
		out  *uint64
	}{
		{"CommandBucket.Begin", &h.Begin}, {"CommandBucket.End", &h.End}, {"CommandBucket.EndCapacity", &h.Capacity}, {"CommandCountMax", &h.Maximum},
	} {
		v, err := r.Objects.Uint(ctx, at, "_COMMAND_HISTORY", f.name)
		if err != nil {
			return h, err
		}
		*f.out = v
	}
	n, err := r.commandSize()
	if err != nil {
		return h, err
	}
	// Preserve int((End-Begin)/size), including truncation toward zero for
	// reversed, unaligned intervals. Do not subtract unsigned pointers first.
	h.Count, err = commandCount(h.Begin, h.End, n)
	if err != nil {
		return h, err
	}
	h.LastDisplayed, err = r.Objects.Int(ctx, at, "_COMMAND_HISTORY", "LastDisplayed")
	if err != nil {
		return h, err
	}
	h.Handle, err = r.ProcessHandle(ctx, at)
	return h, err
}

func (r Reader) Application(ctx context.Context, at uint64) (*string, []byte, error) {
	f, err := r.Objects.Field("_COMMAND_HISTORY", "Application")
	if err != nil {
		return nil, nil, err
	}
	address, err := memory.Add(at, f.Offset)
	if err != nil {
		return nil, nil, err
	}
	return r.Text(ctx, address)
}

// WalkBucket uses the supplied end for active entries. With nil end it also
// scans unused slots, preserving the baseline's history-size multiplier.
// Limit exhaustion, faults, cancellation and emitter errors are explicit.
func (r Reader) WalkBucket(ctx context.Context, h History, end *uint64, maxSlots uint64, emit func(uint64, Command) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if maxSlots == 0 || maxSlots > 1_000_000 || emit == nil {
		return fmt.Errorf("invalid command bucket bounds or emitter")
	}
	n, err := r.commandSize()
	if err != nil {
		return err
	}
	stop := h.Capacity
	if end != nil {
		stop = *end
	} else {
		size, err := r.Objects.Size(symbols.TypeRef{Kind: "struct", Name: "_COMMAND_HISTORY"})
		if err != nil {
			return err
		}
		if size == 0 || h.Maximum > math.MaxUint64/size {
			return fmt.Errorf("history capacity overflows")
		}
		calculated, err := memory.Add(h.Begin, size*h.Maximum)
		if err != nil {
			return err
		}
		if calculated > stop {
			stop = calculated
		}
	}
	for at, index := h.Begin, uint64(0); at < stop; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index >= maxSlots {
			return fmt.Errorf("command bucket exceeds %d slots", maxSlots)
		}
		valid, err := r.ValidCommand(ctx, at)
		if err != nil {
			return err
		}
		if valid {
			c, err := r.Command(ctx, at)
			if err != nil {
				return err
			}
			if err := emit(index, c); err != nil {
				return err
			}
		}
		// The last entry may end past an unaligned exclusive stop.
		if stop-at <= n {
			break
		}
		at, err = memory.Add(at, n)
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}
