package plugins

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const nanosPerSecond = 1000000000

func linuxTimespec(ctx context.Context, e plugin.Environment, address uint64, typ, field string) (*big.Int, error) {
	prefix := ""
	if field != "" {
		prefix = field + "."
	}
	seconds, err := e.Objects.Int(ctx, address, typ, prefix+"tv_sec")
	if err != nil {
		return nil, err
	}
	nanos, err := e.Objects.Int(ctx, address, typ, prefix+"tv_nsec")
	if err != nil {
		return nil, err
	}
	if nanos < 0 || nanos >= nanosPerSecond {
		return nil, fmt.Errorf("invalid Linux timespec nanoseconds %d", nanos)
	}
	n := new(big.Int).Mul(big.NewInt(seconds), big.NewInt(nanosPerSecond))
	return n.Add(n, big.NewInt(nanos)), nil
}

type linuxBootClock struct {
	nanos  *big.Int
	source string
	base   uint64
	err    error
}

func linuxClock(ctx context.Context, e plugin.Environment) (clock linuxBootClock) {
	clock.err = fmt.Errorf("no supported boot clock symbol is declared")
	for _, name := range []string{"tk_core", "timekeeper", "wall_to_monotonic"} {
		symbol, err := e.Symbols.Lookup(name)
		if err != nil {
			continue
		}
		clock.source = name
		clock.base, clock.err = memory.Add(symbol.Address, e.KernelSlide)
		if clock.err != nil {
			return clock
		}
		if symbol.Type == nil {
			clock.err = fmt.Errorf("clock symbol %s has no declared type", name)
			return clock
		}
		typ := symbol.Type.Name
		if name == "tk_core" {
			ktime := func(path string) (int64, error) {
				field, err := e.Objects.Field(typ, path)
				if err != nil {
					return 0, err
				}
				if field.Type.Kind == "struct" || field.Type.Kind == "union" {
					path += ".tv64"
				}
				return e.Objects.Int(ctx, clock.base, typ, path)
			}
			real, err := ktime("timekeeper.offs_real")
			if err != nil {
				clock.err = err
				return clock
			}
			boot, err := ktime("timekeeper.offs_boot")
			clock.nanos, clock.err = new(big.Int).Sub(big.NewInt(real), big.NewInt(boot)), err
			return clock
		}
		var wall *big.Int
		var sleep *big.Int
		if name == "timekeeper" {
			if _, err := e.Objects.Field(typ, "wall_to_monotonic"); err != nil {
				if errors.Is(err, object.ErrFieldAbsent) {
					clock.err = fmt.Errorf("timekeeper has no supported wall clock fields")
					continue
				}
				clock.err = err
				return clock
			}
			wall, err = linuxTimespec(ctx, e, clock.base, typ, "wall_to_monotonic")
			if err == nil {
				sleep, err = linuxTimespec(ctx, e, clock.base, typ, "total_sleep_time")
			}
		} else {
			wall, err = linuxTimespec(ctx, e, clock.base, typ, "")
			if err == nil {
				sleep = new(big.Int)
				if sym, lookupErr := e.Symbols.Lookup("total_sleep_time"); lookupErr == nil {
					if sym.Type == nil {
						err = fmt.Errorf("total_sleep_time has no declared type")
					} else if address, addErr := e.Symbol("total_sleep_time"); addErr != nil {
						err = addErr
					} else if sym.Type.Kind == "struct" {
						sleep, err = linuxTimespec(ctx, e, address, sym.Type.Name, "")
					} else {
						var seconds uint64
						seconds, err = e.Objects.Scalar(ctx, address, *sym.Type)
						sleep = new(big.Int).Mul(new(big.Int).SetUint64(seconds), big.NewInt(nanosPerSecond))
					}
				}
			}
		}
		clock.err = err
		if err == nil {
			clock.nanos = new(big.Int).Neg(new(big.Int).Add(wall, sleep))
		}
		return clock
	}
	return clock
}

func linuxCreationCounter(ctx context.Context, e plugin.Environment, address uint64) (evidence.Value, string) {
	for _, name := range []string{"start_boottime", "real_start_time", "start_time"} {
		field, err := e.Objects.Field("task_struct", name)
		if err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return evidence.Missing("start_counter_layout_unavailable", err), name
		}
		if field.Type.Kind == "struct" {
			n, err := linuxTimespec(ctx, e, address, "task_struct", name)
			if err != nil {
				return evidence.Missing("start_counter_unreadable", err), name
			}
			if !n.IsUint64() {
				return evidence.Missing("invalid_start_counter", fmt.Errorf("start counter is negative or exceeds uint64 nanoseconds")), name
			}
			return evidence.Number(n.Uint64()), name
		}
		if scalar, err := e.Symbols.Type(field.Type.Name); err == nil && scalar.Signed {
			n, err := e.Objects.Int(ctx, address, "task_struct", name)
			if err != nil {
				return evidence.Missing("start_counter_unreadable", err), name
			}
			if n < 0 {
				return evidence.Missing("invalid_start_counter", fmt.Errorf("task start counter is negative")), name
			}
			return evidence.Number(uint64(n)), name
		}
		return optionalUint(ctx, e, address, "task_struct", name, false), name
	}
	return evidence.Missing("start_counter_layout_unavailable", fmt.Errorf("no task start counter is declared")), ""
}

func linuxTimestamp(nanos *big.Int) evidence.Value {
	seconds, remainder := new(big.Int), new(big.Int)
	seconds.DivMod(nanos, big.NewInt(nanosPerSecond), remainder)
	if !seconds.IsInt64() || nanos.Sign() < 0 || seconds.Cmp(big.NewInt(253402300799)) > 0 {
		return evidence.Missing("invalid_linux_timestamp", fmt.Errorf("timestamp is outside the supported positive UTC date range"))
	}
	return evidence.Text(time.Unix(seconds.Int64(), remainder.Int64()).UTC().Format(time.RFC3339Nano))
}

func (clock linuxBootClock) apply(counter evidence.Value) (display, exact, boot, proof evidence.Value) {
	if clock.err != nil || clock.nanos == nil {
		v := evidence.Missing("boot_clock_unavailable", clock.err)
		return v, v, v, v
	}
	proof = evidence.Value{Kind: "structure", Data: map[string]string{"source": clock.source, "offset": fmt.Sprintf("0x%x", clock.base), "root_boot_epoch_ns": clock.nanos.String(), "display_model": "whole_boot_seconds_plus_task_counter", "namespace": "root"}}
	if clock.nanos.Sign() <= 0 {
		v := evidence.Missing("invalid_boot_clock", fmt.Errorf("root boot epoch must be positive"))
		return v, v, v, proof
	}
	boot = linuxTimestamp(clock.nanos)
	n, err := counter.Uint()
	if err != nil {
		return counter, counter, boot, proof
	}
	if boot.Kind == "missing" {
		return boot, boot, boot, proof
	}
	exact = linuxTimestamp(new(big.Int).Add(clock.nanos, new(big.Int).SetUint64(n)))
	seconds := new(big.Int).Div(new(big.Int).Set(clock.nanos), big.NewInt(nanosPerSecond))
	base := new(big.Int).Mul(seconds, big.NewInt(nanosPerSecond))
	display = linuxTimestamp(base.Add(base, new(big.Int).SetUint64(n)))
	return display, exact, boot, proof
}
