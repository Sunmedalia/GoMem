package plugins

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxBoottimePlugins() []builtin {
	var columns []evidence.Column
	for _, g := range []struct{ kind, names string }{
		{"uint64", "NamespaceID RepresentativePID"}, {"address", "NamespaceAddress TaskOffset"},
		{"string", "BootTimeExact BootEpochNS NamespaceState TimelineType TimelineDescription RecordType"},
		{"structure", "ClockEvidence NamespaceEvidence Coverage"}, {"string", "Error"},
	} {
		for _, name := range strings.Fields(g.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: g.kind})
		}
	}
	columns = append([]evidence.Column{{Name: "TIME NS", Kind: "uint64"}, {Name: "Boot Time", Kind: "string"}}, columns...)
	return []builtin{{plugin.Spec{Name: "linux.boottime", Upstream: "linux.boottime.Boottime", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate boot times per time namespace, with raw clock sources, exact nanoseconds and timeline fields",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Native task traversal bound"}}, Columns: columns}, linuxBoottime}}
}

// Python's fromtimestamp accepts a binary64 timestamp and rounds its fraction
// to microseconds. Keep that compatibility display separate from exact nanos.
func linuxBootDisplay(nanos *big.Int) evidence.Value {
	sec, fraction := new(big.Int), new(big.Int)
	sec.DivMod(nanos, big.NewInt(nanosPerSecond), fraction)
	if nanos.Sign() <= 0 || !sec.IsInt64() || sec.Cmp(big.NewInt(253402300799)) > 0 {
		return evidence.Missing("unparsable_boot_time", nil)
	}
	stamp := float64(sec.Int64()) + float64(fraction.Int64())/nanosPerSecond
	whole := math.Floor(stamp)
	microseconds := int64(math.RoundToEven((stamp - whole) * 1000000))
	seconds := int64(whole)
	if microseconds == 1000000 {
		seconds++
		microseconds = 0
	}
	if seconds > 253402300799 {
		return evidence.Missing("unparsable_boot_time", nil)
	}
	return evidence.Text(time.Unix(seconds, microseconds*1000).UTC().Format(time.RFC3339Nano))
}

func linuxBootClockEvidence(ctx context.Context, e plugin.Environment, clock linuxBootClock) (evidence.Value, error) {
	if clock.err != nil || clock.nanos == nil {
		cause := clock.err
		if cause == nil {
			cause = fmt.Errorf("boot clock has no nanosecond value")
		}
		return evidence.Missing("boot_clock_unavailable", cause), cause
	}
	var captures []map[string]evidence.Value
	read := func(symbol, field string) error {
		s, err := e.Symbols.Lookup(symbol)
		if err != nil {
			return err
		}
		if s.Type == nil {
			return fmt.Errorf("%s has no clock type", symbol)
		}
		address, err := e.Symbol(symbol)
		if err != nil {
			return err
		}
		typ := *s.Type
		if field != "" {
			f, err := e.Objects.Field(typ.Name, field)
			if err != nil {
				return err
			}
			address, err = memory.Add(address, f.Offset)
			if err != nil {
				return err
			}
			typ = f.Type
		}
		size, err := e.Objects.Size(typ)
		if err != nil || size == 0 || size > 64 {
			return fmt.Errorf("invalid clock field extent %d: %v", size, err)
		}
		raw, err := memory.Read(ctx, e.Kernel, address, int(size))
		if err != nil {
			return err
		}
		captures = append(captures, map[string]evidence.Value{"Symbol": evidence.Text(symbol), "Field": evidence.Text(field), "Address": evidence.Address(address), "Raw": evidence.Bytes(raw)})
		return nil
	}
	var err error
	switch clock.source {
	case "tk_core":
		for _, field := range []string{"timekeeper.offs_real", "timekeeper.offs_boot"} {
			if err = read(clock.source, field); err != nil {
				break
			}
		}
	case "timekeeper":
		for _, field := range []string{"wall_to_monotonic", "total_sleep_time"} {
			if err = read(clock.source, field); err != nil {
				break
			}
		}
	case "wall_to_monotonic":
		err = read(clock.source, "")
		if err == nil {
			if _, lookupErr := e.Symbols.Lookup("total_sleep_time"); lookupErr == nil {
				err = read("total_sleep_time", "")
			}
		}
	default:
		err = fmt.Errorf("unsupported clock source %s", clock.source)
	}
	details := map[string]evidence.Value{"Source": evidence.Text(clock.source), "RootEpochNS": evidence.Text(clock.nanos.String()), "Fields": {Kind: "structure", Data: captures}}
	if err != nil {
		details["Error"] = evidence.Missing("clock_capture_unreadable", err)
	}
	return evidence.Value{Kind: "structure", Data: details}, err
}

// A nil ID denotes kernels without time namespaces or a null time_ns pointer.
// A real ID zero is a different de-duplication key, although the fixed renderer
// displays both as unavailable. A bad pointer never becomes the legacy key.
func linuxBootNamespace(ctx context.Context, e plugin.Environment, task uint64) (id *uint64, details evidence.Value, err error) {
	fields := map[string]evidence.Value{}
	details = evidence.Value{Kind: "structure", Data: fields}
	for _, f := range []struct{ typ, member string }{{"task_struct", "nsproxy"}, {"nsproxy", "time_ns"}} {
		if _, cause := e.Objects.Field(f.typ, f.member); cause != nil {
			if errors.Is(cause, object.ErrFieldAbsent) {
				fields["State"] = evidence.Text("legacy_no_time_namespace")
				return
			}
			err = cause
			return
		}
	}
	proxy, cause := e.Objects.Uint(ctx, task, "task_struct", "nsproxy")
	if cause != nil {
		err = cause
		return
	}
	fields["NSProxy"] = evidence.Address(proxy)
	if proxy == 0 {
		err = fmt.Errorf("null nsproxy for a declared time namespace layout")
		return
	}
	namespace, cause := e.Objects.Uint(ctx, proxy, "nsproxy", "time_ns")
	if cause != nil {
		err = cause
		return
	}
	fields["Address"] = evidence.Address(namespace)
	if namespace == 0 {
		fields["State"] = evidence.Text("null_time_namespace")
		return
	}
	number, cause := e.Objects.Uint(ctx, namespace, "time_namespace", "ns.inum")
	if cause != nil {
		err = cause
		return
	}
	id = &number
	fields["ID"] = evidence.Number(number)
	fields["State"] = evidence.Text("time_namespace")
	return
}

func linuxBootNamespaceOffset(ctx context.Context, e plugin.Environment, fields map[string]evidence.Value) (*big.Int, error) {
	offset := new(big.Int)
	namespace, _ := fields["Address"].Uint()
	if namespace == 0 {
		return offset, nil
	}
	if _, cause := e.Objects.Field("time_namespace", "offsets"); cause != nil {
		if errors.Is(cause, object.ErrFieldAbsent) {
			fields["OffsetState"] = evidence.Text("offsets_not_declared")
			return offset, nil
		}
		return nil, cause
	}
	f, cause := e.Objects.Field("time_namespace", "offsets.boottime")
	if cause != nil {
		return nil, cause
	}
	address, cause := memory.Add(namespace, f.Offset)
	if cause != nil {
		return nil, cause
	}
	size, cause := e.Objects.Size(f.Type)
	if cause != nil || size == 0 || size > 64 {
		return nil, fmt.Errorf("invalid namespace timespec extent %d: %v", size, cause)
	}
	raw := make([]byte, int(size))
	got, cause := e.Kernel.ReadAt(ctx, raw, address)
	if got < 0 || got > len(raw) {
		return nil, fmt.Errorf("invalid namespace timespec capture length %d", got)
	}
	fields["OffsetAddress"], fields["OffsetRaw"] = evidence.Address(address), evidence.Bytes(raw[:got])
	fields["RequestedBytes"], fields["CapturedBytes"] = evidence.Number(size), evidence.Number(uint64(got))
	fields["ReadComplete"] = evidence.Bool(cause == nil && got == len(raw))
	if cause != nil || got != len(raw) {
		if cause == nil {
			cause = fmt.Errorf("short namespace timespec capture")
		}
		return nil, cause
	}
	offset, cause = linuxTimespec(ctx, e, namespace, "time_namespace", "offsets.boottime")
	if cause != nil {
		return nil, cause
	}
	fields["OffsetNS"] = evidence.Text(offset.String())
	return offset, nil
}

func linuxBoottime(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.boottime requires kernel memory and symbols")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	clock := linuxClock(ctx, e)
	clockEvidence, err := linuxBootClockEvidence(ctx, e, clock)
	if err != nil {
		return err
	}
	init, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("task_struct", "tasks")
	if err != nil {
		return err
	}
	head, err := memory.Add(init, links.Offset)
	if err != nil {
		return err
	}
	var tasks, unique, duplicates, diagnostics, timesRead, unparsable uint64
	seen := map[string]bool{}
	var failures pluginFailures
	base := func(task uint64, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
		for _, c := range linuxBoottimePlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		if kind != "summary" {
			r.Provenance.Offset = fmt.Sprintf("0x%x", task)
		}
		r.Cells["TIME NS"] = evidence.Missing("not_available", nil)
		r.Cells["RecordType"], r.Cells["ClockEvidence"] = evidence.Text(kind), clockEvidence
		return r
	}
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(task uint64) error {
		tasks++
		id, details, cause := linuxBootNamespace(ctx, e, task)
		r := base(task, "time_namespace")
		r.Cells["TaskOffset"], r.Cells["NamespaceEvidence"] = evidence.Address(task), details
		if cause != nil {
			diagnostics++
			failures.add(cause)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("time_namespace_unreadable", cause)
			return out(r)
		}
		key, label := "legacy", "None"
		if id != nil {
			key = fmt.Sprint(*id)
			label = key
			r.Cells["NamespaceID"] = evidence.Number(*id)
			if *id != 0 {
				r.Cells["TIME NS"] = evidence.Number(*id)
			}
		}
		if seen[key] {
			duplicates++
			return nil
		}
		seen[key] = true
		unique++
		fields := details.Data.(map[string]evidence.Value)
		offset, cause := linuxBootNamespaceOffset(ctx, e, fields)
		if cause != nil {
			diagnostics++
			failures.add(cause)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("time_namespace_offset_unreadable", cause)
			return out(r)
		}
		r.Cells["NamespaceState"] = fields["State"]
		if address, ok := fields["Address"]; ok {
			r.Cells["NamespaceAddress"] = address
		}
		r.Cells["RepresentativePID"] = optionalUint(ctx, e, task, "task_struct", "pid", false)
		nanos := new(big.Int).Sub(new(big.Int).Set(clock.nanos), offset)
		r.Cells["BootEpochNS"] = evidence.Text(nanos.String())
		r.Cells["BootTimeExact"], r.Cells["Boot Time"] = linuxTimestamp(nanos), linuxBootDisplay(nanos)
		if r.Cells["Boot Time"].Kind == "missing" {
			unparsable++
			r.Cells["BootTimeExact"] = evidence.Missing("unparsable_boot_time", nil)
		}
		timesRead++
		r.Cells["TimelineType"], r.Cells["TimelineDescription"] = evidence.Text("CREATED"), evidence.Text("System boot time for time namespace "+label)
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(r)
	})
	if err != nil {
		return err
	}
	r := base(0, "summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"times_read": formatCount(timesRead), "unparsable_times": formatCount(unparsable), "tasks": formatCount(tasks), "namespaces": formatCount(unique), "duplicates": formatCount(duplicates), "diagnostics": formatCount(diagnostics)})
	if err = out(r); err != nil {
		return err
	}
	return failures.err("Linux time namespaces")
}
