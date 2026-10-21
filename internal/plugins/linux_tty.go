package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxTTYPlugins() []builtin {
	columns := []evidence.Column{{Name: "Name", Kind: "string"}, {Name: "Address", Kind: "address"}, {Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "Driver", Kind: "address"}, {Name: "Device", Kind: "address"}, {Name: "Matches", Kind: "structure"}}
	for _, c := range linuxModxviewPlugins()[0].spec.Columns {
		if c.Name != "Address" && c.Name != "Name" {
			columns = append(columns, c)
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.tty_check", Upstream: "linux.malware.tty_check.Tty_Check", Platform: "linux", NeedsKernel: true, Description: "Attribute tty line-discipline receive_buf handlers", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Driver list and module traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}, {Name: "max-devices", Kind: "uint", Default: "4096", Description: "Maximum devices per tty driver, 1..1000000"}}, Columns: columns}, linuxTTY}}
}

func linuxTTY(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("tty inspection requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	for _, name := range []string{"tty_driver", "tty_struct", "tty_ldisc"} {
		if _, err := e.Symbols.Type(name); err != nil {
			return fmt.Errorf("tty layout unavailable: %w", err)
		}
	}
	link, err := e.Objects.Field("tty_driver", "tty_drivers")
	if err != nil {
		return err
	}
	for _, spec := range []struct{ typ, field string }{{"tty_driver", "ttys"}, {"tty_driver", "num"}, {"tty_struct", "name"}, {"tty_struct", "ldisc"}, {"tty_ldisc", "ops"}} {
		if _, err := e.Objects.Field(spec.typ, spec.field); err != nil {
			return err
		}
	}
	opsField, err := e.Objects.Field("tty_ldisc", "ops")
	if err != nil || opsField.Type.Underlying() == nil || opsField.Type.Underlying().Name == "" {
		return fmt.Errorf("tty_ldisc.ops target type unavailable: %w", err)
	}
	opsType := opsField.Type.Underlying().Name
	if _, err := e.Objects.Field(opsType, "receive_buf"); err != nil {
		return err
	}
	maxDevices, err := strconv.ParseUint(p["max-devices"], 0, 32)
	if err != nil || maxDevices < 1 || maxDevices > 1000000 {
		return fmt.Errorf("max-devices must be 1..1000000")
	}
	list, err := e.Symbol("tty_drivers")
	if err != nil {
		return fmt.Errorf("tty_drivers unavailable: %w", err)
	}
	columns := linuxTTYPlugins()[0].spec.Columns
	emit := func(r evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, c := range columns {
			if _, ok := r.Cells[c.Name]; !ok {
				r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
			}
		}
		return out(r)
	}
	s, err := linuxGatherModuleSources(ctx, e, p, emit)
	if err != nil {
		return err
	}
	if err := s.kernel(); err != nil {
		if err := s.issue(0, "kernel", "kernel_bounds_unavailable", err); err != nil {
			return err
		}
	}
	modules := linuxFlattenModuleSources(s.results, mask)
	index, err := linuxKernelSymbolIndex(ctx, e, mask)
	if err != nil {
		return err
	}
	width := uint64(e.Symbols.PointerSize())
	pointerType, err := e.Symbols.Type("pointer")
	if err != nil {
		return err
	}
	endian := pointerType.Endian
	var drivers, devices, nulls, skipped, unknown, limited, unreadable uint64
	err = e.Objects.WalkList(ctx, list, link.Offset, s.maxNodes, func(driver uint64) error {
		drivers++
		n := s.reader(map[string]evidence.Value{})
		count, err := n.uint(driver, "tty_driver", "num")
		if err != nil {
			s.failures.add(err)
			return nil
		}
		array, err := n.uint(driver, "tty_driver", "ttys")
		if err != nil {
			s.failures.add(err)
			return nil
		}
		limit := count
		if limit > maxDevices {
			// The declared count can be far larger than resident devices. Keep the
			// bound as coverage, not as a failed read of the devices already found.
			limited++
			limit = maxDevices
		}
		for i := uint64(0); i < limit; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			slot, err := memory.Add(array, i*width)
			if err != nil {
				s.failures.add(err)
				return nil
			}
			raw, _, err := linuxCaptureRange(ctx, e.Kernel, slot, int(width))
			if err != nil {
				unreadable++
				continue
			}
			device, err := linuxSyscallPointer(raw, endian)
			if err != nil {
				return err
			}
			if device == 0 {
				nulls++
				continue
			}
			r := linuxModuleRow(e, device, "tty", "tty_drivers")
			r.Cells["Driver"], r.Cells["Device"] = evidence.Address(driver), evidence.Address(device)
			r.Cells["Module"], r.Cells["Symbol"], r.Cells["Name"] = evidence.Missing("not_available", nil), evidence.Missing("not_available", nil), evidence.Missing("name_unavailable", nil)
			fields := map[string]evidence.Value{}
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			n := s.reader(fields)
			name, nameErr := e.Objects.String(ctx, device, "tty_struct", "name", 64)
			if nameErr != nil {
				skipped++
				s.failures.add(nameErr)
				r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("device_observation"), evidence.Text("name_unreadable"), evidence.Missing("name_unreadable", nameErr)
				if err := s.out(r); err != nil {
					return err
				}
				continue
			}
			ldisc, err := n.uint(device, "tty_struct", "ldisc")
			if err != nil || ldisc == 0 {
				if err == nil {
					err = fmt.Errorf("tty %#x has a null line discipline", device)
				}
				skipped++
				s.failures.add(err)
				r.Cells["Name"] = evidence.Text(name)
				r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("device_observation"), evidence.Text("ldisc_unreadable"), evidence.Missing("ldisc_unreadable", err)
				if err := s.out(r); err != nil {
					return err
				}
				continue
			}
			ops, err := n.uint(ldisc, "tty_ldisc", "ops")
			if err != nil || ops == 0 {
				if err == nil {
					err = fmt.Errorf("tty %#x has null line-discipline operations", device)
				}
				skipped++
				s.failures.add(err)
				r.Cells["Name"] = evidence.Text(name)
				r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("device_observation"), evidence.Text("ops_unreadable"), evidence.Missing("ops_unreadable", err)
				if err := s.out(r); err != nil {
					return err
				}
				continue
			}
			receive, err := n.uint(ops, "tty_ldisc_ops", "receive_buf")
			if err != nil {
				skipped++
				r.Cells["Name"] = evidence.Text(name)
				r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("device_observation"), evidence.Text("receive_buf_unreadable"), evidence.Missing("receive_buf_unreadable", err)
				if err := s.out(r); err != nil {
					return err
				}
				continue
			}
			match, symbol, matches, err := linuxModuleLookup(n, modules, index, receive)
			s.failures.add(err)
			r.Cells["Name"], r.Cells["Address"] = evidence.Text(name), evidence.Address(receive)
			if match != nil {
				r.Cells["Module"] = evidence.Text(match.name)
			} else {
				unknown++
			}
			if symbol != "" {
				r.Cells["Symbol"] = evidence.Text(symbol)
			} else if err != nil {
				r.Cells["Symbol"] = evidence.Missing("module_symbol_unavailable", err)
			}
			ranges := []map[string]evidence.Value{}
			for _, m := range matches {
				ranges = append(ranges, map[string]evidence.Value{"Module": evidence.Text(m.name), "Base": evidence.Address(m.base), "Size": evidence.Number(m.size)})
			}
			r.Cells["Matches"] = evidence.Value{Kind: "structure", Data: map[string]any{"ranges": ranges}}
			r.Cells["Status"] = evidence.Text("inspected")
			devices++
			if err := s.out(r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := linuxModuleRow(e, list, "summary", "tty_drivers")
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"drivers": formatCount(drivers), "devices": formatCount(devices), "null_devices": formatCount(nulls), "skipped_devices": formatCount(skipped), "unattributed": formatCount(unknown), "read_layout_errors": strconv.Itoa(s.failures.count), "scope": "tty receive_buf ownership is not a malware verdict"})
	if err := s.out(summary); err != nil {
		return err
	}
	return s.failures.err("Linux tty inspection")
}
