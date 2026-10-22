# Deprecated plugin names — development preview

Volatility 3 v2.28.2 keeps older class names that forward to renamed plugins.
GoMem accepts those exact class names and runs the existing native command.
The requested name is the task, cache, and row-provenance identity. Each row
also records `RequestedPlugin` and `ImplementedPlugin`. A repeated deprecated
name replays its own completed task; it does not reuse the native-name task.

`gomem plugins CLASS` prints the target parameter schema under the requested
class name. `gomem analyze CLASS` validates those parameters and prints the
delegation before execution. The alias does not change result semantics.

The wired names are:

- `linux.check_afinfo.Check_afinfo` to `linux.check_afinfo`
- `linux.check_creds.Check_creds` to `linux.check_creds`
- `linux.check_idt.Check_idt` to `linux.check_idt`
- `linux.check_modules.Check_modules` to `linux.check_modules`
- `linux.check_syscall.Check_syscall` to `linux.check_syscall`
- `linux.hidden_modules.Hidden_modules` to `linux.hidden_modules`
- `linux.keyboard_notifiers.Keyboard_notifiers` to `linux.keyboard_notifiers`
- `linux.modxview.Modxview` to `linux.modxview`
- `linux.malfind.Malfind` to `linux.malfind`
- `linux.netfilter.Netfilter` to `linux.netfilter`
- `linux.tty_check.tty_check` to `linux.tty_check`
- `windows.amcache.Amcache` to `windows.amcache`
- `windows.cachedump.Cachedump` to `windows.cachedump`
- `windows.drivermodule.DriverModule` to `windows.drivermodule`
- `windows.hashdump.Hashdump` to `windows.hashdump`
- `windows.hollowprocesses.HollowProcesses` to `windows.hollowprocesses`
- `windows.ldrmodules.LdrModules` to `windows.ldrmodules`
- `windows.lsadump.Lsadump` to `windows.lsadump`
- `windows.malfind.Malfind` to `windows.malfind`
- `windows.processghosting.ProcessGhosting` to `windows.processghosting`
- `windows.psxview.PsXView` to `windows.psxview`
- `windows.scheduled_tasks.ScheduledTasks` to `windows.scheduledtasks`
- `windows.suspicious_threads.SuspiciousThreads` to `windows.suspicious_threads`
- `windows.svcdiff.SvcDiff` to `windows.svcdiff`

`TestDeprecatedHiddenModuleAlias` runs the hidden-module synthetic fixture
through both names. The deprecated run has the same module names and record
types, a separate cache entry, sealed alias provenance, and a successful
replay with byte-identical JSONL. `TestDeprecatedNetfilterAlias` applies the
same checks to namespace list, entries and split-array fixtures with device
hooks, comparing every result cell except the alias identity markers. The stored task list uses the same requested
name as each task's provenance. Calling every alias against every real corpus remains open, so none of
these entries is accepted.

A Debian 3.2 CLI smoke test also runs `linux.netfilter.Netfilter` offline:
task `39236220ecc348ae99ba711eb7b60b3e` completes with 573 source/list rows
and zero hooks, preserves the deprecated name in row provenance and replays
byte-identical JSONL. This remains a negative control, not full alias or
Netfilter capability acceptance.

`TestDeprecatedMalfindAlias` checks every result cell, requested task identity,
row seals and cached JSONL for the native suspicious-mapping fixture.

`TestDeprecatedWindowsMalfindAlias` verifies native Windows findings, exact cells,
requested task identity, sealed provenance and byte-identical cache replay.
