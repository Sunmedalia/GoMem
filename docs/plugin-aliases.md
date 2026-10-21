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
- `linux.tty_check.tty_check` to `linux.tty_check`
- `windows.amcache.Amcache` to `windows.amcache`
- `windows.cachedump.Cachedump` to `windows.cachedump`
- `windows.drivermodule.DriverModule` to `windows.drivermodule`
- `windows.hashdump.Hashdump` to `windows.hashdump`
- `windows.hollowprocesses.HollowProcesses` to `windows.hollowprocesses`
- `windows.ldrmodules.LdrModules` to `windows.ldrmodules`
- `windows.lsadump.Lsadump` to `windows.lsadump`
- `windows.processghosting.ProcessGhosting` to `windows.processghosting`
- `windows.psxview.PsXView` to `windows.psxview`
- `windows.scheduled_tasks.ScheduledTasks` to `windows.scheduledtasks`
- `windows.suspicious_threads.SuspiciousThreads` to `windows.suspicious_threads`
- `windows.svcdiff.SvcDiff` to `windows.svcdiff`

`TestDeprecatedHiddenModuleAlias` runs the hidden-module synthetic fixture
through both names. The deprecated run has the same module names and record
types, a separate cache entry, sealed alias provenance, and a successful
replay with byte-identical JSONL. The stored task list uses the same requested
name as each task's provenance. Calling every alias against every real corpus remains open, so none of
these entries is accepted.
