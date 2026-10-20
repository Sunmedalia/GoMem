#!/usr/bin/env python3
"""Development-only AST inventory; never imports or executes upstream plugins.

The locked source tree digest prevents using a different release accidentally.
Requirements preserve literal values and tag expressions for manual semantic review.
"""
import argparse
import ast
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def tree_digest(source):
    digest = hashlib.sha256()
    for path in sorted((source / "volatility3").rglob("*.py")):
        digest.update(path.relative_to(source).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def value(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return {"expression": ast.unparse(node)}


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    actual = tree_digest(source)
    if actual != lock["python_tree_sha256"]:
        raise ValueError(f"baseline source digest mismatch: {actual}")
    base = source / "volatility3/framework/plugins"
    classes = {}
    for path in sorted(base.rglob("*.py")):
        module = path.relative_to(base).with_suffix("").as_posix().replace("/", ".")
        if module.endswith(".__init__"):
            module = module[:-9]
        tree = ast.parse(path.read_text())
        imports = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = node.module + "." + alias.name
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue

            def resolve(expr):
                text = ast.unparse(expr)
                first, dot, rest = text.partition(".")
                text = imports.get(first, module + "." + first if not dot else first)
                if dot:
                    text += "." + rest
                return text.removeprefix("volatility3.plugins.").removeprefix("volatility3.framework.plugins.")

            identifier = module + "." + node.name
            requirements = []
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name == "get_requirements":
                    for call in ast.walk(method):
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr.endswith("Requirement"):
                            requirements.append({"kind": call.func.attr, **{k.arg: value(k.value) for k in call.keywords if k.arg}})
            alias = next((resolve(k.value) for k in node.keywords if k.arg == "replacement_class"), None)
            classes[identifier] = {"id": identifier, "source": path.relative_to(source).as_posix(), "line": node.lineno,
                                   "bases": [resolve(b) for b in node.bases], "requirements": requirements,
                                   "alias_target": alias}

    def is_plugin(identifier, seen=None):
        seen = set() if seen is None else seen
        if identifier in seen:
            return False
        seen = seen | {identifier}
        c = classes[identifier]
        return any(b.endswith("PluginInterface") or b.endswith("PluginRenameClass") or
                   b in classes and is_plugin(b, seen) for b in c["bases"])

    partial = {"banners.Banners": "banners", "windows.pslist.PsList": "windows.pslist",
               "linux.pslist.PsList": "linux.pslist", "windows.modules.Modules": "windows.modules",
               "linux.lsmod.Lsmod": "linux.lsmod", "windows.threads.Threads": "windows.threads",
               "windows.vadinfo.VadInfo": "windows.vadinfo", "linux.proc.Maps": "linux.maps",
               "windows.dlllist.DllList": "windows.dlllist", "windows.pedump.PEDump": "windows.pedump",
               "windows.cmdline.CmdLine": "windows.cmdline", "linux.psaux.PsAux": "linux.psaux", "linux.envars.Envars": "linux.envars", "linux.elfs.Elfs": "linux.elfs", "linux.psscan.PsScan": "linux.psscan", "linux.lsof.Lsof": "linux.lsof", "linux.sockstat.Sockstat": "linux.sockstat", "linux.pagecache.InodePages": "linux.inodepages", "linux.pagecache.Files": "linux.files", "linux.pagecache.RecoverFs": "linux.recoverfs", "windows.registry.hivelist.HiveList": "windows.hivelist", "windows.registry.printkey.PrintKey": "windows.printkey", "windows.registry.hivescan.HiveScan": "windows.hivescan", "windows.registry.hashdump.Hashdump": "windows.hashdump", "windows.registry.lsadump.Lsadump": "windows.lsadump", "windows.registry.cachedump.Cachedump": "windows.cachedump", "windows.registry.userassist.UserAssist": "windows.userassist", "windows.registry.getcellroutine.GetCellRoutine": "windows.getcellroutine", "windows.registry.amcache.Amcache": "windows.amcache", "windows.registry.scheduled_tasks.ScheduledTasks": "windows.scheduledtasks", "windows.filescan.FileScan": "windows.filescan", "windows.psscan.PsScan": "windows.psscan", "windows.thrdscan.ThrdScan": "windows.thrdscan", "windows.mutantscan.MutantScan": "windows.mutantscan", "windows.driverscan.DriverScan": "windows.driverscan", "windows.symlinkscan.SymlinkScan": "windows.symlinkscan", "windows.modscan.ModScan": "windows.modscan", "windows.bigpools.BigPools": "windows.bigpools", "windows.unloadedmodules.UnloadedModules": "windows.unloadedmodules", "windows.envars.Envars": "windows.envars", "windows.sessions.Sessions": "windows.sessions", "windows.crashinfo.Crashinfo": "windows.crashinfo"}

    def requirements(identifier, seen=None):
        seen = set() if seen is None else seen
        if identifier in seen or identifier not in classes:
            return []
        c = classes[identifier]
        if c["requirements"]:
            return c["requirements"]
        targets = [c["alias_target"]] if c["alias_target"] else c["bases"]
        return [r for b in targets for r in requirements(b, seen | {identifier})]

    plugins = []
    validation_path = ROOT / "docs/validation.json"
    validations = json.loads(validation_path.read_text())["results"] if validation_path.exists() else []
    for identifier, c in sorted(classes.items()):
        if not is_plugin(identifier):
            continue
        native = partial.get(identifier)
        plugins.append({"id": identifier, "platform": identifier.split(".")[0] if identifier.split(".")[0] in ("windows", "linux", "mac") else "generic",
                        "source": c["source"], "line": c["line"], "alias_target": c["alias_target"],
                        "requirements": requirements(identifier), "applicability": "All declared module, architecture, version and optional-library requirements must be satisfied; parameter semantics require differential acceptance.",
                        "native": native, "status": "partial" if native else "missing", "accepted": False,
                        "corpora": ([f"synthetic-{identifier.split('.')[0]}-x64"] if identifier.startswith(("linux.", "windows.")) else ["synthetic-linux-x64", "synthetic-windows-x64"]) if native else [],
                        "comparison": "not_run", "gaps": ["Official-corpus differential acceptance pending"] if native else ["Native implementation and validation pending"]})
        matching = [v for v in validations if v["id"] == identifier and v["report"]["matched"]]
        if matching:
            plugins[-1]["corpora"] += sorted({v["corpus"] for v in matching})
            plugins[-1]["comparison"] = "selected_fields_match"
            plugins[-1]["validation_record"] = "docs/validation.json"
        if identifier == "windows.pslist.PsList":
            plugins[-1].update(applicability="Active process list with exact EPROCESS, handle/session types and independent PEB address spaces; virtual or physical offset display, PID sets and main PE extraction.",
                              comparison="selected_extended_fields_and_physical_offsets_match_main_PE_bytes_match", validation_record="docs/windows-process-modules.md",
                              gaps=["Full version/architecture and parameter/failure coverage pending", "Opaque session layouts are not guessed; handle count requires a declared HandleCount field", "Bidirectional damaged-list recovery, timeline and full PE extraction acceptance pending"])
        if identifier == "linux.pslist.PsList":
            plugins[-1].update(applicability="Active tasks with typed cred/kuid fields and root boot clock; PID/TID/PPID, nanosecond counters and explicit time models. Optional threads use thread_group or signal.thread_head/thread_node with ownership checks.",
                              corpora=["synthetic-linux-x64", "synthetic-linux-clock-and-signal-threads", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_ten_fields_match_133_processes_316_tasks_with_explicit_microsecond_rounding", validation_record="docs/linux-tasks.md",
                              gaps=["Real modern kernel/32-bit clock and thread layout matrix pending; modern paths have synthetic tests only", "ELF main-image extraction has selected legacy x64 validation only; timeline and damaged task-list bidirectional recovery remain pending", "Credential/clock read errors are retained per field; UID values are raw kernel IDs, not user namespace remapping"])

        if identifier == "linux.pagecache.RecoverFs":
            plugins[-1].update(applicability="Cached REG/DIR/LNK objects from the mounted superblock walk. Archive prefixes use s_uuid or major:minor; regular files expand to logical size only when cached pages exist and stay within max-file/maxsize. Holes and short physical reads are explicit. Fast symlinks are archived without traversal; absolute targets are rewritten with PurePath semantics and the original bytes remain in the row.",
                              corpora=["synthetic-linux-cached-filesystem-archive", "official-linux-sample-1-syslog-member"],
                              comparison="synthetic_archive_is_reproducible_and_selected_syslog_member_matches_padded_page_cache_sha256", validation_record="docs/linux-recoverfs.md",
                              gaps=["Full RecoverFs tarball has no byte-for-byte baseline differential; tar mtime and gzip MTIME are fixed instead of using the plugin run time", "Files above max-file, duplicate prefixed paths and symlinks without a readable i_link fail the member and the task; a bounded Debian 3.2 run is not a complete filesystem export", "Real modern filesystems, 32-bit layouts, tmpfs-only on a real tmpfs and complete compression/version matrix remain unaccepted", "Metadata, ownership and original mode bits are not replicated into tar headers"])
        if identifier == "linux.pagecache.Files":
            plugins[-1].update(applicability="Task mount namespaces through legacy/modern list or rb_root, superblock roots and list/hlist cached dentries. First superblock mount scope is explicit; hardlink aliases, negative-entry counts, raw paths and exact inode clocks are retained. Type and first exact raw-path filters do not prune directory descent.",
                              corpora=["synthetic-linux-filesystem-list-union-hlist-and-rb-layouts", "synthetic-linux-hardlinks-fast-symlinks-and-corruption", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_9434_inodes_nine_fields_match_28302_timestamps_and_full_RAW_filesystem_census_verified_seven_path_display_differences", validation_record="docs/linux-files.md",
                              gaps=["Real modern/32-bit namespace and dentry layouts remain unaccepted; the real census is one legacy x64 acquisition", "Cached superblock trees at a representative first mount do not prove namespace visibility, disk completeness or all mount aliases", "Raw paths exclude deleted-display markers; fast i_link targets are annotations only and find matches the undecorated path", "RecoverFs filesystem export, full mountinfo rendering, timeline integration and complete parameter/version/failure matrix are pending"])
        if identifier == "linux.pagecache.InodePages":
            plugins[-1].update(applicability="Explicit regular inode address or first raw-path lookup through mounted superblock trees, typed legacy radix or XArray root. Page/index/mapping ownership, fixed/dynamic x64 vmemmap or flatmem PFNs, bounded sparse recovery with logical and physical gaps.",
                              corpora=["synthetic-linux-x64-radix-xarray", "synthetic-linux-x86-pae-flatmem", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_four_inodes_nine_pages_six_fields_and_46838_export_bytes_match_RAW_verification_plus_regular_syslog_path_lookup", validation_record="docs/linux-pagecache.md",
                              gaps=["RecoverFs filesystem export, full mount alias visibility and timeline are pending; path lookup uses the explicitly scoped native Files traversal", "Real modern XArray, dynamic vmemmap, flatmem/32-bit and full parameter/version matrix remain unaccepted; selected real data is one legacy x64 acquisition", "Large folios, sibling/internal XArray entries, NUMA/32-bit sparsemem and five-level paging have explicit unsupported errors; exceptional values remain evidence without payload decoding", "Uncached logical bytes and unreadable physical bytes are padded with gap provenance; raw i_size is preserved even when no pages are captured"])
        if identifier == "linux.sockstat.Sockstat":
            plugins[-1].update(applicability="Descriptor-backed sockets identified by exact file operations and typed socket_alloc ownership. Task/thread identities, separate task/socket namespace addresses, INET/UNIX/netlink/packet/vsock/Bluetooth/XDP handlers and cBPF/eBPF metadata; field availability remains explicit.",
                              corpora=["synthetic-linux-x64-network-families", "synthetic-linux-network-namespace-and-filter-layouts", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_1021_sockets_match_thirteen_fields_INET_UNIX_bytes_independently_verified_five_Bluetooth_layout_gaps_retained", validation_record="docs/linux-sockstat.md",
                              gaps=["Full real modern/32-bit family, namespace, interface and filter layout matrix pending; many family paths have synthetic tests only", "Abstract UNIX names retain their explicit length and bytes rather than first-NUL truncation; macOS reference IPv6 nulls arise from host AF_INET6=30 versus Linux=10", "Five selected Bluetooth sockets lack bt_sock in the supplied ISF and remain explicit decoding errors; complete task reports failure", "No closed-socket scan, orphan sockets, packet capture, filter bytecode export or network timeline acceptance"])
        if identifier == "linux.lsof.Lsof":
            plugins[-1].update(applicability="Task/thread FD tables through typed files_struct.fdt or legacy inline fields, with raw/scoped paths and inode metadata. files-only selects filesystem traversal rather than filtering inode types. Timestamps retain exact signed seconds and nanoseconds.",
                              corpora=["synthetic-linux-x64", "synthetic-linux-x86-pae", "synthetic-linux-inode-time-and-namespace-layouts", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_3795_common_descriptors_match_ten_fields_one_captured_descriptor_and_zero_timestamps_preserved", validation_record="docs/linux-lsof.md",
                              gaps=["Real modern/32-bit kernels, full namespace/path/parameter/failure coverage and timeline integration pending", "Default view retains open high-numbered descriptors even when fd[0] is NULL; reference skips such tables in the selected baseline", "Raw timestamp precision, epoch-zero and modern split timestamp fields intentionally retain captured values rather than reference display bugs; cached inode fallback/version matrix remains partial"])
        if identifier == "linux.psscan.PsScan":
            plugins[-1].update(applicability="Physical scheduler-pointer task candidates using exact task_struct layouts and little-endian 32/64-bit symbols. One bounded physical pass; PID/exit-state heuristics, coverage and read diagnostics are explicit. Parent pointers use the kernel address space.",
                              corpora=["synthetic-linux-x64", "synthetic-linux-x86-pae", "official-linux-sample-1", "official-linux-sample-1-reencoded-avml"],
                              comparison="selected_321_tasks_match_six_fields_with_independent_RAW_scan_and_316_active_task_coordinates", validation_record="docs/linux-psscan.md",
                              gaps=["Real modern/32-bit acquisitions and full parameter/failure/version coverage pending", "Scheduler pointer and PID/exit-state checks identify candidates, not proven processes; task inline fields are assumed physically contiguous", "Default TID limit mirrors the reference (pid < 65535); max-pid can explicitly widen it. Stale/exiting candidates are not proof of hiding"])
        if identifier == "linux.elfs.Elfs":
            plugins[-1].update(applicability="VMA-start ELF signatures in independent process spaces; strict bounded ELF32/64 headers for extraction. Page-rounded PT_LOAD concatenation uses actual mapped addresses by default, or the pinned reference base-plus-p_vaddr profile.",
                              corpora=["synthetic-linux-x64", "synthetic-elf32-64-endianness", "official-linux-sample-1"],
                              comparison="selected_2419_entities_match_5442_read_diagnostics_retained_mapped_bytes_independently_verified", validation_record="docs/linux-elf.md",
                              gaps=["Real modern/32-bit acquisition and complete version/parameter/failure coverage pending", "ET_EXEC and high-address vDSO bytes intentionally differ in mapped layout; reference arithmetic exceeding uint64 is rejected explicitly", "Strict headers, aggregate extraction size and empty-load rejection differ from permissive reference cases; output is not original disk ELF"])
        if identifier == "windows.modules.Modules":
            plugins[-1].update(applicability="Loaded kernel list, exact base and case-sensitive base-name substring filters. PE extraction tries kernel then typed per-session process roots, with bounded attempts recorded.",
                              comparison="selected_core_fields_and_157_paths_match_19_read_errors_preserved_PE_ImageBase_difference_explained", validation_record="docs/windows-process-modules.md",
                              gaps=["Full version/architecture, session mapping and failure/parameter acceptance pending", "19 path errors remain distinct from reference nulls in the selected image", "PE files retain canonical ImageBase high bits; explicit byte differences and filename mapping remain recorded"])
        if identifier == "windows.threads.Threads":
            plugins[-1].update(applicability="Active process thread lists; exact ETHREAD/EPROCESS types. Start paths currently require modern RTL_AVL_TREE VAD layout. External swap/prototype pages are unresolved.",
                              gaps=["Full version/architecture and parameter coverage pending", "ExitTime signed union differences explicitly preserved; see docs/windows-threads.md", "This active-list walk is not a pool scan; windows.thrdscan covers ETHREAD pool headers. No extracted artifacts"])
        if identifier == "windows.registry.hivelist.HiveList":
            plugins[-1].update(applicability="Active CmpHiveListHead walk using the exact _CMHIVE layout. Signature must be 0xBEE0BEE0. The selected name is the first nonempty FileFullPath, FileUserName or HiveRootPath; all three fields stay in the row. A forward list break walks backward once and keeps hives already emitted. dump writes the 4096-byte base block plus the measured stable store. Kernel-canonical pages fall back to the Registry process; user addresses never use the kernel. Unreadable ranges are zero-padded, logged, and fail the task.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_24_hive_offsets_and_names_match_summary_retained_dump_false", validation_record="docs/windows-hivelist.md",
                              gaps=["Reconstructed files have synthetic byte checks and one real SAM smoke read; no byte-for-byte baseline differential", "Only one Windows 10 x64 crash dump has a selected-field list differential; 32-bit and damaged-list acceptance remain pending", "The upstream FileFullPath column is get_name(); native retains each path field. FileOutput is the literal disabled unless dump is requested", "Unlinked hive recovery is windows.hivescan, not a fallback inside this list walk"])
        if identifier == "windows.registry.hivescan.HiveScan":
            plugins[-1].update(applicability="64-bit Windows 8.1 and later only, detected by _KPRCB.PendingTickFlags when PE version metadata is absent. In-use PoolBigPageTable entries whose Key is the four bytes CM10. Freed entries have the low Va bit set and are skipped. The candidate address is the stored Va. A hive signature is reported but does not filter the row. Earlier Windows builds need the paged pool header scanner and fail explicitly.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_24_big_pool_offsets_match", validation_record="docs/windows-hivescan.md",
                              gaps=["Paged pool header scanning for pre-8.1 and 32-bit hives is not connected. windows.filescan has a separate header scanner and does not recover hives", "Only one Windows 10 x64 crash dump has a selected-offset differential", "Signature and tag are native evidence; the reference column compared here is Offset only"])
        if identifier == "windows.bigpools.BigPools":
            plugins[-1].update(applicability="PoolBigPageTable entries typed as _POOL_TRACKER_BIG_PAGES. PoolBigPageTable is read as unsigned long long and PoolBigPageTableSize as unsigned long on both 32-bit and 64-bit. Key 0 is omitted. The low Va bit marks a free allocation and stays in Allocation when show-free is set; the default omits those rows. The tag keeps the four little-endian key bytes whose values are strictly between 32 and 127, deleting the others. An empty tag stays an empty string. tags is a comma-separated exact list with no trimming; an empty value disables filtering. PoolType names come from _POOL_TYPE, keeping the alphabetically first name for a duplicate value. That matches the pinned enumeration on this ISF because every enum object is sorted. An unknown value is Unknown choice N. A missing PoolType or NumberOfBytes member is not applicable. A read the pinned generator would raise fails the task. A missing _POOL_TRACKER_BIG_PAGES fails explicitly and does not load the fallback big-pool JSON. max-entries bounds the table at 1..5000000 and defaults to 2000000. The summary row is not an allocation.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_7425_rows_match_allocation_tag_pool_type_bytes_and_status", validation_record="docs/windows-bigpools.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 32768 table entries, 7425 allocated rows, 1543 hidden free rows and 23800 key-0 rows", "Real 32-bit images are pending. The eight-byte table pointer is synthetic when the symbol pointer width is 4", "The pinned fallback ISF for a missing _POOL_TRACKER_BIG_PAGES is intentionally not copied", "Pre-Vista rows without PoolType or NumberOfBytes are synthetic only", "max-entries is a native bound and is not an upstream parameter", "show-free and tags were checked on the synthetic image, not differentially on the crash dump"])
        if identifier == "windows.unloadedmodules.UnloadedModules":
            plugins[-1].update(applicability="MmUnloadedDrivers records using the pinned unloadedmodules-x64 and unloadedmodules-x86 layouts, which are not in the kernel PDB. A 64-bit pointer reads the count as 8 bytes and each record as 40 bytes: the name is the _UNICODE_STRING at the start, StartAddress is at 16, EndAddress at 24 and CurrentTime at 32. The address mask is 0x0000ffffffffffff. A 32-bit pointer reads the count as 4 bytes and each record as 24 bytes: StartAddress is the unsigned long at 8, EndAddress at 12, and CurrentTime remains the 8 bytes at 16. The mask is 0xffffffff. A name length of 0 is an empty string and does not read the buffer. One unreadable address, time or name is counted and skipped. A table-pointer or count read failure fails the task. A missing MmUnloadedDrivers or MmLastUnloadedDriver symbol fails explicitly; the pinned plugin logs and returns no rows. A count above 1024 is capped at 1024 and recorded. A row is kept only when CurrentTime is greater than 1024 and both masked addresses are page aligned and greater than the masked MmSystemRangeStart. An unreadable range start uses 0xFFFF800000000000 or 0x80000000 before that mask. Native addresses keep the stored bits. Time uses the existing FILETIME conversion. The summary row is not a module.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_9_rows_match_name_addresses_and_time", validation_record="docs/windows-unloadedmodules.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. Its count is 9, with no skipped or unreadable entries", "Real 32-bit images are pending. The 24-byte x86 layout is implemented but not exercised on a real image", "A missing MmUnloadedDrivers or MmLastUnloadedDriver symbol fails the task. The pinned plugin logs and returns no rows", "Timeline output is not implemented", "Native addresses keep the stored bits. The comparison masks both sides with 0x0000ffffffffffff because the reference already applied the layer address mask", "The 1024-entry cap and the unreadable-name skip were checked on the synthetic image, not on this crash dump"])
        if identifier == "windows.envars.Envars":
            plugins[-1].update(applicability="Active-process PEB environment blocks in each process address space. Environment is the pointer in _RTL_USER_PROCESS_PARAMETERS and EnvironmentSize is its byte count. A missing EnvironmentSize uses Length. Pointers are masked with 0x0000ffffffffffff or 0xffffffff. A zero size does not read the buffer. The block is UTF-16LE, split on NUL, and the final segment is dropped. A segment without '=' uses all but its last character as the name and the whole segment as the value. An empty name or value is dropped. Block is the address of the Environment pointer field, formatted like Python hex(); the block address itself stays in Environment. A short or invalid read emits no partial variables. No PEB, a null parameter pointer, an empty block or a block with no variables is a diagnostic and does not fail the task. An unreadable pointer, size or buffer fails the task; the pinned plugin skips that process and still succeeds. max-env defaults to 1048576, is capped at 16777216, and is not an upstream parameter. silent is accepted but does not filter: the pinned generator reads the config key SILENT, so its registry and common-variable lists are unreachable. The summary records silent_requested and silent_applied.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_2960_rows_match_pid_process_block_variable_and_value", validation_record="docs/windows-envars.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 2960 variables. Twenty-six processes had unreadable parameters or environment pages and failed the task; the pinned plugin skips them", "Three processes have no PEB and remain diagnostics. The unreadable pages are prototype or swap entries this engine does not resolve", "Real 32-bit images are pending", "silent does not filter, matching the pinned SILENT config-key mismatch. Registry-backed suppression is therefore not executed", "max-env, the no-equals split, the dropped final segment and the Length fallback were checked on the synthetic image"])
        if identifier == "windows.sessions.Sessions":
            plugins[-1].update(applicability="Active processes with the same session ID read as windows.pslist. A null Session pointer is not applicable, not integer 0. A nonzero pointer reads _MM_SESSION_SPACE.SessionId, so a stored 0 stays 0. The Windows 11 _PSP_SESSION_SPACE fixed-offset fallback is not guessed. USERDOMAIN and USERNAME are joined as domain/user. Names are compared case-insensitively and the later value wins. The result is unavailable only when it is exactly /. SESSIONNAME is also case-insensitive; absence is unavailable, while an empty value is kept. Environment parsing matches windows.envars. An unreadable parameter or environment page still emits the process row with unavailable user and session type, records the error, and fails the task. The pinned plugin skips that environment block and still succeeds. No PEB is unavailable and does not fail the task. Create time uses the existing FILETIME conversion. max-env defaults to 1048576 and is not an upstream parameter. The summary row is not a session.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_120_rows_match_session_user_and_create_time", validation_record="docs/windows-sessions.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 120 processes, 4 unavailable session IDs, 110 unavailable session types, 10 RDP-Tcp#0 values and 34 unavailable user names", "Twenty-six environment reads failed on prototype or swap pages. The rows remain and the task fails; the pinned plugin skips the environment block and succeeds", "Real 32-bit images are pending", "The Windows 11 _PSP_SESSION_SPACE offset fallback is not guessed", "Timeline output is not implemented", "Case-insensitive overwrite and an unreadable environment were checked on the synthetic image"])
        if identifier == "windows.crashinfo.Crashinfo":
            plugins[-1].update(applicability="Windows complete dumps (type 0x1) and bitmap dumps (type 0x5) only. The header is read from the crash layer and no kernel symbols are required. A non-crash image fails the task and emits no row. 64-bit uses the pinned _DUMP_HEADER64 layout and 32-bit uses _DUMP_HEADER. Signature is the 4-byte field, so PAGEDU64 is reported as PAGE. Type 0x1 is Full Dump (0x1) and type 0x5 is Bitmap Dump (0x5). Other types are rejected while opening the layer, before this plugin runs. Bitmap HeaderSize, Pages and BitmapSize come from _SUMMARY_DUMP at the end of the header. A full dump leaves those three cells not applicable. SystemUpTime formats ticks/10 microseconds like str(datetime.timedelta), with a half microsecond rounded to even. SystemTime drops the 100-nanosecond remainder, subtracts the FILETIME epoch, and prints UTC with a numeric +00:00 offset. A zero second count is not applicable. Values outside years 1 through 9999, or that the platform clock cannot represent, are unparsable. Comment is the 128-byte field, decoded as UTF-8 and cut at the first NUL or U+FFFD; the terminator is not kept. SystemTimeRaw is the unconverted FILETIME and is not a reference column.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_1_row_matches_header_bitmap_uptime_comment_and_time", validation_record="docs/windows-crashinfo.md",
                              gaps=["Only one Windows 10 x64 bitmap crash dump has a selected-field differential. It has one row, bitmap header 176128, 511191 pages and bitmap size 1310720", "Real 32-bit images are pending. The 4096-byte header offsets are synthetic", "Dump types other than 0x1 and 0x5 fail while the layer is opened, so the plugin Unknown/Unsupported text is not reached on an opened image", "Comment truncation at NUL and at the first invalid UTF-8 sequence or literal U+FFFD was checked on the synthetic image", "System time comparison uses whole UTC seconds. The sample value is 2025-03-06T17:59:20+00:00"])
        if identifier == "windows.filescan.FileScan":
            plugins[-1].update(applicability="Executive file objects from pool headers tagged Fil\\xe5 or File. Windows 10 and later scans the kernel virtual layer; earlier Windows scans physical memory. PE metadata is preferred. Otherwise ObHeaderCookie means Windows 10 or later, a _HANDLE_TABLE without HandleCount means Windows 8 or later, and KdCopyDataBlock means Vista or later. Windows 8 and later carves top-down from InfoMask and the optional headers present in the symbols, including padding. Earlier Windows carves bottom-up from the alignment-rounded _FILE_OBJECT size. Alignment is 16 bytes for 8-byte pointers and 8 bytes for 4-byte pointers. The object type must be File, using ObTypeIndexTable or else ObpObjectTypes, and ObHeaderCookie when that symbol exists. A file is valid only when FileName.Length is nonzero and the first byte of FileName.Buffer is readable in the kernel layer. A later name read failure drops that row and counts it; it is not stored as an empty name. An odd-length UTF-16 buffer keeps U+FFFD for the trailing byte, and a NUL ends the name. Identical page-table pages are not scanned. Resident Windows transition pages are included. A non-unmapped read error fails the task after a diagnostic row. Unmapped holes are skipped. The summary row is not a file entity.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_4866_rows_match_low_48_offset_and_name", validation_record="docs/windows-filescan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential", "32-bit images and real pre-Windows 8 bottom-up scans remain pending; those paths are synthetic only", "windows.psscan, windows.thrdscan, windows.mutantscan, windows.driverscan, windows.symlinkscan and windows.modscan use this scanner", "windows.hivescan still reads PoolBigPageTable and does not use this header scanner", "Reference offsets omit the canonical high bits. The comparison masks both sides to the low 48 bits; native rows keep the full address", "Three file names on the selected image could not be read and were omitted, matching the pinned plugin. They are counted in the summary, not emitted as empty names"])
        if identifier == "windows.psscan.PsScan":
            plugins[-1].update(applicability="EPROCESS objects from pool headers tagged Pro\\xe3 or Proc. The scan layer, carving direction, pool-type polarity, alignment and page-table rules are the same as windows.filescan. Process constraints skip the object-type name check. A candidate is kept only when the pinned EPROCESS checks pass: the UTF-8 image name, truncated at NUL or U+FFFD, is nonempty; unless the name is System and the PID is 4, CreateTime is a UTC datetime whose year is after 1998 and before the local current year plus 10, and an ExitTime datetime in that same window is not earlier than creation. PID is nonzero, divisible by 4 and no greater than 0xFFFFFFFC. DirectoryTableBase, or its first array element, is nonzero outside the low 12 bits. ThreadListHead.Flink and Blink are both at least 0x80000000. A field read that the pinned generator would raise is omitted. Handles without a HandleCount member stay unavailable. A null session pointer is not applicable. Wow64 is false when neither process pointer exists. dump=false reports the literal Disabled. A dump error becomes the literal Error outputting file and does not by itself fail the task. physical translates the scanned address through the kernel layer. The summary row is not a process.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_121_rows_match_identity_times_session_and_wow64", validation_record="docs/windows-psscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 121 pool processes, including one MpCmdRun.exe that is absent from the active list", "32-bit images and real pre-Windows 8 bottom-up scans remain pending; the bottom-up path is synthetic", "Timeline output is not implemented", "dump was not compared on this image. The reference and native default are the literal Disabled", "The local year window follows datetime.now().year. This comparison was run in 2026", "Reference offsets omit the canonical high bits. The comparison masks both sides to the low 48 bits"])
        if identifier == "windows.thrdscan.ThrdScan":
            plugins[-1].update(applicability="ETHREAD objects from pool headers tagged Thr\\xe5 or Thre. The scan layer, carving direction, pool-type polarity, alignment and page-table rules are the same as windows.filescan. Thr\\xe5 skips the object-type name check. Thre requires type Thread, using ObTypeIndexTable or else ObpObjectTypes, and ObHeaderCookie when that symbol exists. A candidate passes the pinned ETHREAD checks when UniqueThread and UniqueProcess are both divisible by 4. Unless the process ID is 4, CreateTime is a UTC datetime whose year is after 1998 and before the local current year plus 10. CreateTime shifts a signed QuadPart right by 3 when ThreadsProcess exists; otherwise it uses QuadPart directly. ExitTime always uses the unshifted QuadPart. FILETIME whole seconds use Python floor division, and a zero second count is not a datetime. Values outside years 1 through 9999 stay unparsable. A field read that the pinned generator would raise drops the thread. After those reads, PID 0, a PID above 0xFFFFFFFC, or a PID not divisible by 4 is dropped. The owning process is ThreadsProcess, or else Tcb.Process. Start paths are resolved only when that process passes the pinned EPROCESS checks and its UniqueProcessId is not 4. The path set is the modern VAD walk used by windows.threads, keeping file names that contain a backslash. System threads, invalid owners, addresses outside a file VAD, and names without a backslash stay unavailable without an error. Timeline output is not implemented. The summary row is not a thread.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_1752_rows_match_identity_paths_and_times", validation_record="docs/windows-thrdscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. Its 1752 pool threads have the same low-48 offsets as the active thread list, so this image has no unlinked thread", "32-bit images and real pre-Windows 8 bottom-up scans remain pending; the bottom-up path is synthetic", "Timeline output is not implemented", "The local year window follows datetime.now().year. This comparison was run in 2026", "Reference offsets omit the canonical high bits. The comparison masks both sides to the low 48 bits", "ExitTime follows the pinned signed FILETIME conversion, including year-1600 values. windows.threads still preserves the raw unsigned bits for that column"])
        if identifier == "windows.mutantscan.MutantScan":
            plugins[-1].update(applicability="KMUTANT objects from pool headers tagged Mut\\xe1 or Muta. The scan layer, carving direction, pool-type polarity, alignment, page-table rules and object-type check are the same as windows.filescan. Both tags require type Mutant. The pinned KMUTANT check accepts every carved object, so top-down carving keeps every aligned header whose pointer count is in range and whose type matches. The name comes from the object header. Windows 7 and later reads ObpInfoMaskToOffset at InfoMask masked with 0x3; a NameInfoOffset member is used when present. A zero offset, a length of zero, a maximum of zero, or a length above the maximum is an unavailable name. An unreadable name stays on the row as an error rather than an empty string. The summary row is not a mutant.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_742_rows_match_low_48_offset_and_name", validation_record="docs/windows-mutantscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 742 mutants and 448 unavailable names", "32-bit images and real pre-Windows 8 bottom-up scans remain pending; mutant bottom-up placement uses the shared scanner but has no separate fixture", "Reference offsets omit the canonical high bits. The comparison masks both sides to the low 48 bits", "Unavailable names on this image had no read error. A later read error stays distinct from a reference null"])
        if identifier == "windows.modscan.ModScan":
            plugins[-1].update(applicability="LDR_DATA_TABLE_ENTRY objects from pool headers tagged MmLd. There is no executive object type, so the object begins immediately after the pool header. The scan layer, alignment and nonpaged-or-free pool polarity are the same as windows.filescan. The minimum block size is 76 bytes. DllBase and SizeOfImage must be readable, and a failed read fails the task. BaseDllName and FullDllName follow UNICODE_STRING.String: length zero is an empty string, and an unreadable string is missing. The read error is removed from the compared cell and kept on NameError or PathError. name is a case-sensitive substring of a readable base name; an unreadable base name is not filtered out. base is an exact DllBase, and zero disables filtering. dump=false reports the literal Disabled. dump=true reuses the kernel-then-session PE extractor. A missing layer becomes the pinned cannot-find string, and a failed reconstruction becomes Error outputting file. The summary row is not a module.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_177_rows_match_offset_base_size_names_and_disabled_output", validation_record="docs/windows-modscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 177 modules. One base name and 20 paths were unreadable; the compared cells match the reference nulls and the errors stay on NameError or PathError", "32-bit images and real pre-Windows 8 physical scans remain pending", "dump extraction was not differentially compared. The default File output is the literal Disabled on all 177 rows", "base=0 disables filtering, matching windows.modules. The pinned optional integer would select DllBase 0", "max-nodes and max-session-layers bound only the dump session walk and are not upstream parameters", "Reference offsets and bases omit the canonical high bits. The comparison masks both sides to the low 48 bits"])
        if identifier == "windows.symlinkscan.SymlinkScan":
            plugins[-1].update(applicability="OBJECT_SYMBOLIC_LINK entries from pool headers tagged Sym\\xe2 or Symb. The scan layer, carving direction, alignment and object-type check are the same as windows.filescan, except both tags select paged or free pool. On Vista and later an odd PoolType is paged. Both tags require type SymbolicLink. The pinned check accepts every carved object. The source name is the object-header NameInfo string and does not use the KMUTANT length checks. A zero name-info offset or an unreadable name drops the row. A LinkTarget length of zero is an empty string and does not read the buffer; an unreadable target drops the row. CreationTime uses the unshifted QuadPart. A failed CreationTime read fails the task. A zero second count is not set, and values outside years 1 through 9999 stay unparsable. Timeline output is not implemented. The summary row is not a symlink.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_219_rows_match_offset_time_and_names", validation_record="docs/windows-symlinkscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 219 symlinks, including one empty target", "32-bit images and real pre-Windows 8 bottom-up scans remain pending. The bottom-up path uses the shared scanner and has no separate symlink fixture", "Twelve name or target reads were dropped and counted. 523 candidates failed the SymbolicLink type check", "Reference offsets omit the canonical high bits. The comparison masks both sides to the low 48 bits", "Timeline output is not implemented", "The local year window follows datetime.now().year. This comparison was run in 2026"])
        if identifier == "windows.driverscan.DriverScan":
            plugins[-1].update(applicability="DRIVER_OBJECT entries from pool headers tagged Dri\\xf6 or Driv. The scan layer, carving direction, pool-type polarity, alignment and object-type check are the same as windows.filescan. Both tags require type Driver. The pinned DRIVER_OBJECT check accepts every carved object. The DriverStart field must be readable for 8 bytes. A start of zero or a start strictly above MmSystemRangeStart is kept; an unreadable MmSystemRangeStart uses 0xFFFF800000000000 on 64-bit and 0x80000000 on 32-bit. The driver name is the object-header name, without the KMUTANT length checks. The service key is DriverExtension.ServiceKeyName, and the other name is the embedded DriverName. Empty strings and invalid addresses become unavailable. A read error is removed from the compared cell so it matches that null, and kept on ServiceKeyError, DriverNameError or NameError. A row whose three names are all unavailable is omitted. The summary row is not a driver.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_142_rows_match_offset_start_size_and_names", validation_record="docs/windows-driverscan.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has 142 drivers", "32-bit images and real pre-Windows 8 bottom-up scans remain pending. The Dri\\xf6 bottom-up path adds _DRIVER_EXTENSION to the rounded size in the shared scanner and has no separate fixture", "One service-key buffer is the noncanonical address 0x508f8d480000017d. The compared cell matches the reference null; ServiceKeyError keeps the read error", "Reference offsets and starts omit the canonical high bits. The comparison masks both sides to the low 48 bits"])
        if identifier == "windows.registry.hashdump.Hashdump":
            plugins[-1].update(applicability="Active SYSTEM and SAM hives from CmpHiveListHead. The boot key is only ControlSet001\\Control\\Lsa JD, Skew1, GBG and Data class data, decoded as UTF-16LE hex and then permuted. SAM F revision 2 is MD5 plus RC4; revision 3 is AES-CBC and keeps the first 16 bytes. User V revision 1 is MD5 plus RC4; revision 2 is AES. The NT salt is read at nt_offset+8. Empty LM and NT digests are the standard constants. A missing hive, boot key, or user record fails the task. windows.hashdump.Hashdump is only the deprecated upstream alias.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="synthetic_rc4_and_aes_vectors_match_pinned_algorithm_selected_image_has_zero_hash_rows_because_JD_class_cell_is_swapped", validation_record="docs/windows-hashdump.md",
                              gaps=["The selected Windows 10 19041 crash dump has a nonpresent JD class page, so neither implementation produced account hashes", "The reference completes with a warning and no rows; native fails the task and retains the read error", "No resident-hash corpus differential yet. 32-bit images and other real revisions remain pending"])
        if identifier == "windows.hashdump.Hashdump":
            plugins[-1]["gaps"] = ["Deprecated alias of windows.registry.hashdump.Hashdump; native command is windows.hashdump"]

        if identifier == "windows.registry.lsadump.Lsadump":
            plugins[-1].update(applicability="Active SYSTEM and SECURITY hives from CmpHiveListHead. The boot key is the same ControlSet001 LSA class permutation as windows.hashdump. Vista or later is metadata.windows.pe major.minor when revision is present; otherwise KdCopyDataBlock as a symbol or type selects Vista. Vista reads Policy\\PolEKList, hashes the boot key plus bytes 28:60 one thousand times with SHA-256, and decrypts each 16-byte block from offset 60 with a fresh zero IV. The LSA key is decrypted bytes 68:100. Earlier Windows reads Policy\\PolSecretEncryptionKey, uses MD5 of the boot key plus bytes 60:76 hashed one thousand times, RC4-decrypts bytes 12:60, and keeps bytes 16:32. Secrets are Policy\\Secrets\\*\\CurrVal. Vista reuses the AES derivation with the LSA key. Earlier Windows uses SystemFunction005 DES and the pinned seven-byte key window. A missing hive, boot key, LSA key, secrets key, or secret value fails the task. windows.lsadump.Lsadump is only the deprecated upstream alias.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="synthetic_vista_aes_and_prevista_des_vectors_match_pinned_algorithm_selected_image_has_zero_secret_rows_because_JD_class_cell_is_swapped", validation_record="docs/windows-lsadump.md",
                              gaps=["The selected Windows 10 19041 crash dump has a nonpresent JD class page, so neither implementation produced secrets", "The reference completes with a warning and no rows; native fails the task and retains the read error", "No resident-secret corpus differential yet. 32-bit images and real pre-Vista hives remain pending", "A secret without CurrVal fails that record; the reference skips it", "A short final AES block is an error; the reference raises TypeError"])
        if identifier == "windows.lsadump.Lsadump":
            plugins[-1]["gaps"] = ["Deprecated alias of windows.registry.lsadump.Lsadump; native command is windows.lsadump"]
        if identifier == "windows.registry.cachedump.Cachedump":
            plugins[-1].update(applicability="Same SYSTEM and SECURITY hives, boot key, Vista check, and LSA key as windows.lsadump. NL$KM is decrypted through that secret path. Vista cache entries use AES-CBC with NL$KM bytes 16:32 and the 16-byte IV at offset 64. Earlier Windows uses HMAC-MD5 of the IV keyed by NL$KM, then RC4. User, domain, and DNS offsets use the pinned Python 3 padding, which is the length modulo 4. NL$Control and entries with a zero user length or an empty IV are skipped. A missing hive, boot key, LSA key, NL$KM, or Cache key fails the task. A readable cache that contains only skipped slots succeeds with no rows. windows.cachedump.Cachedump is only the deprecated upstream alias.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="synthetic_vista_aes_cbc_and_xp_hmac_rc4_vectors_match_pinned_algorithm_selected_image_has_zero_cache_rows_because_JD_class_cell_is_swapped", validation_record="docs/windows-cachedump.md",
                              gaps=["The selected Windows 10 19041 crash dump has a nonpresent JD class page, so neither implementation produced cached credentials", "The reference completes with a warning and no rows; native fails the task and retains the read error", "No resident-cache corpus differential yet. 32-bit images and real pre-Vista hives remain pending", "An empty NL$KM fails the task; the reference warns and returns no rows"])
        if identifier == "windows.cachedump.Cachedump":
            plugins[-1]["gaps"] = ["Deprecated alias of windows.registry.cachedump.Cachedump; native command is windows.cachedump"]
        if identifier == "windows.registry.printkey.PrintKey":
            plugins[-1].update(applicability="Active hives only. Cell indexes use the exact HMAP. Kernel-canonical bins are read from the kernel layer, with a Registry-process retry when that page is not present. Lower addresses require the Registry process and are never read from the kernel. Unreadable hives stay visible and do not fail the task by themselves.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_478_root_rows_match_offset_type_key_name_volatile_and_second_timestamps", validation_record="docs/windows-printkey.md",
                              gaps=["Stable hive reconstruction is separate and not yet differentially accepted", "Only the default root listing of one Windows 10 x64 crash dump is differentially checked; recurse, key filtering, 32-bit and other versions are synthetic or unaccepted", "Reference JSON drops 100ns fractions and wraps SZ display in quotes; native keeps the fraction, raw bytes and decoded text", "Prototype pages that neither the kernel nor the Registry process can read are skipped per subkey and recorded, not padded"])
        if identifier == "windows.registry.amcache.Amcache":
            plugins[-1].update(applicability="The first readable hive whose name contains amcache, case-insensitively. Windows 10 reads Root\\InventoryApplication, Root\\InventoryApplicationFile and Root\\InventoryDriverBinary. Windows 8 reads Root\\Programs and the two-level Root\\File keys. A missing section is skipped. Program rows keep the first key position and the last duplicate id. Files sort by program id and hang under a matching program; other files stay at the root. SHA-1 values strip every leading zero. InstallDate and LinkDate follow the pinned helper, which rejects every decoded value before its date parser. Unreadable value bytes stay unparsable and are not zero-padded.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_157_rows_match_fields_and_program_file_tree", validation_record="docs/windows-amcache.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential. It has no InventoryDriverBinary rows and no Windows 8 File/Programs keys", "InstallDate and LinkDate remain unparsable because the pinned helper never reaches its strptime branch", "A value cell that cannot be read is not zero-padded; this image did not need that distinction", "32-bit images, timeline output and a second Amcache hive remain pending"])
        if identifier == "windows.scheduled_tasks.ScheduledTasks":
            plugins[-1]["gaps"] = ["Deprecated alias of windows.registry.scheduled_tasks.ScheduledTasks; native command is windows.scheduledtasks"]
        if identifier == "windows.registry.scheduled_tasks.ScheduledTasks":
            plugins[-1].update(applicability="The first readable hive whose name contains software, case-insensitively. Task rows are the direct subkeys of Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks. Names come from the first Id REG_SZ under each TaskCache\\Tree key; the displayed name is that key's own name. A missing Tasks key is an absent row. Each task is the Cartesian product of its actions and triggers, and an empty side is one unavailable row. The decoder keeps the pinned behavior: TimeMode members are strings, so every integer schedule mode is Unknown and time descriptions are unavailable; Idle and Registration triggers are stored as Logon; an email action is consumed and emitted as unavailable; DynamicInfo's first and second FILETIMEs are swapped in the creation and last-run columns; COM CLSIDs drop leading zeroes; empty principal, display, description and working-directory strings are unavailable, while an empty action argument is kept. Unreadable value bytes stay errors and are not zero-padded.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_311_rows_match_actions_triggers_times_and_names", validation_record="docs/windows-scheduledtasks.md",
                              gaps=["Only one Windows 10 x64 crash dump has a selected-field differential", "Timeline output is not implemented", "32-bit images and other Windows versions remain pending", "Time trigger descriptions stay unavailable because the pinned TimeMode values are strings; Idle and Registration are reported as Logon", "Message-box and email actions are covered by synthetic blobs; this image has no message box", "A value cell that cannot be read is not zero-padded; this image did not need that distinction"])
        if identifier == "windows.registry.getcellroutine.GetCellRoutine":
            plugins[-1].update(applicability="Active hives from CmpHiveListHead and kernel modules from PsLoadedModuleList. Module names use the pinned splitext stem. A repeated stem or an unreadable base or size fails the task. An unreadable module name is skipped. GetCellRoutine is read from the embedded _HHIVE. A handler inside ntkrnlmp, ntkrnlpa, ntkrpamp, or ntoskrnl, compared case-sensitively and including the address at base+size, is not reported. Any other containing module is a hook. An address outside every module is not available. An unreadable pointer stays a row and is not treated as a kernel handler.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_image_has_zero_hook_rows_and_zero_unreadable_pointers", validation_record="docs/windows-getcellroutine.md",
                              gaps=["The selected Windows 10 19041 crash dump has no GetCellRoutine outside the kernel modules, so the differential is a negative control", "Synthetic coverage includes an external module, the inclusive kernel end, a case-sensitive kernel name, an unmapped pointer, an unreadable pointer, and a duplicate stem", "No resident hooked hive has been compared. 32-bit images and session-only modules remain pending", "A hive whose registry layer cannot be constructed is still examined when the header pointer is readable"])
        if identifier == "windows.registry.userassist.UserAssist":
            plugins[-1].update(applicability="NTUSER.DAT hives from the active hive list, optionally filtered by offset with the low 48 bits. The key is software\\microsoft\\windows\\currentversion\\explorer\\userassist. A missing key is skipped. Win7 and later is _KUSER_SHARED_DATA.CookiePad: values are 72 bytes, ID is not applicable, and focus time is timedelta(seconds=(FocusTime+500)/1000). Earlier Windows uses the 16-byte layout and subtracts 5 from counts of 5 or more. Value names are ROT-13. On Win7 and later a known-folder GUID replaces every occurrence when the first backslash component matches, case-sensitively. Count paths use the hive name's last component. Key and subkey Raw Data is the string N/A. A failed value read stays an error and is not zero-padded.",
                              corpora=["synthetic-windows-x64", "official-windows-10-19041"],
                              comparison="selected_36_of_37_rows_match_one_nonpresent_value_is_not_zero_padded", validation_record="docs/windows-userassist.md",
                              gaps=["The selected Windows 10 19041 crash dump has one UEME_CTLSESSION value whose cell is nonpresent. The reference zero-pads 1612 bytes and parses count 0; native keeps registry_value_unreadable", "Two other nonpresent value cells are skipped by the reference and retained as unreadable rows", "Only one Windows 10 x64 crash dump and synthetic Win7/missing-key cases are checked. XP corpus, 32-bit, timeline output and other versions remain pending", "A missing UserAssist key is skipped without a persisted warning row"])
        if identifier == "windows.cmdline.CmdLine":
            plugins[-1].update(applicability="Native EPROCESS.Peb -> PEB.ProcessParameters -> typed RTL_USER_PROCESS_PARAMETERS.CommandLine, read in each process root. Raw UTF-16LE and partial captures are retained.",
                              corpora=["synthetic-windows-x64", "synthetic-windows-x86-pae", "official-windows-10-19041"],
                              comparison="selected_readable_command_lines_match_errors_and_empty_strings_preserved", validation_record="docs/windows-cmdline.md",
                              gaps=["Full version/architecture and all failure/parameter combinations pending", "Read errors remain distinct from reference nulls; empty captured strings are not marked unreadable", "ArgsFull retains the declared string, including post-NUL text and BOM; raw bytes remain authoritative"])
        if identifier == "linux.envars.Envars":
            plugins[-1].update(applicability="User tasks only; PF_KTHREAD 0x00200000 tasks are counted and skipped. Environment bytes are read through each task page table. The default 8192-byte bound matches the pinned sanity check. Entries are split on raw NUL and the first '='. A missing separator stops that task. Unmapped, oversized and malformed blocks stay visible and fail the task.",
                              corpora=["synthetic-linux-x64", "official-linux-sample-1"],
                              comparison="selected_1402_variable_rows_match_order_and_fields_11_baseline_omissions_retained_as_failures", validation_record="docs/linux-envars.md",
                              gaps=["Full Linux version/architecture and parameter matrix pending", "The pinned plugin omits unmapped, oversized and malformed environments and still succeeds; native output fails the task and keeps those 11 diagnostics", "Kernel-thread selection uses the stable PF_KTHREAD bit, not a null mm"])
        if identifier == "linux.psaux.PsAux":
            plugins[-1].update(applicability="Active task mm argument ranges read through independent process roots; 4096-byte default bound, explicit raw bytes and null-mm display provenance. PPID uses parent tgid.",
                              corpora=["synthetic-linux-x64", "synthetic-linux-x86-pae", "official-linux-sample-1"],
                              comparison="selected_92_captured_and_39_null_mm_displays_match_two_read_errors_preserved", validation_record="docs/linux-psaux.md",
                              gaps=["Full Linux version/architecture and failure/parameter coverage pending", "Two argument read errors remain distinct from reference nulls", "Null mm brackets are derived from comm, not proof that a task was originally a kernel thread"])
        if identifier == "windows.vadinfo.VadInfo":
            plugins[-1].update(applicability="Modern RTL_AVL_TREE VADs with exact MMVAD_SHORT types and native MmProtectToValue table; PID sets and inclusive address filtering.",
                              gaps=["Old VAD layouts and complete version/architecture coverage pending", "Extraction has selected x64 region byte comparisons only; full failure/version/parameter acceptance pending", "Path read errors remain distinct from baseline nulls; see docs/windows-vad.md"])
        if identifier == "linux.proc.Maps":
            plugins[-1].update(applicability="mmap lists or typed Maple Tree nodes; exact VMA/filesystem symbols. Full view retains page offsets beyond positive inode size; include-past-eof=false selects the baseline heuristic view.",
                              gaps=["Maple Tree has synthetic ABI tests only; real modern kernels, pivot/meta validation and complete versions pending", "Extraction has selected legacy x64 region byte comparisons only; full parameter/version acceptance pending", "Full parameter combinations and scoped/raw path semantics need complete acceptance; see docs/linux-maps.md"])
        if identifier == "windows.dlllist.DllList":
            plugins[-1].update(applicability="Active process PEB load-order lists in independent process spaces; native symbol layouts and minimal declared WoW64 loader fields. Read failures remain diagnostics.",
                              gaps=["Full Windows version/architecture and Python regex semantics pending", "WoW64 LoadTime/LoadCount deliberately unavailable until verified 32-bit layouts exist", "Physical offset process scanning, full PE dump acceptance and timeline export pending"])
        if identifier == "windows.pedump.PEDump":
            plugins[-1].update(applicability="Mapped Intel PE32/PE32+ images with resident, bounded headers. Explicit process roots or kernel/typed session roots; 256MiB image limit. Independent PID extraction failures retain rows and allow remaining selected processes.",
                              corpora=["synthetic-windows-x64","synthetic-pe32-pe32plus","official-windows-10-19041"],
                              comparison="selected_process_PE_bytes_match_kernel_ImageBase_difference_explained",validation_record="docs/pe-reconstruction.md",
                              gaps=["Kernel/session ImageBase retains canonical high bits; differs explicitly from pinned baseline", "Full architecture/version/session mapping and failure/parameter coverage pending", "Uncaptured or invalid headers fail rather than producing empty PE files; see docs/pe-session-validation.json"])
    infrastructure = []
    for group, directory in [("layers", "volatility3/framework/layers"), ("symbols", "volatility3/framework/symbols"),
                             ("renderers", "volatility3/cli"), ("automagic", "volatility3/framework/automagic")]:
        for path in sorted((source / directory).rglob("*.py")):
            if path.name == "__init__.py":
                continue
            if group == "renderers" and path.name not in ("text_renderer.py", "volshell.py") and "volshell" not in path.parts:
                continue
            module = path.relative_to(source).with_suffix("").as_posix().replace("/", ".")
            infrastructure.append({"id": module, "category": group, "source": path.relative_to(source).as_posix(),
                                   "status": "partial" if path.stem in ("physical", "intel", "lime", "elf", "crash", "intermed", "text_renderer") else "missing",
                                   "accepted": False, "applicability": "See locked source; source-module inventory includes support modules.",
                                   "corpora": [], "comparison": "not_run"})
            if module == "volatility3.framework.automagic.linux":
                infrastructure[-1].update(status="partial", corpora=["synthetic-linux-x64", "official-linux-sample-1"],
                                          comparison="selected_kernel_identity_only", validation_record="docs/linux-discovery.md")
            if module == "volatility3.framework.layers.avml":
                infrastructure[-1].update(status="partial", corpora=["synthetic-avml-v2", "official-linux-sample-1-reencoded-avml"],
                                          applicability="AVML v2 inclusive physical regions and Snappy framed data with 64KiB decoded frame bounds; CRC32C on reads, exact stored-length trailers and bounded random-access cache.",
                                          comparison="reencoded_physical_bytes_and_selected_entities_only", validation_record="docs/avml.md")
            if module in ("volatility3.framework.automagic.windows", "volatility3.framework.automagic.pdbscan"):
                infrastructure[-1].update(status="partial", corpora=["synthetic-windows-crash-x86-pae-x64", "official-windows-10-19041"],
                                          applicability="Windows complete/bitmap dumps with usable header root/list anchors; KDBG or validated module-list/PE/symbol discovery.",
                                          comparison="selected_kernel_identity_and_entities_only", validation_record="docs/windows-discovery.md")
            if module in ("volatility3.framework.layers.msf", "volatility3.framework.symbols.windows.pdbconv"):
                infrastructure[-1].update(status="partial", corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"],
                                          comparison="selected_types_and_entities_only", validation_record="docs/pdb-symbols.md")
    for identifier in ("source.file", "source.http", "source.https", "source.ftp", "source.s3", "source.gs", "source.leechcore",
                       "symbols.pdb-msf", "symbols.dwarf", "symbols.local-index", "symbols.pdb-conversion-cache", "symbols.isf.zip", "symbols.isf.gzip", "symbols.isf.xz", "symbols.auto-download",
                       "exploration.address-space", "exploration.types", "exploration.search", "exploration.disassembly", "paging.swap",
                       "export.extracted-files", "extension.yara", "extension.capstone", "renderer.arrow", "renderer.mermaid"):
        infrastructure.append({"id": identifier, "category": "acceptance", "status": "partial" if identifier in ("source.file", "symbols.pdb-msf", "symbols.dwarf", "symbols.local-index", "symbols.pdb-conversion-cache", "symbols.auto-download", "symbols.isf.zip", "symbols.isf.gzip", "symbols.isf.xz", "exploration.types", "exploration.address-space", "exploration.search") else "missing",
                               "accepted": False, "applicability": "Baseline prerequisites and exact semantics must be verified on official or reproducible VM corpus.", "corpora": [], "comparison": "not_run"})
        if identifier == "export.extracted-files":
            infrastructure[-1].update(status="partial",corpora=["synthetic-artifact-lifecycle","official-linux-sample-1","official-windows-10-19041"],
                                      applicability="Task-bound extraction sink, case schema v2, padding logs, bundle v2 and Windows modern VAD/Linux VMA dumps; selected x64 regions only.",
                                      comparison="selected_region_bytes_and_storage_tests_only",validation_record="docs/artifacts.md")
        if identifier == "symbols.dwarf":
            infrastructure[-1].update(corpora=["synthetic-dwarf-c-elf-macho"], comparison="selected_layouts_only",
                                      validation_record="docs/native-symbols.md")
        if identifier == "symbols.local-index":
            infrastructure[-1].update(corpora=["synthetic-linux-x64", "synthetic-windows-x64"], comparison="kernel_identity_tests_only",
                                      validation_record="docs/native-symbols.md")
        if identifier == "symbols.pdb-msf":
            infrastructure[-1].update(corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"], comparison="selected_types_and_entities_only",
                                      validation_record="docs/pdb-symbols.md")
        if identifier in ("symbols.auto-download", "symbols.pdb-conversion-cache"):
            infrastructure[-1].update(corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"],
                                      applicability="Windows only; explicit or verified crash-discovered DTB/kernel base and resident exact PE CodeView identity; HTTPS uncompressed PDB transport.",
                                      comparison="selected_entities_and_cache_failures_only", validation_record="docs/pdb-symbols.md")
    return {"schema": "gomem.capabilities/v1", "baseline": lock, "release": "development-preview", "plugin_count": len(plugins),
            "accepted_plugins": 0, "plugins": plugins, "infrastructure": infrastructure}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.dumps(generate(args.source), ensure_ascii=False, indent=2) + "\n"
    target = ROOT / "docs/capabilities.json"
    if args.check:
        if target.read_text() != data:
            sys.exit("capability inventory differs; regenerate it")
    else:
        target.parent.mkdir(exist_ok=True)
        target.write_text(data)
    print(f"{json.loads(data)['plugin_count']} upstream plugin classes inventoried; none certified complete")


if __name__ == "__main__":
    main()
