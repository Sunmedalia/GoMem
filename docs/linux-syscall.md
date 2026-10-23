# Linux system call tables (development preview)

`linux.check_syscall` reads Linux system-call tables in native Go. It corresponds to Volatility 3 v2.28.2 `linux.malware.check_syscall.Check_syscall` **when Capstone is not available**. A handler named `UNKNOWN` has no exact symbol at that address. That is a lead, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.check_syscall --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The fixed plugin first tries to size a table by disassembling `sysenter_do_call` or `system_call_fastpath` and reading a `CMP` immediate. GoMem does not ship that disassembler. Every sizing record says `NativeDisassembly=unavailable`, and the count falls back to the same second method: the minimum positive value among the number of symbols prefixed `__syscall_meta__` and the pointer-sized distance from the table's unslid symbol address to the next higher symbol. A distance that is not a multiple of the pointer width is truncated. If both counts are zero, the table is not silently treated as empty; the task fails.

`sys_call_table` is required. Its display name is `64bit` or `32bit` according to the symbol pointer width. `ia32_sys_call_table` is optional and, when present, is named `32bit`. Its absence is an explicit observation. Table Address is the unslid symbol address. Reads use that address plus the Linux kernel slide. Full canonical handler addresses stay in the evidence; comparisons with the fixed JSON renderer mask x64 and ARM64 addresses to the low 48 bits.

Each selected pointer is captured once and decoded from those bytes. Exact symbols are indexed by the relocated address and the architecture mask, sorted by name, and rendered with the component after the first `!`, matching the fixed split. Address zero is a normal pointer and can have a symbol. An address with no exact symbol is `UNKNOWN`; nearby functions are not guessed. `max-entries=65536` (1..1,000,000) rejects an inferred table larger than the bound before reading it.

Unreadable entries keep the partial read and the task fails, while later entries are still visited. The fixed generator logs those entries and continues successfully. Missing `sys_call_table`, an unknown pointer width, or cancellation and output errors stop without pretending the table was checked. Completed tasks are cached; failed tasks are not reused as success.

On the user's Debian 3.2 x64 RAW image, the unmodified reference was run in an environment without Capstone. Both sides therefore use metadata/next-symbol sizing. The image has no `__syscall_meta__` symbols. The next symbols select 312 entries for `sys_call_table` and 349 for `ia32_sys_call_table`. All 661 rows match Table Address, Table Name, Index, Handler Address, and Handler Symbol, in order, after the low-48 mask. None are `UNKNOWN`. The corpus test rereads all 661 pointer captures. Cache output is byte-identical and the task bundle verifies. This does not show what a Capstone-enabled reference would have counted, and it is not a hooked-table sample.

Synthetic coverage is 24 combinations of x64, x86, and PAE with eight profiles: both sizing inputs, metadata shorter than the next symbol, no following symbol, no ia32 table, kernel slide, a qualified symbol, and a symbol at zero. Sixteen fixed-source cases check the size arithmetic, including a non-multiple distance. Positive runs reread every pointer and reuse cache.

```sh
python3 tools/build_syscall_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxSyscall|OfficialLinuxSyscall)' -count=1 -v
make check
```

[Validation record](linux-syscall-validation.json) and the [field mapping](diff/linux.check_syscall.json) keep this scope. Capstone sizing, real modified tables, native 32-bit images, an independent ARM64 differential, and complete acceptance remain pending. The local Kali ARM64 smoke run completes with 403 selected syscall rows, two table observations and one summary.
