# Linux interrupt descriptor inspection (development preview)

`linux.check_idt` natively implements the selected interrupt-entry inspection of Volatility 3 v2.28.2 `linux.malware.check_idt.Check_idt`. It emits Index, Address, Module and Symbol, with descriptor bytes, source module observations and coverage. Attribution and a missing symbol are investigation evidence, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.check_idt --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The symbol pointer width determines descriptor type priority. For 32-bit symbols, try `gate_struct`, `desc_struct`, `gate_struct32`; for 64-bit symbols, try `gate_struct64`, `gate_struct`, `idt_desc`. The first existing type wins. Its size must be 1..4,096 bytes. Missing types fail explicitly, while the fixed plugin logs the unsupported layout and returns an empty table. A corrupt first-choice type is not bypassed in favor of another name.

The table starts at the relocated `idt_table` symbol. Of its 256 entries, only indices **0..19 and 128**, in that order, are inspected, matching the fixed generator. The descriptor stride comes from the chosen symbol type. Each entry-start readability probe captures one byte, followed by the actual member reads. No claim is made about unselected entries or the readability of unused descriptor padding.

When a descriptor has `a`, the address is `(b & 0xffff0000) | (a & 0xffff)`; this path takes priority even if split fields exist. Otherwise, `offset_low`, `offset_middle` and optional `offset_high` are combined, with absent high bits set to zero. The split result is masked to low 48 bits on x64 or low 32 bits on x86/PAE, matching the baseline. The raw high field and canonical descriptor coordinate remain evidence. Zero addresses remain rows with unavailable module/symbol and status `uninitialized_zero`.

Nonzero handlers reuse the [module source and range helpers](linux-modxview.md): Lsmod, SysFs and Scanner, followed by the symbol-derived `__kernel__` range. First-seen masked bases win; the first overlapping half-open range supplies the module. Every match remains in `Matches`. Exact kernel symbols and ELF32/64 module symbols are resolved using the [shared symbol policy](linux-kthreads.md), including the inclusive 4,097-entry module symbol window and 512-byte name captures. Interior addresses do not receive a nearest-symbol guess.

The pinned module helper has a known ownership error: after selecting the first matching range, it uses the final range object's offset for non-kernel symbol resolution. GoMem resolves against the **selected matching module** and records both objects in `symbol_owner_policy`. The IDT fixed-source oracle retains the original generator output and separately calls the unmodified module-symbol helper on the selected owner. Synthetic module symbols match that selected-owner helper; complete generator symbol parity is not claimed. Real Debian entries all belong to the kernel and are unaffected by this difference.

`idt_entry` records contain decoded entries, including zero/unattributed entries. `entry_observation` preserves unreadable entry-start or member reads. Module source/candidate/selection observations are also retained, followed by a summary of checked, zero, unattributed, missing-symbol, unreadable and overlapping entries. `EntryAddress`, `DescriptorType`, symbol digest, raw field captures and source diagnostics make each attribution traceable. Symbol-derived bounds and coordinates are labeled metadata, not bytes read from the image.

Unreadable entries, partial fields, unavailable required module sources, kernel bounds and module symbols fail the task while keeping partial results. The fixed generator can silently skip an invalid entry start or stop on a later exception; native inspection continues across independent entries. This stricter failure policy prevents an empty result from implying successful coverage. Cancellation and output errors stop immediately, including during module discovery or after the first IDT row. Shared limits are `max-nodes=131072` (1..1,000,000) and `max-scan-bytes=268435456` (1..8 GiB); module captures retain the 4,096-byte shared bound.

On the user's Debian 3.2 x64 RAW image, all **21 entries** match the four baseline columns and order. All resolve to `__kernel__` and exact symbols, with no read errors or overlaps. Native output contains 570 records, and the corpus test independently rereads **1,899 complete raw captures**. Persisted row seals, cache reuse, byte-identical CLI cache output and a task evidence bundle verify. This is a normal-image control, not real malicious-IDT acceptance.

Fifteen synthetic combinations cover x64/x86/PAE and packed, split-low, split-high, mixed-field precedence and entry-start holes. Sixteen fixed type-selection cases exercise every presence combination in each priority list; ten fixed generator profiles cover width/layout decisions, zero entries, interior symbols, module symbols, unknown ranges and end-exclusive bounds. Native index/address/module/order match the generator; module symbols follow the selected-owner comparison described above. Synthetic rows retain 131..152 complete reread captures per profile. Failures include unsupported/invalid types, missing globals, missing fields/sources/bounds, partial field bytes, unavailable module symbols, parameter limits, cancellation and output failures. Failed tasks are persisted and never reused as completed results. `FuzzLinuxIDTDescriptor` passed 539,015 mutated byte/layout executions.

```sh
python3 tools/build_idt_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxIDT|OfficialLinuxIDT)' -count=1 -v
make check
```

[Validation record](linux-idt-validation.json) and [field mapping](diff/linux.check_idt.json) preserve the comparison scope. Real altered IDTs, modern/32-bit real kernels, all damaged-layout behaviors, full aliases/parameters and complete capability acceptance remain pending. The user's Kali ARM64 LiME image still lacks a supported virtual translator and actual matching kernel symbols for this Intel-only check; physical VMCOREINFO validation does not establish IDT support.
