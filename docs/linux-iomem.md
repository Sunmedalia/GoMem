# Linux I/O memory resources (development preview)

`linux.iomem` implements native traversal corresponding to the pinned Volatility 3 v2.28.2 `linux.iomem.IOMem`. It requires matching Linux symbols, a supported kernel address space, `iomem_resource`, and the `resource` type with `name`, `start`, `end`, `child`, and `sibling` fields. Missing symbols/layout fails explicitly. This capability remains **partial**, with no release acceptance claimed.

```sh
bin/gomem analyze linux.iomem --image memory.raw --symbols kernel.json --case case-001 --format jsonl
```

Traversal includes the root itself, visits children before siblings, and preserves enumeration order. `Start` and `End` are inclusive unsigned resource extents, serialized as lossless hexadecimal addresses. Inverted ranges and `0xffffffffffffffff` are retained unchanged. Field offsets and widths come from symbols; synthetic x86/PAE tests include 64-bit extents with 32-bit pointers.

Each resource has its object `Offset`, traversal `ParentOffset`, `Depth`, and sealed evidence `parent_id`. Parentage comes from the traversed child/sibling links, not a separately trusted `resource.parent`. Five field captures record their virtual addresses, raw bytes, read status and decoded values. `NameEvidence` retains up to 128 contiguous bytes, address, captured/requested lengths, and read errors. Names follow the fixed helper's UTF-8 replacement decoding, stopping at the first NUL or U+FFFD. Empty names and capped unterminated names remain valid displays. A readable prefix before a hole remains usable; incomplete capture is explicitly recorded even if a NUL precedes the hole.

The traversal uses an iterative stack and a fresh seen set for every run. Native limits are `max-nodes=131072` (1..1000000 visits, including repeated/damaged nodes) and `max-depth=256` (1..1024, root depth zero). Repeated nodes and exceeded limits emit diagnostic evidence. Unreadable extents emit the available captures and stop that branch. A bad child/sibling link does not suppress an independently readable link. Name or link failures retain the resource with an error. All such failures mark the task failed; cancellation and output errors propagate. The final summary counts resource rows, visits and diagnostic observations, including resources with read issues; it does not assert that the memory was fully intact.

The fixed helper recursively traverses resources and has a mutable default `seen` set. The native implementation intentionally avoids cross-run state and Python recursion limits. The development oracle passes an explicit fresh set to the unmodified helper. Object construction/name reads in the oracle are mocked, so those cases establish traversal and display expectations rather than real-memory acceptance. The fixed plugin can abort on unreadable link access, while the native reader retains partial evidence and continues independent branches. The native seen check occurs before reading duplicate resources; their fields are not reread.

## Validation

- 17 pinned-source oracle cases cover root/child/sibling ordering, root siblings, self/ancestor cycles, shared nodes, inverted/full-width extents, empty/NUL/UTF-8/replacement/capped names, and invalid name/child pointers.
- Native tests cover those cases through real synthetic paging, nonstandard offsets, x64/x86/PAE, partial name captures (with and without a NUL), missing symbols/layout, unreadable extents/links, limits, cancellation, output failure, persisted evidence verification and cache reuse.
- The user-provided Debian sample (`images/linux-sample-1.bin.gz`, decompressed SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) yields **116 resources**, 116 visits, zero diagnostic observations. Name, Start, End, depth and all ancestor paths match the **unmodified** pinned reference. All **696** field/name captures are independently reread from the kernel layer. [The validation record](linux-iomem-validation.json) records reference and output digests, fresh/cache equality and independent bundle verification.
- `docs/diff/linux.iomem.json` compares multisets and composite Name/Start/End ancestor paths. It does not compare native object offsets, which the reference renderer omits. Structurally identical duplicate subtrees cannot prove unique underlying object identity. Unknown record types and absent parents are errors, not discarded rows.

```sh
.cache/reference-venv/bin/python tools/build_iomem_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxIOMem|OfficialLinuxIOMem)' -count=1
make check
```

Real modern kernels, native x86/PAE images, ARM64, and complete corrupted metadata/memory-smear behavior remain pending. The Kali ARM64 user image still has no implemented address translator; this Linux x64 differential does not establish Kali support.
