# Linux network operation handlers (development preview)

`linux.check_afinfo` checks network operation pointers against **exact kernel symbols** using native Go. It maps to the pinned Volatility 3 v2.28.2 `linux.malware.check_afinfo.Check_afinfo`. A reported handler lacks an exact symbol; this is a lead for investigation, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.check_afinfo --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The layout test is the presence of `tcp_seq_afinfo.seq_fops`, matching the baseline rather than guessing a kernel version. Legacy globals are inspected in this order: `tcp6_seq_afinfo`, `tcp4_seq_afinfo`, `udplite6_seq_afinfo`, `udp6_seq_afinfo`, `udplite4_seq_afinfo`, `udp4_seq_afinfo`. Modern globals are `raw_seq_ops`, `udp_seq_ops`, `arp_seq_ops`, `unix_seq_ops`, `udp6_seq_ops`, `raw6_seq_ops`, `tcp_seq_ops`, `tcp4_seq_ops`, `tcp6_seq_ops`, `packet_seq_ops`. Absent globals are explicit optional observations; present globals require typed metadata. Typed structure globals and pointers are supported, as are embedded or typed-pointer operation containers.

Legacy checks inspect `seq_fops` when present, then independently inspect `seq_ops`. If there is no `seq_ops`, they inspect `seq_show`; if neither sequence field exists, the task fails after preserving preceding file-operation results. When both sequence fields exist, `seq_ops` wins. File-operation and sequence-operation member lists come from the declared `file_operations` and `seq_operations` types. Members starting with `__UNIQUE_ID_rh_kabi_hide` are recorded without reading their value. Ordinary zero members are unimplemented operations and do not undergo symbol lookup. Other pointers use absolute exact-symbol membership. The special `seq_show` path renders Member as `show`, uses the **relative** exact-symbol index without the kernel slide, and also checks zero. These differences are intentional fixed-source semantics.

Both symbol indexes use the architecture address mask: low 48 bits on x64 and ARM64, or low 32 bits on x86/PAE. Evidence retains full canonical addresses and sorted exact aliases, the symbol digest and lookup mode. Interior addresses receive no nearest-symbol guess.

The symbol layer now preserves member declaration order from ISF JSON object keys, DWARF and CodeView. `Type.MemberNames()` ignores deleted or duplicate order entries; fields added programmatically without order are appended alphabetically. ISF serialization emits the standard ordered `fields` object, with no extra schema property. Repeated ISF field names keep the first insertion position and last value, matching Python JSON dictionary behavior. Tests cover declaration order distinct from name/offset order, round trips, mutations, malformed input and selected compiled DWARF/PDB types. This is selected order validation, not full symbol-system acceptance.

Output contains `symbol_observation`, `container_observation`, `member_observation`, flagged `handler`, `diagnostic` and `summary` records. Every readable member decision is retained, including zero and known pointers, so an empty handler table can be checked for actual inspection coverage. `FieldEvidence` contains bounded raw field/container captures, or symbol metadata for global coordinates. Symbol-derived metadata is not represented as bytes read from memory. Summary counts distinguish present/absent globals, visits, checks, zeros, ignored members, flags and errors.

`max-members=65536` (1..1,000,000) bounds considered members across all globals, including ignored members. The shared capture bound is 4,096 bytes per field/container. Null operation pointers, missing target metadata, field failures and bound exhaustion preserve available evidence and fail the task. Independent globals can continue after a source error; the fixed generator may terminate at its first exception. Complete equivalence for damaged containers and all declared target extents remains pending. Cancellation and output errors stop immediately.

The user's Debian 3.2 x64 RAW image is a real **negative control**: the unmodified fixed plugin emits zero handlers. A separate development probe delegates the original `_check_members` implementation and records its inputs and decisions. Its plugin table matches the separate unmodified run. Native output has 199 records: 6 globals, 12 containers, 180 member observations and one summary. All 180 member decisions, five mapped fields and order match the probe; 132 are zero and 48 have exact symbols. The Go corpus test independently compares all 48 alias lists and rereads 192 complete raw captures. The probe does not cover the direct `seq_show` branch; synthetic fixtures and fixed-source generator oracles cover that branch. A zero handler result does not establish that the image is clean.

There are 33 synthetic combinations of x64/x86/PAE paging and 11 profiles, plus 12 fixed generator cases. They exercise legacy/modern layouts, embedded/pointer fields, `seq_show` precedence and zero behavior, absent globals, kernel slides and relative-symbol lookup. Failure tests cover fops-only layouts, null/unreadable/untyped pointers, partial reads, bounds, cancellation and output errors. Persisted rows and completed-task cache reuse verify. The real CLI cache output is byte-identical; the exported task bundle verifies independently. `FuzzISF` passed 862,196 executions after the order-preserving parser change.

```sh
python3 tools/build_afinfo_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxAFInfo|OfficialLinuxAFInfo)' -count=1 -v
make check
```

[Validation record](linux-afinfo-validation.json) and the two [handler](diff/linux.check_afinfo.json)/[member observation](diff/linux.afinfo-observations.json) mappings retain the comparison scope. Real positive hooks, full architecture/layout/error coverage and deprecated-alias acceptance remain pending. The local Kali 6.8.11 ARM64 smoke run completes with 36 member observations, 10 symbol observations and one summary.
