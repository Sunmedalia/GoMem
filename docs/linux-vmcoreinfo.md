# Linux VMCOREINFO ELF notes (development preview)

`linux.vmcoreinfo` implements a native physical-layer counterpart to the pinned Volatility 3 v2.28.2 `linux.vmcoreinfo.VMCoreInfo`. No symbols or kernel address translation are required, including for the user's ARM64 LiME image. The capability remains **partial**; arbitrary virtual primary layers and full acceptance remain pending.

```sh
bin/gomem analyze linux.vmcoreinfo --image memory.raw --offline --case case-001 --format jsonl
```

The scanner searches enumerated physical ranges for the exact aligned `VMCOREINFO\0\0` signature. It handles matches spanning read chunks and physically adjacent segments, preserving physical coordinates across container file offsets; holes never join signatures. The preceding 12-byte little-endian ELF note header must declare name size 11, type zero and a nonzero descriptor size. The descriptor starts after the 12 aligned name bytes, must start with `OSRELEASE=`, and must consist entirely of Python `string.printable` ASCII bytes. NUL is not printable, even after a blank line. These checks follow the fixed helper, including its little-endian ELF note type for both 32- and 64-bit formats.

Parsing follows CR/LF/CRLF/VT/FF line breaks, stopping at the first empty line. Keys and string values retain whitespace; the first equals sign separates them, so empty keys and additional equals signs in values are retained. Duplicate keys preserve their first insertion position and use their final value and line coordinates. `SYMBOL(` keys and `KERNELOFFSET` parse hexadecimal; `NUMBER(`, `LENGTH(`, `SIZE(`, `OFFSET(` and `PAGESIZE` use Python base-zero numeric syntax. Signs, radix prefixes and valid underscores are supported; legacy nonzero leading-zero octal is rejected. Hexadecimal keys display lower-case signed `0x` strings; other numeric keys display decimal. `TypedValue` retains the exact integer as a decimal string beyond uint64/JSON numeric precision. String keys keep an explicitly inapplicable numeric cell.

Each `entry` has the upstream Offset, Key and Value plus the final raw line's `LineOffset` and `LineLength`. `note_observation` records capture the entire 12-byte header plus 12-byte aligned name and the descriptor, with raw bytes, virtual-independent physical addresses, requested/captured lengths and read status. Rejected header/tag/printability candidates remain observations with explicit status. Their omission from the fixed plugin's rendered table is represented explicitly by `docs/diff/linux.vmcoreinfo.json`; unknown native record types are rejected by that comparator. A summary reports candidates, parsed tables, entries, ordinary rejections and diagnostic counts.

Native defaults are `max-candidates=131072`, `max-rows=1000000` and `max-descriptor=1048576`. Candidate/row maxima are 1000000; the descriptor maximum is 16777216 bytes. The parser checks cancellation and caps distinct keys before building an oversized result. Numeric input is limited to 65536 radix digits, with the fixed reference interpreter's default 4300-digit decimal input bound. These are explicit resource limits, rather than silent truncation. Extreme nondecimal integers converted to decimal can differ from interpreters with another integer-string conversion setting; such inputs have not established release parity.

Header underflow, incomplete reads, malformed lines/numbers and native bounds emit failed diagnostics, preserving captured evidence and continuing independent notes where possible. Scan failure fails the task. Cancellation and output errors return immediately, retaining previously persisted rows. The fixed plugin may abort on malformed candidates; native partial output must not be interpreted as a complete scan. No-note scans legitimately complete with a zero-table summary.

Validation includes 268 fixed-source parser and unmodified plugin-renderer cases, synthetic raw images with chunk-crossing signatures, multiple notes, duplicate keys, values larger than 64 bits, invalid headers/tags/ASCII/numbers/lines, truncated descriptors, bounds, cancellation, output errors, sealed SQLite storage, cache replay and descriptor fuzzing. Reference tooling now accepts repeatable `--stacker` options and records the exact stacker list in its manifest; a unit test verifies argument termination before the plugin and preserves default behavior.

The two user's images both have positive physical-layer differentials:

- Debian RAW (decompressed SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`): one valid table, **47 entries**, no rejections or diagnostics.
- Kali ARM64 LiME (SHA256 `cf04d76ab9177d7ee355cc96020d29ae194c065c692304ff25e594ab510c639d`): one valid table, **111 entries**, plus two observed header-mismatch signatures and no failed diagnostics.

All Offset/Key/Value fields and enumeration order match the unmodified fixed plugin on equivalent physical layers. All six raw captures (two valid header/name captures, two descriptors, two rejected headers) and all 158 final-value line coordinates are independently reread. [The validation record](linux-vmcoreinfo-validation.json) retains source/image/output hashes, native summaries, cache equality and bundle checks.

The baseline's default Debian automagic chooses a LinuxIntel32e virtual primary and returns 94 entries from two aliases of the same physical table. The physical differential explicitly uses `tools/reference.py --stacker LimeStacker` so its saved configuration selects `physical.FileLayer`. Kali's baseline primary is a LiME physical layer. This selected-layer condition is part of the comparison; virtual aliases are neither merged nor silently discarded. Native arbitrary virtual-layer scanning is still pending.

```sh
python3 tools/build_vmcoreinfo_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" GOMEM_KALI_IMAGE="$PWD/images/kali.raw" go test ./internal/engine -run 'Test(OfficialVMCoreInfo|VMCoreInfo)' -count=1 -v
make check
```

Successful ARM64 physical note parsing does not provide an ARM64 translator or establish process/network/plugin support for that kernel. Other note-layer/endian/version conditions, the full damaged-image matrix and release acceptance remain pending.
