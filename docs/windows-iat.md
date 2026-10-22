# Windows IAT imports (development preview)

`gomem analyze windows.iat --image MEMORY --case CASE` implements native main-image import enumeration for the locked Volatility v2.28.2 `windows.iat.IAT` command. It uses the active process list, each selected process's native page root, `_EPROCESS.Peb` and `_PEB.ImageBaseAddress`. It does not enumerate every loaded DLL or claim IAT-hook detection. `pid` is a comma-separated process filter. Kernel/process/PE reads remain local and read-only; Python and pefile are reference tools only.

## Coordinates and fields

The six baseline columns are PID, Name, Library, Bound, Function and Address. Descriptor and thunk order, duplicates and missing ordinal names are preserved. `Bound` is `TimeDateStamp != 0`, not an assessment of whether the captured pointer was modified.

The pinned generator reconstructs the mapped PE with ImageBase rewritten to its mapping address. pefile's import address already includes that base, and the generator adds it once more. GoMem preserves this behavior in **Address = ImageBase + IATSlot**, while **IATSlot = ImageBase + FirstThunk + original index × PE pointer width** retains the actual slot coordinate. `ResolvedPointer` holds the original captured slot value, including an available zero. An unreadable/unacquired slot stays typed missing. Neither Address nor IATSlot is automatically the called function's target address. All addresses are lossless hexadecimal strings.

Rows also retain the process object offset and identity, image base, descriptor RVA, selected lookup-table RVA, ordinal or hint, and explicit name-prefix flags. Known ordinal-only imports use the pinned pefile ordinal dictionaries for oleaut32.dll, ws2_32.dll and wsock32.dll; an unknown ordinal in a known dictionary becomes `ordN`, while unknown libraries retain a missing Function. Ordinal zero is skipped. The 696 name entries are MIT data with [copyright and license](../LICENSES/pefile-MIT.txt), generated and checked by `tools/build_iat_ordinal_names.py`. The parser and process engine execute in Go.

## Bounded parsing and failures

The parser reads mapped bytes on demand, without loading a whole image or inserting missing pages. PE reconstruction's mapped section layout informs this path, while source acquisitions always retain original bytes. It parses both lookup and address tables, selects a nonempty lookup table before fallback, and preserves the tested overlap, repetition, address-spread and ordinary invalid ordinal/name selection rules. The import directory size does not bound descriptor traversal in the pinned parser: a zero/small size can still produce imports. The optional-header directory count must include the import entry.

Names are acquired one byte at a time until a genuine NUL or the pinned 512-byte cap. Reaching the cap retains a valid bounded prefix with `NameTruncated`/`LibraryTruncated`, and fails complete coverage; no terminator is invented. Invalid function names are filtered, and invalid library characters produce the baseline `*invalid*` marker while raw bytes remain evidence. A damaged descriptor can be rejected without hiding independently readable later descriptors. Padded names from unreadable source pages are deliberately not emitted.

`memory_read` rows retain layer, offset, requested/captured length, bytes and errors; `diagnostic` rows link unavailable process/PE state to process identity. A null PEB is an explicit unavailable observation, not a source-read failure. Missing symbols, corrupt/truncated headers, unreadable PEB/image data, exhausted traversal limits and invalid source read counts fail coverage rather than becoming successful empty output. Useful imports remain stored. Cancellation/output failure stops further acquisition. Successful tasks can replay sealed case-store results; failed tasks execute again.

Native task budgets are `max-nodes` (131,072), `max-descriptors` (4,096), `max-imports` (100,000), `max-thunks` (2,000,000, including both tables' inspected terminators) and `max-read-bytes` (64 MiB of captured process/PE bytes). They bound the entire task; descriptor traversal checks the remaining budget before confirming its next terminator, so a result exactly at that bound can conservatively remain incomplete. Lists, tables, names, image size and arithmetic also have internal bounds. These are explicit native resource controls, not upstream parameters.

## Validation

`tools/build_iat_oracle.py` verifies the pinned source-tree digest and executes the actual unmodified IAT generator, process/PEB extensions, Intel translators, PE reconstruction and pefile import parsing. Ninety paged x86/x64 cases cover named/ordinal/known-missing imports, bound timestamps, empty/invalid tables, zero/small directory size, invalid names/DLLs, duplicate and repeated thunks, independent later descriptors, capped names, PID filters and two processes with separate page roots and different captured pointer/name bytes. Native tests add PAE, for 135 combinations. All six columns, order and missing values match. Every capture is checked against original physical fixture bytes and independent translators; store seals and exact successful replay are verified. Native read holes, short/invalid counts, list corruption, all task budgets, filters, failure retry, output-stop and cancellation are tested. Fuzz targets exercise both the parser and the complete bounded plugin pipeline.

The Windows 10 19041 control produced **6,404 native imports versus 6,406 reference imports**, with no native-only rows after typed ordinal-missing normalization. The complete differential therefore remains **unmatched**. The two reference-only HeapSetInformation rows belong to dllhost.exe PIDs 1968 and 2348: their DLL name starts at `0x7ff74df83ffa`, has the readable prefix `api-ms`, then faults at `0x7ff74df84000`. Reference reconstruction padding supplies a NUL at the missing byte. Native output keeps the failed acquisition instead of asserting that truncated library name. Both exceptions are linked to process objects, original descriptors, lookup entries and each prefix/fault evidence seal in [the validation record](windows-iat-validation.json).

The real run examined 120 processes (103 nonnull images, three null PEBs), 877 descriptors and 14,154 thunk inspections. It stored 6,404 imports, 95 diagnostics and 184,362 exact read captures (364,773 bytes), with 209 read faults and 301 coverage errors including contextual errors. The task failed with partial evidence. `tools/verify_pe_symbols --plugin windows.iat` independently reconstructs 120 process spaces, verifies all row seals, rereads all 184,362 original calls, checks every available captured pointer and validates actual/baseline coordinates. It binds the result to the full JSONL hash and requires a terminal summary. `tools/verify_iat_padded_names.py` uses that bound verification to explain the two source-backed differences without removing them or changing differential status.

Broader Windows builds, real x86/WoW64 images, malformed reconstruction/pefile corner cases, comprehensive parameter/failure acceptance and investigative validation remain pending. In particular, the pinned pefile parser has additional global descriptor-error and all-invalid-name thresholds; the native parser currently continues bounded independent descriptors/names and has not established those pathological stopping semantics. Native strict header bounds and preserved read errors are not identical to silent baseline skips or zero-padded reconstruction. This capability remains partial and is not formal release acceptance.

```sh
.cache/reference-venv/bin/python tools/build_iat_oracle.py --check
.cache/reference-venv/bin/python tools/build_iat_ordinal_names.py --check
go test -race ./internal/engine -run '^TestIAT' -count=1
go test -race ./pkg/pe ./internal/plugins ./tools/verify_pe_symbols
go test ./pkg/pe -run '^$' -fuzz FuzzMappedPEImports -fuzztime 10s
go test ./internal/plugins -run '^$' -fuzz FuzzIATPipeline -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```
