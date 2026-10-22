# Native mapped-PE exports (development preview)

`pkg/pe.ReadExports` provides bounded export-table acquisition from an Intel PE32 or PE32+ memory layer. It is a shared parsing component for future `windows.pe_symbols`, suspended-thread and related address-attribution analysis. These plugins are not implemented by this change and retain their matrix status.

The parser validates the image through the existing `pe.Plan` reconstruction planner, then reads the declared export directory, address/name/ordinal arrays, DLL name, symbol names and forwarder strings. It reads mapped RVAs directly, without loading or padding the whole image. Function bodies are not dereferenced. Names retain original bytes rather than guessing a text encoding.

## Semantics and evidence

Named exports follow name-table order, including aliases. Remaining ordinal-only exports follow export-address-table order. Zero-RVA slots are omitted. Ordinals use widened arithmetic so a large ordinal base cannot wrap. Duplicate function addresses remain separate entries. `NameAt` uses exact absolute addresses and returns the first matching export's name, matching the pinned `ExportSymbolFinder`; it does not select a nearby symbol. `AddressForName` returns the first matching named export. Lookup name bytes are copied so callers cannot mutate the index through a lookup result.

An RVA inside the export directory identifies a forwarder. Its original NUL-terminated string remains metadata, and the reported address is the forwarder string's address. Recursive module/ordinal resolution is not performed. Symbol consumers must distinguish this metadata from executable code and must implement the baseline's PDB-first resolution separately.

The API always returns an `ExportTable`, including on failure. `Complete=true` with no entries establishes a successfully parsed empty directory; `Complete=false` and a non-nil error retain any preceding complete entries as partial evidence. Consumers must check both the error and completeness before caching a result as successful. The table itself is not a case database or a plugin result. CLI consumers must convert addresses into the structured evidence model's hexadecimal address values.

`ExportLimits.Observe` receives every actual acquisition: address, requested length, owned raw byte copy and read error. It can persist evidence or stop analysis by returning an error. Short reads are errors even when the layer returns nil. Cancellation and observer failure stop subsequent acquisitions. Budget exhaustion before an acquisition reports an error without fabricating a read record. Strings are read through the first NUL only, so an unrelated hole immediately after a terminator does not invalidate the name. Holes in function bodies likewise do not invalidate export metadata.

Default bounds are 65,536 entries, 16 MiB captured bytes and 4,096 bytes per terminated string (including room for the terminating NUL). Allowed bounds are 1..1,000,000 entries, 1..1 GiB captured bytes and 1..65,536 string bytes. Both declared array counts and total emitted entries are bounded; aliases consume output entries. Array extents, target/name RVAs, directory size and forwarding strings must fit their declared image/directory. The existing 256 MiB image and Intel machine/header limits apply.

Malformed tables produce explicit failures instead of pefile's silent skipping/truncation behavior. Names are retained as raw bytes; pefile's display-name character heuristic is not applied. Consequently successful normal-table comparison is not a claim of full malformed-input parity or full upstream PE extension support.

## Verification

`tools/build_pe_exports_oracle.py` checks the fixed Volatility source digest and uses pefile 2024.8.26 plus the unmodified `ExportSymbolFinder`. Eighteen deterministic fixtures combine PE32/PE32+ with aliases, ordinal-only exports, duplicate addresses, zero named targets, empty/absent directories, named/ordinal forwarders and oversized ordinal-base arithmetic. Native tests compare ordered entries and exact lookup results. Every observed byte is independently compared to fixture memory.

Fault tests inject a partial read at every normal acquisition occurrence, and cancel or reject output at every observer boundary. Further controls cover invalid ordinals/RVAs/arrays, unterminated strings, malformed directories, invalid read counts, byte/entry/string budgets, nil sources and address overflow. An incomplete name table retains preceding entries with `Complete=false`. Unrelated holes prove that function bodies and bytes after a NUL are not speculatively read. Fuzzing enforces acquisition/output/string/image bounds.

The supplied Windows 10 19041 dump (SHA256 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`) provides a real x64 control. The saved upstream reconstructed kernel PE at `0xfffff8043601f000` has SHA256 `39cf271274ae4d6a8732804773ee175f3fe2e1dcebc54ff0c74e6b0d64091f5e`. pefile and the pinned finder produce 3,093 exports and exact-name lookups. Native parsing reads the kernel directly from the original dump: all ordered entries and lookups match; 70,938 reads and 103,424 captured bytes were independently reread. The reconstructed artifact's padding is not substituted for native unreadable memory.

```sh
.cache/reference-venv/bin/python tools/build_pe_exports_oracle.py --check
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
go test ./pkg/pe -run '^$' -fuzz FuzzMappedPEExports -fuzztime 10s
```

CI installs the pinned pefile dependency and checks the oracle and fuzz target. Optional corpus verification requires `GOMEM_CORPUS_DIR`, `GOMEM_PE_EXPORT_REFERENCE` (generated JSON), and `GOMEM_PE_EXPORT_MAPPED` (the hashed upstream mapped PE):

```sh
.cache/reference-venv/bin/python tools/build_pe_exports_oracle.py \
  --mapped-pe PATH_TO_MAPPED_PE --mapped-base 0xfffff8043601f000 \
  --output .cache/pe-exports-validation/kernel-reference.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_PE_EXPORT_REFERENCE="$PWD/.cache/pe-exports-validation/kernel-reference.json" \
GOMEM_PE_EXPORT_MAPPED=PATH_TO_MAPPED_PE \
go test ./internal/engine -run '^TestOfficialWindowsKernelPEExports$' -count=1 -v
```

No plugin is newly accepted. Real PE32/forwarded-export corpora, process/module collection, PDB-first fallback and broader version/corruption/extension acceptance remain pending. Measurements are in [pe-exports-validation.json](pe-exports-validation.json).
