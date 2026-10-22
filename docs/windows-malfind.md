# Windows Malfind (development preview)

`gomem analyze windows.malfind --image MEMORY --case CASE` implements the locked Volatility v2.28.2 `windows.malware.malfind.Malfind` selection pipeline in Go. The deprecated `windows.malfind.Malfind` name delegates to the same implementation with separate requested-name provenance and cache. This is an executable-region heuristic; a finding does not establish malicious injection.

## Selection and evidence

The plugin walks active processes and their native process page roots, collecting VADs without acquiring irrelevant mapped-file paths. `pid` is a comma-separated filter. Protection strings come from the typed `MmProtectToValue` table. A protection containing both EXECUTE and WRITE selects the first route. Other executable regions require the first hardware-dirty page, probed in 4 KiB steps with the pinned exclusive end; an invalid translation aborts this route for that region. A candidate must then have private memory and tag `VadS`, or shared memory whose protection is not exactly `PAGE_EXECUTE_WRITECOPY`.

For each candidate, the plugin examines full 4 KiB pages from the VAD start through its inclusive end, skipping unreadable pages and selecting the first readable nonzero page. All-zero or entirely unreadable regions produce no finding, but unreadable acquisitions fail coverage. Private-memory and commit-charge alternatives support the tested direct, u/u1 and Core layouts. Native list, symbol and VAD failures remain explicit rather than disappearing as successful empty output.

Findings retain PID, process name, inclusive Start/End, tag, protection, commit charge, private flag, first 64 bytes, notes and disassembly. The pinned note prefixes are `MZ`, `55 8b`, `55 48` and `55 89`; their exact strings are tested. Process identity/object offset, VAD object offset, nonzero-page coordinate and optional dirty-page coordinate/physical hardware leaf are additional evidence. Dirty leaf details include original physical entry address, entry value, width and mapped page size. A separate translator records actual physical page-table acquisitions; cache hits do not invent reads.

Go's native x86 decoder retains the original input bytes, origin and 32/64-bit mode, including tested WoW64 process fields. Decoder text is not claimed equivalent to Capstone syntax. If the first 64 bytes are unreadable but a later page selected the region, the finding remains, with typed missing hexdump, disassembly and notes plus the actual failed read. Upstream's padded zero bytes are not substituted for missing source bytes.

`memory_read` rows retain layer, coordinate, requested/captured lengths, original bytes and read errors. `diagnostic` rows preserve unavailable metadata; the terminal `summary` records processes, regions, probes, findings, missing pages and acquisition coverage. Cancellation or an output failure stops acquisition. Completed tasks replay sealed case-store results; failed tasks run fresh.

## Extraction and bounds

`--param dump=true` exports each selected region to the case artifact directory. Missing source pages produce explicit extraction gap records and zero-padding in the artifact, with partial status; source evidence retains the original failed acquisition. Actual reference extraction bytes are compared for normal and hole fixtures. No padding is presented as captured memory. `maxsize` defaults to 1 GiB per region; zero disables this size limit. Regions above the limit retain the finding with an explicit skipped extraction reason.

Task-wide native controls are `max-nodes` (131,072), `max-regions` (1,000,000), `max-pages` (16,777,216 dirty/nonzero probes) and `max-read-bytes` (512 MiB of captured metadata, process and page-table acquisitions). Exhaustion fails coverage and stops further source acquisition. These controls are native resource bounds, not upstream options. A dump also respects cancellation, output-stop and the acquisition budget.

## Validation and remaining gaps

`tools/build_windows_malfind_oracle.py` verifies the locked source-tree digest and executes the actual unmodified Malfind generator, injection-site helper, Windows process/VAD extensions, Intel translators and VadInfo extraction. Seventy x86/x64 cases cover private/shared/tag/protection distinctions, dirty and clean executable pages, invalid translation, first/later zero or missing pages, note headers, Core/u1 precedence, WoW64, PID filters and separate process roots. Native PAE expands these to 105 combinations. Tests compare baseline columns, order, notes, hexdump, actual disassembly object input/mode and dump bytes, with explicit first-byte missing exceptions. Every raw capture is independently reread, then verified through sealed SQLite storage and successful byte-identical cache replay.

Fault tests exercise node/region/page/byte limits, cycles, metadata and process-root holes, short/invalid reads, failed-task retry, PID filters, extraction limits/gaps and cancellation/output-stop during metadata, probes, findings and extraction. The bounded pipeline fuzz target has completed 96,936 executions in ten seconds without failure.

The Windows 10 19041 control has six findings (one in PID 1944, five in PID 1956), matching ten selected fields against the pinned reference: PID, Process, Start, End, Tag, Protection, CommitCharge, PrivateMemory, Notes and Hexdump. All are private `VadS` regions with `PAGE_EXECUTE_READWRITE`. The run visits 120 processes and 19,999 VADs; 1,676 nonzero-page probes include 1,670 missing-page reads. Coverage remains failed/partial. This control does not exercise the dirty-page route. A separate PID-filtered extraction run compares all six files: 6,516,736 bytes exactly match the actual reference dumps. Of those, 5,173,248 bytes are explicit zero-padding across 1,263 missing-page gaps; equality of padded files does not establish source availability. All 19,377 acquisition calls in the extraction run are independently reread. `tools/verify_malfind_artifacts.py` binds to that verifier report and checks every artifact byte, zero-padding span, gap source coordinate/error and total against the original ordered dump calls. Tampered bytes, padding, gap coordinates/errors, provenance and missing/duplicate calls are rejected by tests. The reference environment lacks Capstone; its rendered Disasm hex is not evidence of decoder-text parity.

`tools/verify_pe_symbols --plugin windows.malfind` independently rebuilds process spaces from the original image, verifies seals/provenance, rereads every capture and checks each finding's original 64 bytes, disassembly input/origin/mode label, nonzero page and available hardware dirty leaf. The verifier binds its result to the complete JSONL hash and requires a terminal summary. See [the validation record](windows-malfind-validation.json) for the final run and differential hashes.

Broader Windows versions, real x86/WoW64, dirty-page corpora, all parameter/rendering behaviors and investigative positive/normal acceptance remain pending. This capability is partial; selected-field equality does not establish complete release acceptance.

```sh
.cache/reference-venv/bin/python tools/build_windows_malfind_oracle.py --check
go test -race ./internal/engine -run '^TestWindowsMalfind|^TestDeprecatedWindowsMalfind' -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzWindowsMalfindPipeline -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```
