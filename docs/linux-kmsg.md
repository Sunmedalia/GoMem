# Linux kernel logs

Development preview; native `linux.kmsg` maps to Volatility 3 v2.28.2 `linux.kmsg.Kmsg`. This is a partial capability, not full acceptance.

All four pinned ring families have native readers: pre-3.5 text buffers, 3.5–3.11 `log` records, 3.11–5.10 `printk_log` records, and modern `printk_ringbuffer` descriptor/data rings. Dispatch follows symbol/type predicates in the pinned order, rather than guessing from a version banner. The kernel layer may use x64, x86, PAE or ARM64 symbol layouts. Text comes from runtime pointers (`log_buf` or `prb`); static backing arrays are not substituted for dynamically allocated rings.

The reference fields are `facility`, `level`, `timestamp`, `caller` and `line`. Numeric nanoseconds become seconds with six decimal digits by truncation, without floating-point rounding. Unknown facilities/levels display their numeric values. Caller IDs become `Task(n)` or `CPU(n)` when declared; missing callers remain typed missing. Unicode line splitting retains blank interior lines and treats CRLF as one separator. Packed level bitfields use declared type information.

## Ring behavior

Text buffers retain the pinned pointer-to-string truncation at NUL or the first Unicode replacement character, followed by rotation using `log_end - log_buf_len` without modulo reduction. Rotation operates on decoded characters, as in the reference. Nonmatching line remnants are skipped. Decimal priorities accept Unicode decimal digits; arbitrarily large normal priorities use exact integers, with an explicit 4300-digit resource limit. A text log's `Offset` is its captured buffer origin, not a claimed direct offset of the line after decoding and rotation.

Structured records follow first/next indices and zero-length wrap markers. Payloads split into log lines; dictionary bytes split on NUL and retain the leading space and final empty dictionary component used by the reference. Native lengths must fit the declared ring and record. Repeated offsets, malformed extents or unreadable bytes explicitly fail with partial evidence.

Modern readers follow descriptor tail IDs toward the repeatedly read head ID, apply the pointer-width state/ID masks, and retain committed/finalized entries. Descriptor/data and ID wrap are supported. For normal distinct endpoints, the pinned iteration stops before the head. Equal endpoints do not imply an empty ring in the pinned algorithm: iteration can traverse the whole masked ID space. Native record limits make that condition fail explicitly. A bounded reference prefix is tested for this case; no successful-empty assertion is made.

Text blocks retain the pinned `min(text_len, end-begin)` cap before skipping the ID word, including its possible read past the logical block end. Wrapped blocks restart at zero; odd begin positions have no text but can still emit device dictionary lines. Device/subsystem arrays use the pinned NUL/replacement-character truncation. Descriptor low-ID mismatches are recorded as `StoredID` and `IDMatches`; they do not filter messages, matching pinned selection. These observations do not establish consistency against concurrent kernel writers.

## Evidence and limits

| RecordType | Meaning |
| --- | --- |
| `log` | Five reference fields, origin offset; modern rows also link descriptor and traversal ID |
| `descriptor` | Visited descriptor, traversal/stored IDs, state and ID consistency |
| `ring_read` | Every actual acquisition attempt, with address, original bytes, requested/captured lengths, completeness and error |
| `ring_summary` | Layout, visited records, emitted lines, reads, acquired bytes and completion |

`max-records=1000000` counts text lines including malformed remnants, structured records including wrap markers, or modern descriptors of all states. `max-lines=1000000` bounds emitted log lines. Each accepts 1..1000000. `max-bytes=67108864` bounds cumulative captured bytes, including repeated metadata reads; it accepts 1..1073741824. Large buffer reads use chunks no larger than 16 MiB. Raw images remain read-only. Budget-rejected scalar reads retain explicit failed acquisition evidence; large requests rejected before acquisition are reported by incomplete summaries.

Read/layout/length/cycle/limit failures cannot become successful empty results. Failed tasks are retried instead of reused as completed cache entries. Output errors and cancellation stop the sink at every tested output boundary. A declared `dwarf2json` producer version no newer than 0.4.1 explicitly rejects the symbol table; absent/non-numeric versions or other producers follow the pinned permissive gate. GoMem checks its selected table rather than unrelated framework tables.

## Verification

`tools/build_kmsg_oracle.py` verifies the locked source digest and executes unmodified `ABCKmsg` dispatch/readers on actual ISF-backed byte objects. It covers 64 cases: two pointer widths, four layouts and eight scenarios (normal, empty, wrap, multiline, invalid UTF-8, caller/packed level, unknown labels and Unicode). Four additional controls check masked ID wrap and bounded equal-head/tail prefixes. Native engine tests run 102 paging cases across x64, x86 and PAE. All five ordered fields, original-byte captures, SQLite seals and completed cache replay are checked. Failure retries, every direct output/cancellation boundary, limits and malformed rings have separate tests and fuzzing.

The supplied Debian 3.2 x64 image, SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`, yields 1445 ordered logs matching the reference on all five fields. The optional corpus test verifies manifest/image/output hashes, independently rereads all four acquisitions (buffer and three scalar reads), pages through every stored seal and checks byte-identical cache reuse. The comparison profile normalizes explicitly unavailable callers to reference null.

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_kmsg_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxKmsgRings -fuzztime 10s
GOMEM_CORPUS_DIR=/path/to/corpus \
GOMEM_KMSG_REFERENCE=/path/to/reference \
go test ./internal/engine -run TestOfficialLinuxKmsg -count=1
```

Real structured/modern rings and real 32-bit images remain unvalidated. Full kernel-version, damaged-image, renderer/export and capability acceptance remain pending. [Measurements](linux-kmsg-validation.json), [field mapping](diff/linux.kmsg.json).
