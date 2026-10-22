# Byte-regex scanning reference (native implementation pending)

`tools/build_regex_oracle.py` locks the unmodified v2.28.2 `RegExScanner`,
`regexscan.RegExScan` generator and `linux.vmaregexscan.VmaRegExScan` generator.
The source tree digest is checked before execution. The fixtures are
`internal/engine/testdata/regex-oracle.json` and its digest-bound
`byte-regex-semantics.jsonl`. This is implementation reference
evidence; both plugin classes remain **missing** in the capability matrix.
The [native matching core](byte-regex.md) is implemented separately; acquisition
and plugin integration remain pending. The selected-range page walker and
Intel chunk planner are now implemented as acquisition foundations; neither
executes a regex plugin.

Run with Python 3.12, matching CI:

```sh
python3.12 tools/build_regex_oracle.py --check
# If Python 3.12 is managed by uv:
uv run --no-project --python 3.12 python tools/build_regex_oracle.py --check
```

Python 3.14 changed `\B` on empty input. The generator rejects other Python
minor versions rather than silently rewriting the fixed 3.12 reference.
Python and Volatility remain development dependencies only.

## Reference scope

- 35 scanner cases cover binary bytes, UTF-8 pattern encoding, ASCII character
  classes and folding, greedy/lazy matching, lookarounds, backreferences, named
  groups, conditionals, atomic groups, possessive quantifiers, anchors, inline
  flags, empty-match progression, overlap suppression and invalid syntax.
- The same inputs exercise 120 short-layer generic generator configurations
  and 96 padded-layer configurations. Both partial rows and terminal failures
  are retained. Short BufferDataLayer acquisition failures are reference-layer
  behavior, not proof that every supported container fails identically.
- 42 VMA generator cases use actual byte-backed `task_struct`, `mm_struct` and
  `vm_area_struct` objects with the official extensions. Actual x86, PAE and
  x64 translation creates the process layers and reads their mappings. No
  scanner, field, VMA traversal or process-layer method is mocked. Cases cover
  invalid patterns, missing pages, absent mm and signatures across VMA ends.
- Two actual 16 MiB layer-scanning cases retain chunk-boundary ordering. The
  full-overlap case emits each occurrence once. A final span only 1,000 bytes
  larger than 16 MiB revisits a preceding match, so that case emits its address
  twice. Fixed scanner offset suppression alone does not eliminate this
  iterator behavior.
- 17 additional actual Intel iterator plans cover x86/PAE/x64 physical
  discontinuities, virtual gaps, contiguous mappings, coalesced overlapping
  sections, empty mappings and default 16 MiB full/partial final windows.
  Unlike the DataLayer cases above, the Intel iterator advances by the fixed
  chunk size. Parts refer to physical addresses while chunk ends use virtual
  coordinates.
- 12,580 Python 3.12 byte `finditer` configurations compare complete match spans
  across 622 distinct patterns. These include deterministic generated grammar
  cases, capture-dependent backtracking and conditional/reference syntax. The
  JSONL file is checked against its SHA256 and case count before native tests.

## Required native semantics

Patterns become UTF-8 bytes before compilation. The matching alphabet is bytes;
Go rune-regex behavior cannot be assumed equivalent. For example, `é+` becomes
two literal bytes with the quantifier applied to the second byte. Invalid
UTF-8 match data is decoded with Python's replacement behavior for display,
while original bytes must remain lossless evidence.

The scanner compiles with DOTALL and yields the starts of nonoverlapping
`finditer` matches, with Python's empty/nonempty progression at one position.
Matches starting at or past `chunk_size` are suppressed in each scanner call.
The generic command re-searches the acquired context without implicit DOTALL;
it can return a later match from that context. The VMA command instead calls
`re.match` at the context start, also without implicit DOTALL. If extraction
fails, either command displays the whole acquired context. A lookbehind that
matched in the scan buffer can fail after context acquisition loses its prefix.

The generic command honors `maxsize`. The Linux VMA generator always acquires
128 bytes despite its advertised `maxsize`; all VMA cases set it to four to
exercise this behavior. PID output is `tgid`, not thread `pid`. Names come from
the original comm array. A null mm skips the task, and an invalid pattern is not
compiled when all tasks are skipped. Mapped pages outside selected VMAs must
not contribute scan matches. Upstream silently skips unavailable scan mappings;
native analysis must additionally retain explicit incomplete-coverage evidence.

Native plugin implementation, raw scan and result
acquisitions, original page-table provenance, sealed storage/cache checks,
failure tests, real-corpus comparisons and full renderer/export validation are
still required. These reference cases do not justify a status upgrade or an
acceptance claim.

## Native acquisition foundations

`pkg/memory.PageMapOptions.Sections` restricts the table traversal before child
reads. Explicit intervals are clipped before physical availability checks;
missing tables outside the selected intervals do not contaminate their coverage.
Nil retains the default whole-space final-byte exclusion, while an explicit
empty selection performs no reads. Explicit ranges may include the final byte.
x64 canonical addresses and flat 48-bit coordinates select the same bytes.

`pkg/memory.ScanPlanner` takes coalesced, ordered physical/virtual mappings for
one coalesced section. It streams bounded chunks with separate physical read
addresses and virtual scan coordinates, preserving the initial empty chunk for
a nonzero first mapping. Callers must flatten x64 starts before planning and
create a new planner per section. The planner performs no reads, buffering of
image data, or regex matching. Chunk size plus overlap is bounded to 32 MiB;
individual memory reads remain bounded to 16 MiB. Future acquisition must split
larger parts into bounded reads and retain whole-part failure semantics.

Native tests compare 42 VMA and 17 additional iterator plans against the actual
baseline, including independent hardware translation of each planned read.
Selected-table tests prove exclusion of an unrelated missing child and clipping
of a partially available physical page. Tests cover cancellation, emitter errors,
chunk bounds, invalid/overflowing/unordered intervals and closed-planner reuse.
The planner fuzz invariant checks every chunk's source correspondence and exact
coverage/overlap count. These tests establish planning only; acquisition errors,
scan digests and plugin results remain to be integrated and verified.
