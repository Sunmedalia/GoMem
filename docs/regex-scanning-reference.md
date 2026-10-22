# Byte-regex scanning reference (native implementation pending)

`tools/build_regex_oracle.py` locks the unmodified v2.28.2 `RegExScanner`,
`regexscan.RegExScan` generator and `linux.vmaregexscan.VmaRegExScan` generator.
The source tree digest is checked before execution. The fixtures are
`internal/engine/testdata/regex-oracle.json` and its digest-bound
`byte-regex-semantics.jsonl`. This is implementation reference
evidence; both plugin classes remain **missing** in the capability matrix.
The [native matching core](byte-regex.md) is implemented separately; acquisition
and plugin integration remain pending.

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
