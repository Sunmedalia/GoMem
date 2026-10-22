# Native byte regex core (development preview)

`pkg/byteregex` provides the native matching core for the generic and Linux VMA
regex commands. It has no external regex dependency and does not use
Python at runtime. This package alone does not implement either plugin or
establish full Python `re` compatibility. The commands are partial, with their
separate [acquisition/plugin validation](regex-scanning.md).

## Matching semantics

`Compile(pattern, dotAll)` encodes the text parameter as UTF-8 bytes. Each
literal, class and quantifier operates on bytes, with ASCII-only `\d`, `\s`,
`\w`, boundaries and case folding. Available constructs include alternation,
capturing/named/noncapturing groups, numeric/named backreferences, conditions,
positive/negative lookarounds, fixed-width lookbehind, atomic groups,
greedy/lazy/possessive repetition, anchors, escaped bytes, inline comments and
global/scoped ASCII, case, multiline, DOTALL and verbose flags.

`Search` supports a starting byte index and optional anchoring. Lookbehind sees
the original prefix. `FindIter` follows Python 3.12 empty-match progression:
after an empty result, a nonempty alternative at that same offset can still be
returned. Its exclusive `maxStart` bound implements scanner overlap suppression
without limiting the end of a match that begins before that bound.

The parser assigns group numbers in declaration order and retains group widths
to validate lookbehind. Capture states are isolated across backtracking choices.
Positive lookarounds and atomic groups commit their first successful branch.
Byte-set prefiltering accelerates candidate starts. Fixed-width repeated byte
sequences, including their captures, run iteratively while retaining the
original greedy/lazy ordering. Backtracking, capture-dependent expressions and
empty repeats use bounded continuations.

## Explicit resource and feature boundaries

- Compile: valid UTF-8 parameter, at most 65,536 pattern bytes, 32,768 nodes,
  nesting depth 128, 1,024 capture groups and repeat bounds at most 1,000,000.
- Search/iteration: input at most 32 MiB; default 100,000,000 VM operations and
  one second per invocation. Callers can supply a smaller/larger positive
  timeout and step budget through `Limits`.
- Nonlinear evaluation depth is limited to 4,096. A sufficiently complex long
  match can exhaust this bound even when simple fixed-width repetitions do not.
- Execution returns `ErrBudget` on operation, timeout or evaluation-depth
  exhaustion. It checks caller cancellation at least every 1,024 VM operations,
  around emitted matches, and before returning a search result. It launches no
  background matching goroutines. Emission failure ends iteration immediately.
- Locale-dependent `(?L)` expressions return an explicit unsupported-feature
  error. No host locale is guessed. Large valid Python patterns exceeding the
  resource bounds also fail explicitly; they are not treated as no matches.

The eventual plugins must expose resource controls, preserve failed task status
and acquired evidence, and avoid caching an incomplete scan as a clean result.
Matching does not provide acquisition, swap recovery, text decoding, page-table
provenance, evidence persistence or scan completeness.

## Validation

The fixed upstream `RegExScanner` supplies 35 byte-scanner cases. Python 3.12
supplies 12,580 full-span comparisons across 622 distinct patterns with DOTALL
both enabled and disabled. Generated grammar cases are deterministic. The
reference generator checks the exact pinned Volatility source tree before
producing its digest-bound JSONL. See [reference coverage](regex-scanning-reference.md).

Native tests additionally exercise long literals and captured repetitions,
caller deadlines, cumulative iteration budgets, concurrent reuse of a compiled
program, emitter failure and cancellation on emission. Fuzzing covers parser
entry and execution under bounded input and work, checking match bounds,
ordering and empty-match progression. These checks validate this core's tested
semantics; selected real-image plugin comparisons are recorded separately, and
release acceptance remains pending.
See the [machine-readable validation record](byte-regex-validation.json).

```sh
go test -race ./pkg/byteregex
go test ./pkg/byteregex -run '^$' -fuzz FuzzByteRegex -fuzztime 15s
go test ./pkg/byteregex -run '^$' -bench BenchmarkByteRegexScan -benchmem
uv run --no-project --python 3.12 python tools/build_regex_oracle.py --check
```
