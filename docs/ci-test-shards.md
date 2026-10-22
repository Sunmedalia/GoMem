# Complete engine race tests in CI shards

The growing engine suite exceeded the hosted Ubuntu runner's 30-minute Go test deadline in run `39716090445`. The timeout stack shows the PE-symbol command still executing its ordinary x86 duplicate-module cases; the same complete local race suite passes. Native Windows, Linux and macOS tests passed in that run.

CI keeps the complete unsharded native suite on all three systems. The Ubuntu race suite now runs the engine in four independent jobs and all other packages in the acceptance job. No engine test is omitted to meet the deadline. Each job retains the 30-minute deadline.

`tools/test_engine_shard.py` discovers the compiled engine's top-level tests, fuzz seed functions and examples using `go test -list .`. SHA256 of each full function name, modulo the shard count, assigns it to exactly one group. Discovery rejects empty/duplicate inventories, and a selected empty shard fails. Anchored Go regular expressions select entire top-level functions, so every nested subtest runs. Benchmark functions remain outside ordinary `go test`, as before. Fuzz mutation runs remain separate CI steps.

Each engine job uploads a JSON manifest even on failure. It contains the discovered inventory partition, selected functions and exact runner expression. All four engine jobs and the acceptance job must pass; no individual shard establishes complete CI success. Optional corpus tests keep their existing explicit environment requirements and skips do not establish corpus acceptance.

```sh
python3 tools/test_engine_shard.py --shard 0 --list-only --manifest /tmp/engine-tests-0.json
python3 tools/test_engine_shard.py --shard 0
python3 tools/test_engine_shard.py --shard 1
python3 tools/test_engine_shard.py --shard 2
python3 tools/test_engine_shard.py --shard 3
python3 tools/test_engine_shard.py --other-packages
```

Python tests verify exact/disjoint coverage, inclusion of examples and fuzz seeds, stable membership when another test is added, and rejection of invalid inventories/counts. A local singleton-shard smoke run executes the real Go runner; the full `make check` command remains available unchanged.
