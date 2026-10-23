# Repository Guidelines

## Project Structure & Module Organization

GoMem is a native Go, read-only memory-forensics engine with a CLI and interactive TUI.

- `cmd/gomem/`: executable entry point; `internal/cli/`: Cobra commands.
- `internal/engine/` and `internal/plugins/`: analysis orchestration and OS-specific plugins; `internal/tui/`, `store/`, and `report/`: interface, persistence, and reporting.
- `pkg/`: memory readers, symbols, typed objects, evidence, registry, and PE/ELF parsing.
- Tests sit beside source as `*_test.go`; reusable fixtures live in `testdata/` directories and `internal/testfixture/`.
- `tools/`: fixture generators, benchmarks, and reference validation; `docs/`: capability matrices, validation records, and plugin notes.

## Build, Test, and Development Commands

Use Go 1.26.2 or a newer 1.26 toolchain; Python 3.12 matches CI validation.

- `make build`: build `bin/gomem`; `bin/gomem doctor --offline`: check local readiness.
- `make fixtures`: generate deterministic sample images in `.cache/fixtures`.
- `go run ./cmd/gomem plugins`: list available plugins locally.
- `make test`: run all Go tests.
- `make check`: run Go vet, race tests, Python unit tests, and argument-fixture checks.
- `python3 tools/build_inode_mode_oracle.py --check`: run the additional CI oracle check.
- `make baseline matrix`: fetch the pinned Volatility baseline and verify the capability matrix.
- `make fuzz` / `make bench`: exercise fuzz targets or collect benchmarks.

## Coding Style & Naming Conventions

Format Go changes with `gofmt` using standard tab indentation. Use lowercase package names, exported `MixedCaps` identifiers, and descriptive filenames such as `windows_svcscan.go`. Follow existing OS prefixes for plugins and tests. Use `go vet ./...` for static checks; keep Python tooling consistent with its existing four-space indentation.

## Testing Guidelines

Use Go's `testing` package with `TestXxx`, `FuzzXxx`, and `BenchmarkXxx`; Python tests use `unittest` and `test_*.py`. Cover malformed input, missing pages, bounds, and explicit read failures. No numeric coverage threshold is configured. Optional corpus tests require their documented environment variables, including `GOMEM_CORPUS_DIR`; skipped corpus tests do not establish release acceptance.

## Commit & Pull Request Guidelines

Recent history uses concise, imperative `feat: ...` subjects. Follow that pattern for features and describe other changes clearly. PRs should explain behavior, affected plugins, validation commands/results, and remaining limitations; link relevant issues and include screenshots for TUI changes. Update capability and validation documentation when analysis behavior changes.

## Evidence Handling

Preserve read-only image access and the native runtime: Python and Volatility are development tools only. Keep dumps, case databases, and caches out of commits. Preserve distinctions between unavailable data, read errors, and empty results.
