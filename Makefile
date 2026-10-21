GO ?= go
BASELINE := .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75

.PHONY: build test check fixtures baseline matrix fuzz bench dist clean
build:
	$(GO) build -trimpath -o bin/gomem ./cmd/gomem
test:
	$(GO) test ./...
check:
	$(GO) vet ./...
	$(GO) test -race ./...
	python3 -m unittest discover -s tools -p 'test_*.py'
	python3 tools/build_argument_fixtures.py --check
fixtures:
	$(GO) run ./tools/fixture --out .cache/fixtures
baseline:
	python3 tools/fetch_baseline.py
matrix:
	python3 tools/baseline_matrix.py --source $(BASELINE) --check
fuzz:
	$(GO) test ./pkg/elfimage -run '^$$' -fuzz FuzzModuleELFRebuild -fuzztime 10s
	$(GO) test ./pkg/pe -run '^$$' -fuzz FuzzMappedPEReconstruction -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxVMAMetadata -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsCommandLineUTF16 -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsVADTraversal -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzScheduledTaskBlobs -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxArgumentDisplay -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxClockArithmetic -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzVMCoreInfoDescriptor -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleParameterGraph -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleMemoryLayouts -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleELFSymbols -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxPsTreeHierarchy -fuzztime 10s
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzDetect -fuzztime 10s
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzAVML -fuzztime 10s
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzSnappyBlock -fuzztime 10s
	$(GO) test ./internal/engine -run '^$$' -fuzz FuzzMappedPE -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzISF -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxIDTDescriptor -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxSyscallTableSize -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzDWARF -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzSymbolIndex -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzMSF -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzCodeView -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzPDB -fuzztime 10s
bench:
	$(GO) test -run '^$$' -bench . -benchmem ./pkg/memory ./internal/store ./internal/tui
	$(GO) run ./tools/bench
dist: test
	python3 tools/dist.py
clean:
	rm -rf bin dist
