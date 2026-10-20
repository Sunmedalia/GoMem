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
fixtures:
	$(GO) run ./tools/fixture --out .cache/fixtures
baseline:
	python3 tools/fetch_baseline.py
matrix:
	python3 tools/baseline_matrix.py --source $(BASELINE) --check
fuzz:
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzDetect -fuzztime 10s
	$(GO) test ./internal/engine -run '^$$' -fuzz FuzzMappedPE -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzISF -fuzztime 10s
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
