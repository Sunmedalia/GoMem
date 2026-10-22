GO ?= go
BASELINE := .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75

.PHONY: build test check fixtures baseline matrix fuzz bench dist clean
build:
	$(GO) build -trimpath -o bin/gomem ./cmd/gomem
test:
	$(GO) test -timeout 30m ./...
check:
	$(GO) vet ./...
	$(GO) test -race -timeout 30m ./...
	python3 -m unittest discover -s tools -p 'test_*.py'
	python3 tools/build_argument_fixtures.py --check
fixtures:
	$(GO) run ./tools/fixture --out .cache/fixtures
baseline:
	python3 tools/fetch_baseline.py
matrix:
	python3 tools/baseline_matrix.py --source $(BASELINE) --check
fuzz:
	$(GO) test ./pkg/wingui -run '^$$' -fuzz '^FuzzGUIObjects$$' -fuzztime 20000x
	$(GO) test ./pkg/wingui -run '^$$' -fuzz '^FuzzGUILayout$$' -fuzztime 2000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz '^FuzzConsoleRelations$$' -fuzztime 20000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz '^FuzzConsoleObjects$$' -fuzztime 20000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz '^FuzzConsoleObjectLayout$$' -fuzztime 2000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz '^FuzzConsoleScreen$$' -fuzztime 20000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz '^FuzzConsoleScreenLayout$$' -fuzztime 2000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzCmdScanPipeline -fuzztime 2000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz '^FuzzConsolesPipeline$$' -fuzztime 2000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz FuzzConsoleHistoryLayout -fuzztime 20000x
	$(GO) test ./pkg/winconsole -run '^$$' -fuzz FuzzHistoryBucket -fuzztime 20000x
	GOMEM_BASELINE_DIR="$(CURDIR)/$(BASELINE)" $(GO) test ./internal/plugins -run '^$$' -fuzz FuzzCallbacksPermutedPagePipeline -fuzztime 20000x
	GOMEM_BASELINE_DIR="$(CURDIR)/$(BASELINE)" $(GO) test ./internal/plugins -run '^$$' -fuzz FuzzCallbacksGeneratorPipeline -fuzztime 20000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzCallbackPoolObjects -fuzztime 20000x
	$(GO) test ./pkg/wincallbacks -run '^$$' -fuzz FuzzCallbackIndexes -fuzztime 20000x
	GOMEM_BASELINE_DIR="$(CURDIR)/$(BASELINE)" $(GO) test ./pkg/winnet -run '^$$' -fuzz FuzzNetworkIndexes -fuzztime 20000x
	GOMEM_BASELINE_DIR="$(CURDIR)/$(BASELINE)" $(GO) test ./internal/plugins -run '^$$' -fuzz FuzzNetworkAcquisition -fuzztime 20000x
	$(GO) test ./pkg/winnet -run '^$$' -fuzz FuzzNetworkLayout -fuzztime 200000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzPoolScannerOriginalCaptures -fuzztime 100000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsVADRegexPipeline -fuzztime 100000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzRegexPluginPipeline -fuzztime 40000x
	$(GO) test ./pkg/memoryscan -run '^$$' -fuzz FuzzAcquireCorrespondence -fuzztime 178000x
	$(GO) test ./pkg/memoryscan -run '^$$' -fuzz FuzzMemoryScanPipeline -fuzztime 886000x
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzScanPlan -fuzztime 904000x
	$(GO) test ./pkg/byteregex -run '^$$' -fuzz FuzzByteRegex -fuzztime 98000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzMFTPipeline -fuzztime 82000x
	$(GO) test ./pkg/ntfs -run '^$$' -fuzz FuzzMFTRecord -fuzztime 824000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsStringsPipeline -fuzztime 48000x
	$(GO) test ./pkg/winpath -run '^$$' -fuzz FuzzWindowsModulePath -fuzztime 248000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsMalfindPipeline -fuzztime 26000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzSuspendedThreadPipeline -fuzztime 48000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzDebugRegisterPipeline -fuzztime 44000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzETWPatchPipeline -fuzztime 22000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzIATPipeline -fuzztime 26000x
	$(GO) test ./pkg/pe -run '^$$' -fuzz FuzzMappedPEImports -fuzztime 20x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzPESymbolRequest -fuzztime 80000x
	$(GO) test ./pkg/pesymbols -run '^$$' -fuzz FuzzModuleSymbolRequests -fuzztime 458000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxSockscan -fuzztime 4000x
	$(GO) test ./pkg/object -run '^$$' -fuzz FuzzViewDataAndNativeLayers -fuzztime 32000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxPsCallStack -fuzztime 20000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzFullResolver -fuzztime 12000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzModuleLookup -fuzztime 12000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzFtraceLookup -fuzztime 18000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzBPFLookup -fuzztime 52000x
	$(GO) test ./pkg/object -run '^$$' -fuzz FuzzLatchTree -fuzztime 60000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzCoreLookup -fuzztime 106000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxKallsymsSources -fuzztime 40000x
	$(GO) test ./pkg/kallsyms -run '^$$' -fuzz FuzzCoreTables -fuzztime 116000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxTracepointAcquisition -fuzztime 34000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxFtraceAcquisition -fuzztime 32000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxFramebufferAcquisition -fuzztime 40000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxFramebufferPixels -fuzztime 94000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxPerfEvents -fuzztime 12000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxKmsgRings -fuzztime 48000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxPIDHash -fuzztime 14000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxEBPFIDR -fuzztime 52000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxLibraryList -fuzztime 4000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxMalfindDisassembly -fuzztime 84000x
	$(GO) test ./pkg/elfimage -run '^$$' -fuzz FuzzModuleELFRebuild -fuzztime 962000x
	$(GO) test ./pkg/pe -run '^$$' -fuzz FuzzMappedPEExports -fuzztime 440x
	$(GO) test ./pkg/pe -run '^$$' -fuzz FuzzMappedPEReconstruction -fuzztime 1564000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxVMAMetadata -fuzztime 100000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsCommandLineUTF16 -fuzztime 54000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzWindowsVADTraversal -fuzztime 6000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzScheduledTaskBlobs -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxArgumentDisplay -fuzztime 110000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxClockArithmetic -fuzztime 118000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzVMCoreInfoDescriptor -fuzztime 142000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleParameterGraph -fuzztime 8000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleMemoryLayouts -fuzztime 114000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxModuleELFSymbols -fuzztime 38000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxPsTreeHierarchy -fuzztime 10s
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzDetect -fuzztime 58000x
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzAVML -fuzztime 1258000x
	$(GO) test ./pkg/memory -run '^$$' -fuzz FuzzSnappyBlock -fuzztime 716000x
	$(GO) test ./internal/engine -run '^$$' -fuzz FuzzModuleRSDS -fuzztime 66000x
	$(GO) test ./internal/engine -run '^$$' -fuzz FuzzMappedPE -fuzztime 48000x
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzISF -fuzztime 348000x
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxIDTDescriptor -fuzztime 10s
	$(GO) test ./internal/plugins -run '^$$' -fuzz FuzzLinuxSyscallTableSize -fuzztime 10s
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzDWARF -fuzztime 20x
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzSymbolIndex -fuzztime 346000x
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzMSF -fuzztime 50000x
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzCodeView -fuzztime 4000x
	$(GO) test ./pkg/symbols -run '^$$' -fuzz FuzzPDB -fuzztime 10s
bench:
	$(GO) test -run '^$$' -bench . -benchmem ./pkg/memory ./internal/store ./internal/tui
	$(GO) run ./tools/bench
dist: test
	python3 tools/dist.py
clean:
	rm -rf bin dist
