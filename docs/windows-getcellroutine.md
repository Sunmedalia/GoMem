# Windows hive GetCellRoutine

`windows.getcellroutine` 对应固定基线的 `windows.registry.getcellroutine.GetCellRoutine`。它读取活动 hive 的 `GetCellRoutine`，再对照 `PsLoadedModuleList` 里的模块范围。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.getcellroutine --image memory.dmp --case ./case-001 --offline --format jsonl
```

模块名用 `BaseDllName` 去掉最后一个扩展名，规则和 Python `os.path.splitext` 相同：点在第一个字符时不切。重复的 stem，或者基址、映像大小读失败，会让整个任务失败。名字读失败的模块跳过。`ntoskrnl`、`ntkrnlmp`、`ntkrnlpa`、`ntkrpamp` 这四个名字视为内核处理函数，区分大小写。地址范围含右端点 `base+size`，和固定基线的 `offset <= base + size` 一致。

处理函数落在这四个模块里时不输出。落在其他模块里时，每个这样的模块一行，`RecordType=hook`。哪个已读到的模块都不包含它时，一行 `RecordType=unmapped`，`Module` 的缺失原因是 `not_available`，对应基线 JSON 的 null。指针本身读失败时一行 `RecordType=unreadable`，不会把它当成“在内核里所以正常”。字段在符号里不存在时任务失败，而不是把每个 hive 都记成不可读。

合成样本覆盖内核地址、含右端点的内核区间、紧挨右端点的未映射地址、`hook.sys`、把 `ntoskrnl.exe` 改成大写后不再视为内核、不可读指针、重复 stem，以及基址所在页不在内存中。没有 `GetCellRoutine` 字段时失败。

官方 Windows 10 19041 样本的活动 hive 都能读到这个指针，而且都落在内核模块内。固定基线因此是 0 行。本地也是 0 条挂钩、0 条未映射、0 条不可读，任务完成。这只说明这张镜像没有可观察的挂钩，不是对真实挂钩 hive 的验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-getcellroutine.jsonl \
  --reference reference-windows-getcellroutine.json \
  --mapping docs/diff/windows.getcellroutine.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsGetCellRoutine|TestOfficialWindowsGetCellRoutine' -count=1
go test ./internal/plugins -run TestModuleStem -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.getcellroutine.GetCellRoutine` 生成。当前保持 partial、accepted=false。32 位和带有真实挂钩的镜像还没有对照。
