# Windows 注册表键枚举

`windows.printkey` 对应固定基线的 `windows.registry.printkey.PrintKey`。它复用 `windows.hivelist` 的活动 hive 列表，再用精确 `_CMHIVE` / `_DUAL` / `_HMAP_ENTRY` 布局读取单元格。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.printkey --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.printkey --image memory.dmp --case ./case-001 \
  --param offset=0xc2040000 --param key=ControlSet001 --param recurse=true
```

默认只列出每个 hive 根键的直接子键和值，顺序是稳定子键、易失子键、值。`recurse=true` 继续向下走，遇到已经出现过的单元格索引就停止，避免循环。`key` 是 hive 根以下的路径，按 `\` 分段、大小写不敏感。`offset` 可以是完整虚拟地址，也可以只给 64 位地址的低 48 位。`max-nodes` 默认 1000000，范围 1..1000000；超过上限会失败。

单元格索引先查 HMAP。内核规范地址（64 位 `>= 0xffff800000000000`，32 位 `>= 0x80000000`）先读内核层，这一页不在时再试父进程为 4 的 `Registry` 进程，并在 `Hive.Fallbacks` 里计数。更低的地址只读该进程，不会从内核层猜测。找不到 Registry 进程时，这些用户地址保持不可读。

一个 hive 打不开或指定键不存在时，仍发出一行 `RecordType=key`：`Key` 为 hive 名加路径，`Name`、`Volatile`、`LastWriteTime` 的缺失原因是 `unreadable` 且不带错误文本，`Data` 为空，原因放在 `Error`。这一行不让任务失败。子键或值列表中途缺页时，已经读到的项照常发出，再追加一行 `RecordType=diagnostic`，原因是 `registry_walk_incomplete`，任务仍然完成。空值名写成 `(Default)`。键行的 `Data` 为空。`REG_DWORD` / `REG_QWORD` 用十进制，`REG_SZ` 把原始 UTF-16 放在 `DataRaw`，解码文本放在 `Data`，不再套一层引号。时间用 `RFC3339Nano`，保留 100ns，时区为 `Z`。

官方 Windows 10 19041 样本在默认参数下得到 478 个键/值行和 2 条诊断，任务状态为 `completed`。选定的 hive 偏移、类型、键、名称和 Volatile 多重集与固定基线一致，其中包括 7 个不可读 hive。时间截断到秒后一致；其中 471 行的本地时间带有基线 JSON 丢掉的 100ns 分数。2 个 `REG_SZ` 在基线里被额外加上引号，解码后的文本一致。两条诊断来自内核层和 Registry 进程都读不到的 prototype 或交换页，分别落在 `\REGISTRY\MACHINE\SYSTEM` 与 `\REGISTRY\MACHINE\HARDWARE`。

合成样本覆盖内核映射 hive、big data 值、UTF-16 名称，以及必须走进程层的用户 bin。真实镜像只验收了这一份 x64 崩溃转储的默认根列表。`recurse`、`key` 筛选、32 位、其他 Windows 版本、hive 文件重建和物理 `hivescan` 都还没有对照验收。

```sh
python3 tools/diff_results.py \
  --native native-printkey.jsonl \
  --reference reference-windows-printkey.json \
  --mapping docs/diff/windows.printkey.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsPrintKey|TestOfficialWindowsPrintKey' -count=1
go test ./pkg/registry -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.printkey` 生成，未加 `recurse`。当前保持 partial、accepted=false。
