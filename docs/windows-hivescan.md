# Windows 注册表 hive 池扫描

`windows.hivescan` 对应固定基线的 `windows.registry.hivescan.HiveScan`。在 64 位 Windows 8.1 及以后，它读取 `PoolBigPageTable`，保留仍在使用且标签为 `CM10` 的大页分配。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.hivescan --image memory.dmp --case ./case-001 --offline --format jsonl
```

版本判断优先用符号里的 PE 版本。当前官方符号没有这份元数据时，用 `_KPRCB.PendingTickFlags` 是否存在作为 8.1 及以后的回退条件，和固定基线一致。指针不是 8 字节，或者没有这个成员时，命令直接失败，并说明旧式分页池头扫描还没有实现。不会把空结果当成“没有 hive”。

`PoolBigPageTable` 是表指针，`PoolBigPageTableSize` 是条目数。条目布局来自 `_POOL_TRACKER_BIG_PAGES`：`Va` 和 `Key`。`Key` 为 0 的条目无效。`Va` 最低位为 1 表示已释放，默认不输出。`Key` 的四个小端字节必须正好是 `CM10`。命中的 `Offset` 是表里保存的 `Va`。签名会读出来放在 `Signature`，读失败只标记该单元格，不把这一行丢掉，也不用签名过滤。`max-entries` 默认 2000000，范围 1..5000000。表长超过上限时失败，不截断。某一条读失败会保留诊断并让任务失败，已经读到的命中仍在。

官方 Windows 10 19041 样本的大页表有 32768 条，24 个在用的 `CM10`，没有读取失败，任务成功。这 24 个地址的低 48 位与固定基线 `windows.registry.hivescan` 的 24 行一致，签名都是 `0xBEE0BEE0`。它们也和活动 hive 链表的 24 个对象是同一组地址。参考 JSON 丢掉了规范地址的高位，比较时只掩低 48 位，本地结果仍保留完整地址。

合成样本覆盖一个有效 `CM10`、一个已释放的 `CM10`、一个 `Key` 为 0 的条目和另一个标签，并拒绝过小的 `max-entries`。没有 `_KPRCB.PendingTickFlags` 时不产生行。32 位和 Windows 8 以前的 hive 仍会明确失败。文件对象的池头扫描在 `windows.filescan`，不从这里恢复 hive。其他系统版本都还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-hivescan.jsonl \
  --reference reference-windows-hivescan.json \
  --mapping docs/diff/windows.hivescan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsHiveScan|TestOfficialWindowsHiveScan' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.hivescan` 生成。当前保持 partial、accepted=false。
