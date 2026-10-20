# Windows 进程池扫描

`windows.psscan` 对应固定基线的 `windows.psscan.PsScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `Pro\xe3` 和 `Proc`，雕出 `_EPROCESS`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.psscan --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.psscan --image memory.dmp --case ./case-001 --offline --param pid=408,4
bin/gomem analyze windows.psscan --image memory.dmp --case ./case-001 --offline --param physical=true
```

进程约束跳过对象类型名检查。候选要同时满足固定基线的 `_EPROCESS` 检查：按 UTF-8 解码镜像名，在 NUL 或 `U+FFFD` 处截断，结果不能为空。名称不是 `System` 或者 PID 不是 4 时，`CreateTime` 必须能变成 UTC 时间，年份晚于 1998 并且早于本地当前年份加 10。`ExitTime` 如果也能变成这样的时间，年份要落在同一窗口，而且不能早于创建时间。PID 非 0、能被 4 整除，并且不大于 `0xFFFFFFFC`。`DirectoryTableBase` 取标量或数组的第一个元素，不能为 0，也不能只剩低 12 位。`ThreadListHead` 的 `Flink` 和 `Blink` 都要大于等于 `0x80000000`。读失败按无效候选丢掉，不输出空进程。

`HandleCount` 不在符号里时，句柄数保持不可用。会话指针为 0 时记为不适用。`Wow64Process` 和 `WoW64Process` 都不存在时，Wow64 为 false。`dump=false` 时文件列是字面量 `Disabled`。转储失败写成 `Error outputting file`，这一行仍然保留，不单独让任务失败。`physical=true` 把扫描到的地址交给内核层翻译。摘要行不计入进程。

官方 Windows 10 19041 样本扫了和文件扫描相同的 6416 个内核范围、387,543,040 字节，得到 121 个进程。PID、PPID、15 字节镜像名、线程数、句柄不可用、会话、Wow64、按秒对齐的创建和退出时间、以及 `Disabled` 都和固定基线一致。活动链表里有 120 个进程；多出来的是 PID 408 的 `MpCmdRun.exe`，它不在 `PsActiveProcessHead` 上。这张镜像没有 `HandleCount`，两边的句柄列都是空。4 个会话指针为 0。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。

合成样本覆盖自下而上的对齐进程、PID 不能被 4 整除的拒绝，以及 `pid` 过滤。32 位真实镜像、Windows 8 以前的真实镜像和时间线输出还没有验收。`dump` 可以沿用进程 PE 重建，这次对照没有打开它。

```sh
python3 tools/diff_results.py \
  --native native-windows-psscan.jsonl \
  --reference reference-windows-psscan.json \
  --mapping docs/diff/windows.psscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsPsScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.psscan.PsScan` 生成。当前保持 partial、accepted=false。年份窗口用的是运行时的本地年份，这次对照发生在 2026 年。
