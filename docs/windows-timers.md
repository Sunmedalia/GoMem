# Windows 内核定时器

`windows.timers` 对应固定基线的 `windows.timers.Timers`。它遍历内核定时器表，输出到期时间、周期、信号状态，以及 DPC 例程所在的模块和符号。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.timers --image memory.dmp --case ./case-001 --offline --format jsonl
```

有 PE 版本时，只有 Windows 8 及以后走处理器定时器表。固定基线把版本当成四元组，`is_windows_7` 和 `(6, 1)` 的相等比较不会成立。没有 PE 版本时，Windows 7 和 Windows 8 的符号回退也会走这条路径。更早的内核使用 `KiTimerTableListHead`：64 位或 Vista 及以后是 512 项，否则是 256 项。

Windows 8 及以后从 `KiProcessorBlock` 找到每个 PRCB。`TimerTable.TableState` 存在时，`TimerEntries` 必须是二维数组。本样本是 2 乘 256，一共 512 条链表。链表只沿 `Flink` 走，不检查回指。链表头本身不是定时器。链接或对象读不到就停止这一条链表，已经输出的行保留，任务仍然成功。循环链表也停止。单条链表超过 100000 项则任务失败。

`Header.Type` 必须是 8 或 9，分别对应通知定时器和同步定时器。类型读不到则任务失败。其他类型计数后跳过。`KiWaitNever` 和 `KiWaitAlways` 都存在时，DPC 指针按固定算法解码：先与 `KiWaitNever` 异或，再按它的低 8 位循环左移，然后与定时器地址的规范形式异或、做 64 位字节交换，最后与 `KiWaitAlways` 异或。解码结果、等待键或 `DeferredRoutine` 读不到，以及例程指针掩码后为 0，都跳过这个定时器。两个等待键都不存在时，直接把 `Dpc` 当成 `_KDPC` 指针。

到期时间是 `DueTime.HighPart:DueTime.LowPart`。格式与 Python 的 `#010x` 相同，宽度把 `0x` 算进去，负数的负号留在 `0x` 外面。周期是无符号 32 位值。`SignalState` 按有符号 32 位解释，非 0 记为 `Yes`，否则记为 `-`。这三个字段读不到则任务失败。

模块和符号规则与 `windows.driverirp` 相同。没有模块时，模块和符号都不可用。有模块但没有符号时，只有符号不可用。同一地址的多个符号各占一行，名称按符号名排序。原生地址保留规范高位。

官方 Windows 10 19041 样本有 1 个处理器、512 条链表。检查了 317 个定时器，类型全部有效。273 个 DPC 被跳过。输出 44 行，9 个已信号，35 个未信号。44 个例程都落在已加载模块里，23 个没有内核符号，没有一个地址对应多个符号。低 48 位偏移、到期时间、周期、信号、例程、模块和符号与固定基线一致。摘要行不是定时器。

合成样本覆盖 DPC 解码、64 位循环移位、字节交换和到期时间格式。真实 32 位镜像、Windows 7 的处理器表和 `KiTimerTableListHead` 路径还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-timers.jsonl \
  --reference reference-windows-timers.json \
  --mapping docs/diff/windows.timers.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestTimerDecode|TestOfficialWindowsTimers' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.timers.Timers` 生成。当前保持 partial、accepted=false。
