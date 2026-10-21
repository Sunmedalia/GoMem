# Windows 线程池扫描

`windows.thrdscan` 对应固定基线的 `windows.thrdscan.ThrdScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `Thr\xe5` 和 `Thre`，雕出 `_ETHREAD`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.thrdscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

`Thr\xe5` 跳过对象类型名检查。`Thre` 必须是 Thread，类型表用 `ObTypeIndexTable`，没有它再用 `ObpObjectTypes`，存在 `ObHeaderCookie` 时按基线异或。候选先过固定基线的 `_ETHREAD` 检查：`UniqueThread` 和 `UniqueProcess` 都能被 4 整除。PID 不是 4 时，`CreateTime` 必须能变成 UTC 时间，年份晚于 1998 并且早于本地当前年份加 10。符号里有 `ThreadsProcess` 时，创建时间先把有符号 `QuadPart` 算术右移 3 位；否则直接用 `QuadPart`。`ExitTime` 不移位。FILETIME 的整秒用 Python 的向下取整，秒数为 0 不是时间，年份超出 1 到 9999 记为不可解析。这些字段读失败就丢掉该线程，不输出空行。读完之后，PID 为 0、大于 `0xFFFFFFFC`，或者不能被 4 整除，也丢掉。

所属进程优先取 `ThreadsProcess`，否则取 `Tcb.Process`。只有该进程通过固定基线的 `_EPROCESS` 检查，并且 `UniqueProcessId` 不是 4，才解析启动路径。路径来自 `windows.threads` 使用的共用 VAD 索引（旧版结构有合成参考，见 [VAD 说明](windows-vadwalk.md#旧版入口与对象级对照)），只保留名字里含有反斜杠的文件。System 线程、无效所属进程、不在文件 VAD 里的地址，以及没有反斜杠的名字，都记为无错误的不可用。时间线没有实现。摘要行不是线程。

官方 Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，得到 1752 个线程。低 48 位偏移、PID、TID、两个启动地址、两个路径、按秒对齐的创建时间和退出时间都与固定基线一致。这 1752 个偏移和活动线程链表相同，这张镜像里没有未链接线程。4 个创建时间为空。退出时间包含基线解释成 1600 年的有符号值；`windows.threads` 对这一列仍保留无符号原始位，不把两边说成同一件事。类型检查没有丢掉候选，也没有读失败。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。

合成样本覆盖自下而上的对齐线程、PID 4 允许空创建时间、PID 0 在雕刻之后被丢掉，以及 Windows 10 自上而下时类型必须是 Thread。32 位真实镜像、Windows 8 以前的真实镜像和时间线还没有验收。年份窗口用的是运行时的本地年份，这次对照发生在 2026 年。

```sh
python3 tools/diff_results.py \
  --native native-windows-thrdscan.jsonl \
  --reference reference-windows-thrdscan.json \
  --mapping docs/diff/windows.thrdscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsThrdScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.thrdscan.ThrdScan` 生成。当前保持 partial、accepted=false。
