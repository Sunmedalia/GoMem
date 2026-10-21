# Windows 服务记录扫描

`windows.svcscan` 对应固定基线的 `windows.svcscan.SvcScan`。它在 `services.exe` 的进程地址空间里搜索 `serH`，沿 `PrevEntry` 读出服务记录，再从 SYSTEM hive 补上 `ImagePath` 和 `ServiceDll`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.svcscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

目前只接受指针宽度为 8 的 Windows 10 19041 x64 布局。其他宽度直接失败。只扫描映像名恰好是 `services.exe` 的进程。页表建不起来就跳过该进程，不让整次任务失败。

VAD 使用和 `MMVAD.traverse` 相同的前序，不按起始地址排序。每个 VAD 里搜索 `serH`，偏移不是 8 的倍数就丢掉。`_SERVICE_HEADER.ServiceRecord` 在头地址加 16。记录的 `Order` 大于 `0xFFFF`，或者启动类型、状态不在已知枚举里，就结束当前链。类型标志按内核驱动、文件系统驱动、adaptor、recognizer、own process、share process、interactive 的顺序用 `|` 连接。

名称、显示名和路径按 UTF-16LE 最多读 512 字节，在第一个 NUL 截断。读不满就是不可用。只有状态是 `SERVICE_RUNNING` 且类型字符串包含 `PROCESS` 时才输出 PID。驱动在运行时把记录加 296 处的指针直接当成 UTF-16 字符串，例如 `\FileSystem\srvnet`。服务没有运行时，路径不适用。

偏移列沿用基线的指针对象地址。链上第一条是记录本体，后面每条是上一条 `PrevEntry` 字段的地址，也就是上一条记录加 16。去重也沿用基线的元组比较：PID 或路径不可用时，每次都是新的缺省对象；注册表字段只有服务名已经在映射里时才是同一个对象。因此只有 PID 是数字、路径是字符串、并且服务名能在注册表映射里找到时，重复记录才会截断当前链。同一个偏移可以出现多次，不能按服务名去重。单条链超过 100000 条会停下并计数，这张镜像没有触发。

注册表取名称包含 `machine\system` 的第一个 hive，路径先试 `CurrentControlSet\Services`，失败再试 `ControlSet001\Services`。读不到的子键和值跳过，不让任务失败。`ImagePath` 和 `ServiceDll` 区分大小写。值单元格读失败时按空字符串处理，对应基线用零填充后再去掉末尾 NUL。没有这两个值时，对应列不可用。

`max-nodes` 默认 131072，限制活动进程和每个 VAD 树，不是上游参数。摘要行不是服务。

官方 Windows 10 19041 样本有 1 个 `services.exe`，142 个 `serH` 头，350 个注册表服务键，共 1578 行，与固定基线一致。其中 746 个偏移互不相同。启动类型是 1196 个 demand、181 个 auto、97 个 boot、67 个 system、37 个 disabled。1152 个 stopped，426 个 running。1373 个 PID、1162 个内存路径、868 个注册表路径和 1296 个 DLL 为空。4 个注册表路径是空字符串。首行是 `SSDPSRV`，order 446，PID 4536，偏移 `0x1ffc9a78660`。

真实 32 位镜像、其他 Windows 版本、Vista 以前的 `sErv` 标签、`windows.svclist`、`windows.svcdiff` 和时间线还没有实现。坏标签或父指针不一致的 VAD 树会让任务失败；这张镜像的树已经由 `windows.vadwalk` 接受。

```sh
python3 tools/diff_results.py \
  --native native-windows-svcscan.jsonl \
  --reference reference-windows-svcscan.json \
  --mapping docs/diff/windows.svcscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestSvcScan|TestService|TestOfficialWindowsSvcScan' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.svcscan.SvcScan` 生成。当前保持 partial、accepted=false。
