# Windows 服务记录扫描

`windows.svcscan` 对应固定基线的 `windows.svcscan.SvcScan`。它在 `services.exe` 的进程地址空间里搜索 `serH`，沿 `PrevEntry` 读出服务记录，再从 SYSTEM hive 补上 `ImagePath` 和 `ServiceDll`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.svcscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

现在原生读取固定基线中的全部 16 套服务布局（XP/2003、Vista、Windows 8、Windows 10 15063/16299/17763/18362/19041/25398，各架构以基线实际提供为准）。支持 4/8 字节指针；其他宽度或没有匹配版本时明确失败。布局解析已用合成对象对照，真实镜像目前仍只有 19041 x64；旧版 VAD 根、树与文件读取也已接入 [共用读取器](windows-vadwalk.md#旧版入口与对象级对照)，并通过结构级合成参考；这些验证不等于旧版端到端验收。只扫描映像名恰好是 `services.exe` 的进程。页表建不起来就跳过该进程，不让整次任务失败。

VAD 使用和 `MMVAD.traverse` 相同的前序，不按起始地址排序。每个 VAD 里搜索 `serH`，偏移不是 8 的倍数就丢掉。`_SERVICE_HEADER.ServiceRecord` 偏移随布局选择；19041 x86 的偏移也是 16，不能从指针宽度推算。Vista 之前搜索 `sErv`，命中减去布局中的 `Tag` 偏移，只输出该记录，不要求 8 字节对齐、不走链、不做全局元组去重。记录的 `Order` 大于 `0xFFFF`，或者启动类型、状态不在已知枚举里，就结束当前链。类型标志按内核驱动、文件系统驱动、adaptor、recognizer、own process、share process、interactive 的顺序用 `|` 连接。

名称、显示名和路径按 UTF-16LE 最多读 512 字节，在第一个 NUL 截断。读不满就是不可用。只有状态是 `SERVICE_RUNNING` 且类型字符串包含 `PROCESS` 时才输出 PID。驱动在运行时把布局的 `DriverName` 指针直接当成 UTF-16 字符串，例如 `\FileSystem\srvnet`。服务没有运行时，路径不适用。

偏移列沿用基线的指针对象地址。链上第一条是记录本体，后面每条是上一条 `PrevEntry` 字段的地址，槽偏移随布局变化，19041 x64 为上一条记录加 16。去重也沿用基线的元组比较：PID 或路径不可用时，每次都是新的缺省对象；注册表字段只有服务名已经在映射里时才是同一个对象。因此只有 PID 是数字、路径是字符串、并且服务名能在注册表映射里找到时，重复记录才会截断当前链。同一个偏移可以出现多次，不能按服务名去重。遇到 `PrevEntry` 循环或单条链超过 100000 条会让任务失败并保留已输出记录，这张镜像没有触发。

注册表取名称包含 `machine\system` 的第一个 hive，路径先试 `CurrentControlSet\Services`，失败再试 `ControlSet001\Services`。读不到的子键和值跳过，不让任务失败。`ImagePath` 和 `ServiceDll` 区分大小写。值单元格读失败时按空字符串处理，对应基线用零填充后再去掉末尾 NUL。没有这两个值时，对应列不可用。

`max-nodes` 默认 131072，限制活动进程和每个 VAD 树，不是上游参数。摘要行不是服务。

官方 Windows 10 19041 样本有 1 个 `services.exe`，142 个 `serH` 头，350 个注册表服务键，共 1578 行，与固定基线一致。其中 746 个偏移互不相同。启动类型是 1196 个 demand、181 个 auto、97 个 boot、67 个 system、37 个 disabled。1152 个 stopped，426 个 running。1373 个 PID、1162 个内存路径、868 个注册表路径和 1296 个 DLL 为空。4 个注册表路径是空字符串。首行是 `SSDPSRV`，order 446，PID 4536，偏移 `0x1ffc9a78660`。

真实 32 位镜像、其他 Windows 版本的整镜像差分、旧版端到端流程和时间线仍待完成。服务链表与扫描差异已提供，见[服务对照](windows-services.md)。坏标签或父指针不一致的 VAD 树会让任务失败；这张镜像的树已经由 `windows.vadwalk` 接受。

```sh
python3 tools/diff_results.py \
  --native native-windows-svcscan.jsonl \
  --reference reference-windows-svcscan.json \
  --mapping docs/diff/windows.svcscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestSvcScan|TestService|TestOfficialWindowsSvcScan' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.svcscan.SvcScan` 生成。当前保持 partial、accepted=false。

## 服务布局与独立参考

`tools/build_service_oracle.py` 先校验锁定的 Python 源码摘要和归档 SHA256，再逐字节校验 16 份服务 ISF；从中生成 Go 偏移事实表。上游部分字段超过其声明结构大小，原生读取器按字段作有界读取，不依赖错误的结构总长。25398 x64 的 `ServiceProcess` 与 `DriverName` 偏移分别为 336 和 296，分别读取。32 位指针截断为 32 位；64 位服务用户指针按基线掩为 48 位。指针为零时仍由实际内存映射决定是否可读，不预先替换成不可用。

224 个记录参考由固定版本的 `SERVICE_RECORD` 和 `SvcScan.get_record_tuple` 实际解码生成，覆盖每套布局的运行进程、驱动、停止、非法 Order/Start/State、缺失名称/PID/路径、坏高位、零指针、截断结构和短字符串读取。136 个版本选择参考直接运行上游版本谓词和布局选择表，覆盖完整/缺失 build 的 PE 元数据及符号/类型回退。Go 测试比较全部 11 列的值或不可用结果；这些是合成对象级验证，不能替代整镜像分析。

保留固定基线的三个版本选择特例：完整四段 PE 元数据不满足其三段 15063 等值判断；Windows 8 x86 的专用规则因上游架构标志重复而不可达，最终使用 Vista x86；缺少整个类型时，成员存在性回退按基线的特殊布尔逻辑处理。缺少 build 的三段 PE 元数据会转用符号回退。扫描标签另外按 Vista 版本谓词选择，不从布局名称猜测。Coverage 记录实际 `layout` 和 `pointer_size`。

```sh
.cache/reference-venv/bin/python tools/build_service_oracle.py --check
go test ./internal/plugins -run 'TestServiceLayoutOracle|TestServiceVersionOracle|TestServiceLegacy' -count=1
```
