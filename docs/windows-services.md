# Windows 服务链表与扫描对照

`windows.svclist` 对应固定基线的 `windows.svclist.SvcList`；`windows.svcdiff` 对应 `windows.malware.svcdiff.SvcDiff`，也覆盖弃用别名 `windows.svcdiff.SvcDiff` 的分析语义。运行时全部使用 Go。

```sh
bin/gomem analyze windows.svclist --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.svcdiff --image memory.dmp --case ./case-001 --offline --format jsonl
```

两条命令共享 [svcscan 的服务记录解析与注册表映射](windows-svcscan.md)。字段布局现已扩展到基线全部 16 套，并分别通过对象级合成对照，见 [svcscan 的布局验证](windows-svcscan.md#服务布局与独立参考)。链表门槛沿用上游的 Windows 10 15063+ x64 判断：优先使用完整四段 PE 版本元数据；元数据不完整（包括缺少 build）时，回退检查 `ObHeaderCookie`、`_HANDLE_TABLE.HandleCount` 和 `_EPROCESS.KeepAliveCounter`。32 位仍明确拒绝；这与基线的链表插件门槛一致。字段偏移实现不代表完整版本矩阵已通过整镜像验收。

`svclist` 按 VAD 前序，取第一个文件路径忽略大小写后以 `\services.exe` 结尾的区域。只在这里搜索 `Sc27`，命中必须按 8 字节对齐。每个头都完整遍历 `PrevEntry`，不使用扫描插件的全局元组去重。第一条显示记录本体地址，后续条目显示前一条记录的 `PrevEntry` 槽地址；证据来源保留实际读取的记录地址。不存在主映像 VAD 或进程层无法建立时，在 Coverage 中计数。未知版本明确失败。循环链表与 100000 条遍历上限让任务失败并保留此前输出。

`svcdiff` 共用一次注册表映射，分别执行扫描与链表枚举。名称区分大小写，每个名称保留最后一次扫描记录；输出扫描存在、链表不存在的名称及该记录，按名称排序以便复现。无法读取名称、跳过进程层或缺少主映像 VAD 时明确失败，防止将不完整枚举当成隐藏服务。Coverage 保留扫描行数、扫描名称数、链表行数、链表名称数和差异数。没有任何 `services.exe` 时双方都是空集合，与基线一致；这不能证明镜像中不存在隐藏服务。

选定 Windows 10 19041 样本有一个可读取的 `services.exe`。基线 `svclist` 返回 646 行、646 个名称，其中 189 个 running、457 个 stopped；启动类型为 480 个 demand、78 个 auto、43 个 boot、29 个 system、16 个 disabled。551 个 PID、460 个内存路径、331 个注册表路径和 519 个 DLL 不可用。对照映射比较全部 11 列，并保留不可用原因与重复行语义。扫描的 1578 行包含相同的 646 个名称，`svcdiff` 返回 0 行。真实隐藏服务阳性仍需新增镜像，合成测试覆盖扫描差异、同名最后记录、大小写、重复链、跨页标签、取消、循环和输出失败。

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestOfficialWindowsSvc(Scan|List|Diff)$' -count=1 -timeout 30m -v
go test ./internal/plugins -run 'TestSvcScan|TestService' -count=1
```

参考由锁定的 `tools/reference.py` 分别运行 `windows.svclist.SvcList` 与 `windows.malware.svcdiff.SvcDiff` 生成。差分映射是 `docs/diff/windows.svclist.json` 和 `docs/diff/windows.svcdiff.json`。其他 Windows 版本的整镜像对照、旧版 VAD 入口、真实 32 位和时间线仍未完成。能力保持 partial、accepted=false。
