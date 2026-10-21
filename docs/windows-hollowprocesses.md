# Windows 进程空洞线索

`windows.hollowprocesses` 对应固定基线 `windows.malware.hollowprocesses.HollowProcesses`，原生读取进程、PEB、加载链表和 VAD。运行时不调用 Python、Volatility 或目标系统代码。旧路径 `windows.hollowprocesses.HollowProcesses` 是上游弃用别名。

```sh
bin/gomem analyze windows.hollowprocesses --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.hollowprocesses --image memory.dmp --case ./case-001 --offline -p pid=384,488
```

先枚举原生 PEB 的加载顺序 DLL，再枚举 WoW64 PEB，支持直接 32 位 PEB 指针和 `_EWOW64PROCESS.Peb`、`_WOW64_PROCESS.Wow64` 两种包装。DLL 以基址、VAD 以起点建立映射。同基址后出现的值覆盖旧值，DLL 检查顺序仍保留第一次出现的位置。少于 3 个不同 DLL 基址或少于 5 个不同 VAD 起点的进程跳过。

检查顺序和 Notes 保留固定基线语义：

1. 原生 PEB 的 `ImageBaseAddress` 是否与内核 `SectionBaseAddress` 不同。
2. 是否有 VAD **恰好起始**于 `SectionBaseAddress`；如果有，其初始保护是否恰好等于 `PAGE_EXECUTE_WRITECOPY`。
3. 加载顺序 DLL 如有同基址 VAD，其初始保护是否恰好等于 `PAGE_EXECUTE_WRITECOPY`。DLL 没有对应 VAD 时，上游为减少采集不一致导致的误报而忽略。主 EXE 在加载列表里时，同一个区域可以由 EXE 和 DLL 两项检查分别报告。

VAD 使用共用树和保护缓存，支持直接及 Core 包装。空或不可读的 VAD 文件路径在 Notes 中使用 `<Non-File Backed Region>`；这不能证明原本没有文件映射。DLL 路径使用加载条目自身的 `FullDllName`，不回退到 VAD 文件名。长度为零、奇数字节、无效代理项和内嵌 NUL 按基线字符串语义处理。不可读 DLL 路径在 Notes 中是 `-`，`Path`、`PathError` 保留缺失原因和读取错误。

每条 finding 保存进程身份和对象地址、规则、映像/节基址，以及适用的 VAD 对象地址、保护、路径、加载条目地址和所在进程层。进程身份包含镜像、地址空间、对象地址、PID 和可用创建时间。证据来源偏移是进程对象地址，案件引擎补全镜像哈希、符号摘要、参数和原始行 ID。

无法建立进程层、读取 PEB 加载指针、DLL 基址或路径时，输出 diagnostic。加载链只跟随 Flink；零指针、已访问的节点或不可读/无效节点按基线结束，最后一类另有诊断。节点上限、VAD 结构、保护和节基址读取错误让任务失败，保留此前输出。摘要记录 processes、short_dll_sets、short_vad_sets、checked、findings 和 diagnostics。diagnostic 与 summary 不计为发现；即使 finding 为零，也必须检查这些覆盖信息。`max-nodes` 默认 131072，限制活动进程、VAD 树和每个 PEB 加载链，是原生参数。

这些检查给出调查线索。JIT、合法解包、终止进程和采集不一致都可能影响保护或映射。需要结合代码、原始 VAD、PEB 和其他证据判断，不能仅据该插件确认进程空洞。

## 验证与缺口

选定 Windows 10 19041 x64 镜像检查 120 个进程，21 个因 DLL 数不足跳过，99 个进入检查，没有 VAD 数不足的进程；两个引擎均为 0 条发现。原生保留 330 条诊断：311 个 DLL 路径读取失败、14 个 PEB 加载指针不可读、5 次加载链在无效或不可读节点结束。镜像 SHA-256 为 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`。这仅是正常对照。

576 个参考直接调用固定 Python 检查函数，比较完整 Notes，覆盖正常/异常/附加保护、缺失 EXE VAD、不同映像基址、空/不可读/Unicode 路径、缺失 DLL VAD和重叠规则。完整合成流程覆盖四种线索、正常对照、精确起点、阈值、重复基址覆盖、原生/WoW64 顺序和 32 位加载字段、错误诊断、取消、输出失败和遍历上限。

```sh
.cache/reference-venv/bin/python tools/build_hollowprocess_oracle.py --check
go test ./internal/plugins -run TestHollowProcess -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsHollowProcesses -count=1 -v
```

真实阳性、其他 Windows 版本、原生 x86/WoW64 端到端差分、完整参数及误报验收仍缺失。保持 partial、accepted=false。
