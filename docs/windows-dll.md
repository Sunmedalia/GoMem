# Windows 进程 DLL 与加载器诊断

`windows.dlllist` 对应固定基线 `windows.dlllist.DllList` 的部分原生能力，保持开发预览、`accepted=false`。

```sh
bin/gomem analyze windows.dlllist --image memory.dmp --case ./case-001 --format jsonl
bin/gomem analyze windows.dlllist --image memory.dmp --case ./case-001 --offline --param pid=384
bin/gomem analyze windows.dlllist --image memory.dmp --case ./case-001 --offline --param name='ntdll\.dll$' --param ignore-case=true
```

插件沿活动进程链表获取进程对象，建立每个进程独立的物理页表根，再读取用户地址空间的 PEB、PEB_LDR_DATA 和 InLoadOrderModuleList。原生 x86/PAE/x64 结构来自精确符号。输出 DLL 对象地址、基址、大小、名称、路径、加载计数、100ns 时间与原始时间值、PEB、架构、布局摘要和进程身份；身份与 pslist 相同，包含镜像、内核地址空间、对象、PID 和可用创建时间。

WoW64 同时遍历原生与 32 位 PEB：按符号声明识别 EWOW64PROCESS.Peb、旧 WOW64_PROCESS.Wow64 或直接 PEB 指针。32 位加载链、基址、大小和 Unicode 字符串使用单独的四字节指针布局，`Architecture=wow64-x86`，并在 `LayoutSHA256` 保存该布局的独立摘要。基本偏移按锁定上游 [wow64.json](https://github.com/volatilityfoundation/volatility3/blob/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/wow64.json) 核验。

该上游表的 LDR 类型声明大小为 160 字节，而 LoadTime 偏移为 256，且没有 LoadCount 字段。GoMem 不读取这一越界时间，而把 WoW64 LoadTime/LoadCount 明确标为 `unsupported_loader_field`。其他原生加载时间与计数仍按目标类型解析；计数按上游有符号 short 解释，例如 0xffff 为 -1。完整 32 位加载元数据需要后续匹配的符号与版本验证，不能把本次稳定基本字段实现当作完成。

`pid` 支持集合；`base` 采用精确基址筛选，零与上游一样不启用筛选。`name` 对名称或全路径匹配，使用 Go RE2；`ignore-case` 控制大小写。Python 的后向断言等不兼容表达式直接报错，不伪装成无命中。读取失败使名称筛选无法可靠执行时，记录诊断并使任务失败。`max-nodes` 限制进程及单个 PEB 链表，`max-modules` 限制总遍历量，过滤不会绕过限制。物理 offset 进程扫描、DLL PE 重建/dump 和时间线导出尚未实现，相关未知参数会明确拒绝。

`RecordType=module` 为模块；`RecordType=diagnostic` 保留非空 PEB 不可读、loader 不可用或损坏链表等阶段与具体错误。诊断后继续其他进程，最终任务失败，防止未读加载器被当作正常空列表。空 PEB 且无 WoW64 指针的进程不产生 DLL。可选名称、路径和加载元数据缺页以带错误的 missing 单元格保留；FullDllName 独立读取，不因 BaseDllName 缺页而放弃可读路径。取消和输出错误保留此前结果。

官方 Windows 10 19041 镜像取得 5,742 个模块，含 5,525 条原生及 217 条 WoW64 记录；PID、进程名、基址、大小的完整多重集一致。其中两个核心键在原生和 WoW64 列表中重复，比较和存储均保留，不能用 PID/基址字典去重。全量任务另保留 19 条诊断（14 条 PEB 不可读、五条加载链表不完整），因此任务状态为 failed，原始总行数为 5,761。

相同镜像直接加载原生 PDB 时，也得到相同的 5,742 个核心字段匹配模块和 19 条诊断；转换符号摘要单独记录，未依赖预生成 ISF 才能完成枚举。

可读名称 5,414 条、共同可读路径 5,410 条、原生加载计数 5,525 条和原生加载时间 5,524 条与上游一致，时间按上游整秒精度对照。328 个名称和 311 个路径读取错误保留具体缺页原因，上游对应 null。另有 21 个路径在基本名称缺页时仍可读取，上游因两个名称共用异常处理而显示 null。WoW64 时间未参与一致性判断。只选 PID 384 时，两个模块的八个字段完整匹配且无诊断。

[核心映射](diff/windows.dlllist.json) 显式选择 module 记录，并在报告中保留原始行数和排除的诊断数量；不将这些诊断计为成功空结果。另有 [可读样本映射](diff/windows.dlllist.readable.json)，包括名称、路径、有符号计数和时间。[聚合验证记录](windows-dll-validation.json) 保存任务状态、摘要、异常类别和适用范围，镜像及原始路径不提交。

常规测试覆盖原生/WoW64、合成 x86/PAE、独立进程根、PID/基址/正则筛选、符号和布局、缺页、空 loader、循环、上限、取消与输出失败。`GOMEM_CORPUS_DIR` 设为绝对语料目录后，`go test ./internal/engine -run TestOfficialWindowsDLLsAndExplicitDiagnostics -v` 核验完整多重集、诊断及可读字段。旧版 Windows、完整 WoW64 元数据、物理扫描、PE 导出和全部参数差分仍待完成。
