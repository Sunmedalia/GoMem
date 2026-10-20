# 映射 PE 重建与导出

`windows.pedump` 及 `windows.dlllist dump=true` 原生重建 Intel PE32/PE32+，当前仍为部分实现和未完整验收。重建文件保持内存布局，不能视为原始磁盘 PE。实现对照锁定的 [PE reconstruction](https://github.com/volatilityfoundation/volatility3/blob/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/extensions/pe.py)：保存 SizeOfImage 范围及 slack，将 ImageBase 设为映射基址，将节的 PointerToRawData 设为 RVA，VirtualSize 和 SizeOfRawData 设为按 SectionAlignment 向上对齐的虚拟大小。

```sh
bin/gomem analyze windows.pedump --image memory.dmp --case ./case-001 --param pid=384 --param base=0x12340000 --format jsonl
bin/gomem analyze windows.pedump --image memory.dmp --case ./case-001 --param kernel-module=true --param base=0xfffff80000000000
bin/gomem analyze windows.dlllist --image memory.dmp --case ./case-001 --param pid=384 --param name='ntdll\.dll$' --param dump=true
```

必须选择非空 PID 集合或 kernel-module，不能同时使用。进程模式使用独立进程 CR3；内核模式先使用已验证内核层，必要时回退到精确 SessionId 对应的进程层。ExtractionAttempts 保存尝试，文件来源指向实际选择的层；会话目录与 `modules` 共用边界和诊断规则。`max-session-layers` 默认 256，上限 4096。某个 PID 的地址空间或头部失败会保留错误行并使任务失败，其余独立 PID 继续；取消和输出错误立即停止。DOS/NT 头、机器与 magic、可选头、节表、映像范围和对齐均有界检查。SizeOfImage 上限为固定基线的 256MiB，节数上限 4096；越界和畸形字段明确失败。PE 头及节头必须真实可读，数据缺页才允许填充并记录日志。更多异常合法布局及全部 Windows 版本仍待语料验收。

流式覆盖层只改写成功读取的头部字节，每个 Patches 项保存文件偏移、原因、原字节和新字节；其他捕获数据保持不变。每次读取最多一页，填充日志与区域提取共享，日志记录源层/地址。输入镜像始终只读。修改记录随原始结果和文件进入证据包；提取失败或取消保留阶段、原因与已产生证据。

官方样本的一个 200KiB 用户空间 PE 在显式文件名映射后逐字节一致；原生文件名中的 EPROCESS 地址保留完整高位，上游使用 48 位形式，[映射](diff/windows.pedump.files.json) 只改比较名称，不修改文件字节。该映像仅捕获 4KiB，其余 196KiB 明确记录为缺页填充。

内核 PE 为 17,063,936 字节，除 ImageBase 字段高 16 位对应的两个字节外全部相同。GoMem 保留完整 `0xfffff8043601f000`，上游写入其 48 位形式；这是有依据的输出差异，原始比较保持 matched=false。原始摘要、确切差异偏移及缺页字节数见 [验证记录](pe-reconstruction-validation.json)。没有归一化这两个字节以冒充完全一致。

另一个用户进程 PE 头不可读时，GoMem 任务失败、保留 missing 证据，且不创建空文件；上游提前新建文件后失败，留下零字节文件而没有结果行。该负例按失败行为验证，未算作恢复成功。

DLL 枚举的 dump 联动另验证了 PID 488 的 28KiB 映像，文件名、大小和逐字节内容均一致，其中 16KiB 是显式缺页填充；不把这个选定案例推广为所有 DLL 都能恢复。

`windows.pslist` 的主映像与 `windows.modules` 的内核/会话模块提取也使用此重建器。modules 通过已验证 SessionId 的进程层回退并保存尝试记录；其选定字段、文件差分和独立证据包核验见 [进程/模块验证](windows-process-modules.md)。显式 `windows.pedump kernel-module=true` 使用同一回退路径，ISF/PDB 的真实会话提取与多 PID 失败保留范围见 [会话 PE 验证](pe-session-validation.json)。

常规测试用 Go debug/pe 重新解析重建结果，检查两种位宽、重写字段、slack、补丁原值、源不变、坏签名/机器/大小/对齐/节及取消；真实样本检查用户与内核摘要，独立包核验器再检查文件/缺页日志。`FuzzMappedPEReconstruction` 验证解析计划与修改边界，已接入 CI。完整版本、架构、session 层及模块/进程参数组合的完整验收、数字签名有效性及所有合法特殊 PE 仍待补齐。
