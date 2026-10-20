# Windows 进程字段与模块导出

`windows.pslist` 输出活动进程的 PID、PPID、名称、线程数、句柄数、会话、WoW64、创建/退出时间及原始 FILETIME。句柄数只解释精确 `_HANDLE_TABLE.HandleCount`；符号中没有该成员时标记 `unsupported_handle_count`，不按句柄表形状推算。会话只解释 `_MM_SESSION_SPACE.SessionId`；Windows 11 不透明会话类型没有可验证字段时保留缺失原因，不猜固定偏移。

```sh
bin/gomem analyze windows.pslist --image memory.dmp --case ./case-001 --param physical=true --format jsonl
bin/gomem analyze windows.pslist --image memory.dmp --case ./case-001 --param pid=488 --param dump=true
bin/gomem analyze windows.modules --image memory.dmp --case ./case-001 --param name=win32k --param dump=true
bin/gomem analyze windows.modules --image memory.dmp --case ./case-001 --param base=0xfffff8043601f000
```

`physical=true` 只改变 Offset 的展示地址；VirtualOffset、Identity 和来源偏移仍使用内核虚拟地址，可继续关联线程、VAD、DLL 和分诊。OffsetSpace 明确区分 physical 与 kernel_virtual，物理偏移不做高位掩码。

进程 dump 使用各自 CR3 读取原生 PEB.ImageBaseAddress，重建主映像；WoW64 也按锁定基线读取原生 PEB。空 PEB 标记 `no_process_peb`，不创建文件；非空 PEB、页表或头部读取失败保留该进程行，任务失败，其他独立进程继续处理。FileOutput 绑定实际进程层，Patches 保存头部修改。缺页和磁盘文件的区别见 [PE 重建](pe-reconstruction.md)。

`windows.modules` 增加 FullDllName 路径及筛选：base 精确匹配完整原生地址，零不筛选；name 是区分大小写的 BaseDllName 子串，不是正则，也不匹配完整路径。过滤字段不可读时保留带错误的行并令任务失败；其他可选字段错误保留在单元格。

模块 dump 先检查已验证内核层能否读取 DOS 头，再在必要时按进程链表顺序缓存每个已验证 SessionId 的第一个可构建进程层。ExtractionAttempts 保存层、对象、PID、SessionId、阶段和错误，文件来源指向实际选择的层。选中层后仍需严格验证 PE 头和节表才创建文件。单个模块失败不阻止后续提取，所属任务失败。

会话目录仅在需要时建立，受 max-nodes 和 max-session-layers（默认 256，上限 4096）限制；超限或链表不完整明确失败。读取诊断最多保留前 64 项，额外数量单独记录；候选层及实际读取尝试完整记录。省略诊断不会使未读字节变成已捕获数据。每会话仅选择首个可构建根，复杂会话映射和完整失败语义仍待验收。

官方 Windows 10 19041 样本对照：

| 路径 | 结果 |
| --- | --- |
| pslist 虚拟/物理偏移 | 各 120 行的 10 个选定字段一致；时间比较到秒，100ns 精度保留 |
| 原生 PDB pslist | 同一 120 行的选定字段一致 |
| modules 路径 | 157 条可读路径一致；19 条错误对应上游 null，完整比较仍为不一致 |
| PID 488 主映像 | 28,672 字节逐字节一致，含 16,384 字节明确缺页填充 |
| ntoskrnl.exe | 17,063,936 字节仅 ImageBase 高位两字节不同，含 8,347,648 字节填充 |
| win32k.sys 会话 0 | 内核层不可读，经 PID 488 会话层提取；634,880 字节仅 ImageBase 两字节不同，含 81,920 字节填充 |
| 原生 PDB win32k.sys | 同一回退与重建字节，保留两个字节差异 |

模块文件名保留完整规范地址；显式名称映射不修改文件字节。内核/会话 PE 的两字节差异保持 matched=false，不能算作逐字节一致。四份证据包通过独立核验。[摘要与完整差分](windows-process-modules-validation.json) 保留错误、比较映射和构建/符号身份。

```sh
python3 tools/diff_results.py --native native-pslist.jsonl --reference reference-pslist.json --mapping docs/diff/windows.pslist.enriched.json
python3 tools/diff_results.py --native native-physical.jsonl --reference reference-physical.json --mapping docs/diff/windows.pslist.physical.json
python3 tools/diff_results.py --native native-modules.jsonl --reference reference-modules.json --mapping docs/diff/windows.modules.paths.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestOfficialWindowsProcessFieldsAndModulePaths|TestOfficialWindowsMainAndSessionPEs' -count=1
```

参考提取使用 `tools/reference.py --plugin windows.pslist ... --dump-dir NEW_DIR -- --pid 488 --dump` 或 modules 的 `--base BASE --dump`，再用 `tools/compare_extractions.py` 核验。对照入口见 [验证说明](validation.md)。旧版本/架构、特殊 PE、损坏链表双向恢复、完整会话与失败语义、时间线和全部参数组合仍未完整验收；保持开发预览。
