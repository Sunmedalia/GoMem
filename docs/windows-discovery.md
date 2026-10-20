# Windows 转储的自动配置

Windows 32/64 位完整或 bitmap 转储可从头部读取机器类型、PAE 标志、DTB、内核模块/进程链表地址和调试数据地址。这些字段是采集线索；在目标内存中验证之前，不作为成功的内核配置。

```sh
bin/gomem analyze windows.pslist --image memory.dmp --case ./case-001
bin/gomem analyze windows.modules --image memory.dmp --case ./case-001 --offline
bin/gomem doctor --image memory.dmp --case ./case-001 --offline
```

`--arch auto` 为默认值：完整/bitmap 转储按机器和 PAE 标志选择 x64、x86 或 PAE，其余镜像保持 x64 默认。显式 `--arch`、`--dtb`、`--kernel-base` 优先；CR3 的标志位在记录缓存参数前按实际转换器规范化。读取原始格式的参数仍可手工指定。

自动发现先尝试解码后的 KDBG：检查标签、大小、链表地址是否与转储头一致，再读取候选内核的 PE/CodeView。KDBG 编码、缺页、错误或候选未通过后续符号校验时，沿转储头的内核模块链表进行有界探测。链表须满足前后向、尾部与循环检查；每个节点仅探测前 256 字节中的指针。候选必须指向有效、架构一致的映射 PE，且为已知内核 PDB 身份或与显式符号身份完全匹配。

获取精确符号后，再验证 `PsLoadedModuleList` 和可用 `PsActiveProcessHead` 的 RVA 加基址是否等于转储头中的地址。模块探测路径还要求指针槽正是符号声明的 `DllBase` 字段，不能把偶然出现的内核指针当作模块基址。多个不同基址同时通过会报歧义。默认最多遍历 4096 个模块、保留 128 个候选、处理八种不同 PDB 身份，超限要求显式参数。

符号优先级为显式文件、匹配的本地索引、已验证 PDB 缓存及按精确身份在线获取。显式索引无匹配不会被下载掩盖；默认案件索引无匹配允许进入 PDB 获取。`--offline` 始终禁止网络。PE 的机器类型、可选头宽度、映像大小和 CodeView 范围也参与验证。

仅当 DTB 来自转储头的自动选择时，引擎还会遍历活动进程链表，寻找唯一 PID 4 的 System 对象。其页表根须在新地址空间重新验证相同 System 对象、精确 PE/PDB 和相同模块/进程链表头，才会采用；失败继续使用转储头的已验证根，并保存 `system_root_error`。`initial_dtb`、`dtb`、`system_process` 记录替换依据，显式 `--dtb` 不会被替换。官方样本从 `0x112c98000` 选择 `0x6d4000`；历史自动配置记录保留原始构建结果，新增验证见 [线程验证](windows-threads-validation.json)。

`doctor` 返回 `crash_header_hints` 和已验证的 `windows_discovery`；失败保存为 `windows_discovery_error`。自动配置失败时，物理段/字面扫描等不依赖内核的能力仍可使用；内核插件会返回实际失败原因，不能变为成功的空输出。案件任务保存最终 DTB、架构、内核基址、镜像与符号摘要。自动/显式配置相同时可复用同一已完成任务。

合成测试覆盖 x86、PAE、x64，解码和编码 KDBG、错误 KDBG 指针、伪造 PE、错误页表、符号/身份不匹配、链表损坏、错误指针槽、损坏 PE 大小，以及显式覆盖和缓存复用。官方 Windows 10 19041 完成无手工地址参数的进程/模块对照；通过只读层遮蔽 KDBG 标签，还验证了真实模块链表回退。具体范围和摘要见 [windows-discovery-validation.json](windows-discovery-validation.json)。这些结果不代表全部 Windows 版本或参数完成验收。

RAW、ELF/虚拟机格式中的通用 Windows DTB/基址搜索、ARM64、五级页表、无可读链表的恢复仍未实现。普通 `doctor` 输出包含未完成的自动配置诊断；正式发布仍由独立的 `--strict` 验收门槛阻止。
