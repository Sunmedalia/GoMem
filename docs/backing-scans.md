# 带来源信息的映射与扫描接口（v0.1 开发预览）

`Intel.VisitBackingMappings` 和 `memoryscan.VisitBackingChunks` 是原生框架接口，支持 Intel 硬件映射及已配置的 Windows pagefile。现有插件没有统一迁移到这些接口；它们不表示所有插件已支持交换页，也不改变物理扫描的范围。

映射接口按虚拟地址顺序流式输出 `BackingMapping`：Virtual、Offset、Length、可选 Pagefile 编号及运行时 Layer。RAM 和不同编号的 pagefile 永不合并；相邻虚拟地址只有在同一来源中的偏移也连续时才合并。x64 的低半区/高半区保持独立，不能把非规范地址空洞合进一条线性映射。JSON 把地址和偏移写为十六进制字符串，编号为零的 pagefile 也明确保留；Layer 不进入序列化，不泄露或复制运行时读句柄。

`BackingMapOptions` 要求显式的页表/条目预算，支持与原物理映射接口相同的 section 选择和规范地址转换。默认仍排除地址域最后一字节；显式 section 可请求该字节，但后续扫描计划会拒绝无法表示的排他结束地址。新接口逐项检查 uniform 表，不沿用旧接口对相同条目整表的抑制；如果由此展开的重复表超过预算会明确失败。硬件映射使用实际 Translate 的帧地址，不采用旧映射接口中特定 Windows 显示掩码；这些变化不声称逐项复现旧扫描器的所有策略。

缺表、缺来源文件、缺目标范围默认报错。非零且无法解析的 Windows 软件项（包括 prototype 等）也明确报 unsupported；故障回调里的 Unresolved 映射不提供假的偏移或 RAM 来源。调用者可以保留诊断并继续，但 Unavailable 始终累计，扫描分块接口在交付可用分块后仍返回覆盖不完整错误。零项表示未映射，不是读取故障。已确定的映射在后续故障前尽量交付；取消或输出回调错误立即中止，最后仍在规划中的分块可能尚未交付。

`VisitBackingChunks` 把连续虚拟区域切成有界窗口，保留跨 RAM/pagefile 边界的 overlap；遇到虚拟空洞则结束当前区域，不拼接空洞两侧的字节。每块最多 32MiB、4096 个来源分段；单次底层读取不超过 16MiB，任务另有 MaxChunks 预算。PrimaryLength 标记由当前块负责的命中起点，`BackingBuffer.Accepts` 据此排除 overlap 重复命中。各块的 primary 字节连续、无重叠地覆盖所有成功规划的虚拟区域。

`AcquireBacking` 在任何 I/O 前验证整块的分段、连续性和预算，并复制输入描述，避免调用后修改参数改变已有证据来源。它记录每个已尝试分段的原始捕获前缀、长度、SHA-256、完整性和错误。任一分段短读或失败时，整块 Data 为 nil、Complete 为 false，禁止搜索；已经取得的原始前缀仍保留，绝不压缩或补零形成虚假连续字节。取消停止后续来源读取，未尝试的计划仍在 Chunk 中。成功缓冲的 `Sources(start,length)` 精确拆出命中字节所对应的原始来源和偏移，支持跨来源命中。缓冲与捕获字节由调用者只读使用，运行时 Layer 不得超出所属案件引擎的生命周期。

验证记录：

- 原有 54 个实际固定 Windows Intel 层交换对照现在也验证分块 section 的映射偏移、文件编号、范围和不可用的高层交换块。页内位移差异见 [Windows pagefile 说明](windows-pagefiles.md)；不把这些对照扩张为完整上游扫描验收。
- x86/PAE/x64 的 RAM、file 0、file 1 混合映射保留来源边界，对每条输出用原始 Layer 和 Virtual 两条读取路径核对字节。覆盖 section 截断、缺来源/根表、条目/表预算、取消、输出错误、未知软件项及 x64 规范地址边界。
- 扫描控制用三种分页模式、不同窗口大小验证跨 RAM/pagefile 的四字节命中只出现一次，原始两段偏移/字节准确；primary 重组与完整虚拟原文一致。短读、非法读取长度、计划错误和取消均不能形成可搜索缓冲。
- `FuzzWindowsPagefileResolve` 同时检查任意叶项的 Resolve、带来源映射和实际字节，10,000 次通过；`FuzzBackingScanSources` 随机选择模式、窗口和 section，重组 primary 字节并从来源独立重读，1,000 次通过。

旧 `MappedRanges` / `PageMappings` 只返回物理坐标，配置 pagefile 时继续明确拒绝。全插件迁移、逐段提取/报告接入、真实配套 pagefile 阳性语料、Linux swap、压缩存储和 prototype 解析仍未完成。当前 API 没有替代 YARA，也不支持 ARM64 backing 枚举；矩阵保持 partial。
