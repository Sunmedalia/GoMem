# Xen ELF Core 内存层（v0.1 开发预览）

GoMem 原生识别 ELF64 Core 中的 `.xen_pages` 与 `.xen_pfn` / `.xen_p2m`，提供来宾物理地址视图。PFN 表按 64 位整数解析；P2M 表按 16 字节 PFN/GMFN 对解析，使用 PFN 定位来宾物理页，不把 GMFN 当作文件偏移。支持 ELF 声明的大小端序，页内容直接从原镜像按需读取。

```sh
bin/gomem doctor --image guest.core --offline
bin/gomem analyze generic.info --image guest.core --case ./case-xen --offline
bin/gomem analyze linux.pslist --image guest.core --symbols kernel.json --case ./case-xen --offline
```

`doctor` 的 `image_format` 为 `xen`，`xen_core` 显示实际布局、页大小、总页数、有效/无效页数及已解析的 Note 信息。Windows/Linux 插件使用同一地址转换器；自动根发现仍受既有平台/符号条件限制。没有 CPU 状态自动恢复或 Xen 特有操作系统插件。

## 格式与错误处理

按 [Xen 官方 Core 格式说明](https://xenbits.xen.org/docs/4.6-testing/misc/dump-core-format.txt) 解析页索引；`.note.Xen` 存在时，校验 NONE、Header 和 Format Version Note。支持格式版本 0.1，检查 Core magic、页数及 4KiB 至 2MiB 的二次幂页大小。CPU 数量作为元数据保留，Xen 版本描述等未知 Note 不用于地址转换。

无 `.note.Xen` 时提供与基线同类的 4KiB 读取路径，并兼容旧式 `0xffffffff` 无效标记；此时 `has_notes=false`。有完整 Note 时使用规范的 64 位无效标记，`0xffffffff` 是可用 PFN。PFN 0 保留；无效页保持未映射，不补零。P2M 的 64 位无效 PFN/GMFN 必须成对。

必须恰有一个 PFN/P2M 索引，索引条目数与页存储长度一致。重复关键节、压缩/无存储关键节、重叠 PFN、越界/溢出、截断、错误 Note 和不支持的版本均明确失败；识别到 Xen 后不回退到普通 PT_LOAD 或 RAW。相邻物理/存储页合并为范围，页索引以 64KiB 块解析。当前上限为 16,777,216 个索引条目、1,048,576 个碎片范围和 1MiB Note。

共同 ELF 入口增加元数据预算：程序/节表各最多 65,536 项，节名表不超过 16MiB，单个节名不超过 4096 字节，累计节名不超过 16MiB。拒绝压缩节名表及尚未由 Go ELF 读取器支持的扩展程序计数 `PN_XNUM`，并在 `debug/elf` 分配之前检查扩展计数、表范围和节名。这些限制会明确拒绝超预算文件。

## 对照和验证

`tools/build_xen_oracle.py --check` 在未修改的固定 Volatility 基线中实例化真实 `XenCoreDumpLayer`，保留映射、读取散列及异常。11 个 Core 的文件散列、预期物理页散列和基线结果存于 `pkg/memory/testdata/xen-oracle.json`。

| 控制 | 结果 |
|---|---|
| 普通 PFN、旧 32 位无效标记、带 4KiB Note 的 PFN | 3 组指定路径的映射和读取字节与基线一致；原生合并相邻范围 |
| PFN 0 | 原生保留，基线跳过 |
| 64 位无效 PFN | 原生保持缺页，基线生成超 64 位地址并读取失败 |
| 两组 P2M | 原生正确读取，基线符号布局导致 `AttributeError` |
| 带 Note 的 `0xffffffff` PFN | 原生保留，基线跳过后无映射 |
| 64KiB 页 | 原生使用声明大小，基线固定为 4KiB |
| 大端 ELF、重排节名字符串表 | 原生按头字段读取；基线失败或误取节 |

这些差异保留为未完成对齐项，没有记作完整验收通过。

Go 测试覆盖以上页字节、跨页/洞、PFN 0、坏元数据、重复/压缩节、超预算 ELF、取消和实际读取错误。`FuzzXenCore` 与已有 `FuzzDetect` 各 10,000 次执行通过。Windows/Linux 合成分页样本分别通过 PFN/P2M 容器运行进程分析、封存检查和缓存回放，另验证 HTTP Range 源上的 Xen P2M 自动组层；比较指定进程列，容器哈希与原 RAW 哈希保持区分。

`GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialXenReencodedLinux$' -count=1 -v` 将真实 Debian 512MiB RAW 流式重编码为两种索引的 Core。两种容器的完整物理字节 SHA-256 均为 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`，自动 DTB 发现、133 条有序指定进程列、案件封存和缓存通过。

重编码语料不是真实 Xen 采集器语料。仍缺真实 PV/HVM producer 样本、版本/架构覆盖、CPU/完整 Note 语义以及完整验收；Xen 保持 partial。VMware、QEMU 仍待实现。
