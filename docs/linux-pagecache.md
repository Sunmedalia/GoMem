# Linux 页缓存与 inode 文件恢复（开发预览）

`linux.inodepages` 对应固定基线的 `linux.pagecache.InodePages` 显式 inode 路径。完整能力尚未验收，`find` 路径查找、`Files` 文件系统枚举及 `RecoverFs` 仍未实现。

```sh
bin/gomem analyze linux.inodepages --image memory.raw --symbols exact.json.xz \
  --case case-001 --offline --format jsonl \
  --param inode=0xffff88001a87e518 --param dump=true
```

只接受非零 inode 地址、非负引用计数、正规文件类型和非负 i_size。内嵌 address_space.page_tree/i_pages 使用声明的 radix_tree_root/xarray 类型；节点宽度来自 slots 指针数组，支持旧 height、path 和新 shift。检查根/子节点高度、指针对齐、重复节点、索引溢出和遍历上限；读失败保留已验证的前缀并报告失败。max-nodes/max-pages 均为 1..1,000,000，默认分别为 131,072/1,000,000，后者限制所有非零叶条目。

PageVAddr、PagePAddr、MappingAddr、Index、DumpSafe 和 Flags 提供可对照字段；TreeIndex、TreeValue、Slot、Span 保留树中原始来源。page.index 必须与树索引一致，page.mapping 必须与目标 inode.i_mapping 完全一致。原始 FlagsRaw 独立保存，Flags 按 pageflags 位索引和字典序展示，不把未知位移除出原始值。节点/字段读取错误使任务 failed；读取错误不能当成正常空树。

物理地址使用 `struct page` 数组中的精确 PFN：四级 x64、mem_section 标识的 vmemmap 使用固定 VMEMMAP_START 或读取 vmemmap_base 符号值；flatmem 读取 mem_map 指针值。记录数组基址、类型大小、推导来源及可用 max_pfn，验证整除、范围和溢出。PFN 0 是有效地址。NUMA、32 位 sparsemem、五级页表和其余架构不猜测地址。vmemmap 路径沿用固定基线的内存模型判据，尚需现代真实镜像验证。

XArray 值、radix exceptional 值保留条目，不作为 struct page 解引用。大 folio（多索引跨度）、sibling 和保留内部值尚不解码，明确输出错误并使任务失败；不会将单个 4KiB 页伪装为整个 folio。现代树和内存模型当前主要通过合成测试，不能据此宣称实机兼容矩阵已完成。

DumpSafe 表示页归属、索引、布局和逻辑文件范围满足导出条件；Captured 另表示整个 4KiB 物理页可读。物理读取缺失会使任务 failed，但仍按捕获前缀恢复并记录剩余物理空洞。页超出 EOF 时不导出，不推断原磁盘内容。

导出只进入案件目录，文件名使用完整虚拟 inode 地址。按逻辑页索引顺序写出恰好 i_size 字节（默认上限 1GiB，maxsize 可设为 0..4GiB-1），不加载整文件。没有缓存的逻辑范围填零，并在独立 gap 日志中记录文件偏移、长度、`file-cache:inode:<address>` 坐标和 `uncached_page` 原因。物理页读取失败则保存真实物理层、物理偏移和读取错误。树或页验证失败导致的未知范围标记为 `coverage_unknown_due_to_cache_error`，任务同时 failed。填零不是恢复到原始字节；完整文件长而无缓存会产生全空洞文件，合法零长度文件单独导出为空文件。成功且含空洞的文件状态为 completed_with_gaps。

每次输出包含 summary 行，即使没有缓存页，也可检查文件大小、nrpages、树节点/条目数、内存模型、产物及错误。nrpages 是内核的基页计数，不能在存在 exceptional/folio 时当作叶条目数量；保留计数供审查。错误时已验证的页仍可导出，原始镜像始终只读。

选定 Debian 3.2 x64 镜像的 syslog/messages/auth.log/utmp 四个 inode 共 9 页，六个页字段和 46,838 字节导出与固定基线一致。syslog 前 20,480 字节没有缓存，原生显式保留空洞而基线仅在文件中留零。独立 Python 校验器从 RAW 页表、ISF 字段、radix 全部叶条目和 PFN 计算重新核对页集合、归属、全部导出字节与空洞坐标，不导入 Volatility 或调用 GoMem。选定 RAW 的 AVML 重编码另验一致性；这仍是一份旧内核采集，不能当成多个独立语料。[机器验证记录](linux-pagecache-validation.json)

```sh
python3 tools/verify_pagecache.py --native rows.jsonl --case case-001 \
  --image memory.raw --symbols exact.json.xz --dtb 0x1605000
```

独立校验器刻意限制为旧 radix、固定 vmemmap、RAW/x64 和最多 16MiB 的选定文件，未覆盖 XArray 或现代内存模型。通用证据包验证器另检查文件、gap 日志、行和来源哈希；整套版本/架构、参数语义及故障覆盖仍在能力矩阵中保持未完成。
