# Linux 映射、文件路径与执行线索

`linux.maps` 对应固定基线 `linux.proc.Maps` 的部分原生能力，保持开发预览和 `accepted=false`。支持带 `mm_struct.mmap` 的 VMA 链表及带 `mm_mt` 的 Maple Tree；旧链表使用官方 Debian 3.2 镜像验证，Maple Tree 当前只有显式合成 ABI 测试，尚未验收真实现代内核的全部 pivot、meta 和版本语义。

```sh
bin/gomem analyze linux.maps --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.maps --image memory.raw --case ./case-001 --offline --param pid=100,101 --param address=0x400000,0x700000
bin/gomem analyze linux.maps --image memory.raw --case ./case-001 --offline --param include-past-eof=false
```

原生输出保留 VMA 对象地址、PID/名称、区间、原始标志及 rwx 权限、页偏移、inode/设备、文件对象、路径及原始字节。进程身份沿用 pslist 的镜像、地址空间、对象、PID 和启动纳秒值。VMA 内存区间本身为 `[Start, End)`；地址筛选保留固定上游 `Start <= address <= End` 的边界行为，因此位于边界的地址可能同时选择相邻区域。`max-nodes` 和 `max-regions` 对遍历生效，即使筛选后没有输出也不能绕过上限；损坏链表、owner、重叠、树父节点、重复槽、深度和未知节点类型会使任务失败，取消会保留已输出行。

Maple Tree 按类型声明读取 dense、leaf、range 和 allocation-range 槽，核对根和父节点、树高度、指针宽度与节点上限，并支持直接根指针。编码依据为 [Linux v6.1 maple_tree.h](https://github.com/torvalds/linux/blob/v6.1/include/linux/maple_tree.h)。当前未验证完整 pivot 区间及活跃 meta 边界，不能把合成测试视为全部 6.1+ 内核验收。针对 VMA/树与路径元数据的 Go fuzz 已接入常规 fuzz 和 CI；其结果仅验证有界解析及输出不变量。

路径解析支持旧 `vfsmount` 与内嵌 `mount`，以及旧/新 file、fs root、qstr 布局。跨挂载点回到进程根；若映射来自 chroot 前的文件并到达可验证的全局挂载根，输出 `PathScope=global_root`，避免冒充进程根内路径。动态名字只识别声明符号对应的 simple/socket/pipe/anon_inode 回调，绝不执行目标代码；未知回调保留错误。带斜线的叶 dentry 标签标为 `dentry_label`。其他作用域为 `process_root`、`anonymous_name` 或 `dynamic_name`。`PathRaw` 保留 UTF-8 替换前的字节；删除状态由 inode link 数记录，规范路径以 ` (deleted)` 标示。

默认保留 inode 页偏移超过正 inode 大小的映射，提供 `InodeSize` 与 `FileOffsetPastEOF`，它们是元数据线索，不能自动判为恶意。固定上游的有效性启发式会过滤这些映射；`include-past-eof=false` 提供对应视图。无法读取 inode 大小或偏移的条目仍保留明确错误，不会因该选项静默过滤。两个视图分别缓存并写入参数来源。

官方 Linux 样本的完整视图为 14,045 个区域，其中 55 个页偏移超过 inode 大小；对应过滤视图为 13,990 个，与固定上游的十字段多重集完全一致：PID、Process、Start、End、Protection、PgOff、Major、Minor、Inode、Path。[比较映射](diff/linux.maps.json) 仅去掉上游给已删除绝对路径增加的一个显示空格，保留文件名内部及其他空格；不归一化读取错误。样本含 135 条全局根路径及八条叶标签路径，均明确标记作用域。[验证记录](linux-maps-validation.json) 保存视图、参数、摘要及分诊结果，原始镜像和路径列表不提交。

Linux 分诊按已封存的映射分页执行直接 RWX 和删除文件/memfd 执行规则，引用原始映射和进程身份。非执行区域无需推断删除状态；普通执行文件删除状态不可读时检查失败，不能当作正常。合成场景提供两个进程的阳性和正常对照、未知删除状态、证据引用及白名单测试；官方样本在这两条窄规则下没有命中，整体仍因扫描进程、扫描模块和持久化等缺口报告 incomplete。该结果不代表镜像正常或完整恶意内存检查完成。

设置绝对 `GOMEM_CORPUS_DIR` 后，`go test ./internal/engine -run TestOfficialLinuxMapsBothViews -v` 核验完整/过滤视图、全部基线实体、55 个有证据的额外映射、路径和作用域。常规合成测试覆盖全部上述树布局、旧/新挂载及根布局、损坏结构、未知回调、原始非 UTF-8 路径、地址边界、PID 集合和取消；现可用 `--param dump=true` 提取区域；Linux maxsize 排除相等或更大区域，零会跳过全部。所选区域已完成上游字节对照，见 [提取说明](artifacts.md)。真实新内核、架构、恶意 VM 和完整参数仍待验收。
