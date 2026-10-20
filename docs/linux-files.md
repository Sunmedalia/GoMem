# Linux 缓存文件系统枚举（开发预览）

`linux.files` 对应固定基线 `linux.pagecache.Files` 的缓存 inode 枚举和筛选；`linux.inodepages` 可据此用 find 路径定位正规文件并导出页缓存。完整能力仍未验收。

```sh
bin/gomem analyze linux.files --image memory.raw --symbols exact.json.xz \
  --case case-001 --offline --format jsonl
bin/gomem analyze linux.files --image memory.raw --symbols exact.json.xz \
  --param type=REG --param find=/var/log/syslog
bin/gomem analyze linux.inodepages --image memory.raw --symbols exact.json.xz \
  --case case-001 --param find=/var/log/syslog --param dump=true
```

数据源是活动任务的挂载命名空间，不是打开文件列表。每个捕获的 namespace 选一个可读任务根，遍历旧 vfsmount/新 mount 链表，或新版 namespace.mounts 的 rb_root，再为每个超级块选择第一个挂载路径。Mount、Namespace、TaskOffset、MountID 及可用 NamespaceID 保存来源；旧内核缺少 namespace inode 字段时明确缺失，仍保留结构地址。挂载结构以地址去重，不凭可能重用的数字 ID 混同对象。

从 super_block.s_root 遍历缓存 dentry，支持旧 d_u.d_child union、中期 d_child/list_head，以及新版 d_sib/hlist_head。检查父目录、链表双向关系、hlist.pprev、树父指针、循环和重复节点。rb_tree 检查结构关系，不声称验证了红黑树颜色平衡。负 dentry（d_inode=NULL）计入覆盖但不伪造文件；正 inode 的号码、引用计数、超级块归属、mapping、类型、设备、大小、页数、链接数和精确纳秒时间均读取并保留错误。损坏分支保留诊断和已捕获结果，任务 failed；取消和输出错误立即停止。

每个 inode 第一条为 file；不同 dentry 指向已出现的 inode 时另输出 alias，保留 FirstDentry、ParentDentry 和原始路径。类型筛选为 REG/DIR/LNK/CHR/BLK/FIFO/SOCK，可逗号或空格分隔，只影响输出，不剪掉目录遍历。find 在类型筛选后返回第一个完全相等的原始路径，包括硬链接别名；不要求它出现在打开文件列表。完整扫描未命中只证明捕获的缓存树没有匹配，不能证明磁盘上不存在该文件。

FilePath/MountPoint 是有效 UTF-8 展示；PathRaw/MountPointRaw 保存原始字节。find 接收不含 NUL 的绝对 UTF-8 路径，不进行清理或折叠；非 UTF-8 名称仍可枚举，后续可使用明确 inode 地址。快符号链接 i_link 可读取时只注释为 `path -> target`，SymlinkTargetRaw 独立保存字节，不执行或遍历目标；不可用的旧布局不猜测目标，截断读取保留前缀并失败。find 始终匹配没有箭头注释的原始路径。基线 Files 的 find 会比较注释后的字符串，这一差异明确保留。

路径作用域固定标为 superblock_tree_at_first_mount。底层超级块可能包含被覆盖的挂载目录、不可见的 inode 或根本不同的 bind mount 子树；此视图不证明进程实际可访问、挂载覆盖顺序或磁盘目录完整性。MountRoot/SuperblockRoot 分别记录根，不能混为一谈。MountAttachment 保存挂载附着的底层 dentry；其 inode/链接计数和 Deleted 标志，与 MountRoot 的对应值分开保存。纯路径不拼接“(deleted)”展示标记，inode 删除状态单独保留。完整 mountinfo 渲染、全部挂载别名与可见性分析仍待实现。

max-nodes 默认 131,072，限制任务与单个子链表；max-mounts/max-dentries 默认各 1,000,000；三者均可设为 1..1,000,000。max-depth 默认 256，可设为 1..1,024，另有 16KiB 路径界限；边界深度的空目录仍可正常完成。所有输出有 summary，记录挂载、超级块、dentry、负条目、唯一 inode、别名计数及完整性。find 成功时标明在首个匹配后停止，不能用其 summary 宣称整棵树已扫描。

inodepages 的 inode 与 find 二选一；路径查找失败、遍历不完整或对象不是正规文件时明确失败。每个页和导出 summary 的 InodeLookup 保存匹配 dentry、挂载和路径元数据、查找覆盖、首条诊断及诊断计数，来源保留在同一任务证据内。[缓存导出适用条件](linux-pagecache.md)

选定 Debian 3.2 x64 采集共 2 个命名空间、13 个挂载、11 个超级块；11,619 个 dentry 包括 2,185 个负条目和 9,434 个唯一 inode。九个实体字段全部匹配固定基线，完整路径仅有 7 条展示差异：基线把附着目录的删除标记拼进挂载路径及其后代，原生使用纯路径并保存独立删除证据。28,302 个原始时钟值独立核验；其展示与基线的 epoch-zero/浮点微秒处理分开比较。syslog 经 find 定位到同一 inode，3 页与导出字节匹配。[机器验证记录](linux-files-validation.json)

`tools/verify_files.py` 使用独立 RAW/x64 页表读取器，从 init_task 重新遍历任务、命名空间、挂载、超级块、完整目录和负条目集合，核对父关系、文件名原始字节、inode、字段和纳秒时钟；不导入 Volatility 或调用 GoMem。该校验器只覆盖选定旧链表布局，现代结构目前只有合成测试。AVML 为同一采集的重编码一致性验证，不是第二份独立采集。批量导出由 linux.recoverfs 提供，但仍未完成与基线压缩包的逐字节差分；时间线及完整平台/版本矩阵仍未完成。
