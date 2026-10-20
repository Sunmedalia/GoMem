# Linux 缓存文件系统恢复（开发预览）

`linux.recoverfs` 对应固定基线 `linux.pagecache.RecoverFs`。它复用 `linux.files` 的挂载超级块遍历，把目录、正规文件和快符号链接写入案件内的一个压缩包，并另存逐成员清单。完整能力仍未验收。

```sh
bin/gomem analyze linux.recoverfs --image memory.raw --symbols exact.json.xz \
  --case case-001 --offline --param compression=gz
bin/gomem analyze linux.recoverfs --image memory.raw --symbols exact.json.xz \
  --case case-001 --param tmpfs-only=true --param max-file=65536
```

压缩格式为 `gz`、`bz2` 或 `xz`。归档时间固定为 Unix epoch，便于重复运行得到相同成员元数据；这与基线使用插件运行时间不同。tar 权限固定为目录 `0755`、文件和符号链接 `0444`，不复制 inode 的所有者或原始 mode。

每个超级块的一级目录优先使用 `s_uuid`。旧内核没有该字段时使用 `major:minor`，并在 PrefixSource 标明来源。硬链接只归档第一次遇到的路径。`tmpfs-only` 要求文件系统类型字符串恰好为 `tmpfs`；类型不可读时保留诊断并失败，不把未知类型当成非 tmpfs 后悄悄跳过。

正规文件只有在存在已校验缓存页时才按逻辑大小展开，未缓存区间写入零并记入清单。没有任何缓存页的文件写成空成员，避免把整段逻辑大小伪装成已恢复数据。单文件超过 `max-file`（默认 128MiB）或累计超过 `maxsize`（默认 1GiB）时，该成员不写入，行和任务都失败。页树结构损坏、folio 或归属不符同样失败；已经通过校验的页仍会写入，缺页不会被说成“文件不存在”。

快符号链接不跟随目标。绝对目标按 `pathlib.PurePath` 的方式改写成相对链接：重复分隔符和 `.` / `..` 会折叠，指向文件系统根的链接变成 `.` 或相应数量的 `..`。SymlinkTargetRaw 保留改写前的原始字节。内核没有 `i_link`，或目标不可读时，该成员失败，不用文件名猜测目标。相同归档路径第二次出现时也失败，不覆盖先写入的成员。

`FileOutput` 是压缩包，`Manifest` 是 JSONL 清单，两者都进入案件制品并带哈希。tar 成员时间和 gzip 头的 MTIME 都固定，重复运行得到相同压缩字节。遍历诊断、超限和读取错误都保留；任务失败不撤销已经写出的部分制品。此视图仍是某个超级块缓存树的第一挂载路径，不证明进程可见性、磁盘完整性或全部挂载别名。

合成样本覆盖缓存字节、空文件、目录、相对符号链接、绝对链接改写、三种压缩格式、gzip 字节复现、tmpfs 过滤、无案件目录失败和超限跳过。

选定 Debian 3.2 x64 采集在 `max-file=65536` 下写出 1,491 个目录和 4,982 个正规文件，共 6,473 个成员、18,573,745 个逻辑字节。`/var/log/syslog` 成员为 30,143 字节，SHA-256 为 `39301d85a3087a5f5736512ccbfe986c606976280e52487594b93f93d949cd8f`，与已核对的补零页缓存一致；开头 20,480 字节是未缓存页。该内核的 inode 没有 `i_link`，2,351 个符号链接全部失败。另有 391 个文件超过 64KiB，以及 6 个重复前缀路径。任务因此失败，但已经写出的制品保留。这不是完整文件系统导出，压缩包也还没有与固定基线逐字节对照。现代内核、32 位和真实 tmpfs 仍未验收。[机器验证记录](linux-recoverfs-validation.json)
