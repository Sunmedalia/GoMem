# Linux 打开文件描述符与 inode 证据

`linux.lsof` 枚举活动任务及其线程的文件描述符，通过精确符号读取 files_struct.fdt / fdtable，兼容较旧的 files_struct 内联 fd/max_fds。PID 筛选先作用于主任务列表，再展开所属线程，与固定基线的组选择规则一致。共享描述符表按各任务输出，保留 TID 和独立任务身份，不把共享文件误当作同一个进程。

```sh
bin/gomem analyze linux.lsof --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.lsof --image memory.raw --symbols exact.json.xz --param pid=2652,3576
bin/gomem analyze linux.lsof --image memory.raw --symbols exact.json.xz --param files-only=true
```

`files-only` 对齐基线的路径策略：绕过动态 dentry 名称，直接执行文件系统路径遍历；它不按 REG 类型筛选描述符。默认路径在进程根下跨挂载解析，保留 PathRaw 和 PathScope；已知动态回调支持 simple、socket、pipe、anon_inode，以及旧/新 ns_dname 布局。命名空间名称从声明的 proc_ns_operations.name 读取，绝不调用镜像中的函数。未知回调、空指针或循环均保留读取错误。files-only 对不在挂载根下的自指 dentry 保留基线的部分路径展示，PathScope 明示 disconnected_dentry；PathInProcessRoot=false，不把它当成进程根下的真实完整路径。默认动态解析仍拒绝无法解释的断开路径。一般删除文件的 Path 展示不添加基线的前导空格；动态名称与 inode 链接状态分别保存，避免把非文件路径当作正常路径。

每条证据含文件对象 Offset、Dentry、InodeOffset、描述符表地址、Slot、FD、任务对象和所属进程对象及身份。父进程 ID 不是文件身份依据。inode 优先用已声明且非零的 file.f_inode，否则使用 dentry.d_inode；来源保存在 InodeSource。未知 inode 类型明确 missing，ModeRaw 和权限字符串仍保留。inode 模式采用 Linux POSIX 位；独立 Python stat 参考覆盖七种 Linux inode 类型及未设置类型的所有权限组合，共 32,768 例，不受宿主 whiteout/door/port 类型差异影响。

Changed/Modified/Accessed 支持旧 i_*time timespec、6.6 后 __i_*time，以及 6.11 后分离的秒/纳秒字段，保存有符号秒、纳秒和实际字段名。计算不经过浮点，支持公元 1–9999 年的 UTC 日期。零时间和负 Unix 时间保留原值及 UTC 解释；零值可能来自未初始化的 inode，不能据此推断事件确实发生在 1970 年。坏纳秒、缺失布局或无法读取字段分别保留错误；现代 split 布局读取真实纳秒字段，固定基线该分支使用 has_member 的布尔值，存在明确差异。

读取以源页为界，保留截断读取中的完整指针前缀；剩余槽位以 diagnostic 记录起始 FD/Slot 和 SkippedSlots，继续可独立读取的页和任务。全 file 对象范围另存 FileExtent；该范围不可读时为 file_partial，仍尝试恢复可读的路径和 inode 字段，完整任务失败。取消和输出错误立即停止。max-fds 默认/上限 500,000；max-slots 默认 10,000,000、上限 100,000,000，计入空槽和共享表的逐任务遍历。max-nodes/max-tasks 约束任务和线程；超限明确失败，不冒充干净空结果。

选定 Debian 3.2 x64 样本原生输出 3,796 条，基线输出 3,795 条。独立 RAW 页表和描述符槽位检查证明，额外记录来自 PID 1 的 FD 10 `/run/initctl`：表地址有效、max_fds=64、FD 0 为空，但 FD 10 非空且对象全部可读。基线 get_fds() 解引用得到首个 file*，调用者再将该值与 0 比较，因此跳过这个表。GoMem 检查表指针并扫描全部槽位，保留这条捕获证据；未添加默认隐藏它的过滤器。

3,795 个共同记录的十字段（含 PID/TID/FD、路径、设备、inode、类型、权限和大小）一致；路径比较显式使用已有 linux_path_display 配置，仅移除基线删除路径的一个前导显示空格，原始字符串不改写。24 条此类显示差异逐项计数。完整集合比较保留多出的记录，matched=false；不会把共同子集相等当成完整插件验收。

独立工具重走 RAW 四级 x64 页表，枚举完整活动任务/线程集合对应的所有 FD 槽位，再直接按 ISF 解码 inode 字段、权限、设备、完整对象范围及全部 11,388 个时间字段，不执行 GoMem 引擎或导入 Volatility。路径不在此工具的验证范围内，单独与基线和合成挂载/命名空间语料对照。样本中 3,062 个零时间字段均保留；共同记录里 Changed 有 103 处、Modified 有 102 处浮点微秒显示与精确整数舍入不同。已从原始秒/纳秒复算全部 11,385 个共同时间字段，重现基线的浮点展示及非正值空值规则，未把这些差异归为未知原因。[机器验证记录](linux-lsof-validation.json)

```sh
python3 tools/diff_results.py --native native.jsonl --reference reference.json --mapping docs/diff/linux.lsof.json
python3 tools/verify_lsof.py --native native.jsonl --active active-with-threads.jsonl --image memory.raw --isf exact.json.xz --kernel-dtb 0x1605000
python3 tools/build_inode_mode_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialLinuxLsof$' -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzLinuxInodeTimestamp$' -fuzztime 10s
```

真实现代/32 位、完整挂载命名空间和 cached inode 回退场景仍待扩大；file.f_inode 非零但不可读时当前保留该来源的错误，不猜测另一个对象。时间线聚合、文件页缓存恢复与网络 socket 字段不包含在本次实现中。现代时间及 namespace ABI 只有合成验证，AVML 是同一采集的重编码一致性检查；保持 partial、accepted=false。
