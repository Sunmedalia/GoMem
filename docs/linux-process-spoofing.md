# Linux 进程名称来源对照

`linux.process_spoofing` 对应固定基线 `linux.malware.process_spoofing.ProcessSpoofing`。原生读取 task_struct、mm_struct、exe_file、挂载/dentry/inode 及进程参数页，不调用 Python 或 Volatility。

```sh
bin/gomem analyze linux.process_spoofing --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.process_spoofing --image memory.raw --symbols exact.json.xz --param pid=1,100 --offline
```

输出全部选定活动任务的八个对照列：PID、PPID、Exe_Path、Cmdline_Basename、Comm、Cmdline_Spoofed、Comm_Spoofed 和 Exe_Deleted。PPID 使用可读 real_parent.tgid，不使用 task.parent 或父线程 PID；父对象为空或不可读时按基线显示 0，不可读情况另留原因。PID 过滤针对 task.pid，默认不枚举用户线程。`max-nodes` 是原生任务链遍历上限，默认 131072。

可执行文件路径相对任务的文件系统根重建。常规路径逐级检查 dentry、挂载点及原始 qstr 字节，兼容旧 vfsmount 和现代嵌入 mount 的父链。qstr 解码在第一个 NUL 或替换字符处停止；空组件保留上游 `<potentially smeared>` 标记。退出至全局根、逃逸或断开的路径另记录 Scope。有效可读 inode 的链接数为零时，常规路径按基线加一个前导空格及 ` (deleted)`。inode 有效性要求 i_ino 大于零且有符号 i_count.counter 非负。

动态 d_dname 通过匹配本地内核符号解释，绝不执行镜像中的函数。支持 simple、socket、pipe、anon_inode 和已有 namespace 标签读取。按基线，simple_dname 的路径无条件带 ` (deleted)`，不依赖 i_nlink；同址多个符号、未知回调和无效 inode 会显示相应的基线标签。namespace 已有新旧 stashed 布局读取仍需更多真实语料及上游失败分支验收。

命令行读取范围为 arg_end-arg_start，最多读取固定 MAX_ARG_STRLEN=131072 字节。这是基线的固定上限，不沿用 psaux 的 4096 默认值。原生使用各任务自己的页表，保留第一处映射缺失之前的连续前缀；失败后的可读页不会拼接进字符串。UTF-8 解码遵循替换规则，并在第一个 NUL 或 U+FFFD 处停止，再用 PurePosixPath.name 语义取名称：忽略空与点组件，保留 `..`，不做 shell 分词，也不使用宿主系统的路径规则。argv[0] 内含空格、冒号、反斜杠或人为标题均原样参与比较。

可执行 basename 仅去掉一个末尾 ` (deleted)`。有至少两个非空名称来源才判断；命令行比较需要可执行 basename 和 argv[0] 名称，comm 比较需要可执行 basename 和 comm。comm 的截断按 Python 的前 15 个 Unicode 码点处理。缺失/空名称在对照列显示基线的字面 `N/A`；CmdlineCompared 和 CommCompared 另说明实际比较是否执行，不能把未执行时的 false 当作正常结论。

额外证据保留对象地址、含启动时间的进程身份、MM/文件指针、用户层/地址范围、请求及捕获长度、原始参数与 comm、文件系统组件原始字节、声明长度、回调符号、部分读取及具体错误列表。命令行 Capped 区分固定上限与缺页；有连续前缀时仍可输出基线的 basename，同时 ReadComplete=false、ReadError 和 Error 明确保留缺失后缀。summary 记录任务、实际比较、差异和诊断数量；它不是进程或发现。案件回读、缓存重跑和导出都保留原始行摘要。

名称差异只是观察结果。程序别名、脚本解释器、合法的进程标题修改、shell 登录前缀和采集不一致均可能解释差异。本插件不自动将行认定为恶意进程。每字段失败保留后继续独立任务；结构性任务链/PID 故障、遍历上限、取消和输出错误会使任务失败。文件路径另有 256 步、16KiB 和 4096 字节 qstr 的原生边界，超限明确留错，不无限遍历。

## 验证与缺口

固定源码参考包含 1801 个用例：1728 个三来源比较组合、20 个 PurePosixPath 名称、11 个原始字节解码、36 个删除后缀提取组合和 6 个动态文件名输出。Unicode、空值、15 字符边界、替换字符、嵌入 NUL、路径末尾点/斜杠和列布尔均有对照。

用户 Linux 样本解压后与官方 Debian 3.2 x64 镜像 SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` 一致。使用 `linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz`，133 行的八列全部一致。92 个任务完成命令行名称比较，94 个完成 comm 比较；9 个命令行名称不同，2 个 comm 不同。2 个参数区没有可读前缀，上游显示 N/A，原生同时保存读取错误。缺失比较不能算作正常通过。

PID 集合 1、2388、2575、3754、8503 的独立固定参考也通过 5 行八列对照：4 个命令行比较/差异，5 个 comm 比较、2 个 comm 差异、1 个读取诊断。两种运行均验证 SQLite 回读后的每行 Verify 和已完成任务复用。最终构建另以 fresh CLI 运行 134 行（133 个任务加 summary），八列差分一致，单任务证据包通过独立 verify_bundle 校验；make check 全部通过。名称差异包含 avahi/sshd 标题、dash/sh、会话启动别名和登录 shell 等，未认定为恶意阳性。[差分映射](diff/linux.process_spoofing.json) 严格比较八列，没有排除读取失败的进程。

合成真实页表/对象测试覆盖正常和两类差异、删除/无效 inode、动态回调及符号别名、空 mm/文件、错误指针、空/倒置参数范围、部分读取、131072 固定上限、替换字符、NUL/空 qstr、路径循环/断开、父线程组 PID、错误符号、独立进程页表、x86/PAE 指针、输出失败、取消、边界及案件封存/缓存。没有在运行时使用 Python。

```sh
.cache/reference-venv/bin/python tools/build_process_spoofing_oracle.py --check
go test ./internal/plugins ./internal/engine -run TestLinuxProcessSpoofing -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxProcessSpoofing -count=1 -v
```

完整误报、真实恶意伪装、现代内核、原生 x86/PAE 实际镜像、ARM64、更多 namespace/dynamic-name/损坏路径分支仍待验收。原生任务链读取比上游双向容错更严格，损坏链差分尚未完成。矩阵保持 partial、accepted=false；不以单一正常样本宣布完整能力对齐。
