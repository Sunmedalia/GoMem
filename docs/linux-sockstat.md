# Linux socket 端点与描述符关联

`linux.sockstat` 从活动任务及线程的描述符表发现 socket，按精确 socket_file_ops/sockfs_dentry_operations 地址识别 file.f_op，再通过声明的 socket_alloc.vfs_inode/socket 字段定位 socket 与 sock。要求 sk_socket 回链匹配，保留 file、dentry、inode、socket、sock、FD 槽位、任务和所属进程地址及身份。它覆盖描述符持有的 socket，不是扫描器，不声称找到关闭、孤立或没有描述符的对象。

```sh
bin/gomem analyze linux.sockstat --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.sockstat --image memory.raw --symbols exact.json.xz --param pid=2652,3576
bin/gomem analyze linux.sockstat --image memory.raw --symbols exact.json.xz --param netns=4026531993
```

PID 筛选先作用于主链表任务，再展开线程。与基线一致，netns 按任务网络命名空间 inode 筛选，空值或 0 表示全部。TaskNet 与 SocketNet 分别保存结构地址；进程可以在创建 socket 后切换命名空间，二者不能混同。旧内核没有命名空间 inode 字段时 NetNS 明确缺失，但结构地址仍可用；请求非零筛选无法判断时输出诊断并失败，不返回假空结果。Packet 接口查找优先使用 socket 所属命名空间，缺少该字段才使用任务命名空间，并记录 DeviceNamespace。

支持的端点路径如下；适用性取决于符号声明，现代及部分协议只有合成验证：

| 类型 | 输出与依据 |
| --- | --- |
| INET / INET6 | 精确字段/网络字节序的地址和端口，保留原始字节与读取位置；支持旧 pinet6 和声明的 common IPv6 布局 |
| UNIX | 按 unix_address.len 读取 sockaddr 的有效名称，保存原始字节和 pathname/abstract 类型；peer 另读对象与 inode，未绑定、无 peer、读取错误分别表示 |
| Netlink | groups 首个原生字长、源/目标 portid、目标组及可用模块名；这些端点字符串不是 IP 地址 |
| Packet | 接口索引、所属命名空间接口列表和 Ethernet 协议；零/负索引显示 ANY |
| VSOCK | 原生字节序 CID 和端口 |
| Bluetooth | 声明类型存在时处理 HCI、L2CAP（指针或内嵌 channel）、RFCOMM、SCO 地址/通道；缺失类型或其余端点布局明确失败 |
| XDP | 声明的 device、状态 enum 和 legacy xdp_prog 的程序 ID/名称；不猜测新的程序数组布局 |

EndpointKind 说明地址/端口列实际含义。UNIX 的端口列为 inode 号，Netlink 为 portid，不能当作 TCP/UDP 端口。raw family/type/protocol/state 独立保留；未知枚举不会伪造为正常值。SourceRaw/DestinationRaw 和端口 raw 值保存字节，ReadProof 包含实际地址、类型/字段、声明长度、捕获长度和完整性。固定大小读取失败时保留已捕获的字节前缀，解码值为 missing；不把缺页补成 0.0.0.0、:: 或端口 0。

抽象 UNIX 名称以 `@` 展示开头 NUL，其余非可打印字节和反斜杠用 `\xNN` 展示，长度范围内的内嵌/末尾 NUL 均保留。这是可导航展示，SourceRaw/DestinationRaw 才是原始名称；pathname 则按首个终止 NUL 展示，仍保存整个声明范围。上游 array_to_string 在抽象名称首字节处截断为空串，本实现不复现这种证据丢失。

过滤器保存 socket_filter/reuseport_filter 的结构地址、可读头、可用 prog/aux、程序类型、ID、名称原始字节及展示。支持旧 aux.prog_type 和新 prog.type。Filters 保留两种过滤器；Filter 列延续基线最后一种过滤器的展示，不意味着前一种不存在。这里只读取元数据，不执行过滤器、不导出程序字节码，也不把过滤器存在本身当成恶意依据。

文件描述符遍历复用有界生产者，不要求无关文件的路径/inode 时间可解析。max-fds/max-slots/max-nodes/max-tasks 沿用打开文件的限制；接口链表受 max-nodes 约束。损坏描述符、socket 所有者、字段、端点或过滤器会保留行与错误，独立对象继续分析；取消或输出错误立即停止。

选定 Debian 3.2 x64 acquisition 的 1,021 条记录包括 791 UNIX、84 IPv4、72 IPv6、68 Netlink、5 Bluetooth 和 1 Packet。身份、命名空间缺失语义、family/type/protocol、端口、状态及过滤器共十三字段全部匹配固定基线，52 条含 cBPF。所给 ISF 缺少 bt_sock，5 条 Bluetooth 保留布局错误，完整任务为 failed；不能因选定字段相等宣称完整成功。

地址展示另有明确差异：341 个 UNIX 抽象端点保留完整名称（源 102、目标 239）；macOS 上固定基线的网络扩展将 Linux family=10 与宿主 socket.AF_INET6=30 比较，72 条 IPv6 的两端地址变成 null。原生实现使用 Linux 类型和值，不依赖宿主 AF 常量。另有一条 Packet 接口名为 eth0，基线因旧内核缺少 NetNS inode 而跳过接口映射。独立工具重走 RAW 页表、完整描述符集合、socket 归属、位字段、156 个 INET socket 的网络字节序、UNIX 长度/名称和 Packet 接口，核验这些输出；不执行 GoMem 引擎或导入 Volatility。[机器验证记录](linux-sockstat-validation.json)

```sh
python3 tools/diff_results.py --native native.jsonl --reference reference.json --mapping docs/diff/linux.sockstat.json
python3 tools/verify_sockstat.py --native native.jsonl --descriptors lsof.jsonl --active active-with-threads.jsonl --image memory.raw --isf exact.json.xz --kernel-dtb 0x1605000
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialLinuxSockstat$' -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzLinuxUnixEndpoint$' -fuzztime 10s
```

差分配置明确只比较十三个核心字段，两列地址另行统计差异和独立核验；这不是对地址不一致的无条件归一化。独立工具只验证选定 legacy RAW/x64 的集合、归属、INET/UNIX 地址、Packet 接口及 cBPF 存在，Netlink 详细端点和现代过滤器仍依赖基线/合成对照。AVML 是同一采集重编码的一致性检查。完整版本/架构、网络命名空间变更场景、全部协议/扩展及网络时间线、closed/orphan socket 扫描仍待验收；保持 partial、accepted=false。
