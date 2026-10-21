# Linux BPF 地址查找底座开发预览

`pkg/kallsyms.LookupBPF` 使用 resident `bpf_tree` 的 latch tree 搜索 BPF 区域。它不把 `bpf_kallsyms` 枚举链当成地址索引，也不以“最近的符号”猜测命中。调用者显式提供根坐标、modern/legacy 布局、地址掩码和节点上限；查询地址先按掩码归一化。

modern 使用 `bpf_ksym.tnode`，legacy 使用 `bpf_prog_aux.ksym_tnode`。比较时同时掩码区域两端，并包含区域末端，以保留固定基线对返回地址的判断。搜索沿用 [latch tree 底座](linux-latch-tree.md) 的 sequence 选择和固定容器坐标差异。

结果保留符号名称、类型、地址、大小、导出标记、名称是否可用、对象/程序/aux 坐标、原始区域两端、选中树及访问节点数。legacy 还保留函数入口、页数和对齐依据。`nil, nil` 表示正常未命中或没有配置根；缺失布局、读取错误、循环、越界、节点上限和取消均为错误。调用者通过 `Reader.Layer` 采集原始字节并限制跨查询的总读取量；该包本身不存储案件。

## 程序区域与现有枚举

`ReadBPFProgram` 读取函数入口、aux、名称、分配区域、页数及 4096/64 字节对齐依据；`ReadBPFRegion` 在比较路径上只读区域，不先读名称。页大小固定 4096，适用范围是固定插件使用的 Intel 架构。

现有 `linux.kallsyms` 的 legacy/pack 枚举已复用该解析器，继续输出 `bpf_func` 作为符号地址。地址查找返回分配区域起点，二者可能不同。缺少 `bpf_binary_header` 时，优先按声明的四字节无符号 `unsigned int` 字节序读取页数；精简原生符号表若还缺少该别名，保留原有四字节读取及指针字节序回退。字节序或布局不合法时失败。`NameAvailable=false` 保留名称不在布局等不可用情况，不伪装成有效空名称。

## 基线差异及验证

固定 Volatility v2.28.2 的 legacy `bpf_lookup_address` 在命中后调用不存在的 `get_addr_region`，因此抛出 `AttributeError`。对照工具保留该异常，不修改方法；另记录未修改的 `_find_bpf_prog`、`get_address_region` 和 `get_name` 的输出。原生 legacy 使用这些实际区域语义：这是带明确差异的实现，不是完整基线方法一致。

`tools/build_bpf_lookup_oracle.py` 校验固定源码摘要，使用真实 ISF、字节内存层和未修改的 Kallsyms、latch tree、BPF 扩展，不 mock 查找或字段方法。480 组、15,600 次查询包括：

- 两种指针宽度，新旧 sequence 布局，sequence 0/1/2/3。
- modern/legacy/pack、正常/空树/缺根、零大小、空名称/损坏 UTF-8/缺名称字段、aux 重定向。
- 带/不带二进制头类型，以及与指针不同字节序的 `unsigned int` 页数。
- 各节点的起点、内部、末端及外侧，canonical 高位查询和两份树不同的区域。

modern 的 5,200 次查询中，988 次五字段命中、4,064 次未命中与基线一致，148 次保留名称字段缺失异常并验证原生失败。legacy/pack 各有 1,136 次固定方法异常，以独立记录的实际搜索/区域/名称原语验证原生结果；其余各 4,064 次未命中一致。这些原语比较不能计作完整 legacy 方法差分通过。

每次对照查询的采集字节均独立重读。另有 720 组 x64/x86/PAE 分页案例与已验证的平坦内存结果比较，并独立核对每次虚拟读取的实际字节。每个读取边界的缺页/取消测试验证不返回伪命中，并验证失败后可在同一 Reader 上重新成功查询。故障测试还覆盖循环、节点上限、容器下溢、错误字段/指针宽度、空指针、页数溢出和名称读取失败。现有全源枚举的分页、原始采集、SQLite 封存和缓存测试也通过共享程序解析器执行。

```sh
python3 tools/build_bpf_lookup_oracle.py --check
go test -race ./pkg/kallsyms -count=1
go test -race ./internal/plugins ./internal/engine -run '^TestLinuxKallsyms' -count=1
go test ./pkg/kallsyms -run '^$' -fuzz '^FuzzBPFLookup$' -fuzztime 10s
```

当前是 Go API 底座，尚未提供完整的 CLI 地址查询、模块/ftrace 查找优先级或 `linux.pscallstack`。真实现代内核 BPF 阳性、实时变化镜像、完整参数/渲染和类级验收仍待补齐；能力矩阵保持部分实现，不能将这些合成对照计为正式验收。见[机器验证记录](linux-bpf-lookup-validation.json)。
