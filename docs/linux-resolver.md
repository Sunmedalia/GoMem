# Linux 驻留地址统一解析器（开发预览）

`pkg/kallsyms.OpenResolver` 在同一只读镜像、符号表和地址掩码下建立 core 索引，`Resolver.Lookup` 按 **core → module → BPF → ftrace** 顺序查找。第一条命中或错误立即结束；后续来源缺失不会使已命中的内核符号失效。模块和 ftrace 配置错误延迟到实际使用该来源时返回。结果保留尝试顺序、可选来源不可用原因、模块门槛/范围/树路径，以及 BPF/ftrace 命中元数据。读取错误不转换成未命中。

每个实例限于一个不变的采集和符号表，不能并发调用。完成读取的模块 ELF 索引与完整模块链表范围在查询间复用；未完成的表不会加入缓存，失败后可以重试。模块对象数和所有驻留表的符号总数均有上限，缓存容量失败不会损坏已验证的表。`ListReused`、`TablesReused` 和 `Stats` 反映复用情况；返回范围是副本。树路径、名称和类型仍按需读取。独立 `LookupModule` 每次使用新缓存。

调用者必须提供记录实际读取的 Layer，并在初始化和所有来源间执行共享字节预算、保存采集记录及无损序列化地址。暖查询的证据依赖先前读取，因此需要保留整个实例的采集记录，不能只保存最后一次查询的读取。此 API 没有案件持久化或落盘缓存协议。

固定基线仍为 Volatility 3 v2.28.2（`881e970121c16f0932fb9d16fbd5fb258cbcbf75`）。各来源的范围、掩码和字段语义沿用已记录的 [core](linux-kallsyms.md)、[module](linux-module-lookup.md)、[BPF](linux-bpf-lookup.md) 和 [ftrace](linux-ftrace-lookup.md) 行为。基线 legacy BPF 完整查找调用不存在的 `get_addr_region`，会抛出 AttributeError；原生使用实际存在的 `get_address_region`，与未修改的区域和名称方法单独对照。这是明确修正，不计为完整方法等价。

`tools/build_resolver_oracle.py` 检查固定源码摘要，运行未修改的 `Kallsyms.lookup_address`，在同一实例执行有序及逆序查询，验证冷/暖查询和来源重叠。96 组字节支撑的实际对象涵盖 32/64 位、modern/legacy/pack BPF、两种序列布局、来源优先级、缺失可选来源及延迟配置错误，共 6,624 次查询。144 组 x86/PAE/x64 分页控制比较完整结果和错误，逐次独立核对成功采集字节；初始化及各来源的每个读取点覆盖失败、取消和重试。另验证范围副本隔离、暖表复用和累计缓存上限。

```sh
python3 tools/build_resolver_oracle.py --check
go test -race ./pkg/kallsyms -count=1
go test ./pkg/kallsyms -run '^$' -fuzz '^FuzzFullResolver$' -fuzztime 10s
```

尚未接入 CLI 地址查询或 `linux.pscallstack`，没有真实现代内核多来源阳性、动态采集一致性或完整性能验收。合成与分页验证不增加已完成验收的插件数；项目仍为开发预览。详见[机器验证记录](linux-resolver-validation.json)。
