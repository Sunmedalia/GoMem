# Linux kallsyms 原生底座开发预览

`pkg/kallsyms` 从镜像中的 `kallsyms_num_syms`、压缩名称流、token 索引/字典以及地址表恢复核心符号。它不把外部 ISF 的名称列表当作分析输出；ISF 只提供布局、表坐标及内核边界。当前是底座 API，**尚未注册 `linux.kallsyms` CLI 插件**，能力矩阵仍为 missing；模块、ftrace 和 BPF 符号源及完整插件参数语义待接入。

## 已实现的核心读取

`FromSymbols` 按声明的整数类型读取符号数量宽度，接受四/八字节计数及指针。采集坐标加内核 slide；用于大小判断的节边界采用固定基线的 ISF 掩码后加 slide。`Open` 接受明确的地址掩码、大小端和读取上限，不推断虚拟地址宽度。支持绝对指针数组，以及固定基线的 ABSOLUTE_PERCPU 相对偏移解释：负值为 `relative_base - 1 - offset`，非负值为绝对值。不是对任意 Linux 相对编码的泛化支持。

地址表分块读取，每块不超过 4096 字节，验证单调顺序后建立索引；不整镜像载入。token 表按需展开并缓存，所有采集都通过传入的只读 `MemoryLayer`，便于插件包装原始读取证据。包本身不产生案件行或持久化记录。

`Stream` 输出名称、类型、地址、可用大小和导出状态，同时保留索引、压缩长度、头宽度、当前/后续偏移及大小区间依据。类型按固定基线的大写字母及 `u/v/w` 推导导出状态，空类型为不可用。别名共享下一个严格更大地址的边界；最后一个地址优先使用 init 节结束，其次 `_end`，再 `_etext`。零/负大小标为不可用，仍保留源区间。别名查找使用二分法，避免大量别名造成平方级回退。

6.1+ 扩展压缩长度占两字节。固定基线的 `get_core_symbols` 在展开后仍按 `compressed_length + 1` 推进，可能落入上一条数据；当前 `Stream` 保留该行为，并输出 `HeaderBytes` 与 `NextOffset`，不能把它描述为完整 Linux 名称流正确性。独立 `Expand` 可按明确偏移解码。oracle 同时覆盖扩展长度在首条和末条的行为。

固定上游逐字节 UTF-8 解码 token，非 ASCII 字节失败；原生也明确报错。读取失败不静默跳过，不用空列表掩盖错误；这与上游部分错误处理不同。调用方收到错误时必须保留不完整状态，不可作为成功缓存。

## 边界与验证

`Limits` 明确限制符号数（1..10000000）、累计实际读取字节（1..1 GiB）、单 token 字节（1..65536）和展开名称长度（1..1 MiB）。不合法读计数、短读、缺页、溢出、无终止 token、非单调地址、无基址的相对表和错误配置均失败。检查取消及每个输出错误边界。

`tools/build_kallsyms_core_oracle.py` 校验锁定源摘要，执行未修改的 `KASConfig.new_from_isf` 和 `Kallsyms.get_core_symbols` 及官方大小展示方法。使用真实 ISF 和字节内存层，仅补充内存层的指针宽度、地址掩码和 `offset` 关键字接口；不替换符号解析方法。52 个案例覆盖两种宽度、两种地址布局及普通、别名、特殊类型、空名、空 token、init 边界、绝对 percpu、空表、首/末条扩展长度、负/零大小、无 `_end`。附加原生测试覆盖大端字序和畸形输入，但不视为真实大端内核验收。

Debian 3.2 x64 镜像 SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` 中，24,648 个核心符号按原顺序逐项对照名称、类型、地址、大小及导出标记；50,183 次读取、477,670 字节独立重读一致。这是核心符号源验证，不是整个 kallsyms 插件、模块源或调用栈验收。

```sh
python3 tools/build_kallsyms_core_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_KALLSYMS_CORE_REFERENCE="$PWD/.cache/kallsyms-core-validation/reference" \
go test -race ./pkg/kallsyms -count=1
```

参考结果用固定 `tools/reference.py`、`linux.kallsyms --core` 产生，测试验证 manifest 的提交、镜像哈希、输出摘要及参数。跳过可选语料测试不构成验收。更多现代内核、真实 x86/PAE/ARM64、大端、损坏镜像、持久化证据、其余符号源和插件入口仍待完成。

[机器可读验证记录](linux-kallsyms-core-validation.json)。
