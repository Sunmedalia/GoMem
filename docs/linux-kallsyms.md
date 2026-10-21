# Linux kallsyms 原生底座开发预览

`pkg/kallsyms` 从镜像中的 `kallsyms_num_syms`、压缩名称流、token 索引/字典以及地址表恢复核心符号。它不把外部 ISF 的名称列表当作分析输出；ISF 只提供布局、表坐标及内核边界。当前还提供 `linux.kallsyms` CLI，四类来源及其验证范围见下文；能力矩阵为部分实现，尚未完整验收。

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

参考结果用固定 `tools/reference.py`、`linux.kallsyms --core` 产生，测试验证 manifest 的提交、镜像哈希、输出摘要及参数。跳过可选语料测试不构成验收。核心层的更多现代内核、真实 x86/PAE、大端及损坏镜像仍待验证；CLI 与案件证据的验证范围见下文。

[机器可读验证记录](linux-kallsyms-core-validation.json)。

## 全源 CLI 开发预览

`linux.kallsyms` 原生接入核心、已加载模块、ftrace 模块映射/跳板及 BPF 符号链。支持固定基线的 Intel x64/x86/PAE；ARM64 不属于该固定类的 `LINUX_ARCHS`，入口明确拒绝。

```sh
bin/gomem analyze linux.kallsyms --image memory.raw --symbols kernel.json.xz \
  --offline --case case-symbols --param core=true --format jsonl
```

`core`、`modules`、`ftrace`、`bpf` 默认 false；没有任何 true 时启用全部来源，多个 true 取并集。官方列为 Addr、Type、Size、Exported、SubSystem、ModuleName、SymbolName、Description。输出顺序按 core → module → ftrace → bpf，各来源保留其内部顺序。单独选择非核心来源时不强制读取无关核心表；固定基线始终初始化核心配置，这是明确的前置条件差异。

模块支持旧式直接表及指针/内嵌 `mod_kallsyms`，5.2+ typetab，以及 `kernel_symbol` 绝对/PREL32 导出表。以固定二分查找语义判定导出：零导出数为 false，找不到条目为不可用，找到但地址不等为 false。保留基线原始地址比较，不擅自掩码两侧来推导导出状态。ELF 名称采用固定 512 字节上下文的替换解码；模块名称和指针字符串保留 NUL/首个 U+FFFD 截断行为。

固定 elf.json 的 Elf32_Sym.st_size 声明为八字节，会覆盖 st_info 等后续字段。官方 Size 列保留此固定行为，`RawELFSize` 另存 ABI 的四字节原值；不将它描述为正确的 ELF32 大小。固定 PREL32 导出名称 helper 将 int 传给只接受 Pointer 的函数，实际抛出 `pointer_to_string takes a Pointer`。原生按声明的有符号相对偏移解析，并对溢出/下溢明确失败；这类用例只验证与相同绝对表内容的原生布局等价，不计为与异常基线成功对齐。

ftrace 支持 `ftrace_mod_maps` 的模块/函数链，以及可用的 `ftrace_ops_trampoline_list`。映射函数地址使用虚拟层掩码，跳板指针遵循层地址掩码；整数字段保持原始值（基线没有额外的显式掩码）。BPF 支持现代 `bpf_ksym` 和旧式 `bpf_prog_aux`，程序名称与 pack 标志跟随 `prog.aux`，而非假定它等于链上的 aux 对象。旧式大小取 JIT 页头的 pages × 4096，普通头按 4096 对齐，启用 pack 时按 64 对齐；现代大小来自 end-start。零/负大小不可用，原始区间依据另外保留。可用类型/符号不存在时按固定内核版本门槛跳过来源；损坏布局和读取错误明确使任务失败。

`symbol_read` 保存全部实际读取及原始字节、地址、请求/采集长度、完整标记和错误；`symbol_source` 保存来源状态或失败，`symbols_summary` 保存计数/预算。实体 `symbol` 带对象/索引/表坐标等依据，核心行带压缩偏移和大小区间。名称跨入缺页时保留实际前缀和原始失败；受影响实体的 `Error` 为 `symbol_name_acquisition_incomplete`，其 `NameReadIssues` 保存坐标、长度和原因。任务失败后不能作为成功缓存复用。真实镜像中的实体字段一致不抹除缺页，也不证明来源完整。

全局 `max-nodes` 默认 131072，上限 1000000；`max-symbols` 默认 1000000，上限 10000000；`max-bytes` 默认 512 MiB，上限 1 GiB。所有下限为 1，采集预算跨来源共享，包含名称、符号及链表读取。每次输出和读取均检查取消/输出失败。链表循环、回链不一致、超界、缺页、错误表布局均保留显式错误；严格链校验与上游的恢复/静默跳过并不完全相同。

## 全源验证

`tools/build_kallsyms_sources_oracle.py` 执行未修改的 `get_all_symbols` 及真实 Linux module/kernel_symbol/BPF 扩展和 ELF 对象，不 mock 来源或解析方法。120 个案例覆盖两种指针宽度、四种模块布局、三种 BPF 布局、正常/空链/零导出/PREL32 导出/重定向 aux。96 个案例的八字段结果与基线匹配；24 个 PREL32 案例记录基线 TypeError，并单独验证原生相对布局。180 个 x64/x86/PAE 分页案例中，144 个可作基线字段对照，36 个仅作相对布局验证。验证原始读取独立重读、输出不可变、SQLite 封存及成功缓存 JSONL 逐字节一致。

附加测试覆盖全部 16 种来源开关组合、每个输出/取消边界、循环链、缺页、表错误、资源上限、部分读取和失败重试；采集入口接入 Go fuzz。真实 Debian 全源基线输出 34,472 个实体（核心 24,648、模块 9,824），八列全部匹配。原生发生 65 次部分名称读取，保留错误并将任务标记失败。这是**带缺页的实体字段对照**，不能作为成功完整采集或 ftrace/BPF 真实阳性验收。

```sh
python3 tools/build_kallsyms_sources_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_KALLSYMS_REFERENCE="$PWD/.cache/kallsyms-validation/reference" \
go test ./internal/engine -run '^TestOfficialLinuxKallsymsSourcesPartialControl' -count=1
```

[全源验证记录](linux-kallsyms-validation.json)、[八字段对照配置](diff/linux.kallsyms.json)。真实现代内核、x86/PAE、ftrace/BPF 阳性、并发损坏镜像、全部参数/渲染方式及完整验收仍待补齐。

## 核心地址查找底座

`Core.Lookup(ctx, address)` 仅解析核心 text/init 区段内的地址，返回首个同址别名、函数内部地址对应的名称、类型、地址、大小及导出标记。名称从每 256 条一个的 resident marker 定位，不使用 ISF 名称代替镜像内容。它与 `Stream` 共享名称游标，不能并发调用。模块、ftrace 的地址查找和 `linux.pscallstack` 尚未实现；BPF API 的独立验证见下文；现有全源枚举不代表这些查找语义已经对齐。

固定基线 `_get_symbol_offset` 在跳过扩展长度名称时从共享游标读取长度高字节，并按 `compressed_length+1` 前进；查询顺序和默认 128 条 LRU 淘汰会影响结果。原生实现保留此行为。180 组真实 ISF/字节对象对照覆盖正向、逆向、枚举后查找、别名、特殊/空名称、扩展长度、init/大小边界、260 条 marker 跨段和缓存淘汰；记录基线异常，不伪造成功。空索引仍在区段内时，基线可能读出残留条目零，GoMem 明确报错。缺失元数据、marker 越界或宽度错误、溢出、预算、读取及取消也明确失败；仍指向可读字节的错误 marker 可能产生基线同样的错误名称，不宣称全部损坏均可检测。压缩 token 索引采用有界批量读取，读取失败后的游标不宣称与基线逐字节读取等价。

Debian 3.2 x64 的 779 次实际 `core_lookup_address` 查询覆盖采样符号、内部地址、前一字节、区段边界及 canonical 高位地址，五字段和空结果逐项匹配；68,487 次读取、276,924 字节独立重读一致。参考生成器校验固定源码及既有 `--core` 参考的镜像、配置、结果摘要，恢复相同页表与符号掩码，不 mock 查找方法。可选测试另校验固定输出摘要：

```sh
python3 tools/build_kallsyms_lookup_oracle.py --check
python3 tools/build_kallsyms_lookup_corpus.py \
  --reference .cache/kallsyms-core-validation/reference \
  --image .cache/corpus/linux-sample-1.bin \
  --output .cache/kallsyms-lookup-validation/reference.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_KALLSYMS_LOOKUP_REFERENCE="$PWD/.cache/kallsyms-lookup-validation/reference.json" \
go test -race ./pkg/kallsyms -run '^TestOfficialDebianCoreLookup$' -count=1 -v
```

参考生成拒绝覆盖既有文件。尚无真实现代/相对布局、x86/PAE、大端语料验收；包本身不持久化证据。见[地址查找验证记录](linux-kallsyms-lookup-validation.json)。

模块与 BPF 的后续树索引查找共用 [latch tree 底座](linux-latch-tree.md)。该底座的对象对照验证不等同于来源地址解析或调用栈验收。

BPF 地址查找和枚举共用程序区域解析器，具体差异、固定 legacy 异常及 API 验证见 [BPF 查找底座](linux-bpf-lookup.md)。该地址 API 尚未接入完整的来源优先级或调用栈命令。

驻留 ftrace 地址区间查找 API 的顺序、指针规范化及对照验证见 [ftrace 查找底座](linux-ftrace-lookup.md)；完整来源解析器及调用栈接入仍待完成。

补充的 4 组 `get_ftrace_symbols` 实际对象对照覆盖高位跳板的指针/整数字段，6 组 Intel 分页验证八字段、原始采集、SQLite 封存和逐字节缓存回放；详见 [ftrace 查找验证记录](linux-ftrace-lookup-validation.json)。这修正了旧枚举路径将高位指针原样显示的问题。
