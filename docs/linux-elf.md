# Linux ELF 枚举与内存段提取

`linux.elfs` 按进程自身页表检查每个 VMA 起始的 ELF 魔数。枚举保留 PID、名称、VMA 对象及范围、进程身份、原始路径和路径作用域。首字节不可读时输出 diagnostic 并将任务标为失败，不把读取失败当成“没有 ELF”。默认只检查魔数；指定 dump 才要求完整可解释的 ELF 头。

```sh
bin/gomem analyze linux.elfs --image memory.raw --symbols exact.json.xz --case ./case-001 --param pid=3476 --param dump=true
bin/gomem analyze linux.elfs --image memory.raw --symbols exact.json.xz --case ./case-001 --param pid=3476 --param dump=true --param elf-layout=reference
bin/gomem analyze linux.pslist --image memory.raw --symbols exact.json.xz --case ./case-001 --param pid=3476 --param dump=true
```

提取支持 ELF32/64 和两种字节序，解释 ET_EXEC/ET_DYN、PT_LOAD、文件/内存大小和对齐。头和程序头表不填零；坏版本、尺寸、算术溢出、不合理对齐或截断使提取失败，不产生伪造头或空文件。程序头最多 4,096 个，表偏移最多 16 MiB。`max-elf-size` 同时限制每段及总输出，默认 1 GiB，上限 4 GiB−1；这些限制比基线只限制单段更严格。

输出依虚拟地址排序，拼接每个 PT_LOAD 的 4 KiB 页对齐内存范围，包含 p_memsz/BSS 和页内余量。相同页对齐起点按最后一个程序头覆盖，延续固定基线的选择规则。不会根据 p_offset 重建磁盘布局，不重写头，也不声称恢复了原始磁盘 ELF。ELF 结构保存每段的源地址、输出偏移、长度、程序头序号和原始字段，全部地址及长度使用字符串无损保存。

两种布局有明确差异：

| 布局 | 源地址解释 | 适用与限制 |
| --- | --- | --- |
| `mapped`（默认） | 用覆盖 ELF 文件头的唯一 p_offset=0 段建立加载地址；ET_EXEC 要求与实际基址一致，ET_DYN 使用该锚点计算加载偏移 | 使用真实映射，支持非零/高地址的 ET_DYN p_vaddr；无法确定加载偏移时失败；零 p_memsz 段不提取 |
| `reference` | 固定基线的 VMA 基址 + 页对齐后的原始 p_vaddr | ET_EXEC 通常再次加上基址；高地址 vDSO 的相加结果可能超出 uint64，此时明确失败，不截断或环绕；保留基线非对齐零 p_memsz 段的页范围 |

缺页按实际源虚拟页读取并填零，逐项记录输出偏移、真实源地址、地址空间及读取错误。`completed_with_gaps` 明确区分捕获内容和填充内容，不能解读为完整恢复。部分写入、取消、无持久案件及坏进程根均可追溯。独立进程出现结构或提取错误后继续其他进程；输出错误或取消立即停止。`max-nodes` 限制每个进程/任务链，`max-regions` 限制总 VMA 遍历；损坏遍历无法给出精确计数时保守消耗本次分配的预算。

`linux.pslist` 的主映像选择沿用基线：VMA 起点必须恰好等于 mm.start_code，再调用同一提取器。空 mm 标为 no_user_mm；没有匹配 VMA、无法读取头或坏页表均保留失败原因。启用 threads 时每个任务使用自身 mm 和 TID 文件名；进程关联身份保持原有规则。

固定 Debian 3.2 x64 镜像的 2,419 个实体通过 PID、Process、Start、End、Path 五字段差分；另有 5,442 条首字节读取诊断，完整任务失败。getty PID 3476 的 9 个 ELF 包含 ET_EXEC 主映像、7 个普通 ET_DYN 库和一个高地址 vDSO。独立工具从 RAW 页表、ISF 字段偏移和 Python struct 重新计算并逐字节核验映射提取结果及缺页关系；不调用 GoMem 引擎或 Volatility。普通 ET_DYN 与基线字节一致，ET_EXEC/vDSO 的差异原样记录。`reference` 的 8 个可表示地址的文件与基线字节一致；无法表示的 vDSO 保留错误，不计为成功。主映像还通过 pslist 路径交叉核验。[机器验证记录](linux-elf-validation.json)

```sh
python3 tools/diff_results.py --native native.jsonl --reference reference.json --mapping docs/diff/linux.elfs.json
python3 tools/verify_elf_extractions.py --native native.jsonl --case ./case-001 --image memory.raw --isf exact.json.xz --kernel-dtb 0x1605000
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialLinuxELFExtraction$' -count=1
go test ./pkg/elfimage -fuzz '^FuzzELFHeaders$' -fuzztime 10s
```

独立工具只验 RAW、四级 x64 和小端 ELF64；不为其他格式/架构背书。合成测试含 ELF32/64、大小端、加载偏移、重复起点、零大小、坏头、截断、边界、取消、多段缺页地址及进程错误隔离；Go 标准库 debug/elf 对照程序头解释。真实现代/32 位系统、完整版本及参数语义、损坏链表恢复和更多 ELF 布局仍未验收；保持 partial、accepted=false。
