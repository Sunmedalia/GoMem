# AVML v2 镜像层

GoMem 原生读取 AVML v2 的物理区间和 Snappy 帧，支持压缩/未压缩帧、流标识、可跳过扩展与填充。未压缩 AVML 采集通常使用已有 LiME 路径。解析依据为 [Microsoft AVML 固定源码](https://github.com/microsoft/avml/blob/d212dd1204b6ad089438fc27ae8530371c095501/src/image.rs)、[Snappy 帧规范](https://github.com/google/snappy/blob/main/framing_format.txt) 与 [块格式](https://github.com/google/snappy/blob/main/format_description.txt)。运行时不依赖 Rust、Python 或本地 Snappy 库。

```sh
bin/gomem analyze generic.info --image memory.lime.compressed --offline --format jsonl
bin/gomem analyze linux.pslist --image memory.lime.compressed --symbols exact.json.xz --case ./case-001 --offline
```

启动仅索引区间、帧长度及位置，不整镜像解压；每帧输出不超过 64KiB，按需解码，并校验 masked CRC32C。读取失败返回包含物理地址/层的错误，保留跨帧读取中已经成功的前缀，不填充或伪造缺页。八字节压缩长度尾部与实际消费量必须一致。版本、保留字段、范围溢出、重叠区间、截断、坏标识和未知不可跳过类型明确拒绝。索引上限为 1,048,576 个数据帧/区间和 4,194,304 个总 chunk；解码缓存最多 128 帧（8MiB），共享层的缓存缺失读取串行化以约束临时分配。

CRC 在数据实际读取时核验，metadata 枚举不代表全镜像 CRC 已通过；没有物理地址的空数据帧在索引时核验。标准 CRC 只能检查数据一致性，不提供签名认证。当前要求物理区间末尾紧跟 AVML 长度尾部；更多非标准布局与历史采集器版本待验收。

物理 Range 的 Encoding 为空表示线性映射；编码区间使用 `snappy-framed`，FileOffset/StoredLength 指向完整编码流，不可将物理位移直接加到 FileOffset。`generic.info` 明确展示 Encoding、解码 Length 和 StoredLength；线性层拒绝错误地把编码 Range 当作普通文件段。通用字符串/banner/PDB 扫描按物理连续性跨越容器记录边界，遇到空洞会断开。

独立参考工具从固定提交下载并核验三个 Microsoft 源文件，再调用原样的图像转换代码和锁定的 Rust snap 依赖。只用于开发验证，输入只读，输出必须新建：

```sh
python3 tools/avml_reference.py encode --input linux-sample-1.bin --output .cache/linux.avml
python3 tools/avml_reference.py decode --input .cache/linux.avml --output .cache/decoded.lime
go run ./tools/verify_memory --image .cache/linux.avml --reference .cache/decoded.lime
```

生成器保存源、Cargo 锁文件、工具二进制、输入和输出摘要。采集器可能省略全零区间；省略区间是物理空洞，不能推断为已捕获零字节。验证器要求双方物理覆盖范围完全一致，然后流式比较所有映射字节并执行额外随机读取。

本批将已有官方 Debian 3.2 x64 样本重新编码为 AVML，独立解码所得 512MiB 与 GoMem 全量物理读取逐字节一致，并通过 1,024 次随机读取；数据摘要与原 RAW 一致。这是同一采集的重编码测试，不是独立原生 AVML 采集。使用已启用原生 Snappy 扩展的固定 Volatility 3 v2.28.2 对照，进程 133、模块 79、基线视图 VMA 13,990 条的选定字段一致；psaux 保留原有两条缺页错误，完整比较仍不一致。选定 36KiB VMA 提取仍有 12KiB 缺页填充，文件内容与上游一致，来源记录 AVML 文件自身的 SHA-256，不混用 RAW 身份。[完整验证记录](avml-validation.json)

基础测试还包含由独立参考生成的合成帧语料，验证压缩与未压缩帧、随机访问、CRC 错误、回溯复制、截断、异常大小、区间空洞和并发缓存。Fuzz 覆盖 AVML 索引入口及 Snappy 解码边界。真实采集器的更多版本、损坏/超大输入、平台与完整插件矩阵仍未通过验收；保持 partial、accepted=false。
