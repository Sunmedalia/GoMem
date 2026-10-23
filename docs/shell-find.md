# 搜索当前虚拟空间（v0.1 开发预览）

```text
gomem shell --image memory.raw --os windows --arch x64 --dtb 0x1000 --pagefile '0=/captures/pagefile.sys' --case ./case --offline
use kernel
find 0x7ff600000000 0x10000 "suspicious text"
use process SEALED_PSLIST_EVIDENCE_ID
find 0x400000 0x20000 "example"
```

`find ADDRESS LENGTH "LITERAL"` 搜索当前选择的 Intel 虚拟空间，要求显式指定起点和字节长度。支持 x86、PAE、x64；不是 ARM64 扫描接口。物理空间会明确报错，原有 `search "LITERAL"` 仍运行物理 IOC 插件。字符串沿用 shell 引号解析，不执行转义展开、脚本或环境变量替换；按实际 UTF-8 字节进行区分大小写的字面匹配，不是正则或 YARA。

扫描长度为 1..1GiB，literal 为 1..65536 字节。采用 1MiB primary 窗口及 literal 长度减一的 overlap，最多 2048 块、65536 张表、4000000 项及 10000 条命中。界限耗尽明确失败，用户可以缩小范围。区间之间的未映射零 PTE 跳过；缺失页表、pagefile、数据范围或不支持的非零 Windows 软件项使本次扫描失败，而不是返回“未发现”。

命中以 JSONL 输出，包含案件采集 SHA-256、当前层名、无损十六进制地址、原始命中字节（JSON base64）、字节 SHA-256 及逐段来源。sources 中 source 为 physical 或 pagefile，保留 pagefile 编号（含零）、来源偏移和长度。跨 RAM/pagefile 边界的匹配保留两段来源；overlap 不重复计数命中，允许不同起点的重叠文本匹配。地址和偏移不写成可能丢精度的 JSON 数值。

末尾输出 interactive_literal_summary，保存请求范围、命中数、映射/分块统计和 complete。读取、预算、源身份或取消失败时 complete=false 并返回错误，已输出的部分命中不是完整扫描证明；输出写入失败立即停止，不再尝试摘要。搜索前、每块读取前后、块输出后和最终完成时检查采集源身份，交换文件也在实际读取前后校验。失败分段不补零、不把两侧字节拼接搜索，来源枚举及字节控制见 [backing 扫描](backing-scans.md)。

这是交互探索输出，不创建插件任务、缓存或封存证据行。ImageSHA256 标识当前原始镜像/pagefile 组合；保留 JSONL 便于人工复核不等于已写入案件证据。完整持久化搜索、交互书签关联、YARA、类型搜索、ARM64 和全 volshell 探索验收仍待完成。

本地测试覆盖跨来源命中及外部单源命中、无命中完整摘要、缺 pagefile 的不完整摘要、边界和参数限制、输出失败、取消、10000 命中上限及采集变化。CLI 从 --pagefile 中文/空格路径、use kernel 到 find 输出原始来源偏移的端到端测试通过。没有真实交换页阳性语料或全部内核版本验收，矩阵保持 partial。
