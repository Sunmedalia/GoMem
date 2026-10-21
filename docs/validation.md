# 验证记录与复现

2026-10-20，Go 1.26.2，macOS arm64 / Apple M4，10 个逻辑 CPU。机器上的实际验证和全部字段映射、输出摘要记录在 [validation.json](validation.json)；未将结果解释为完整能力验收。

用户提供的两份镜像已做只读冒烟测试，记录见 [local-images-validation.json](local-images-validation.json)。Kali 为 ARM64 的 LiME 镜像，130 个物理段、4 处 banner；当前未提供 ARM64 地址转换，进程枚举未运行。压缩 Debian 样本解压摘要与固定官方样本一致，进程 133 条、模块 79 条及 banner 的指定字段对照通过。镜像、案件和原始结果均保留在本地忽略目录。

原生 DWARF、枚举、有符号数、匿名成员与位字段的独立验证见 [native-symbols.md](native-symbols.md)。

原生 PDB/MSF 7.0 已通过编译的 x86/x64 PE 对象和合成页表端到端测试；真实 Microsoft 内核 PDB 在官方 Windows 镜像上枚举 120 个进程、176 个模块，指定字段对照一致。类型差异、范围、源摘要与未支持语义见 [PDB 验证](pdb-symbols.md)。

Windows 完整/bitmap 转储的架构、DTB、内核基址和符号可在适用条件下自动配置。官方样本已完成仅给镜像/案件参数的在线初始化与后续离线进程/模块对照；另用只读层遮蔽 KDBG 标签验证真实模块链表回退。详细条件和构造负例见 [Windows 自动配置](windows-discovery.md)。

## 官方样本的指定字段对照

| 样本 / 能力 | 原生 / 基线行数 | 比较字段 | 结果 |
| --- | --- | --- | --- |
| 官方 Linux sample 1 / pslist | 133 / 133 | 对象地址、PID、PPID、名称 | 一致 |
| 官方 Linux sample 1 / lsmod | 79 / 79 | 对象地址、名称 | 一致 |
| 官方 Linux sample 1 / banners | 1 / 1 | 偏移、banner | 一致 |
| 官方 Windows 10 19041 / pslist | 120 / 120 | 对象地址、PID、PPID、名称 | 一致 |
| 官方 Windows 10 19041 / modules | 176 / 176 | 对象地址、名称、基址、大小 | 一致 |
| 官方 Windows 10 19041 / userassist | 37 / 37 实体，36 行选定字段一致 | hive 偏移、名称、路径、秒级时间、类型、名称、ID、计数、焦点、原始十六进制及父路径 | 1 条 `UEME_CTLSESSION` 因基线零填充而不同；2 条不可读值单元格基线跳过 |
| 官方 Windows 10 19041 / getcellroutine | 0 / 0 | hive 偏移、名称、模块、处理函数地址 | 一致；该样本没有落在内核模块外的处理函数，只是否定对照 |
| 官方 Windows 10 19041 / amcache | 157 / 157 | 类型、路径、公司、秒级时间、SHA-1、产品、版本及程序父路径 | 一致；56 个程序、101 个文件，没有驱动项 |
| 官方 Windows 10 19041 / scheduledtasks | 311 / 311 | 任务名、主体、显示名、启用、秒级运行时间、触发器、动作、参数、上下文、工作目录和键名 | 一致；时间描述保持不可用，CLSID 不去补零 |

进程创建时间、凭据、会话、线程、模块路径/taint/参数、提取文件、全部插件参数及不同内核场景不在上述一致性结论中。Volatility 对虚拟地址去掉高位的表示通过显式 `0x0000ffffffffffff` 掩码统一；GoMem 的结果仍保留完整 64 位地址。比较器使用多重集合，不丢弃重复实体；层级输出必须提供显式树键，否则拒绝比较。

官方 Windows 文件约 2.09GB，Linux 文件为 512MiB。压缩包的发布资产 SHA-256 和大小见 [corpus.json](corpus.json)，不在仓库中提交原始镜像。扩展测试语料、macOS 及其余格式仍待补齐。

## 下载与固定对照

以下为 POSIX shell 示例。Python 3.12+ 仅用于开发工具；GoMem 二进制不需要 Python。

```sh
make baseline
python3 tools/corpus.py linux-sample-1.bin.gz --decompress
python3 tools/corpus.py linux.zip
python3 tools/corpus.py win-10_19041-2025_03.dmp.gz --decompress
python3 tools/corpus.py symbols_win-10_19041-2025_03.zip

python3 -m venv .cache/reference-venv
.cache/reference-venv/bin/python -m pip install \
  .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75 pefile==2024.8.26
```

为对照工具建立符号目录；所有 archive 在上述 helper 中校验摘要后再使用：

```sh
python3 - <<'PY'
from pathlib import Path
from zipfile import ZipFile
root = Path('.cache/corpus')
for archive, target in [('linux.zip', 'linux'), ('symbols_win-10_19041-2025_03.zip', 'windows')]:
    with ZipFile(root / archive) as z:
        for name in z.namelist():
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('unsafe archive path')
        z.extractall(root / 'symbols' / target)
PY

.cache/reference-venv/bin/python tools/reference.py \
  --source .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75 \
  --image .cache/corpus/linux-sample-1.bin --symbols .cache/corpus/symbols \
  --plugin linux.pslist --output .cache/corpus/reference-linux-pslist.json
```

对照入口检查锁定源码的摘要，在独立缓存中离线运行，并保存镜像摘要、JSON 输出摘要和配置摘要。输出采用独占创建，重跑时选择新文件名。当前开发对照仅安装了核心依赖；不代表启用全部 YARA/Capstone/LeechCore 等扩展的正式验收。

原生工具直接读取 ZIP 中的压缩 ISF，无需展开：

```sh
make build
bin/gomem analyze linux.pslist --image .cache/corpus/linux-sample-1.bin \
  --symbols '.cache/corpus/linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz' \
  --dtb 23089152 --os linux --format jsonl > .cache/corpus/native-linux-pslist.jsonl

python3 tools/diff_results.py --native .cache/corpus/native-linux-pslist.jsonl \
  --reference .cache/corpus/reference-linux-pslist.json --mapping docs/diff/linux.pslist.json
```

对照配置记录中，Linux `page_map_offset=23089152`、slide 为 0；Windows `page_map_offset=7159808`，canonical 内核基址为 `0xfffff8043601f000`。这些值仅适用于对应摘要的这两份样本，不能作为通用默认值。

原生 Windows 示例：

```sh
bin/gomem analyze windows.pslist --image .cache/corpus/win-10_19041-2025_03.dmp \
  --symbols '.cache/corpus/symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json' \
  --dtb 7159808 --kernel-base 0xfffff8043601f000 --os windows --format jsonl
```

`lsmod`、`windows.modules` 和 `banners` 使用相应 [字段映射](diff)。准备好命名为 `reference-linux-pslist.json`、`reference-linux-lsmod.json`、`reference-windows-pslist.json`、`reference-windows-modules.json` 的对照结果后，可运行可选回归：

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialCorpus -v
```

该测试检查未压缩镜像摘要，比较进程的四个字段和模块的地址/名称，并断言固定非零实体数。默认未配置公开语料时明确 skip，不计入完整验收。

## 已执行的稳健性验证

`go test ./...`、`go test -race ./...` 和 `go vet ./...` 通过。测试覆盖三种分页模式、4KiB 与大页、canonical 高地址、跨页读取、稀疏洞、LiME/ELF/crash/bitmap 映射、截断、循环/不一致链表、错误符号、取消与部分提交、缓存重放和镜像变更、输入/输出别名拒绝、案件锁和中断恢复、压缩符号、TUI 布局与过期消息、导出完整性及 HTML 转义。

八类分诊评估器都有阳性与正常构造输入；IOC、Windows/Linux 直接 RWX、Linux 删除文件/memfd 执行 pipeline 已贯通。测试验证阳性、正常及未知元数据、原始证据回溯、白名单和任务复用；合成场景和真实样本结果不等同于真实恶意 VM 场景验收。[Windows VAD](windows-vad.md) 和 [Linux VMA](linux-maps.md) 记录范围。Windows 多视图进程、可疑线程与进程空洞输入现已接入分页分诊；已退出多视图候选为信息级，并按对象身份保留同 PID 不同对象。真实 Windows 正常对照、1001 条诊断后仍保留阳性的跨页测试、原始证据引用、白名单和缓存复用见[原生检查分诊](windows-native-triage.md)。读取覆盖不足标为 incomplete，其他输入缺口继续报告 unavailable，整体分诊保持非零状态。

区域提取对照使用 `tools/reference.py --dump-dir NEW_DIRECTORY ... -- --pid PID --address ADDRESS --dump`，目录必须新建。对照 manifest 记录逐文件大小与摘要。原生 `analyze ... --param dump=true` 的 JSONL 和案件目录传给 `tools/compare_extractions.py --native ROWS --case CASE --reference-manifest MANIFEST --reference-dir DIRECTORY --output REPORT`，逐字节比较并核验双方实际文件摘要、原生来源及填充日志摘要。示例范围见 [区域提取记录](region-extraction-validation.json)，均为选定 x64 区域，不代表所有恢复格式或参数已验收。证据包再使用独立 `verify_bundle.py` 核验，包括填充区域确实全零。

DLL 的实体映射显式声明 module/diagnostic 记录选择；比较器保留原始行数和非实体计数，拒绝未知记录类型。核心字段一致只证明模块多重集一致，不会把带诊断的 failed 任务变成通过。可读 PID 子集另用八字段映射核验，[DLL 记录](windows-dll-validation.json) 同时保留两种范围。

对镜像识别与 ISF 入口进行了短时 fuzz，并提供有效容器/ISF 种子。短时 fuzz 不是全面安全证明；更长时间、更多 parser 入口和专项损坏语料仍属待办。

## 性能边界

本机生成 10 万条 SQLite 结果，200 次、每页 100 条的热缓存未筛选 OFFSET 查询，初次测得 P95 约 8.7ms；最新原始记录以 [validation.json](validation.json) 为准。

Go 微基准曾测得 100 条分页查询约 0.94ms/op、TUI 本地导航加渲染约 0.30ms/op。这些是平均值，不是 TUI P95；内存复制吞吐不是物理磁盘扫描吞吐。固定硬件冷启动、全文筛选、真实镜像扫描吞吐、实际 RSS 及上游同条件性能对照尚未完成。

```sh
make bench
go run ./tools/bench --rows 100000 --samples 200
```

Linux/Windows/macOS 的 amd64/arm64 交叉编译通过；本地实际执行环境为 macOS arm64。[GitHub CI](https://github.com/Sunmedalia/GoMem/actions/runs/39367343061) 已在 Windows、Linux、macOS 执行并通过单元/合成集成测试和验收工具检查。远程 CI 未下载真实镜像，不代表各目标上完成真实语料验收。
