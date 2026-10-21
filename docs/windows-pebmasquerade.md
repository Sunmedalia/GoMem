# Windows PEB 字符串长度与审计名称

`windows.pebmasquerade` 原生实现固定基线 `windows.malware.pebmasquerade.PebMasquerade`。枚举活动链全部进程，支持 `pid` 列表；`max-nodes` 是原生遍历上限，默认 131072。运行时不调用 Python 或 Volatility。

```sh
bin/gomem analyze windows.pebmasquerade --image memory.dmp --case ./case-001 --offline --format jsonl
```

每个进程独立读取 EPROCESS.ImageFileName、SeAuditProcessCreationInfo.ImageFileName.Name、原生 PEB.ProcessParameters.ImagePathName 和 CommandLine。一个名称读取失败不影响其余名称；MaximumLength 失败也不抹掉已读取的文本。按符号定义读取 32/64 位指针和字段偏移，不自动切换至 WoW64 PEB。空 ProcessParameters 不读字符串；PEB 或审计指针为零时不预先拒绝，仍按实际可读性处理。

非空文本的检查条件为 `Length//2 != len(text)` 或 `MaximumLength//2-1 != len(text)`。这里的 len 与 Python 一致，计 Unicode 码点，不计 UTF-16 单元。合法的非 BMP 字符、宽松分配的 MaximumLength、NUL 截断等均可能命中；该插件不直接比较内核和 PEB 名称是否相同，长度不一致不能独立证明进程伪装。

固定源码的六列输出中，两个布尔名称对调：`PEB_ImageFilePath_Spoofed` 实际报告命令行长度检查，`PEB_CommandLine_Spoofed` 实际报告映像路径长度检查。原生保留此对照行为，额外提供语义明确的 `ImagePathLengthMismatch` 和 `CommandLineLengthMismatch`。未检查时这两个原生字段是 `missing/not_checked`，而对照列依基线仍为 false。空字符串在名称列为 `missing/not_available`；原始证据中的 Decoded 仍保留空字符串。

`ImagePathEvidence`、`CommandLineEvidence`、`AuditEvidence` 保存类型化的 descriptor、buffer、层、Length、适用的 MaximumLength、完整读取状态和原始 UTF-16 字节。解码使用替换字符并在首个 NUL 截断；部分读取只保留原始捕获，不输出成功文本。每进程 Error 记录具体失败阶段与错误，summary 统计进程、完成的检查、不一致和读取诊断；summary 不是进程。行保留对象地址、含可用创建时间的进程身份及进程层，案件引擎添加镜像哈希、符号摘要、插件参数并封存。

活动链或 PID 不可读、遍历上限、取消和输出失败会终止任务。名称/符号字段读取失败保留在对应进程行，不能当作完整正常检查。每进程使用新 PEB 状态；不复刻固定源码在首次 get_peb 失败后可能引用上一进程局部变量的行为。稳定只读镜像的正常读取不会依赖此缺陷。

## 验证与缺口

固定源码 `_generator` 直接生成 288 个参考用例，覆盖独立路径/命令行、空/缺失字符串、正常及不同 Length/MaximumLength、MaximumLength 异常、无 PEB 和非 BMP 字符，验证实际列顺序。合成完整读取测试覆盖正常对照、两类不一致、NUL/奇数 UTF-16/非法 surrogate、空字符串、映射零地址、零参数、独立名称/审计/两字符串/容量/PEB/页表故障、部分字节、32 位字符串布局、同 PID 不同对象、逐进程状态、布局缺失、取消、输出失败和上限。

选定 Windows 10 19041 x64 镜像 SHA-256 为 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`，使用 `symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json`。120 个进程的全部六列一致。97 个映像路径和 96 个命令行完成检查；路径不一致为零，命令行不一致为 2，涉及 WmiPrvSE.exe PID 5060 和 audiodg.exe PID 6316。此处只记录长度线索，不认定为恶意阳性。

保留 30 项读取诊断：17 个 PEB 不可读，6 个 ImagePathName.Length 不可读，6 个 CommandLine.Length 不可读及 1 个命令行 Buffer 读取失败。任务完成不等于所有字符串检查完整。对照映射见 [windows.pebmasquerade.json](diff/windows.pebmasquerade.json)。

```sh
.cache/reference-venv/bin/python tools/build_pebmasquerade_oracle.py --check
go test ./internal/plugins -run TestPeb -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsPebMasquerade -count=1 -v
```

真实恶意伪装阳性、其他 Windows 版本、完整原生 x86/WoW64 语料及损坏镜像差分仍待补齐。矩阵保持 partial、accepted=false。
