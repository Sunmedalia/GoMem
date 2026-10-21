# Linux 可疑可执行映射分诊（开发预览）

Linux `triage` 共享执行一次 `linux.malfind --show-all-dirty-pages true`，按每页 500 行从案件数据库读取证据。规则版本为 v8：

| 规则 | 等级 | 条件 |
| --- | --- | --- |
| `anonymous-executable-region` | medium | 精确 RX 保护，且 `vm_file` 为零 |
| `executable-dirty-page` | high | 其余可执行映射中的硬件脏页 |

RWX 继续由已有 `executable-writable-region` 规则处理。Windows 将上述两条规则标记为 `not_applicable`。脏页、匿名执行、JIT 和合法补丁之间存在重叠，发现中保留规则依据和误报提示，不据此直接认定注入。

评估器核验封存 ID、插件/镜像/符号/参数一致性、VMA 对象坐标、完整原始捕获、`vm_flags`/`vm_file` 与 VMA 字节的一致性。脏页还要求物理叶项捕获与记录值一致、present/dirty 位成立，以及虚拟地址和页尺寸与区域一致。新增 `Created` 源字段用于结合镜像、内核层、任务对象、PID 和可用创建时间重新计算 `ProcessIdentity`。创建时间不可用时保留缺失状态；读取错误同时影响覆盖状态。

规则不会独立重放整套页表或从符号重新解析所有 VMA 字段；它依赖原生插件采集的结构和地址空间证据。完整引擎的测试和固定上游对照仍是必需的，封存本身不代表来源可信。

Malfind 失败任务中的有效发现仍可分诊。此例外仅用于 Malfind，不放宽差异比较规则对完整源任务的要求。诊断、缺页、提前停止、无效记录或源任务失败均导致检查 `incomplete`；评估继续处理后续页面，保留有效阳性。只有完整源任务、相符的行数和无覆盖故障才能报告 `completed`。独立 `Evaluate` 只有行而无源任务状态，故会输出可用发现并返回 `ErrIncomplete`。

每条案件发现保留源证据 ID、进程/VMA/区域坐标、原始 `FieldEvidence`、展示字节、反汇编、源任务状态/错误/参数。白名单按规则和进程对象身份应用，同 PID 的不同对象不合并。失败源任务不会作为成功缓存复用。扫描计数、缺页数、诊断和无效记录数保存在检查的 `coverage` 中；零发现但有缺页不是干净结果。

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_malfind_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test -race ./internal/triage -run TestOfficialLinuxMalfindTriageCoverage -count=1 -v
```

合成测试覆盖 RX/脏页阳性、RWX 不重复、原始字节与保护位篡改、相同 PID 的不同对象、500 条诊断后的阳性、取消和输出故障、失败源任务的部分发现、白名单及 SQLite 读回封存。端到端引擎覆盖正常、扫描缺页和展示读取缺页场景。

Debian 真实镜像 SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` 的负向回归：两条规则均为 0 发现，3,192 个 dirty scan、210,847 次探测、149,562 个不可用页、2,880 条不完整扫描、0 条无效记录，源任务失败，两条检查均不完整。源插件固定上游对照见 [Malfind 验证](linux-malfind.md)。这不是实际注入阳性验收，能力矩阵仍为 195 项、0 项完整验收。

Kali ARM64 LiME 仅进行物理 VMCOREINFO 冒烟测试；当前不具备 ARM64 虚拟地址转换，因此不声明支持其进程或 Malfind 分析。

机器可读验证记录见 [linux-malfind-triage-validation.json](linux-malfind-triage-validation.json)。完整 CLI 分诊另产生 5 条已有规则线索；它们不属于这两条新规则的阴性对照结论。
