# Linux 凭据对象共享检查

`linux.check_creds` 对应固定基线的 `linux.malware.check_creds.Check_creds`，旧的 `linux.check_creds.Check_creds` 是上游弃用别名。原生实现不调用 Python。

```sh
bin/gomem analyze linux.check_creds --image memory.raw --symbols exact.json.xz --case ./case-001 --offline --format jsonl
```

检查只读取默认活动任务链，不包含 init_task，不额外展开用户线程。它检查 **task.cred**，不替换为 real_cred，也不按 UID 或凭据内容相等来分组。整个 cred 对象可读后，按其精确虚拟地址归组；至少两个活动任务才输出 `shared` 行。CredVAddr 和 PIDs 对应上游两列，PIDs 保留任务枚举顺序、重复 PID，分组保留第一次遇见的顺序。不能用排序或去重掩盖对象关系。

原生另输出每个已检查任务的 `process` 行，保留 PID、任务对象坐标、包含对象地址和可用启动时间的 ProcessIdentity、cred 指针位置及原始字节、完整 cred 原始捕获。共享组的 Members 保留这些任务地址、PID 和身份。重复 PID 的不同任务不会合并成同一身份。组行的来源偏移是 cred 地址；成员行的来源偏移是 task 地址。

空指针、不可读指针及不完整 cred 对象按上游条件排除出共享组；原生额外保存 `diagnostic` 行和可读前缀，最后将任务标为 failed。读取失败不会被当成“没有共享”，也不会把跳过记录伪装成空输出。布局、任务链和 PID 故障、遍历界限、取消及输出错误直接失败。原生 `max-nodes` 默认 131072，允许 1..1000000；cred 类型大小限制为 1..65536 字节。分组只保留有界任务描述，原始对象逐行写入案件，不在分组索引里复制所有字节。

summary 中 processes 是访问的任务数，checked 是完整读取 cred 的任务数，credential_objects 是不同可读 cred 地址数，shared_groups 是至少两个成员的组数，diagnostics 是被跳过的任务数。`process`、`diagnostic` 和 `summary` 都不是共享组。差分映射明确选择 shared，并保留非实体记录计数。

共享本身不证明提权或恶意行为；任务生命周期、内核行为和采集不一致都应结合场景调查。该检查也不证明凭据没有被修改：只比较指针关系，不判断各权限字段的合法性。

## 验证与缺口

9 个固定源码 generator 用例覆盖空集合、独立对象、共享对象、重复 PID、逆序 PID、空指针、不可读对象、跨组顺序和跳过后继续收集成员。原生合成任务链与这些结果对照，并对故障读取明确保存诊断。另有缺失/坏符号、零/超大结构、部分对象捕获、PID 错误、x86/PAE 指针、参数边界、取消、输出错误、SQLite 每行封存核验和已完成任务复用测试。

现有 Debian 3.2 x64 镜像（SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`）中，133 个活动任务使用 133 个不同且可读的 cred 对象，0 个诊断。原生和**未修改**的固定 Volatility 都输出 0 个共享组，这是正常对照；不能当作真实阳性验证。SQLite 回读封存和缓存复用通过。此插件的真实参考未使用 capabilities 的 typedef 适配器。最终 CLI 新任务与缓存 JSONL 逐字节一致，独立证据包核验及 make check 通过；详情见 [验证记录](linux-check-creds-validation.json)。

```sh
.cache/reference-venv/bin/python tools/build_check_creds_oracle.py --check
go test ./internal/engine -run TestLinuxCheckCreds -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxCheckCreds -count=1 -v
```

真实共享凭据阳性、现代内核、实际 x86/PAE 镜像、ARM64、完整任务有效性和损坏链容错仍待验收。矩阵保持 partial、accepted=false，不以零组结果宣布完整能力对齐。
