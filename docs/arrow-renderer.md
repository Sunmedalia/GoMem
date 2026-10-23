# Arrow IPC 结果与案件导出（v0.1 开发预览）

```sh
bin/gomem analyze linux.pslist --image memory.raw --symbols kernel.json --os linux --dtb 0x1000 --case ./case --format arrow > processes.arrow
bin/gomem export --case ./case --format arrow --output investigation.arrow
bin/gomem export --case ./case --task TASK_ID --format arrow --output task.arrow
```

使用 Apache Arrow Go v18.8.0 写出标准 IPC stream，运行时不依赖 Python、PyArrow 或 Volatility。输出是二进制流，适合 PyArrow、Arrow Go 等读取器；不是 IPC file 或 Parquet。CLI 任务状态和错误写入 stderr，部分分析失败仍返回非零退出码，输出中已有证据不是完整扫描证明。

`analyze` 按插件声明列建立投影，uint64/int64/bool 使用对应 Arrow 类型；string/timestamp/address 使用 UTF-8，地址保留无损十六进制、时间保留源文本，避免隐式截断到毫秒。bytes 为 binary，structure/artifact 的投影为其规范 JSON 内容的 binary。真实数值超出类型范围、字节 Base64 损坏或不兼容的值类型明确报错，不转为空值；当前并未保证所有插件的所有动态行都兼容声明列。

每行另有四个保留列：

| 列 | 内容 |
| --- | --- |
| `_gomem_id` | 原始封存证据 ID |
| `_gomem_parent_id` | 原始 ParentID，根行是 Arrow null |
| `_gomem_task_id` | 案件导出的任务 ID；实时 analyze 尚未分配到此投影 |
| `_gomem_evidence` | 完整规范证据 JSON，binary 编码，可恢复为 evidence.Row 并核对封存 ID |

完整记录保留未声明列、每个 cell 的 Kind/Reason/Error、原始字节、嵌套结构、插件参数、地址空间、符号和镜像身份。缺失或列不存在时投影是 null，但完整记录能区分这些情况。显式 nil/空字节的原有证据编码也保留；不依据 PID 猜测树结构，不重新分配证据 ID。schema metadata 提供 `gomem.schema=gomem.arrow-evidence/v1`、列声明及各字段的 gomem.kind。保留列重名、重复列、非法 UTF-8 和未知声明类型明确失败。

按最多 1024 行或约 8MiB 规范证据字节分批，不缓存完整结果。单条规范证据上限 64MiB，超过 8MiB 的单行单独写出；schema 最多 4096 个分析列、metadata 最多 8MiB。上述是证据字节/列预算，不是进程 RSS 上限；投影、序列化和 Arrow 编码有额外内存开销。写入/短写失败会返回并保留错误，Close 释放构建器；消费者必须同时检查命令退出状态。

案件 export 支持全部已结束任务或 `--task`。第一遍按 32 行和插入顺序游标分页核对封存 ID、任务行数，并只收集列名/类型；第二遍分页写出，保留任务顺序和各任务行顺序。多任务同名列类型冲突时采用 value/binary 投影，保存完整 Value JSON，防止猜测类型；只在部分任务出现的列为其他任务写 null。schema 的 `gomem.manifest` 保存任务状态、失败原因、参数及调查信息，因此失败任务不会变成成功空结果。空任务仍保留 manifest。空结果无法从已存储行推断原声明列，这部分列信息暂不恢复。

导出文件只在案件 exports 目录独占创建；取消、封存/行数错误、类型错误或写出失败时删除不完整文件，拒绝覆盖与路径逃逸。提取文件以证据内的引用/哈希保留；Arrow 表不携带外部文件内容，需要完整提取文件时使用 bundle。全部文件/日志的 Arrow 组合封装不属于当前已验收范围。

验证：

- `tools/build_arrow_oracle.py --check` 使用实际未修改固定 Volatility ArrowRenderer、TreeGrid 与 PyArrow 26.0.0，6 组空结果、标量、树、深树、缺失和 Unicode 对照覆盖 int64 边界、uint64 地址、bool、bytes 和父链接。地址从上游 uint64 归一化为十六进制，ID 关系按行顺序比较，不假称二进制逐字节相同。
- `GOMEM_ARROW_REFERENCE_PYTHON=... go test -race ./internal/render -run Arrow -count=1` 由独立 PyArrow 读取原生输出、完整 validate、核对投影及规范证据；该 Python 仅用于开发测试，未设置时独立读取测试跳过，不建立验收。CI 显式启用。
- Go 读取器与 CheckedAllocator 覆盖整数精度、空字符串/false/null、nil/空/原始 bytes、嵌套大整数、读取错误、额外列、树 ID、空流、行数/字节分批、写失败/短写、错误类型、关闭与内存释放。
- 案件控制覆盖 130 行、两个不同类型任务、失败状态 manifest、分页、封存、取消和覆盖拒绝；CLI 从分析到落盘导出均有端到端测试。
- `GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialArrowStreamingResults -count=1 -v` 在真实 Windows/Linux 样本分别核对 120/133 条进程的完整规范证据、封存及缓存回放，全部一致。它验证本地 renderer，不替代插件与上游全字段验收。
- FuzzArrowEvidence 检查损坏/变化类型的 evidence.Value 与 IPC 输出读取。

尚未完成上游浮点、datetime、Disassembly、LayerData、MultiTypeData 和全部渲染选项语义，Parquet 仍未实现。大规模性能/RSS、所有插件动态列及完整语料验收待补，矩阵保持 partial。Arrow 与 FlatBuffers 采用 Apache 2.0，随 LICENSES 保留许可、Arrow NOTICE 和新增依赖许可。
