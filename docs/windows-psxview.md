# Windows 进程多视图对照

`windows.psxview` 原生实现固定基线 `windows.malware.psxview.PsXView` 的四种视图。旧路径 `windows.psxview.PsXView` 是上游弃用别名。

```sh
bin/gomem analyze windows.psxview --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.psxview --image memory.dmp --case ./case-001 --offline -p physical-offsets=true
```

四个布尔列对应四个原始对象来源：

- `pslist`：活动进程链。
- `psscan`：`Proc` / `Pro\xe3` 池对象。
- `thrdscan`：`Thre` / `Thr\xe5` 池线程的所属进程。直接从线程读取 owner，不经过展示插件的 PID/CID 收集过滤，也不读取线程启动路径。
- `csrss`：活动链中名称恰好为 `csrss.exe` 的进程，其句柄表中类型为 Process 的对象体。只解码句柄和类型，跳过与进程对照无关的显示名称和名称头读取。

每个来源都使用固定基线的 EPROCESS 有效性检查，再按上游的名称过滤器筛选：只接受 ASCII 字母、点和空格。数字、下划线、连字符、Unicode 字母均被排除。这个条件也会排除合法进程名，不能把输出解释为所有合法进程的完整清单。

进程和线程池标签在一次共用扫描中匹配，再分别建立来源索引。每个来源以数值偏移为键，同键最后一个对象覆盖前面的对象。结果取键的并集，代表对象按 pslist、psscan、thrdscan、csrss 顺序选取。PID 不参与去重，同 PID 不同对象仍是独立记录。原生按偏移排序；上游集合顺序没有稳定约定。

`physical-offsets` 默认 false。开启后，按照基线通过内核地址转换查询每个对象偏移；页故障时保留原偏移，额外 `TranslationError` 保留错误。旧系统的池扫描对象本来就是物理坐标，而基线默认列名仍为 `Offset(Virtual)`，开启物理选项时也会尝试将这个数值送入内核转换。原生保留此比较语义，同时在 `ObjectOffset`、`ObjectLayer`、`OffsetSpace` 和各 `Sources` 项中记录实际坐标和转换情况。

`Identity` 结合原始对象的镜像、层、偏移、PID 和可用创建时间；证据来源指向代表对象，`Sources` 列保存其余来源的对象坐标。退出时间采用固定基线的有符号 FILETIME 整秒转换，无法形成 datetime 时比较列是空字符串，`ExitTimeRaw` 保留原值。原始镜像只读，案件引擎保存符号摘要、参数和完整结果行。

活动链损坏、缺少必需字段、owner 读取失败、池扫描读失败或超过上限让任务失败。无效/不可读的对象可以被基线有效性检查排除，`*_rejected` 记录收集到的拒绝数。池扫描自己的丢弃和读失败统计保存在摘要 `Sources.pool`；`pool_read_failures` 和 `pool_type_map_entries` 同时平铺在 coverage，供分诊检查适用条件。csrss 不可读表和循环在 coverage 中计数；它们不是正常空结果的证明。布尔 false 只表示该视图没有收集到该键，不能据此确认进程隐藏。

`max-nodes` 默认 131072，限制活动链；`max-processes` 默认 1000000，限制每个来源不同偏移数，均为原生边界参数。没有 PID 筛选参数。summary 和 diagnostic 不计为进程记录。

## 验证与缺口

Windows 10 19041 x64 镜像的两种偏移模式均与固定基线的全部八列匹配：114 条记录，各视图分别为 113、114、112、103 个进程偏移。活动链原始对象共 120 个，7 个未通过过滤。3 个 csrss 进程解码 1034 个句柄对象，各表没有读取失败或循环。线程来源保留 112 个不同进程键，1513 次同键覆盖，127 个所属进程未通过过滤。

唯一不在活动链的 `MpCmdRun.exe`（PID 408）具有退出时间；另有三个活动链对象也具有退出时间。这是残留/退出进程对照，不是已证实的恶意隐藏进程阳性。

该输入也用于 Windows 的 `hidden-process` 分页分诊，已退出候选降为信息级；来源校验、覆盖不足、白名单和缓存验证见[原生分诊](windows-native-triage.md)。

267 个名称和 30 个合并参考直接调用固定源码的过滤与生成函数，覆盖字符、同键覆盖、来源优先级和同 PID 不同对象。合成完整读取流程覆盖四个实际来源、PID 0 线程所属进程、重复句柄、缺失 csrss、可选名称头不存在、原始坐标、转换失败、错误符号、字段故障、取消、输出失败和边界。旧内核、真实 x86、损坏镜像和真实恶意隐藏进程仍待差分验收；保持 partial、accepted=false。

```sh
.cache/reference-venv/bin/python tools/build_psxview_oracle.py --check
go test ./internal/plugins -run 'TestPsXView|TestWindowsHandles' -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsPsXView -count=1 -v
```
