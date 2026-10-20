# Windows 作业链接

`windows.joblinks` 对应固定基线的 `windows.joblinks.JobLinks`。它只读活动进程和 Job 对象，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.joblinks --image memory.dmp --case ./case-001 --offline --format jsonl
```

`Job` 指针为空或读不到时，这个进程跳过，任务仍然成功。能解开 Job 时，先读 `SessionId`、`TotalProcesses`、`ActiveProcesses` 和 `TotalTerminatedProcesses`。其中任何一个读不到，这一行也不输出。`JobLink` 不适用，`Process` 是字面量 `(Original Process)`。

成员来自 `ProcessListHead`，只顺着 `Flink`，用 `_EPROCESS.JobLinks` 的偏移找回进程。重复的链表节点、读不到的 `Flink`，或者对象第一个字节不在内存里，都会停住这条链。不检查反向指针。成员的名称、PID、PPID、WoW64 或镜像路径读不到时，这个 Job 剩下的成员也不再输出，已经输出的行保留。成员的 `JobSess`、`Total`、`Active` 和 `Term` 是 0，`JobLink` 是 `Yes`。路径是进程 PEB 里的 `ImagePathName`，空字符串也保留。

会话 ID 为 0 是真实会话，不是空值。会话指针为 0 时才不适用。两个 WoW64 指针成员都不存在时，`Wow64` 是 false。`physical=true` 显示物理地址，这次官方样本没有把物理偏移放进对照。摘要行不是作业链接。

官方 Windows 10 19041 样本有 41 个作业进程和 28 个链表进程。偏移、名称、PID、PPID、会话、作业会话、WoW64、三个计数、`JobLink`、路径和父子关系与固定基线一致。地址对照时只比较低 48 位。真实 32 位镜像、物理偏移和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-joblinks.jsonl \
  --reference reference-windows-joblinks.json \
  --mapping docs/diff/windows.joblinks.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestFollowForwardLinks|TestOfficialWindowsJobLinks' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.joblinks.JobLinks` 生成。当前保持 partial、accepted=false。
