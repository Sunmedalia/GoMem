# Windows 孤儿内核线程

`windows.orphan_kernel_threads` 对应固定基线的 `windows.orphan_kernel_threads.Threads`。它在 `windows.thrdscan` 的同一套 `_ETHREAD` 池扫描上，只留下起始地址没有落入任何已加载内核模块的内核线程。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.orphan_kernel_threads --image memory.dmp --case ./case-001 --offline --format jsonl
```

池标签、雕刻方向和类型检查与 `windows.thrdscan` 相同。每个线程先读所属进程。Vista 及以后用 `Tcb.Process`，更早的系统用 `ThreadsProcess`。进程号和父进程号是指针，比较前按 64 位低 48 位、32 位低 32 位做掩码。只有进程号或父进程号为 4 的线程继续。所属进程、这两个号码或 `StartAddress` 读不到就跳过，任务仍然成功。

退出时间是 `ExitTime.QuadPart` 的有符号 64 位值，大于 0 就跳过。`Tcb.State` 等于 4 也跳过，4 表示已终止。这两个字段读不到则任务失败，不把缺页当成未退出。起始地址掩码后低于 `MmSystemRangeStart` 的掩码值就跳过。`MmSystemRangeStart` 读不到时，64 位用 `0xFFFF800000000000`，32 位用 `0x80000000`，然后再做掩码。

模块来自 `PsLoadedModuleList`。名称读不到的模块跳过。基址和大小读不到，或者模块主文件名重复，则任务失败。起始地址按规范形式和模块范围比较，范围右端包含在内。落在任一模块里的线程跳过。剩下的线程才进入和 `windows.thrdscan` 相同的字段整理：PID 来自线程 `Cid`，不是所属进程号；垃圾 PID 被丢掉；路径只在所属进程通过检查且进程号不是 4 时解析。

官方 Windows 10 19041 样本扫到 1752 个线程，和 `windows.thrdscan` 保留的数量相同。1490 个不是 System 或其子进程，3 个已退出或已终止，2 个起始地址在内核范围之下，257 个起始地址落在已加载模块里。没有所属进程读失败，也没有整理阶段丢掉的线程。输出 0 行，和固定基线的空结果一致。摘要行不是线程。

这条样本没有真正的孤儿线程，所以路径解析和 `max-nodes` 没有被用到。`max-nodes` 不是上游参数。真实 32 位镜像、有孤儿线程的样本和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-orphan-kernel-threads.jsonl \
  --reference reference-windows-orphan-kernel-threads.json \
  --mapping docs/diff/windows.orphan-kernel-threads.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestOrphanKernelPointerMask|TestOfficialWindowsOrphanKernelThreads' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.orphan_kernel_threads.Threads` 生成。当前保持 partial、accepted=false。
