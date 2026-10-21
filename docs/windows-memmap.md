# Windows 进程内存映射

`windows.memmap` 对应固定基线的 `windows.memmap.Memmap`。它按活动进程的页表输出虚拟地址、物理地址、长度和文件内偏移。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.memmap --image memory.dmp --case ./case-001 --offline --format jsonl --pid 2968
```

`pid` 是一个可选整数，不是逗号列表。省略时包含活动链表里的每个进程。`UniqueProcessId` 或 `Pcb.DirectoryTableBase` 读不到的进程被跳过，任务仍然成功。进程层用这份页表根，按固定基线的 `layer.mapping` 从 0 走到体系结构最大地址。64 位空间的右端是 `2^48-1`，32 位是 `2^32-1`，最后一字节不包含在内。

整页条目完全相同的页表当作无效，整段跳过。Windows x64 的物理地址只保留第 12 到 44 位，转换页也一样。大页只有在物理范围全部落在镜像里时才输出；中间有空洞就整段丢掉。相邻页只有在 48 位虚拟地址和物理地址都连续时才合并，包括跨过规范地址分界的那一段。原生虚拟地址在区段起点落在高半区时补回规范高位。固定基线保留未扩展的 48 位值，对照时 `Virtual` 只比较低 48 位。

`dump` 默认关闭。文件列是字面量 `Disabled`，文件偏移仍按映射长度累加。`dump=true` 时把该进程的映射按顺序写入案件里的 `pid.<pid>.dmp`，成功行的文件列就是这个名字。某一段读失败时，该行是 `Error outputting to file`，缺的字节在案件文件里补零，后面的文件偏移仍然连续。固定基线在失败时不写这些字节，但偏移照样增加。

`max-nodes` 只限制活动链表长度，不是上游参数。摘要行不是映射。

官方 Windows 10 19041 样本上，PID 2968 `notepad.exe` 有 74969 段、415870976 字节。默认不导出时，虚拟地址、物理地址、长度、文件偏移和 `Disabled` 与固定基线一致。`dump=true` 写出的 `pid.2968.dmp` 共 415870976 字节，SHA-256 是 `09f08a08628f23c88482e50920ee474711f2c855d8498fdac8e2094aab32ba50`，与固定基线的文件相同。没有读不到的进程号、页表根或进程名，也没有导出错误。其余 119 个进程，以及真实 32 位和 PAE 镜像，还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-memmap.jsonl \
  --reference reference-windows-memmap-pid2968.json \
  --mapping docs/diff/windows.memmap.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./pkg/memory ./internal/plugins ./internal/engine -run 'TestPageMappings|TestSingleProcessID|TestOfficialWindowsMemmap' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.memmap.Memmap -- --pid 2968` 生成。当前保持 partial、accepted=false。
