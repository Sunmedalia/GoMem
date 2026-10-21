# Windows 加载模块对照

`windows.ldrmodules` 对应固定基线的 `windows.malware.ldrmodules.LdrModules`。它找出进程地址空间里以 `MZ` 开头的 VAD，再看这个基址是否出现在 PEB 的加载、初始化和内存三条链表里。没有调用 Python、Volatility 或目标系统代码。上游的 `windows.ldrmodules.LdrModules` 只是弃用别名。

```sh
bin/gomem analyze windows.ldrmodules --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.ldrmodules --image memory.dmp --case ./case-001 --offline --format jsonl -p pid=384,488
```

VAD 使用和 `windows.vadwalk` 相同的现代树。`VadS` 和 `VadF` 没有文件名。其余 `Vad` 标签走 `Subsection.ControlArea.FilePointer`，低位按 `_EX_FAST_REF` 清掉。文件名读不到时对照列是空，原因留在 `PathError`。

每个进程先建立自己的地址空间。页表建不起来时任务失败。VAD 起点的两个字节在这个地址空间里读。读不到，或者不是 `MZ`，就跳过。三条链表都先走原生 PEB，再走 WoW64。`DllBase` 读不到的条目不进入集合。下一节点不可读就结束当前链表，不因此让任务失败。基址按原始指针比较，展示时仍保留规范地址。

`pid` 是逗号分隔的进程号，空值表示全部活动进程。`max-nodes` 默认 131072，同时限制进程、VAD 和每条链表，不是上游参数。摘要行不是模块。

官方 Windows 10 19041 样本检查了 120 个进程，其中 103 个至少有一个 `MZ` VAD，共 3193 行。2660 个在加载链表里，2580 个在初始化链表里，2660 个在内存链表里。3 个路径不可用。PID、进程名、低 48 位基址、三个布尔值和路径与固定基线一致。PID 4 `System` 的 `\Windows\SysWOW64\ntdll.dll` 映射在三条链表之外。真实 32 位镜像、`pid` 筛选和时间线还没有语料差分。坏标签或父指针不一致的 VAD 树会让任务失败；这张镜像的树已经由 `windows.vadwalk` 接受。

```sh
python3 tools/diff_results.py \
  --native native-windows-ldrmodules.jsonl \
  --reference reference-windows-ldrmodules.json \
  --mapping docs/diff/windows.ldrmodules.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestLdrModules|TestWowLoader|TestVadMZ|TestOfficialWindowsLdrModules' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.malware.ldrmodules.LdrModules` 生成。当前保持 partial、accepted=false。
