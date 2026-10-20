# Windows 已卸载内核模块

`windows.unloadedmodules` 对应固定基线的 `windows.unloadedmodules.UnloadedModules`。它读取 `MmUnloadedDrivers` 指向的记录表，不调用 Python、Volatility 或目标系统代码。记录布局来自锁定的 `unloadedmodules-x64.json` 和 `unloadedmodules-x86.json`，不在内核 PDB 里。

```sh
bin/gomem analyze windows.unloadedmodules --image memory.dmp --case ./case-001 --offline --format jsonl
```

64 位指针下，计数读 8 字节，每条 40 字节：名称是条目起点的 `_UNICODE_STRING`，起始地址在 16，结束地址在 24，时间在 32。地址掩码是 `0x0000ffffffffffff`。32 位指针下，计数读 4 字节，每条 24 字节：起始地址在 8，结束地址在 12，时间仍是 16 处的 8 字节。掩码是 `0xffffffff`。真实 32 位镜像还没有验收。

名称长度为 0 时保留空字符串，不读缓冲区。单条记录的地址、时间或名称读失败记为 `unreadable` 并跳过，不让任务失败。表指针或计数读失败则任务失败。缺少 `MmUnloadedDrivers` 或 `MmLastUnloadedDriver` 时明确失败；固定基线只写日志并返回空结果。

计数大于 1024 时截成 1024，摘要里 `capped` 为 true。过滤使用掩码后的地址：`CurrentTime` 必须大于 1024，起止地址都必须页对齐，并且都大于掩码后的 `MmSystemRangeStart`。这个起始值读失败时用 `0xFFFF800000000000` 或 `0x80000000`，再套同一掩码。本地 `StartAddress` 和 `EndAddress` 保留读到的完整值。基线输出前已经套过地址掩码，对照时两边都再套 `0x0000ffffffffffff`。

时间沿用已有的 FILETIME 换算，格式是 `2006-01-02T15:04:05Z07:00`。对照只比较 UTC 整秒。摘要行不是模块。时间线输出还没有实现。

官方 Windows 10 19041 样本的计数是 9，没有截断、跳过或读失败。9 个模块的名称、起止地址和时间与固定基线一致。名称依次是 `hwpolicy.sys`、`WdBoot.sys`、`dam.sys`、`serial.sys`、`serenum.sys`、`dump_dumpfve.sys`、`dump_vmbkmcl.sys`、`dump_storvsc.sys`、`dump_storport.sys`。内核空间下界掩码后是 `0x800000000000`。

合成样本保留一条有效的 `null.sys`，丢掉时间为 1024、地址未对齐和低于内核空间的三条，并跳过一条名字不可读的记录。计数 2000 时只访问 1024 条，索引 1023 保留，1024 丢掉。缺少符号时任务失败。

```sh
python3 tools/diff_results.py \
  --native native-windows-unloadedmodules.jsonl \
  --reference reference-windows-unloadedmodules.json \
  --mapping docs/diff/windows.unloadedmodules.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsUnloadedModules|TestOfficialWindowsUnloadedModules' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.unloadedmodules.UnloadedModules` 生成。当前保持 partial、accepted=false。
