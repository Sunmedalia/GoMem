# Windows 系统服务表

`windows.ssdt` 对应固定基线的 `windows.ssdt.SSDT`。它只读原生 `KiServiceTable`，不读 Win32k，也不读 `KeServiceDescriptorTableShadow`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.ssdt --image memory.dmp --case ./case-001 --offline --format jsonl
```

`KiServiceLimit` 是 4 字节有符号整数。负数或表项读不到时任务失败。模块来自 `PsLoadedModuleList`，顺序与链表一致。`BaseDllName` 读不到就跳过该模块。`DllBase` 或 `SizeOfImage` 读不到则任务失败。模块名去掉最后一个扩展名，和 `os.path.splitext` 相同；同名 stem 重复时任务失败。

64 位表项是有符号 32 位值。低 4 位是参数个数，算术右移后的剩余值是相对 `KiServiceTable` 的位移，可以是负数。32 位表项就是绝对指针，不再位移。地址落在模块里的条件是 `base <= address <= base+size`，正好等于基址加大小的那个字节也算在内。所有已加载模块都会检查，重叠模块会为同一个服务输出多行。

符号只在内核符号表里按 `地址 - 模块基址` 精确匹配，并按符号名排序。显示名取 `table!名称` 以 `!` 切开后的第二段。没有符号时记为不可用，不附带错误。地址不落在任何模块里时不输出该行。原生地址保留规范高位。

官方 Windows 10 19041 样本有 473 个服务、783 行，全部落在 `ntoskrnl`。加载了 176 个模块。没有落在模块外的地址，也没有缺失符号。其中 18 个地址对应多个内核符号，名称按符号名排序。索引、低 48 位地址、模块名和符号与固定基线一致。摘要行不是服务。

合成样本覆盖 64 位负位移、同一地址的多个符号、重叠模块、不可读模块名、模块外地址，以及 32 位绝对指针。真实 32 位镜像和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-ssdt.jsonl \
  --reference reference-windows-ssdt.json \
  --mapping docs/diff/windows.ssdt.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsSSDT|TestOfficialWindowsSSDT' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.ssdt.SSDT` 生成。当前保持 partial、accepted=false。
