# Windows 系统虚拟地址区

`windows.virtmap` 对应固定基线的 `windows.virtmap.VirtMap`。它列出内核系统虚拟地址区的名称、起始地址和字节数。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.virtmap --image memory.dmp --case ./case-001 --offline --format jsonl
```

`_MI_SYSTEM_VA_TYPE` 和 `_MMPTE` 在选择路径之前就要存在。大页尺寸是 `(4096*4096) // _MMPTE.size`。本样本的 `_MMPTE` 是 8 字节，大页为 2097152。`SystemVaRegions` 路径不使用这个尺寸，但尺寸为 0 时任务失败，和固定基线的除零一致。

有 `MiVisibleState` 时，符号处是指向 `_MI_VISIBLE_STATE` 的指针。结构里同时有 `SystemVaRegions` 和 `SystemVaType` 时，只用前者。`SystemVaRegions` 必须是结构数组。下标 `i` 用枚举 `lookup(i)` 取名称，不读取槽里存的类型字节。名称重复时取字母序的第一个，本符号文件的枚举值都唯一，而且常量按名称排序，因此和固定基线的 JSON 顺序一致。枚举里没有这个值则任务失败。

`BaseAddress` 必须是指针。输出前按 64 位低 48 位、32 位低 32 位做掩码，原生地址再恢复规范高位。`NumberOfBytes` 是原始整数，不是指针。固定基线的列名是 `End offset`，值却是字节数，不是起始地址加长度。原生列名是 `Size`。任一元素读失败则任务失败，不把缺页写成 0。

没有 `SystemVaRegions` 但有 `SystemVaType`，或者只有 `MiSystemVaType` 时，走固定基线的类型数组状态机。`MmSystemRangeStart` 先做同样的指针掩码，算术在掩码后的值上进行。一段连续相同类型的累计长度记到下一个不同名称上，最后一段多出来的页被丢掉。这是固定基线 `_enumerate_system_va_type` 的行为，原生照做，不自行修正。`MiSystemVaType` 的元素个数是 `(0x100000000 - 起始) // 大页`。起始不小于 `0x100000000` 时，固定基线得到负数个数，迭代结果为空，任务仍然成功。元素类型是 `char`，有符号；值落在枚举外则任务失败。

官方 Windows 10 19041 样本走 `SystemVaRegions`。数组有 13 项，下标 0 到 12 都有枚举名，输出 13 行。低 48 位起始地址和字节数与固定基线一致。`MiVaPagedPool` 的起始地址是 `0xfcf68050b648`，不是大页对齐。没有读失败。摘要行不是地址区。

合成测试覆盖状态机、有符号 `0xFF` 和负数枚举、以及 32 位风格的数组长度。真实 32 位镜像、`SystemVaType` 和 `MiSystemVaType` 路径还没有语料差分。

```sh
python3 tools/diff_results.py \
  --native native-windows-virtmap.jsonl \
  --reference reference-windows-virtmap.json \
  --mapping docs/diff/windows.virtmap.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestSystemVa|TestVirtStart|TestOfficialWindowsVirtMap' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.virtmap.VirtMap` 生成。当前保持 partial、accepted=false。
