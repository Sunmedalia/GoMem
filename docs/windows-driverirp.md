# Windows 驱动 IRP

`windows.driverirp` 对应固定基线的 `windows.driverirp.DriverIrp`。它扫描池头里的驱动对象，列出每个 `MajorFunction` 处理函数，以及包含该地址的内核模块和符号。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.driverirp --image memory.dmp --case ./case-001 --offline --format jsonl
```

池标签是 `Dri\xf6` 和 `Driv`，对象类型必须是 Driver。这里不过滤三个名称。`DriverStart` 要能读 8 字节，并且是 0 或者严格高于 `MmSystemRangeStart`。内核起始地址先按层地址掩码处理：64 位保留低 48 位，32 位保留低 32 位，和 `IntelLayer.address_mask` 相同。`DriverStart` 也先做同样的掩码，再和它比较。

`MajorFunction` 的每一项都是指针。槽位读不到就跳过并计数，任务仍然成功。读到的指针先规范成地址，模块范围用这个规范地址；涂抹检查比较的是掩码后的值。小于掩码后的内核起始地址就跳过，不输出。

模块来自 `PsLoadedModuleList`，顺序与链表一致。`BaseDllName` 读不到就跳过该模块。`DllBase` 或 `SizeOfImage` 读不到则任务失败。模块名去掉最后一个扩展名，和 `os.path.splitext` 相同；同名 stem 重复时任务失败。地址落在模块里的条件是 `base <= address <= base+size`，正好等于基址加大小的那个字节也算在内。所有已加载模块都会检查，重叠模块会为同一个处理函数输出多行。

符号只在内核符号表里按 `地址 - 模块基址` 精确匹配，并按符号名排序。显示名取 `table!名称` 以 `!` 切开后的第二段。没有符号时记为不可用，不附带错误。没有模块时，模块和符号都记为不可用，也不附带错误。

驱动名来自对象头的 `NameInfo`。失败时对照列是不适用且不带错误，读取错误留在 `DriverNameError`。原生地址保留规范高位。

官方 Windows 10 19041 样本有 142 个驱动、3972 行。142 乘 28 是 3976 个槽位，其中 7 个低于掩码后的内核起始地址，没有输出；没有槽位读失败。这 7 个都属于同一个读不到名称的驱动，该驱动输出 21 行。另有 804 个候选类型不符。3 个处理函数不在任何模块里。2002 个处理函数落在模块里但没有内核符号。这两部分合起来是参考结果里的 2005 个空符号。`IRP_MJ_PNP` 有一个地址对应两个符号，`IRP_MJ_SYSTEM_CONTROL` 有一个地址对应三个符号，名称按符号名排序。低 48 位偏移、驱动名、IRP、地址、模块和符号与固定基线一致。摘要行不是 IRP。

合成样本覆盖非规范的用户指针、未映射槽位、模块内无符号和模块外地址。真实 32 位镜像和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-driverirp.jsonl \
  --reference reference-windows-driverirp.json \
  --mapping docs/diff/windows.driverirp.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsDriverIRP|TestOfficialWindowsDriverIRP' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.driverirp.DriverIrp` 生成。当前保持 partial、accepted=false。
