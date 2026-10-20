# Windows 隐藏驱动

`windows.drivermodule` 对应固定基线的 `windows.malware.drivermodule.DriverModule`。上游的 `windows.drivermodule.DriverModule` 只是计划移除的弃用别名，原生命令不单独实现它。这个插件找出池扫描得到的驱动里，起始地址没有落在任何已加载内核模块中的对象。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.drivermodule --image memory.dmp --case ./case-001 --offline --format jsonl
```

池标签、对象类型和 `DriverStart` 检查与 `windows.driverirp` 相同。掩码后的起始地址是 0 时保留。其他值小于或等于掩码后的 `MmSystemRangeStart` 时丢掉。8 字节读不到也丢掉，任务仍然成功。

模块来自 `PsLoadedModuleList`。起始地址先规范成地址，再按 `base <= address <= base+size` 判断。只要落在任何一个已加载模块里，就当作正常驱动，不输出。这里不比较符号名，模块范围本身就足够。

三个名称分别是对象头名称、`DriverExtension.ServiceKeyName` 和内嵌的 `DriverName`。空字符串和无效地址都算不可用。读取错误从对照列去掉，留在 `DriverNameError`、`ServiceKeyError` 或 `NameError`。三个名称都不可用时不输出。

已知例外只看对象头名称，而且必须正好是 `ACPI_HAL`、`PnpManager`、`RAW`、`WMIxWDM`、`Win32k` 或 `Fs_Rec`。服务键或备选名相同不会置位。原生地址保留规范高位。

官方 Windows 10 19041 样本有 142 个驱动通过起始检查，和 `windows.driverscan` 的驱动数相同。其中 141 个起始地址落在已加载模块里。唯一输出的是 `RAW`：起始地址为 0，对象头名称是 `RAW`，备选名是 `\FileSystem\RAW`，服务键不可用，已知例外为真。另外五个内置名称都在模块里，没有输出。没有起始地址读失败，也没有三个名称都缺失的驱动。另有 804 个候选类型不符。低 48 位偏移、已知例外和三个名称与固定基线一致。摘要行不是隐藏驱动。

合成样本覆盖起始地址 0、模块内地址、模块外地址、三个名称都缺失、非规范用户指针，以及已知名称只出现在服务键时不置位。真实 32 位镜像和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-drivermodule.jsonl \
  --reference reference-windows-drivermodule.json \
  --mapping docs/diff/windows.drivermodule.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsDriverModule|TestOfficialWindowsDriverModule' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.malware.drivermodule.DriverModule` 生成。当前保持 partial、accepted=false。
