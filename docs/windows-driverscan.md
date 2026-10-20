# Windows 驱动池扫描

`windows.driverscan` 对应固定基线的 `windows.driverscan.DriverScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `Dri\xf6` 和 `Driv`，雕出 `_DRIVER_OBJECT`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.driverscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

两个标签都要求对象类型是 Driver。固定基线的 `_DRIVER_OBJECT` 检查接受每一个雕出来的对象。`DriverStart` 所在的 8 字节必须能读。起始地址为 0，或者严格大于 `MmSystemRangeStart`，才保留。`MmSystemRangeStart` 读不到时，64 位用 `0xFFFF800000000000`，32 位用 `0x80000000`。驱动名取对象头里的名字，不做互斥体那种长度比较。服务键是 `DriverExtension.ServiceKeyName`，另一个名字是对象里的 `DriverName`。空字符串和无效地址都不可用。三个名字都不可用时不输出这一行。读失败从对照列里拿掉，和基线的空值对齐，同时留在 `ServiceKeyError`、`DriverNameError` 或 `NameError`。摘要行不是驱动。

官方 Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，得到 142 个驱动。低 48 位偏移、起始地址、大小和三个名称与固定基线一致。有一个服务键缓冲区是非规范地址 `0x508f8d480000017d`，对照列为空，错误留在 `ServiceKeyError`。另有 804 个候选因为类型不是 Driver 被丢掉。扫描本身没有读失败。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。

合成样本覆盖起始地址为 0 的驱动、高于内核空间起点的驱动，以及低于内核空间起点而被丢掉的驱动。`Dri\xf6` 的自下而上大小会在共享扫描器里加上 `_DRIVER_EXTENSION`，没有单独夹具。32 位真实镜像和 Windows 8 以前的真实镜像还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-driverscan.jsonl \
  --reference reference-windows-driverscan.json \
  --mapping docs/diff/windows.driverscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsDriverScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.driverscan.DriverScan` 生成。当前保持 partial、accepted=false。
