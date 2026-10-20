# Windows 设备树

`windows.devicetree` 对应固定基线的 `windows.devicetree.DeviceTree`。它用和 `windows.driverscan` 相同的池扫描寻找 `Dri\xf6` 和 `Driv`，但不因为三个名称都缺失而丢掉驱动。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.devicetree --image memory.dmp --case ./case-001 --offline --format jsonl
```

`DriverStart` 所在的 8 字节必须能读。起始地址为 0，或者严格大于 `MmSystemRangeStart`，才保留。驱动行深度是 0，类型 `DRV`。设备从 `DeviceObject` 顺着 `NextDevice` 走，深度是 1，类型 `DEV`。附着设备从 `AttachedDevice` 继续走，深度从 2 递增，类型 `ATT`。三层显示的 `Offset` 都是驱动对象地址。`ObjectOffset` 保留这一行实际读取的对象地址。

驱动名和设备名来自对象头的 `NameInfo`。偏移为 0 或读取失败时记为不可解析，行仍然保留，错误留在 `DriverNameError` 或 `DeviceNameError`。长度为 0 的字符串原样保留，不读取缓冲区。重复地址或读不到的链指针只结束当前链。空指针会停下这个驱动剩下的设备：固定基线会先实例化地址 0，再因为无效地址抛出异常。设备类型读失败，或附着设备的 `DriverObject.DriverName` 读失败，也是同样的停止。已经输出的行保留，任务仍然成功。`DeviceType` 使用固定基线的设备类型表，表里没有的值是 `UNKNOWN`。

官方 Windows 10 19041 样本得到 142 个驱动、106 个设备、33 个附着设备，共 281 行，最深 5 层。低 48 位驱动偏移、类型、名称、附着驱动名、设备类型和树深度与固定基线一致。同一棵驱动子树的显示偏移都相同，所以对照除了用偏移做父键，还要比较深度。原生地址保留规范高位。摘要行不是设备树节点。

合成样本覆盖空设备名、不可解析的对象头名称、未知设备类型、空指针停下后续设备、读不到的附着指针仍继续下一个设备，以及指向自己的设备链。32 位真实镜像、Windows 8 以前的真实镜像和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-devicetree.jsonl \
  --reference reference-windows-devicetree.json \
  --mapping docs/diff/windows.devicetree.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsDeviceTree|TestOfficialWindowsDeviceTree' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.devicetree.DeviceTree` 生成。当前保持 partial、accepted=false。
