# Windows 注册表 hive 列表

`windows.hivelist` 对应固定基线的 `windows.registry.hivelist.HiveList`。它用精确内核符号读取 `CmpHiveListHead`，按 `_CMHIVE.HiveList` 遍历活动 hive。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.hivelist --image memory.dmp --case ./case-001 --format jsonl
bin/gomem analyze windows.hivelist --image memory.dmp --case ./case-001 --param filter=SAM
```

每个候选对象先读 `_CMHIVE.Hive.Signature`。只有 `0xBEE0BEE0` 才是 hive。签名读失败或值不符时，发出 `diagnostic` 并停止该方向，不会把坏节点当成空 hive。正向链表断裂时，从链表头的后向指针再走一遍，并用对象地址去重。已经发出的 hive 行保留，任务以失败结束。完整且双向一致的链表不会再反向遍历。

名称按 `FileFullPath`、`FileUserName`、`HiveRootPath` 取第一个非空 UTF-16 字符串，三个字段都保留。长度为 0 的 `UNICODE_STRING` 视为空名称，不再读取缓冲区。三个字段都为空且没有读取错误时，`Name` 为空、`NameSource` 为 `none`，不算失败。任一候选字段读取失败且最终没有选中名称时，该行的 `Name` 标记为 missing，任务失败。某个字段失败但后面的字段给出名称时，失败字段保持 missing，任务可以成功。

`filter` 是选中名称的大小写不敏感子串。名称读取失败的行不会被筛选隐藏。`max-nodes` 默认 1024，范围 1..1000000。

`dump=false` 时 `FileOutput` 固定为 `disabled`。上游未导出时显示 `Disabled`。`dump=true` 按 HMAP 重建 hive 文件：先写 4096 字节 base block，再写稳定存储。内核规范地址先读内核层，缺页时再试 Registry 进程；用户地址只读该进程。读不到的区间写入零字节，并在空洞日志里保留偏移、地址、层和错误。这种空洞让任务失败，已经写出的文件仍留在案件里，状态是 `completed_with_gaps`。`max-hive` 默认 256MiB，包含 base block，范围 4096..4294967296。超过上限或稳定长度本身读失败时不创建文件。易失存储不进入文件。文件名取 hive 名的最后一段，去掉 `.`、`[`、`]`，其余不安全字符换成 `_`。

合成样本把 base block 和唯一的稳定页按源字节写回，零地址的后续页记为空洞而不是从内核地址 0 读取。内核页缺失时改读进程层。没有 HMAP 符号的镜像在写出任何文件之前失败。Windows 10 19041 的 SAM hive 得到 36864 字节：base block 在内核和 Registry 进程里都是 prototype 页，稳定存储里有多页 `hbin`，另有一页用户地址同样不可读。这还不是与固定基线的逐字节对照。

官方 Windows 10 19041 样本正向走完 24 个 hive，没有诊断，任务成功。偏移和选中名称与固定基线的 24 行一致。该样本里每个 `FileFullPath` 成员长度都是 0：21 个名称来自 `FileUserName`，`SYSTEM` 与 `HARDWARE` 来自 `HiveRootPath`，还有 1 个 hive 三个字段都为空。所以上游名为 `FileFullPath` 的列实际是 `get_name()` 的结果，不能把它当成该结构成员的原始值。

合成样本覆盖两个以上有效 hive、三级名称回退、全空名称、单个路径字段不可读、筛选、无效签名后的反向补齐、正向指针断裂后的尾部恢复，以及稳定 hive 的字节重建。真实镜像没有触发反向遍历。根键枚举已有选定字段对照，见 [windows.printkey](windows-printkey.md)。稳定 hive 重建已有合成字节对照和一份真实 SAM 冒烟结果，还没有与固定基线逐字节验收。32 位、其他 Windows 版本、链表中段多处损坏后的物理 `hivescan` 都还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-hivelist.jsonl \
  --reference reference-windows-hivelist.json \
  --mapping docs/diff/windows.hivelist.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsHive|TestOfficialWindowsRegistryHives' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.hivelist` 生成。当前保持 partial、accepted=false。
