# Windows 主引导记录扫描

`windows.mbrscan` 对应固定基线的 `windows.mbrscan.MBRScan`。它扫描物理层里的 `55 AA`，把命中位置前 `0x1FE` 字节当作 512 字节的主引导记录。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.mbrscan --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.mbrscan --image memory.dmp --case ./case-001 --offline --format jsonl -p full=true
```

签名地址是列里的物理偏移，不是扇区起点。起点落在物理地址 0 之前时，缺的字节按零填充，和固定基线的 `layer.read(..., pad=True)` 一样。引导代码是前 `0x1B8` 字节。它全是零就丢掉整段，不输出。磁盘签名在偏移 440，格式是 `aa-bb-cc-dd`。引导代码和整段 512 字节各算一个 MD5。

四个分区项从偏移 446 起，每项 16 字节。标志字节等于 `0x80` 才可启动。类型名来自固定基线的 `windows/mbr.json`，一共 50 个且没有重复值；表外的字节是 `Not Defined PartitionType`。CHS 的扇区是第二字节对 64 取余，柱面是 `(第二字节 - 扇区) * 4 + 第三字节`，CHS 列本身是磁头字节。

`full` 默认关闭。固定基线会把要求的默认值写入配置，所以 `not config.get("full", True)` 走短列。短列的父行深度是 0，四个分区是深度 1。父行的分区字段不适用。参考环境没有 capstone，父行 `Disasm` 是空格分隔的小写十六进制，再被渲染器包上一层引号。分区行的 `Disasm` 是空字符串。`full=true` 额外给出原始标志、原始类型、LBA、CHS 和引导代码十六进制。分区行的引导代码列是字面量 `N/A`。

磁盘签名或分区项里有未映射字节时，任务失败。固定基线只跳过 `PagedInvalidAddressException`，物理崩溃转储层不会抛出它。引导代码里的空洞按零参加哈希，不单独失败。摘要行不是主引导记录。

官方 Windows 10 19041 样本扫到 8494 个签名。29 个引导代码全零。剩下 8465 条主引导记录、33860 个分区项，默认列和 `full=true` 的偏移、签名、两个 MD5、分区类型、可启动标志、扇区数、CHS、LBA 和反汇编列都与固定基线一致。其中 325 个分区可启动。这张镜像没有缺页的分区字段。真实 32 位镜像还没有验收。capstone 反汇编没有实现；当前对照使用的就是没有 capstone 时的十六进制回退。

```sh
python3 tools/diff_results.py \
  --native native-windows-mbrscan.jsonl \
  --reference reference-windows-mbrscan.json \
  --mapping docs/diff/windows.mbrscan.json
python3 tools/diff_results.py \
  --native native-windows-mbrscan-full.jsonl \
  --reference reference-windows-mbrscan-full.json \
  --mapping docs/diff/windows.mbrscan.full.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestMBRScan|TestOfficialWindowsMBRScan' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.mbrscan.MBRScan` 和追加 `-- --full` 生成。当前保持 partial、accepted=false。
