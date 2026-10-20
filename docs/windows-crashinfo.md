# Windows 崩溃转储头

`windows.crashinfo` 对应固定基线的 `windows.crashinfo.Crashinfo`。它只读崩溃转储头，不需要内核符号，也不调用 Python、Volatility 或目标系统代码。不是崩溃转储时任务失败，不输出行。

```sh
bin/gomem analyze windows.crashinfo --image memory.dmp --case ./case-001 --offline --format jsonl
```

64 位使用锁定的 `_DUMP_HEADER64`，头长 8192。32 位使用 `_DUMP_HEADER`，头长 4096。签名只取前 4 字节，所以文件签名 `PAGEDU64` 显示为 `PAGE`。类型 `0x1` 是 `Full Dump (0x1)`，`0x5` 是 `Bitmap Dump (0x5)`。其他类型在打开镜像层时就被拒绝，插件里的 `Unknown/Unsupported` 分支到不了已打开的镜像。

完整转储的 `BitmapHeaderSize`、`BitmapSize` 和 `BitmapPages` 记为不适用。Bitmap 转储从紧接头后的 `_SUMMARY_DUMP` 读取这三项：`HeaderSize`、`BitmapSize` 和 `Pages`。

`SystemUpTime` 把 tick 除以 10 得到微秒，`.5` 时向偶数舍入，再按 Python `str(timedelta)` 格式化。`5` 是 `0:00:00`，`15` 是 `0:00:00.000002`。超过一天时用 `1 day, ` 或 `N days, `。

`SystemTime` 丢掉 100 纳秒余数，减去 FILETIME 纪元，输出 UTC，并且固定写成 `+00:00`，不用 `Z`。秒数为 0 时不适用。年份不在 1 到 9999，或平台时钟无法表示时，记为无法解析。`SystemTimeRaw` 保留原始 FILETIME，不参与对照。

注释是 128 字节。按 UTF-8 解码，在第一个 NUL 或 U+FFFD 处截断，终止符本身不保留。非法字节会先变成 U+FFFD，所以注释在第一个非法序列处结束，而不是把替换字符留在结果里。

官方 Windows 10 19041 样本是 Bitmap 转储，只有 1 行。签名、版本、四个地址、机器类型、CPU 数、调试块、转储类型、运行时间、注释、系统时间和三项 bitmap 都与固定基线一致。`HeaderSize` 是 176128，`Pages` 是 511191，`BitmapSize` 是 1310720。运行时间是 `0:11:23.199374`，系统时间是 `2025-03-06T17:59:20+00:00`，注释是 128 个没有 NUL 的 `PAGE`。真实 32 位镜像还没有验收。

合成样本覆盖 64 位完整转储、bitmap 摘要、运行时间的偶数舍入、注释截断、32 位头偏移，以及普通 RAW 镜像的明确失败。

```sh
python3 tools/diff_results.py \
  --native native-windows-crashinfo.jsonl \
  --reference reference-windows-crashinfo.json \
  --mapping docs/diff/windows.crashinfo.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsCrashInfoHeaderAndBitmap|TestOfficialWindowsCrashInfo' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.crashinfo.Crashinfo` 生成。当前保持 partial、accepted=false。
