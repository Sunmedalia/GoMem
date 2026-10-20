# Windows 内核信息

`windows.info` 对应固定基线的 `windows.info.Info`。它报告内核身份、版本、共享用户数据和内核 PE，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.info --image memory.dmp --case ./case-001 --offline --format jsonl
```

`Kernel Base`、`DTB`、`KdDebuggerDataBlock` 和 `KdVersionBlock` 用 Python `hex` 的形式输出。64 位先保留低 48 位，32 位保留低 32 位。`Symbols` 在符号位置含 `#` 时写成 `jar:file:` 加绝对 zip 路径，再加 `!` 和成员名。`Is64Bit` 看指针宽度。只有 `pae` 架构的 `IsPAE` 是 `True`。

崩溃转储输出三行层信息，名称用固定基线的类名：64 位是 `WindowsIntel32e`、`WindowsCrashDump64Layer` 和 `FileLayer`。32 位崩溃层是 `WindowsCrashDump32Layer`。不是崩溃转储时只输出 Intel 层。真实非崩溃镜像还没有对照。

KDBG 偏移来自锁定的 `kdbg.json`。`OwnerTag` 是 `0x4742444B` 时才输出 `KdDebuggerDataBlock`、`NTBuildLab` 和 `CSDVersion`。`NTBuildLab` 是指针指向的 UTF-8 字符串，最多 32 字节，遇到 NUL 停止。`CmNtCSDVersion` 也是指针，读出的 `unsigned long` 右移 8 位才是 `CSDVersion`。

`KdVersionBlock` 给出 `Major/Minor` 和 `MachineType`。`KeNumberProcessors` 按 `unsigned int` 读取。64 位 `KUSER_SHARED_DATA` 在 `0xFFFFF78000000000`，32 位在 `0xFFDF0000`。`SystemTime` 把 `High1Time` 和 `LowPart` 拼成 FILETIME，按 10000000 整除，打印成 `YYYY-MM-DD HH:MM:SS+00:00`。0 或无法表示的时间是 `-`。`NtSystemRoot` 最多解码 260 字节 UTF-16LE，遇到 NUL 停止。`NtProductType` 用枚举名。内核 PE 给出操作系统主次版本、机器类型，以及 UTC 的 `asctime` 时间戳。摘要行不是信息项。真实 32 位镜像还没有验收。

官方 Windows 10 19041 样本有 24 行。构建号是 `19041.1.amd64fre.vb_release.1912`，版本是 `15.19041`，处理器数是 1，系统时间是 `2025-03-06 17:59:20+00:00`，系统根是 `C:\Windows`。变量和值与固定基线一致。

```sh
python3 tools/diff_results.py \
  --native native-windows-info.jsonl \
  --reference reference-windows-info.json \
  --mapping docs/diff/windows.info.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsInfoFormatting|TestOfficialWindowsInfo' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.info.Info` 生成。当前保持 partial、accepted=false。
