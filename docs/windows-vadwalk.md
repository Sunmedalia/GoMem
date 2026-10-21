# Windows VAD 树

`windows.vadwalk` 对应固定基线的 `windows.vadwalk.VadWalk`。它遍历活动进程的 VAD 树，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.vadwalk --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.vadwalk --image memory.dmp --case ./case-001 --offline --param pid=4
```

支持直接 `_EPROCESS.VadRoot` 指针、内联 `VadRoot.BalancedRoot` 哨兵和 `VadRoot.Root` 指针。空根不输出行，内联哨兵不当作内存区间，但继续遍历其子树。现代 `_RTL_BALANCED_NODE` 保留原有遍历路径；其余布局从实际节点类型解析 `LeftChild/RightChild`、`Left/Right`、`VadNode` 或 `Core.VadNode` 下的链接。父指针按 `Parent`、`u1.Parent`、`ParentValue` 或嵌套版本解析，带平衡位的字段清除低两位。`VadS/VadF` 使用 `_MMVAD_SHORT`，其他 `Vad` 标签按 `_MMVAD` 取 VPN，支持直接字段和 `Core` 包装。

池标签是节点前 12 字节处的 4 个字节；32 位是前 4 字节。`Vad ` 末尾的空格会保留。标签不是 `Vad` 开头、出现环、深度超过 128，或者区间重叠，任务失败。`pid` 是逗号分隔的进程号。`max-nodes` 默认 131072，按进程计算，不是上游参数。摘要行不是 VAD。真实 32 位镜像和 Windows 8 的 `BalancedRoot` 还没有验收。

官方 Windows 10 19041 样本有 120 个进程、19999 个节点，另有 3 个空根。标签是 `VadS` 8237 个、带尾随空格的 `Vad ` 11749 个、`Vadl` 4 个、`VadI` 9 个。PID、进程名、父节点、左右子节点、起止地址和标签与固定基线一致。原生节点地址保留规范高位。基线 JSON 丢掉了 `Offset`、`Parent`、`Left`、`Right` 的高位，这四列对照时只比较低 48 位。`Start` 和 `End` 不需要掩码。

```sh
python3 tools/diff_results.py \
  --native native-windows-vadwalk.jsonl \
  --reference reference-windows-vadwalk.json \
  --mapping docs/diff/windows.vadwalk.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestOfficialWindowsVadWalk|TestVADCorruptionAndProtectionReadFailures' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.vadwalk.VadWalk` 生成。当前保持 partial、accepted=false。

## 旧版入口与对象级对照

共用读取器同时服务于服务扫描、模块枚举、线程启动路径和 VAD 分析。XP/2003 的文件映射从 `ControlArea.FilePointer` 直接读取 `_FILE_OBJECT`；后续布局从 `Subsection.ControlArea.FilePointer` 读取并清除 fast reference 的低位。文件读取失败保留缺失原因和错误内容。区间终点遵循固定基线的 `(((EndingVpn+1)<<12)|(EndingVpnHigh<<44))-1` 算式，高低位相交时也不改成先合并再加一。

`tools/build_vad_oracle.py` 校验固定 Python 源码摘要，使用最小合成 ISF 和缓冲层实际运行上游 `EPROCESS.get_vad_root`、`MMVAD.traverse`、范围、父子字段和文件名读取。12 个参考覆盖 32/64 位直接指针、AVL 哨兵、MM_AVL_NODE、RTL、Core，以及 64 位高 VPN 和低位进位特例。原生比较前序、节点地址、父子链接、范围、标签与文件名；另测空树、坏父指针、循环、未知标签、节点上限、截断读取、文件错误原因和取消。

这是结构级合成对照。真实旧 Windows、32 位地址转换/符号/进程层/注册表联合流程仍需镜像验收。已知内联哨兵允许无标签；其他未知标签、读取失败、父指针不一致或环仍明确失败。固定基线可以跳过这些坏子树，GoMem 不将这种不完整索引当成干净结果。深度上限仍为 128，基线为 100。

```sh
.cache/reference-venv/bin/python tools/build_vad_oracle.py --check
go test ./internal/plugins -run TestWindowsLegacyVAD -count=1
```

本批回归：选定 19041 x64 的 `vadwalk` 19999 行、`ldrmodules` 3193 行、活动线程与线程池扫描各 1752 行、`svclist` 646 行以及 `svcdiff` 的 646 对 646 名称比较均通过现有字段映射；`vadinfo` 区间回归也通过。`FuzzWindowsVADTraversal` 在本机执行 10 秒、128503 次，未出现崩溃；这次短 fuzz 不代表完整健壮性或性能验收。新 oracle 在 CI 中重建核对，fuzz 入口已加入 Makefile 和 CI。
