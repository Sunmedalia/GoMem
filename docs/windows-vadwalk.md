# Windows VAD 树

`windows.vadwalk` 对应固定基线的 `windows.vadwalk.VadWalk`。它遍历活动进程的 VAD 树，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.vadwalk --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.vadwalk --image memory.dmp --case ./case-001 --offline --param pid=4
```

只支持现代 `_RTL_AVL_TREE` 的 `VadRoot`。根指针是 0 时这个进程不输出行。`VadNode` 在 `_MMVAD_SHORT` 偏移 0，所以节点地址就是平衡节点地址。父节点是 `ParentValue` 清掉低 2 位。左、右子节点是指针值，0 表示没有子节点。

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
