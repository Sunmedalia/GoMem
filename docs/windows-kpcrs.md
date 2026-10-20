# Windows 处理器 KPCR

`windows.kpcrs` 对应固定基线的 `windows.kpcrs.KPCRs`。它列出每个处理器的 KPCR 和 PRCB，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.kpcrs --image memory.dmp --case ./case-001 --offline --format jsonl
```

`KeNumberProcessors` 按 `unsigned int` 读取。`KiProcessorBlock` 是符号地址上的 `_KPRCB` 指针数组，一项对应一个处理器。数组槽读失败则任务失败。处理器数大于 1024 也失败，这个上限不是上游参数。

KPCR 基址是指针目标减去 `_KPCR.Prcb` 的偏移。目标的第一个字节没有映射时跳过该处理器。存在 `CurrentPrcb` 且它是指针时，PRCB 列是这个指针的值；否则使用嵌入 `Prcb` 的地址。`CurrentPrcb` 读失败则任务失败。摘要行不是 KPCR。真实 32 位镜像和多处理器镜像还没有验收。

官方 Windows 10 19041 样本有 1 个处理器，没有跳过的 PRCB。KPCR 是 `0xfffff80435031000`，PRCB 是 `0xfffff80435031180`。固定基线的 JSON 丢掉了规范高位，对照时两边都只比较低 48 位。原生行保留完整地址。

合成样本覆盖 `CurrentPrcb` 指针、没有 `CurrentPrcb` 时的嵌入 `Prcb`、处理器数为 0，以及一个未映射的第二个 PRCB。

```sh
python3 tools/diff_results.py \
  --native native-windows-kpcrs.jsonl \
  --reference reference-windows-kpcrs.json \
  --mapping docs/diff/windows.kpcrs.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsKPCRCurrentAndEmbedded|TestOfficialWindowsKPCRs' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.kpcrs.KPCRs` 生成。当前保持 partial、accepted=false。
