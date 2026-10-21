# Windows TrueCrypt 缓存口令

`windows.truecrypt` 对应固定基线的 `windows.truecrypt.Passphrase`。它在已加载模块里寻找 `truecrypt.sys`，再扫描该驱动 `.data` 段中的缓存口令。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.truecrypt --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.truecrypt --image memory.dmp --case ./case-001 --offline --format jsonl -p min-length=8
```

模块名按 `BaseDllName` 转成小写后比较，大小写不敏感，只取链表里的第一个。某个名称读不到时任务失败，不再继续往后找。没有这个模块时任务成功，不输出口令行。固定基线这时只写一条警告。

`.data` 使用节表里的原始 `VirtualSize` 和 `VirtualAddress`，地址是模块基址加上 RVA。`VirtualSize` 不是 4 的倍数就失败。每一项是有符号 32 位小端长度。长度不在 `min-length` 到 64 之间就跳过。后面的那么多字节必须都在 `0x20` 到 `0x7E`。紧接着的一个字节被跳过，不要求它是 0；再后面的三个字节必须全是 0。输出偏移是口令本身，不是长度字段。`min-length` 默认 5，只接受 0 到 64。`max-nodes` 只限制模块链表，不是上游参数。摘要行不是口令。

官方 Windows 10 19041 样本的已加载模块里没有 `truecrypt.sys`。固定基线警告后输出空列表，原生也是 0 条口令。合成镜像能找出 `hello` 和 `abcd`，并拒绝 `0x7F`、过短长度和非零对齐字节。缺少 `.data` 段会失败。还没有带真实缓存口令的镜像，32 位镜像也没有验收。超过单次读取上限的 `.data` 段会失败，而不是分段继续扫。

```sh
python3 tools/diff_results.py \
  --native native-windows-truecrypt.jsonl \
  --reference reference-windows-truecrypt.json \
  --mapping docs/diff/windows.truecrypt.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestTrueCrypt|TestOfficialWindowsTrueCrypt' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.truecrypt.Passphrase` 生成。当前保持 partial、accepted=false。
