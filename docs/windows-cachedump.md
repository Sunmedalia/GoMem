# Windows 缓存域凭据

`windows.cachedump` 对应固定基线的 `windows.registry.cachedump.Cachedump`。它使用和 `windows.lsadump` 相同的 SYSTEM boot key、Vista 判断和 LSA key，再解密 `Policy\Secrets\NL$KM\CurrVal`，用来解开 SECURITY hive 根上 `Cache` 里的域缓存项。没有调用 Python、Volatility 或目标系统代码。废弃入口 `windows.cachedump.Cachedump` 只是上游别名，不另建命令。

```sh
bin/gomem analyze windows.cachedump --image memory.dmp --case ./case-001 --offline --format jsonl
```

Vista 的缓存项用 AES-CBC。密钥是 NL$KM 的第 16 到 32 字节，IV 是条目偏移 64 的 16 字节，整段密文保持链接。更早的系统用 HMAC-MD5，密钥是完整的 NL$KM，消息是这个 IV，再用得到的 16 字节做 RC4。用户名、域名和 DNS 名的对齐按固定基线的 Python 3 除法，也就是长度对 4 取余。用户名从解密结果偏移 72 开始。哈希是前 16 字节，按基线 JSON 渲染成小写、空格分隔的十六进制，原始字节另外保留。

名为 `NL$Control` 的值，以及用户名长度为 0 或 IV 为空的槽位，都会跳过。Cache 键能读到、但只剩下这些槽位时，任务成功且没有凭据行。找不到 hive、boot key、LSA key、NL$KM 或 Cache 键时失败。空的 NL$KM 也失败；基线只警告并返回 0 行。

合成样本与固定基线的 `decrypt_hash` 和 `parse_decrypted_cache` 一致。Vista 与 XP 两条路径都解出用户 `alice`、域 `CORP`、DNS 名 `corp.example`，哈希为 `00112233445566778899aabbccddeeff`。

官方 Windows 10 19041 样本同样读不到 `JD` class。基线输出 0 行且成功，本地是 0 条凭据、1 条诊断，任务失败。选定字段对照是 0 对 0，没有可核对的缓存账户。这不是凭据级验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-cachedump.jsonl \
  --reference reference-windows-cachedump.json \
  --mapping docs/diff/windows.cachedump.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsCredentialDumpsMissingSecurity|TestOfficialWindowsCachedump' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.cachedump.Cachedump` 生成。当前保持 partial、accepted=false。32 位和真实的 Vista 之前镜像还没有做对照。
