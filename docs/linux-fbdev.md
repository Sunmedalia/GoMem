# Linux framebuffer 开发预览

`linux.fbdev` 对应固定 Volatility 3 v2.28.2 的 `linux.graphics.fbdev.Fbdev`。读取 `num_registered_fb` 和 `registered_fb`，按符号布局解析 `fb_info`、设备名称、虚拟分辨率、行长度、状态与屏幕地址。尚未完整验收。

```sh
bin/gomem analyze linux.fbdev --image memory.raw --symbols kernel.json.xz \
  --offline --case case-fb --param dump=true --format jsonl
```

默认 `dump=false`，`Filename` 为 `Disabled`。启用后，颜色位域布局生成 PNG，`grayscale>1` 的 FOURCC 布局导出原始字节。运行时只使用 Go 标准库，不依赖 Pillow、Python 或 Volatility。导出进入案件目录，保留哈希、来源地址、参数及符号摘要；名称中的路径分隔符和控制字符替换成下划线。

## 行为与资源边界

大小采用 `yres_virtual * line_length`，分辨率采用虚拟尺寸。匹配固定基线的像素行为：从缓冲区开头连续消费小端像素，不跨过行填充；不足一个像素的尾部只消费剩余字节，耗尽后使用零值；窄颜色通道不放大至 255；`msb_right` 反转位序；宽于 8 位的颜色值截到 255；未声明 alpha 时使用 255。这些行为可能与实际显示器呈现不同，原始读取证据可用于独立解释。

`max-framebuffers` 默认 256，范围 1..4096；`max-bytes` 默认 64 MiB，范围 1..1 GiB。后者限制累计实际采集字节，以及每个源缓冲区、解码 RGBA 和编码 PNG 的分配/输出。元数据读取也计入采集预算。各缓冲区可能同时存在，总内存不限于一个预算值；PNG 编码和文件写出支持取消。源数据按最多 1 MiB 分块读取。拒绝零尺寸、解码越界、非整字节或大于 64 的 bpp、越界颜色位域和过大的设备数量，避免基线中可能出现的无界资源消耗。

`framebuffer` 为实体行，`framebuffer_read` 为原始读取证据，包含地址、请求/实际长度、完整标记、原始字节和错误。缺页不补零、不伪装为空结果；独立 framebuffer 可以继续，任务整体失败且不会复用为成功缓存。设备名称读取失败保留 typed missing 并使任务失败，较基线的静默缺失更严格。成功提取的独立文件仍保留。缺符号、未声明类型、未配置案件文件存储均明确报错。

## 固定基线对照

`tools/build_fbdev_oracle.py` 校验锁定源代码摘要，用真实 ISF 对象和字节层执行未修改的 Fbdev generator、解析与导出方法。Pillow 仅用于开发对照，固定为 12.2.0。

26 组案例覆盖两种指针宽度及 13 种场景：普通、无设备、空 ID、非法 UTF-8、Unicode、RGB565、RGB24、行填充、短缓冲区、反向位序、宽通道、FOURCC 与 grayscale。39 个 x64/x86/PAE 分页案例分别测试关闭/开启导出，比较七个元数据字段、文件名、原始字节或解码后的 RGBA 像素；PNG 压缩字节不要求与 Pillow 相同。读取证据独立重读，SQLite 行封存与文件哈希核验，缓存 JSONL 逐字节回放。故障测试覆盖缺页、错误布局/数量/尺寸、预算、取消、每个输出错误边界、文件存储失败和失败后新任务重试。两个 fuzz 入口覆盖采集和像素转换。

## 真实镜像

- Debian 3.2 x64：镜像 SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`。两边都没有注册的 framebuffer；原生保留 1 次计数读取。七字段空结果差分通过，仅为阴性对照。
- Kali 6.8.11 ARM64：镜像 SHA-256 `cf04d76ab9177d7ee355cc96020d29ae194c065c692304ff25e594ab510c639d`，符号 SHA-256 `7b27ed03e5abd81b4913ca01a0265aabf0ffc5491a306b9d0b271bfd452ebf56`。原生发现 `fb0` / `virtio_gpudrmfb`，1024×768、32 bpp、行长 4096、RUNNING，屏幕地址 `0xffff800082cb9000`。源 3145728 字节，28 次采集读取，29 条封存记录；导出 PNG 的像素逐一与源 XRGB8888 字节比较，文件验证和缓存回放通过。该缓冲区 RGB 全零、未使用源 alpha 为 255，不能证明恢复了变化丰富的真实屏幕内容。

Kali 源字节 SHA-256 为 `b0078e539a764cab6234dc21344e639e0309929d8b109555e9ca1c8ff8e46360`，导出解码 RGBA SHA-256 为 `5e92aaaa54622f5adaf1af07af2f5f92b1ae24d51696be8ea1daa9ee69881652`。固定基线没有 ARM64 翻译层，自动选择 LinuxIntel、32 位符号掩码，访问 `0x82002000` 发生页表错误。因此 Kali 仅记录为原生阳性采集/导出测试，不宣称真实阳性差分通过。

可选真实检查（跳过不构成验收）：

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_FBDEV_REFERENCE="$PWD/.cache/fbdev-validation/reference" \
GOMEM_FBDEV_KALI_IMAGE="$PWD/images/kali.raw" \
GOMEM_FBDEV_KALI_SYMBOLS="$PWD/symbols/kali-6.8.11-arm64.json.xz" \
go test ./internal/engine -run 'Test(OfficialLinuxFbdev|KaliARM64Fbdev)' -count=1
```

真实 Intel 阳性、FOURCC、更多内核/像素内容、ARM64 分页合成全布局、全部参数与渲染方式仍待验收。[机器可读记录](linux-fbdev-validation.json)、[七字段对照配置](diff/linux.fbdev.json)。镜像、屏幕内容和案件文件不入库。
