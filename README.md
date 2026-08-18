# Shadowrocket 配置

面向最新版 iOS 与 Shadowrocket 的单文件配置。项目不提供节点或代理组，路由中的 `PROXY` 使用 Shadowrocket 当前选择的内置代理。

## 导入与更新

在 Shadowrocket 中通过下列地址下载配置：

```text
https://raw.githubusercontent.com/Criogaid/shadowrocket-config/main/dist/shadowrocket.conf
```

配置内的 `update-url` 使用同一地址。导入前应先在 Shadowrocket 首页添加并选中可用节点；否则所有 `PROXY` 流量都会失败。

## HTTPS 解密

Bilibili 脚本和应用 URL 规则需要在配置详情中开启 HTTPS 解密，并安装、信任 Shadowrocket 生成的 CA 证书。解密会让 Shadowrocket 读取匹配主机的 HTTPS 内容，应只在理解风险的设备上启用。部分应用存在证书固定，开启后可能无法联网。

如果应用异常，先关闭该配置的 HTTPS 解密并重试；普通域名和 IP 路由仍可继续使用。不要为银行、账号、支付或未列入 `[MITM]` 的主机扩大解密范围。验证器要求 `h2 = true` 和精确的主机清单，拒绝额外、重复或扩大后的主机。

## 构建与验证

需要 Python 3.11+ 与 Node.js 20+，不需要 pip、npm 或第三方 Python 包。路由再生成仅支持 Windows amd64 与 Linux amd64；脚本会按固定 SHA-256 下载官方 `SagerNet/sing-box` 1.13.19 可执行文件并缓存到忽略的 `.cache/`。

```bash
python tools/sync_rules.py --check --pinned
python tools/build.py
python tools/build.py --check
python tools/validate.py
python -m unittest discover -s tests -p "test_*.py"
python tools/check_remote.py
node tests/test_scripts.mjs
```

`tools/sync_rules.py` 对 Clash 数据只接受明确的 `payload:` 和两空格、单引号列表格式，将 `+.example.com` 转为 Shadowrocket 后缀记录 `.example.com`，普通域名保持精确语义。复杂服务数据先由固定版本的官方 sing-box 执行 `rule-set decompile`，再严格解析版本 1 源 JSON；仅接受普通规则中的 `domain`、`domain_suffix` 和 `domain_keyword`，拒绝逻辑规则、正则、IP、端口、反转和未知字段。输出分别为 Shadowrocket `DOMAIN-SET` 与带类型的 `RULE-SET` 记录。`--check --pinned` 会从元数据记录的两个完整提交重新下载并反编译，逐字节核对所有生成文件，避免规则和本地哈希被同时篡改后仍通过 CI。`tools/validate.py` 检查完整生成清单、元数据与哈希、代表域名覆盖、配置顺序、脚本绑定、MITM 清单及工作流约束。`tools/check_remote.py` 在线检查四个完整 Clash 文件、固定提交的 SRS 字节哈希、所有 GeoIP CIDR 和精确来源哈希。

## DNS 与路由

主 DNS 沿用本地 `references/Test.conf` 的国内加密组合：AliDNS 使用 DoQ `quic://dns.alidns.com:853` 和 DoH3 `h3://dns.alidns.com/dns-query`，DNSPod 使用 DoH `https://doh.pub/dns-query` 和 DoT `tls://dot.pub:853`。`fallback-dns-server` 保留经当前代理访问的 Quad9 与 Cloudflare。未使用 `direct-dns-server`：该字段虽出现在近期第三方模板中，但实机 DNS 日志显示它没有按远程 DIRECT 域名规则分流，因此不把它作为配置正确性的前提。`[Host]` 将加密 DNS 域名固定到已审查的服务 IP，同时保留域名以维持 TLS SNI。`proxy-dns-server` 使用国内普通 DNS 解决代理节点域名。配置启用 IPv6 但不优先 IPv6，保留私有地址回答，并为 STUN 返回 `1.1.1.1` 与 `::1`。`block-quic = all-proxy` 只禁用代理流量的 QUIC，不影响国内直连 DoQ/DoH3。

仓库每日同步两类上游：

- `Loyalsoldier/clash-rules` 的 `release` 分支仅提供通用 `reject.txt`、`direct.txt`、`proxy.txt`、`private.txt`，转换为 `DOMAIN-SET`。
- `SagerNet/sing-geosite` 的 GPL-3.0 `rule-set` 分支优先提供复杂服务 `geosite-github.srs`、`geosite-apple.srs`、`geosite-icloud.srs`、`geosite-microsoft.srs`，转换为带类型的 `RULE-SET`。

两边都先解析为完整提交号，再从该提交下载字节。转换结果、两个来源提交、输入/输出 SHA-256、记录数，以及 sing-box 版本、官方资产名和 SHA-256 保存在 `rules/generated/metadata.json`；每次自动更新只保留可审查的生成数据差异。固定哈希可以检测转换工具下载被篡改，但对上游提交本身仍是明确的信任关系。

规则顺序为：本地自定义、应用静态规则、生成的拒绝集、GitHub 代理 `RULE-SET`、Apple/iCloud/Microsoft 直连 `RULE-SET`、生成的私有/代理/直连通用域名集、Loyalsoldier GeoIP 私有/CN IP 直连、`FINAL,PROXY`。GitHub 位于 Microsoft 之前，因为 Microsoft 分类包含部分 GitHub/Azure 基础设施。服务分类以 SagerNet 的当前上游数据为权威输入，不声称手工补全，也不保证覆盖所有版本、地区或未来域名。

## 首版应用覆盖

本版只启用能从已许可来源收窄并审查的功能：

- Bilibili：仓库内响应脚本移除开屏和推荐流中明确标记的广告。
- Zhihu、Xiaohongshu：静态广告、推广或水印端点。
- Douyin、Kuaishou、NetEase Music、QQ Music：静态广告端点。
- Taobao、JD、Pinduoduo：开屏或广告服务端点。
- Meituan、Dianping、Eleme：开屏或广告素材端点。
- Amap、Baidu Maps、Didi：开屏或广告端点。
- Cainiao、SF Express、Ctrip、Fliggy：广告端点。

iQIYI 和 Youku 的候选规则会拒绝完整内容或播放响应，不能用 `REJECT-DICT` 安全替代响应转换，因此未启用。Weibo 条目因当前来源记录不能独立追溯而移除。Tencent Video 与 12306 同样未纳入：已审查候选要么依赖未许可代码，要么需要过宽脚本。配置不伪造 VIP/付费状态，不绕过权益，不读取 Cookie/Token/请求正文，不执行签到或账号操作。

Bilibili 可执行脚本由本仓库运行时加载，URL 固定到只包含已审查脚本和许可证的完整提交 `9b925153cffcc243d9e8625f8e8ae43e03d9c410`，不会随 `main` 分支变化。静态能力扫描只是防止明显危险 API 的防护门，不是脚本语义证明；安全依据还包括脚本体积小且可读、固定哈希、端点和清单绑定、完整 fixtures、不可变提交以及人工审查。

静态规则和远程路由数据会随应用及上游变化而失效或误拦截。此配置只能说明已检查的规则范围，不能保证所有版本、地区或 A/B 实验都有效。

## 自定义规则

只编辑 `rules/custom.list`，当前接受 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR` 和 `IP-CIDR6` 规则，每行一条。随后运行：

```bash
python tools/build.py
python tools/validate.py
```

不要直接修改 `dist/shadowrocket.conf`；它会在下一次构建时被覆盖。

## 更新策略与许可证

每日工作流只提交 `rules/generated/` 中变化的路由数据和元数据，不会更新任何可执行脚本。每周工作流只记录可用的脚本/静态来源提交号并创建审查 PR；它不会替换生产脚本、修改 `reviewedCommit`/`localSha256` 或自动合并。任何脚本更新都需要人工检查差异、许可证、能力范围、测试和哈希。

本项目采用 GPL-3.0。静态规则选自 GPL-3.0 的 `fmz200/wool_scripts`；Bilibili 派生脚本来自 MIT 的 `app2smile/rules`；转换路由及远程 GeoIP 数据的许可和上游归属见 `THIRD_PARTY_NOTICES.md`。完整提交号、来源与本地 SHA-256、修改说明见 `vendor/manifest.json` 和 `rules/generated/metadata.json`。
