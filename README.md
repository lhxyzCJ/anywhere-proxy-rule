# Anywhere 分流规则

为 [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere)（iOS / iPadOS / macOS / tvOS）自动构建的多源 `.arrs` 分流规则。

核心策略：

> **默认国外走代理；国内、Apple、Tesla、国外可直连域名和局域网走 DIRECT。**

数据源包括 Loyalsoldier、blackmatrix7、Karing、XTLS Xray 官方 geo 数据和 ACL4SSR。GitHub Actions 每天北京时间 **03:00** 自动拉取、转换并发布新的 Release。

## 订阅地址

下面的地址始终指向最新 Release，每天自动更新：

| 规则集 | 条数 | 用途 | 动作 | 订阅 |
| --- | ---: | --- | --- | --- |
| `All-Direct.arrs` | 约 134,500 | **合并全部 DIRECT 规则（单地址）** | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/All-Direct.arrs) |
| `CN-Domains-1.arrs` | 约 57,500 | 国内域名直连（前半） | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-Domains-1.arrs) |
| `CN-Domains-2.arrs` | 约 57,500 | 国内域名直连（后半） | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-Domains-2.arrs) |
| `CN-IP.arrs` | 约 16,800 | 国内 IPv4 / IPv6 CIDR | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-IP.arrs) |
| `Apple.arrs` | 约 1,800 | Apple / iCloud / App Store CDN | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/Apple.arrs) |
| `Tesla.arrs` | 约 13 | Tesla 中国及全球域名 | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/Tesla.arrs) |
| `Foreign-Direct.arrs` | 约 1,300 | 国外可直连域名（Xray/Karing `@cn` + 常见厂商） | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/Foreign-Direct.arrs) |
| `Steam-Direct.arrs` | 16 | Steam 游戏下载 CDN | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/Steam-Direct.arrs) |
| `LAN.arrs` | 约 170 | 局域网 CIDR、路由器本地域名 | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/LAN.arrs) |

> **只用一个地址：只订阅 `All-Direct.arrs` 即可。** 它已经合并下面所有 DIRECT 集合（当前约 134,500 条）。
>
> 当前 Anywhere 代码允许每套 200,000 条规则；旧版本如果仍然限制 100,000 条，会拒绝这个合并集，此时请更新 App，或继续使用拆分订阅。
>
> **拆分方案：`CN-Domains-1.arrs` 和 `CN-Domains-2.arrs` 必须同时添加。**
>
> `Foreign-Direct.arrs` 不是“国外域名大全”，而是 Xray geosite / Karing 标记为 `@cn` 的国外域名，以及 AMD、Intel、Adobe、Samsung、NVIDIA 等常见驱动/软件厂商分类中适合直连的部分。GitHub、Hugging Face 等仍走代理。
>
> `Steam-Direct.arrs` 只包含游戏下载 CDN（含列出的客户端更新 CDN）。Steam 商店、社区、登录等其它 Steam 域名仍走默认代理；`CN-Domains` 和 `Foreign-Direct` 中非下载类 Steam 域名已被过滤。

条数会随上游变化，以每次 Release 的 `manifest.json` 为准。

## 分流结构

| 集合 | 内容 |
| --- | --- |
| `CN-Domains` | Loyalsoldier `direct`、Karing geosite `cn`、blackmatrix7 `ChinaMax_Domain`、Xray geosite `CN`/`GEOLOCATION-CN`/`TLD-CN`、ACL4SSR `ChinaDomain` 的并集 |
| `CN-IP` | Loyalsoldier `cncidr`、Karing geoip `cn`、blackmatrix7 `ChinaMax_IP`、Xray geoip `CN`、ACL4SSR `ChinaIp` 的并集 |
| `Apple` | Loyalsoldier `apple` + `icloud`、blackmatrix7 `Apple_Domain` + `Apple`、Karing geosite `apple`、Xray geosite `APPLE`、ACL4SSR `Apple` |
| `Tesla` | blackmatrix7 `Tesla`、Karing geosite `tesla`、Xray geosite `TESLA` |
| `Foreign-Direct` | Xray geosite `GEOLOCATION-!CN` 中带 `@cn` 属性的条目，Karing / Xray 的 `microsoft@cn`、`nvidia@cn`、`samsung@cn`、`nintendo@cn`、`google@cn` 等分类，以及 AMD / Intel / Adobe / Samsung / NVIDIA 厂商分类（过滤 Hugging Face、GitHub 等；Steam 只保留下载域名到 `Steam-Direct`） |
| `Steam-Direct` | 仅 `steamcontent.com`、`steamcontent.tnkjmec.com`、`steampipe.akamaized.net`、`steamserver.net`、`cm.steampowered.com`、`steamcdn-a.akamaihd.net`、`client-update.queniuqe.com`、`dl.steam.clngaa.com`、`st.dl.bscstorage.net`、`st.dl.eccdnx.com`、`st.dl.pinyuncloud.com`、`dl.steam.ksyna.com`、`lv.queniujq.cn`、`xz.pphimalayanrt.com`、`steampowered.com.8686c.com`、`content.steamchina.com` |
| `LAN` | Loyalsoldier `lancidr` + `private`、Karing geoip `private`、Xray geoip `PRIVATE` |

这里没有单独的“国外代理列表”。原因是默认路由已经指向代理，国外流量天然走代理；如果再加入一个巨大的 PROXY 规则集，它会和 Apple/Tesla/国外直连集合在同一 User 层竞争，容易出现直连域名被误代理的问题。

`Foreign-Direct` 中有一部分 `.cn` 域名和 `CN-Domains` 重叠，两边都是 DIRECT，重叠不会改变结果。

## 在 Anywhere 中配置

1. 打开 **Routing**，路由模式选择 **Rule**。
2. 默认路由选择你的代理节点、代理组或代理链。
3. **Country Bypass** 选择 **中国 (CN)**。
4. 二选一：
   - **单地址**：只添加 `All-Direct.arrs`，动作设为 **DIRECT**。
   - **拆分**：添加 `CN-Domains-1/2`、`CN-IP`、`Apple`、`Tesla`、`Foreign-Direct`、`Steam-Direct`、`LAN`，全部设为 **DIRECT**。
5. 内置服务规则保持 **Default**，不要批量指派 **PROXY**。
6. 可选：把 **ADBlock** 设为 **REJECT**。

添加订阅的入口：

```text
Routing → 右上角 + → Subscribe Rule Set → 粘贴 All-Direct.arrs 的 URL
```

也可以下载 `.arrs` 后用 `Import Rule Set` 导入。

### 为什么内置服务要留在 Default

Anywhere 的匹配优先级是：

```text
ADBlock > Built-in > User > Neutral > Country Bypass
```

内置服务一旦被指派 **PROXY**，就会进入 Built-in 层，压过你在 User 层设置的国内直连规则。留在 **Default** 后，它们会落到 Neutral 层：没有自定义规则匹配时仍然走默认代理，不会破坏国内直连。

### Prevent DNS Leak

如果开启了 **Prevent DNS Leak**，没有域名规则命中的国内域名不会再按“解析后的 IP”回退到 Country Bypass。此时 `CN-Domains-1/2` 的覆盖范围就很重要；`CN-IP` 也可以让字面 IP 连接继续命中直连。

如果关闭 Prevent DNS Leak，Country Bypass 可以作为国内域名的 IP 兜底，但代价是 DNS 可能泄漏。

这个开关**不是**“所有 DNS 都走代理”的开关。它只关闭“用解析后的 IP 再匹配一次 CIDR”的回退逻辑；被规则判定为 **DIRECT** 的域名仍然使用 **Local Requests** 解析器，默认就是系统 / 运营商 DNS。

### 为什么 DNS 泄漏测试会显示中国 IP

DNS 泄漏测试网站显示的是**解析器出口 IP**，不是你的代理节点出口 IP。

典型链路：

1. 测试域名（例如 `browserleaks.com`）被 `CN-Domains` 判为 **DIRECT**；
2. 页面和它的随机子域名都走直连；
3. 直连解析使用 **Local Requests**（默认系统 DNS，通常是运营商 DNS）；
4. 权威 DNS 记录到中国 DNS 解析器 IP，测试页面就显示中国 IP。

上游 `blackmatrix7/ChinaMax_Domain` 里确实包含 `browserleaks.com`，旧版 `All-Direct.arrs` 会把它当国内域名直连。构建脚本现在通过 `NEVER_DIRECT_DOMAINS` 排除以下测试站点，让它们回落到默认代理：

```text
browserleaks.com / .io / .net / .org
dnsleaktest.com
ipleak.net
whoer.net
dnscheck.tools
dnschecker.org
whatleaks.com
test-ipv6.com
ipv6-test.com
whatismyipaddress.com
```

如果你的订阅还是旧版，先更新订阅；或者在 Anywhere 里新建一个 **PROXY** 规则集，把上面这些域名放进去并排在 `All-Direct` 上面。同层内相同后缀按规则集顺序，后插入的规则集优先。

如果换成不在列表里的测试站仍然显示中国 IP，通常不是规则问题，而是：

- 代理服务端自己使用中国 DNS 解析；
- 代理链的上一跳/落地节点在中国；
- 你用的协议或配置要求本地解析目标域名。

可以看 Anywhere 的请求日志确认该域名是 `DIRECT` 还是走代理；如果确认走代理，就在 **DNS → Proxies → Resolver** 里改成国外 DoH（例如 `https://cloudflare-dns.com/dns-query`），或换一个 DNS 配置正常的节点。不要把 **Local Requests** 改成国外 DoH，否则国内直连站点可能解析到海外 CDN，速度和就近调度都会变差。

## 上游规则

| 上游 | 许可 | 本仓库使用的内容 |
| --- | --- | --- |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | GPL-3.0 | `direct`、`cncidr`、`apple`、`icloud`、`lancidr`、`private` |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | GPL-2.0 | `ChinaMax_Domain`、`ChinaMax_IP`、`Apple_Domain`、`Apple`、`Tesla` |
| [KaringX/karing-ruleset](https://github.com/KaringX/karing-ruleset) | 见上游 | `geo/geosite/*`、`geo/geoip/*`、`ACL4SSR/ChinaDomain`、`ChinaIp`、`Apple` |
| [XTLS/Xray-rules-dat](https://github.com/XTLS/Xray-rules-dat) | GPL-3.0 | 官方 `geosite.dat`、`geoip-lite.dat` |
| [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | CC-BY-SA-4.0 | 通过 Karing 仓库引入 `ChinaDomain`、`ChinaIp`、`Apple` |

转换规则：

```text
+.example.com       -> 2, example.com      # 域名后缀
example.com        -> 2, example.com      # Anywhere 没有 exact-domain，按后缀近似
1.2.3.0/24         -> 0, 1.2.3.0/24       # IPv4 CIDR
2001:db8::/32      -> 1, 2001:db8::/32    # IPv6 CIDR
DOMAIN-KEYWORD,x   -> 3, x                # 域名关键字
```

### Xray GeoSite 的处理

`geosite.dat` 使用 protobuf 存储，构建脚本直接解析，不依赖第三方库：

- `Plain` / `Domain` / `Full` 映射为 Anywhere 的域名后缀规则；`Regex` 跳过。
- `GEOLOCATION-!CN` 只保留带 `@cn` 属性的条目，作为国外可直连域名。
- `MICROSOFT`、`NVIDIA`、`SAMSUNG`、`STEAM` 等分类同样只取 `@cn` 条目。
- `AMD`、`INTEL`、`ADOBE`、`SAMSUNG`、`NVIDIA` 的完整厂商分类用于驱动/软件下载直连；`NVIDIA` 分类里的 Hugging Face 会在过滤阶段排除，GitHub 仍然走代理。
- `geoip-lite.dat` 的 `CN` 转成 IPv4 / IPv6 CIDR，`PRIVATE` 并入 LAN。
- IPv4-mapped IPv6（`::ffff:a.b.c.d`）会折回 IPv4，避免规则永远匹配不到 IPv4 流量。

`PROCESS-NAME`、`IP-ASN`、`GEOIP`、`RULE-SET` 等 Anywhere 不支持的规则会被跳过。`akadns.net`、`akamaized.net`、`cloudfront.net` 这类过宽的 CDN 后缀不会进入 DIRECT 集合，避免把大量国外流量误判为直连。

## 更新机制

- **定时**：每天 `19:00 UTC`，即北京时间 `03:00`。
- **手动**：GitHub 仓库 → **Actions** → **Update rule sets** → **Run workflow**。
- **Release**：标签格式 `rules-YYYY.MM.DD`。同一天重复运行会替换当天的 Release。
- **保留策略**：只保留最近 **3 天**的 Release，更早的 Release 和标签会自动清理；`latest` 订阅链接不受影响。
- **产物**：9 个 `.arrs` 文件（含单地址合并集和 Steam 下载集）、`manifest.json`、`SHA256SUMS`。
- **状态**：仓库根目录的 `status.json` 每天更新一次，记录生成时间和各文件条数。
- **固定链接**：`https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/<文件名>`。

订阅链接使用 GitHub Release 资源。如果所在网络访问 GitHub 不稳定，可以在其他网络下载 `.arrs` 后通过 `Import Rule Set` 导入，或把 `dist/` 目录镜像到你自己的静态托管。

## 本地构建

只需要 Python 3.10+，不依赖第三方库：

```bash
python3 scripts/build.py --out dist
```

启用下载缓存，重复构建时不必重新下载：

```bash
python3 scripts/build.py --out dist --cache-dir .cache
python3 scripts/build.py --out dist --cache-dir .cache --refresh
```

运行测试：

```bash
python3 -m unittest discover -s tests -v
```

脚本会检查每个来源的最小字节数和最小条数；下载不完整、解析异常或上游列表突然缩水时直接失败，不会发布被截断的规则集。

## 目录结构

```text
.
├── .github/workflows/update.yml   # 每日构建、发布、保留 3 天 Release
├── scripts/build.py               # 多源下载、Clash/Karing/Xray 解析、拆分、校验
├── tests/test_build.py            # 解析与转换单元测试
├── status.json                    # 最近一次构建状态（每日更新）
├── LICENSE
├── NOTICE
└── README.md
```

`dist/` 是构建产物，不提交到仓库；规则文件只随 Release 发布，避免仓库历史每天膨胀。

## 数据源与许可

- 规则数据来自上表列出的上游项目，具体来源和许可见 [NOTICE](NOTICE)。
- 本仓库的转换脚本和生成的规则集按 **GPL-3.0** 发布，详见 [LICENSE](LICENSE)。
- 本项目与 NodePassProject 及各规则上游均无隶属关系。
