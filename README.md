# Anywhere 分流规则

为 [NodePassProject/Anywhere](https://github.com/NodePassProject/Anywhere)（iOS / iPadOS / macOS / tvOS）自动构建的 `.arrs` 分流规则。

目标很明确：**默认国外走代理，国内、Apple/iCloud、局域网走直连。**

规则源是 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)，GitHub Actions 每天北京时间 **03:00** 自动拉取、转换并发布新的 Release。

## 订阅地址

下面的地址始终指向最新 Release，每天自动更新，不需要改订阅链接：

| 规则集 | 条数 | 用途 | 动作 | 订阅 |
| --- | ---: | --- | --- | --- |
| `CN-Domains-1.arrs` | 约 55,000 | 国内域名直连（前半） | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-Domains-1.arrs) |
| `CN-Domains-2.arrs` | 约 55,000 | 国内域名直连（后半） | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-Domains-2.arrs) |
| `CN-IP.arrs` | 约 10,000 | 国内 IPv4 / IPv6 CIDR | DIRECT（可选） | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/CN-IP.arrs) |
| `Apple.arrs` | 约 220 | Apple 下载/CDN、iCloud | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/Apple.arrs) |
| `LAN.arrs` | 约 160 | 局域网 CIDR、路由器本地域名 | DIRECT | [订阅](https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/LAN.arrs) |

> **`CN-Domains-1.arrs` 和 `CN-Domains-2.arrs` 必须同时添加。** 两个文件合起来才是完整的国内域名列表，单独一个会漏掉一半。

条数会随上游列表变化，以每次 Release 的 `manifest.json` 为准。

## 在 Anywhere 中配置

1. 打开 **Routing**，路由模式选择 **Rule**。
2. 默认路由选择你的代理节点、代理组或代理链。
3. **Country Bypass** 选择 **中国 (CN)**。
4. 添加上表中的 `.arrs` 订阅，逐条把动作设为 **DIRECT**。
5. 内置服务规则保持 **Default**，不要批量指派 **PROXY**。
6. 可选：把 **ADBlock** 设为 **REJECT**。

添加订阅的入口：

```text
Routing → 右上角 + → Subscribe Rule Set → 粘贴上面的 URL
```

也可以先下载 `.arrs` 文件，再用 `Import Rule Set` 导入。

### 为什么内置服务要留在 Default

Anywhere 的匹配优先级是：

```text
ADBlock > Built-in > User > Neutral > Country Bypass
```

内置服务一旦被指派 **PROXY**，就会进入 Built-in 层，压过你在 User 层设置的国内直连规则。留在 **Default** 后，它们会落到 Neutral 层：没有自定义规则匹配时仍然走默认代理，不会破坏国内直连。

### Prevent DNS Leak

如果开启了 **Prevent DNS Leak**，没有域名规则命中的国内域名不会再按“解析后的 IP”回退到 Country Bypass。此时 `CN-Domains-1/2` 的覆盖范围就很重要；也可以同时加上 `CN-IP.arrs`，让直连 IP 流量继续命中。

如果关闭 Prevent DNS Leak，Country Bypass 可以作为国内域名的 IP 兜底，但代价是 DNS 可能泄漏。

## 这套规则怎么工作

Anywhere 的规则文件只负责“匹配哪些目标”，动作由你在 App 里为每个规则集单独指派。

本仓库生成的规则集全部写入：

```text
routing = 1
```

`routing = 1` 只是**首次导入**时把动作初始化为 DIRECT。订阅刷新只替换规则内容，不会覆盖你本地选择的动作，所以导入后仍然要在 Routing 里确认每条都是 **DIRECT**。

转换关系：

```text
+.example.com       -> 2, example.com      # 域名后缀
example.com        -> 2, example.com      # Anywhere 没有 exact-domain，按后缀近似
1.2.3.0/24         -> 0, 1.2.3.0/24       # IPv4 CIDR
2001:db8::/32      -> 1, 2001:db8::/32    # IPv6 CIDR
```

`PROCESS-NAME`、`GEOIP`、`DST-PORT` 等 Anywhere 不支持的规则会被跳过。`direct.txt` 里的 110,000 多条域名会去重后平均拆成两个文件，每个都低于 Anywhere 单套 100,000 条的上限。

## 更新机制

- **定时**：每天 `19:00 UTC`，即北京时间 `03:00`。
- **手动**：GitHub 仓库 → **Actions** → **Update rule sets** → **Run workflow**。
- **Release**：标签格式 `rules-YYYY.MM.DD`。同一天重复运行会替换当天的 Release，不会产生重复版本。
- **产物**：5 个 `.arrs` 文件、`manifest.json`、`SHA256SUMS`。
- **状态**：仓库根目录的 `status.json` 每天更新一次，记录生成时间和各文件条数。
- **固定链接**：`https://github.com/lhxyzCJ/anywhere-proxy-rule/releases/latest/download/<文件名>`。

订阅链接使用 GitHub Release 资源。如果所在网络访问 GitHub 不稳定，可以在其他网络下载 `.arrs` 后通过 `Import Rule Set` 导入，或把 `dist/` 目录镜像到你自己的静态托管。

## 本地构建

只需要 Python 3.10+，不依赖第三方库：

```bash
python3 scripts/build.py --out dist
```

运行测试：

```bash
python3 -m unittest discover -s tests -v
```

如果已经提前下载了上游 `.txt`，可以离线构建：

```bash
python3 scripts/build.py --out dist --source-dir /path/to/txt-files
```

脚本会检查每个来源的最小条数，下载不完整或解析异常时直接失败，不会发布被截断的规则集。

## 目录结构

```text
.
├── .github/workflows/update.yml   # 每日构建与 Release
├── scripts/build.py               # 下载、转换、拆分、校验
├── tests/test_build.py            # 转换逻辑单元测试
├── status.json                    # 最近一次构建状态（每日更新）
├── LICENSE
└── README.md
```

`dist/` 是构建产物，不提交到仓库；规则文件只随 Release 发布，避免仓库历史每天膨胀。

## 数据源与许可

- 规则数据来自 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)。
- 上游项目使用 GPL-3.0，本仓库的转换脚本和生成的规则集同样按 **GPL-3.0** 发布，详见 [LICENSE](LICENSE)。
- 本项目与 NodePassProject、Loyalsoldier 均无隶属关系。
