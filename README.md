# Clash 完全覆写脚本

<p align="center">
  <img src="./assets/readme/hero.svg" width="100%" alt="Clash 完全覆写脚本：将订阅、固定出口与内网代理编排成可控、可验证的 Mihomo 路由策略。">
</p>

<p align="center">
  <strong>给 Clash Party / Mihomo 的 JavaScript 覆写脚本。</strong><br>
  把订阅、前置代理、家宽 IP 和 Tailscale 子网节点组合成一套可选择、可观察、可回退的路由策略。
</p>

<p align="center">
  <code>Clash Party</code> · <code>Mihomo</code> · <code>JavaScriptCore</code> · <code>macOS / Windows / Linux</code>
</p>

## 从这里开始

> 多台机器、或不想安装 Clash Party：用本仓 `scripts/render-config.js` 按主机文件渲染出 `out/<host>.yaml`；**发布、拉取、systemd、本机 ensure** 在私有仓 `sshopt-private` 的 `scripts/mihomo/`（说明见该仓 `docs/mihomo/CLASH_OVERRIDE_OPS.md`）。下面是单机在 Clash Party 里直接导入脚本的用法。

只想先让分流工作起来，不需要配置家宽 IP 或自定义节点：

1. 在 Clash Party 的覆写列表导入 [`src/完全覆写.js`](./src/完全覆写.js)。
2. 使用规则模式；需要接管应用流量时开启 TUN。
3. 打开代理组，在 `节点选择` 选一个正常节点；AI 相关服务则在 `🤖 AI Agent` 单独选择出口。

脚本会保留你的订阅节点，重建它管理的策略组、DNS 和规则。它不会把密码或凭证写入仓库；固定出口、前置代理与公司节点均放在单独的本地凭证脚本中。

> 详细的 Clash Party 操作、美国静态 IP、无订阅模式和排障步骤见 [低门槛配置教程](./docs/配置教程.md)。

> [文档索引](./docs/README.md)区分当前教程、维护记录与未实现的设计稿。

> 主脚本的节点与用途重构方案见 [统一配置参考（设计稿）](./docs/统一配置参考.md)。全部功能由 `完全覆写.js` 实现，独立生成器是无需 Clash Party 的另一种调用方式。新增参数尚未实现，当前仍使用下面的样本和配置教程。

## 它解决什么问题

- **把“节点”变成“策略”**：订阅节点自动组织为地区组、节点选择和功能组，AI 与普通出海可选不同出口。
- **把复杂出口留在可选层**：前置代理、家宽 IP、链式代理、Tailscale 子网节点和无订阅配置按需启用，不影响纯分流模式。
- **把流量路径做成可验证结果**：网络信息检测源、分组测速、连接图、规则顺序与本地测试分别覆盖不同层面。
- **让 Tailscale 与 TUN 共存**：Tailnet、MagicDNS 与出口节点转发保留在 Tailscale 的职责范围内，避免被 Clash 再代理。

## 流量如何决定

<p align="center">
  <img src="./assets/readme/routing-priority.svg" width="100%" alt="策略概览：代理服务器、Tailnet、安全与 IP 检测、AI Agent、通用服务、国内及兜底；实际顺序以生成规则为准。">
</p>

以下是策略概览，不是逐条规则顺序；实际命中以生成配置及连接日志为准：

1. 代理服务器地址直连，避免局域网内多层 Clash 再代理订阅节点（只被订阅信息节点使用的假地址，如 `www.baidu.com`，不生成直连规则）。
2. Tailnet 地址与 `*.ts.net` 保持 Tailscale 直连，MagicDNS 不进入 Fake-IP 或普通上游 DNS。
3. AI 域名的 UDP/443 与常见 WebRTC STUN UDP 默认被拒绝；支持回退的 HTTPS 客户端可改用 TCP，但这不是对所有 UDP 或 WebRTC 泄漏的完整保证。
4. Claude、OpenAI、Gemini、AI Studio、Antigravity、Kiro、Perplexity、Mistral、xAI 及已覆盖的 AI 进程进入 `🤖 AI Agent`。
5. 开发服务、通用 Google 服务和明确的境外域名再进入 `节点选择` 或 `🌐 国外`。
6. 国内域名/IP（少量显式例外、GeoSite 与 GeoIP）进入 `🇨🇳 国内`；`GEOIP,cn` 不带 `no-resolve`，不在 GeoSite 里的国内站会经 mihomo DNS 解析后按 IP 命中国内；其余流量由最后一条 `MATCH,🐟 兜底` 决定走国内还是国外。
7. 局域网/私网段（10/8、172.16/12、192.168/16、169.254/16、127/8、::1、fc00::/7、fe80::/10）进入 `🎯 直连`，面板可见；出口 IP 防回环的 IP-CIDR 与 `ipip.net` 仍直接写 `DIRECT`。

国内直连以 Mihomo 的 `GEOSITE,cn` 和 `GEOIP,cn` 为主，不重复维护腾讯、阿里、WPS 等整套域名清单。脚本只显式保留 `rivotek.com`（国内 DNS，不在 GeoSite 里）和 `typeless.com`；其中 `typeless.com` 使用海外 DNS，但业务流量仍保持直连。

### 可选：全协议回退

`USER_OPTIONS.fullProtocolFallback` 默认 `null`，随 `location` 取值：cn 开启，overseas 关闭；显式 true/false 优先。它只影响原本走 `节点选择`、`🌐 国外` 的普通流量（cn 下 `🐟 兜底` 也多一个 `🔌 全协议回退` 候选）：

- TCP/443 仍使用当前 `节点选择` / `🌐 国外` 的选择结果，例如你手动选中的公司代理。
- HTTP、IMAP、其他 TCP 端口和 UDP 会进入隐藏的 `🔌 全协议回退`。
- 回退组只收录明确配置 `udp: true` 且完整链路均支持 UDP 的订阅节点或普通自定义出口；HTTP 家宽 IP、HTTP 公司代理，以及经过 HTTP 前置代理的节点不会被放入其中。
- 手动选择组会检查全部候选，而非只看默认项。`🔗 前置` 包含 HTTP 或未声明 UDP 的候选时，依赖它的节点不能保证全协议能力；可用 `front.excludeKeywords` 排除不适合作为前置的节点，普通节点选择不受此过滤影响。
- 如果没有符合条件的节点，回退组不会生成，原有的 `节点选择` / `🌐 国外` 行为保持不变。
- AI Agent、AI DNS、AI QUIC、Tailnet 与已有功能组不使用回退组。

需要恢复旧逻辑时，在 `完全覆写.js` 顶部设置：

```javascript
fullProtocolFallback: false
```

## 选择你的模式

### 纯分流

只导入 `完全覆写.js`。适合已有订阅、希望按服务自动分流的日常场景。`🤖 AI Agent` 仍会出现；你可以从地区组、普通自定义出口、订阅裸节点或 `DIRECT` 中选择。

### 前置代理

在 `🔗 前置` 组中选择 `DIRECT` 就不加前置，选择代理节点就增加一跳。订阅和普通自定义节点默认跟随该组，无需逐个设置开关。新增节点统一写在 `出口IP凭证.js` 的 `_customProxies`；专用节点若也要作为前置，在 `USER_OPTIONS.front.include` 填入名称。无需单独的前置代理脚本，旧 `_frontProxy` 输入仍兼容。

### 家宽 IP 与链式代理

复制 [`src/出口IP凭证_样本.js`](./src/出口IP凭证_样本.js) 为本地 `出口IP凭证.js`，配置 `_homeProxy`。脚本会生成：

- `🏠 家宽IP`：真直连与可选链式家宽出口的选择组。
- `🔗 家宽跳板`：家宽链式节点使用的上游选择组。
- `🔗 前置`：订阅和普通自定义节点的一级跳选择组，默认 `DIRECT`（不加前置）。
- `🤖 AI Agent`：默认优先选择 `🏠 家宽IP`，同时保留普通节点选择。

### 无订阅与自定义出口

先导入 [`src/无订阅基础配置.yaml`](./src/无订阅基础配置.yaml)，再用 `出口IP凭证.js` 填写 `_customProxies`、`_homeProxy` 或自定义规则组。没有订阅时不会创建地区组或自动选择组；没有任何出口时脚本会直接报错，而不是生成不可用配置。

## 代理组模型

**日常可见的组**

- `节点选择`：默认普通代理出口，包含自动选择、地区组、普通自定义出口、订阅节点和 `DIRECT`。
- `自动选择`默认过滤订阅状态信息和名称含“公司代理”的节点；被过滤节点仍保留在`节点选择`中供手动使用，可通过 `USER_OPTIONS.autoSelectExcludeKeywords` 调整。
- `GLOBAL`：全局模式的选择入口；有前置代理时可在这里显式选择它。
- `🤖 AI Agent`：AI 域名与 AI 应用的独立出口选择。
- `🌍 国际媒体`、`📲 Telegram`、`🐙 GitHub`、`Ⓜ️ 微软服务`、`🎮 游戏平台`、`🍎 Apple`、`🎯 直连`：按业务拆分的策略组。`Ⓜ️ 微软服务`、`🍎 Apple` 候选为 `DIRECT`（默认）→ `🇨🇳 国内` → `节点选择` → 地区组。
- `🇨🇳 国内`、`🌐 国外`、`🐟 兜底`：位置无关的三个策略组，规则对所有主机相同，只有默认选项随 `location` 变（见下文）。
- 节点组段：`🏠 家宽IP`、`🔗 家宽跳板`（配置家宽 IP 时）、`🔗 前置`、地区 url-test 组。

**隐藏的内部组**

- `🔌 全协议回退`：可选的非 443 / UDP 出口能力组。
- `🇯🇵 日本服务`：LINE、Yahoo Japan、Sony、Nintendo 等优先日本节点的内部组。
- `🧩 Tailnet 内部直连`、`🧩 Tailscale 控制面`、`🧩 Tailscale 进程`：默认隐藏，排障时可临时显示。

`dedicated: true` 的节点不会进入任何通用组。指定业务可通过 `_customRuleGroups` 明确引用；国内出口和前置用途也可分别通过 `domesticExit`、`front.include` 显式授权。节点位于 Tailscale 子网内不代表只能代理内网业务，接入路径与用途分开设置，见 [Tailscale 子网代理示例](./docs/配置教程.md#tailscale-子网内的代理节点)。

`dedicated` 不填或为 `false` 表示普通节点。兼容旧 `scope: "ordinary" / "dedicated"`；新旧字段同时填写时必须一致，`dedicated` 必须使用布尔值，不能写字符串 `"true"` 或 `"false"`。

自定义业务规则可以覆盖普通服务分类，但不能覆盖代理服务器直连、Tailnet 基础路由、IP 检测路由、Google/AI 一致性及 QUIC/WebRTC 防泄漏规则。出现同类型、同匹配值的冲突时，脚本会直接指出冲突规则并停止生成配置。

节点与代理组的名称必须全局唯一，自定义配置不能覆盖同名订阅节点或受管组。脚本会在全部组创建后检查显式成员和 `dialer-proxy` 的引用，缺失出口和循环链路会显示具体路径。

## AI、DNS 与隐私边界

### IPv6 开关

`完全覆写.js` 顶部的 `USER_OPTIONS.enableIPv6` 默认是 `false`，生成配置时同时设置全局 `ipv6: false` 和 `dns.ipv6: false`，覆盖订阅原有值。需要启用时改为 `true`，两项会同步开启。该开关适用于订阅和无订阅模式，控制 Mihomo 配置；系统网卡和 Tailscale 的 IPv6 设置由各自管理。

修改后重新加载覆写，检查实际配置中的这两项是否一致。

### 社区规则与增量维护

AI、国际媒体、Telegram/Discord 和 GitHub 的基础域名来自社区维护清单，更新时固定上游提交并内嵌到脚本。Muse / Meta AI、Llama、Microsoft Copilot 和 GitHub Copilot 优先进入 `🤖 AI Agent`；普通 Facebook、Instagram、WhatsApp、YouTube 继续使用 `🌍 国际媒体`。精确域名不会自动扩大为后缀，共享登录、CDN 和遥测按记录中的策略处理。

来源、过滤理由、这次调查的证据与后续步骤见 [规则维护与调研记录](./docs/规则维护与调研记录.md)。维护流程：

```bash
node scripts/sync-community-rules.js --dry-run
node scripts/sync-community-rules.js --refresh
node scripts/sync-community-rules.js --check
node tests/validate-community.js
node tests/validate-direct.js
```

离线或仅调整本地分类策略时使用 `--render`。不要手工修改主脚本中的生成区段；工具会记录每次规则增删和上游版本。

### AI Agent

Google 账号与 AI 服务默认使用统一出口：Gemini、AI Studio、Antigravity、账号登录和其余 Google 服务进入 `🤖 AI Agent`；YouTube 内容、Google Play 和 FCM 则按媒体与协议能力优先分流，Kiro 等非 Google AI 服务继续使用各自的精确规则。

Codex CLI 的 `codex` 与桌面端后台进程 `Codex (Service)` 默认进入 `🤖 AI Agent`，避免同一桌面会话因请求域名不同而分散到 GitHub、Google 或通用出海出口；IP 检测和安全基础规则仍优先，检测站按各自观察用途分流。

Sentry、Datadog、Intercom、Statsig、Stripe、WorkOS、SendGrid 等共享基础设施不再凭域名全局进入 AI Agent。AI 桌面应用与 CLI 仍由进程规则覆盖，其他应用访问同一基础设施时按普通业务规则处理。

`USER_OPTIONS.googleTrafficConsistency` 默认开启。脚本使用 Mihomo 内置的 `GEOSITE,google-deepmind` 和 `GEOSITE,google` 补齐 Google 账号、Gemini、Antigravity 等共享端点，并统一到 `🤖 AI Agent`；YouTube、Google Play 和 FCM 仍优先进入国际媒体或全协议出口。这样登录与 AI 请求保持同一出口，同时避免 Play 长连接和视频流量误走仅支持 HTTP 的家宽节点。设为 `false` 可恢复原来的精确域名分流。

当 `rejectAiQuic: true` 时，每一个 AI 域名都会生成一条 UDP/443 `REJECT` 规则，再匹配对应的 TCP/HTTPS AI 规则。对于不支持 UDP 的 HTTP 固定出口，这是防止回退到直连的必要边界。

当 `rejectAppStoreQuic: true` 时，App Store 启动接口 `bag.itunes.apple.com` 的 UDP/443 会被拒绝，促使 macOS 回退到 HTTPS/TCP。该规则不改变 `🍎 Apple` 的出口选择，也不影响 iCloud 或 Apple Push。

### DNS

在默认 cn 环境，海外和未知域名的 DoH 通过 `🤖 AI Agent` 建立连接，国内域名、直连域名和代理服务器解析使用国内 DNS；IP 检测站另按清单指定链路解析。overseas 环境普通境外域名改为本机直连解析，AI 域名仍沿用 `overseasDnsTarget`。DNS 检测页显示的是递归 DNS 提供商地址，不会等于家宽出口 IP，应结合所在地与预期 DNS 路径判断。

电脑或云主机在境外时，把 `USER_OPTIONS.location` 改为 `overseas`：`🇨🇳 国内` 默认改选回国出口（成员来自 `domesticExit`，例如一台国内 VPS），`🌐 国外` 与 `🐟 兜底` 默认直连/国外，DNS 也换成本机直连的境外 DoH。`cn` 的最终兜底默认进入 `🇨🇳 国内`，未收录的境外域名也可能直连；希望未知流量代理时，在 `🐟 兜底` 手动选择 `🌐 国外`。详见[配置教程](docs/配置教程.md#境外使用location)。

| 策略组 | 谁指向它 | cn 默认 | overseas 默认 |
|---|---|---|---|
| `🇨🇳 国内` | 国内例外域名、`GEOSITE,cn`、`GEOIP,cn` | `DIRECT` | `domesticExit` 第一个（如 阿里云回国） |
| `🌐 国外` | 明确的境外域名 | `节点选择` | `DIRECT` |
| `🐟 兜底` | 最后一条 `MATCH` | `🇨🇳 国内` | `🌐 国外` |

三个组都是手动选择组，候选一直都在，可随时切换。

**🔗 前置**：订阅和普通自定义节点默认绑定此组；选择 `DIRECT` 直接连接这些节点，选择代理则先经该代理。自动绑定的节点生成不挂前置的副本 `⤴ 原名`，副本只在前置组出现，保留认证、网卡和协议参数，避免循环。`USER_OPTIONS.front` 的 `include` 额外授权专用候选，`excludePorts` / `excludeKeywords` 排除本机不可达的候选，`prefer` 用正则排序；这些选项不切换当前选择，也不控制业务出口。家宽IP 真直连路径不变，家宽链式仍经 `🔗 家宽跳板`。自定义节点可用 `via: "DIRECT"` 固定直连，或 `via: "名称"` 固定上级。

兼容旧配置：显式 `useFrontProxy: false` 仍固定直连，`true` 仍跟随前置；`allowAsFront: true` 仍授权原节点且保持其直接拨号。希望采用新的统一默认行为时，删除这两个旧字段，专用节点改用 `front.include` 授权。`_frontProxy` 配置后仍排在前置组首位；`frontGroup: false` 保留旧的单节点前置模式。新默认只对未填写旧字段的普通节点生效，客户端已保存的组选择不会被脚本强制重置。

不要同时开启 Clash Party 独立的「DNS 覆写」作为第二个配置入口。它可能在主脚本之后覆盖 `respect-rules`、上游 DNS 与策略路由。

前置副本只解除本次脚本自动绑定的 `🔗 前置`；用户显式填写的 `via` 和订阅原有 `dialer-proxy` 会保留，不生成绕过它们的直连副本。副本名称与已有节点或策略组冲突时自动追加编号。

国内出口与前置可以复用同一个节点：节点写 `dedicated: true`，`domesticExit: ["阿里云回国"]` 授权国内业务，`front.include: ["阿里云回国"]` 授权前置候选。它不会因此进入自动选择、普通节点选择或家宽跳板。专用前置必须本机可直达；引用不存在、被过滤或依赖其他上游的节点会报错，不能强行剥离显式上游。

### Tailscale

默认配置保留 `100.64.0.0/10`、`100.100.100.100/32`、Tailnet IPv6 前缀和 `*.ts.net` 的直连路径，并排除 TUN 路由。Tailscale 控制面和进程默认 `DIRECT`，但可通过 `USER_OPTIONS.tailscale` 改为前置代理或节点选择。

Exit Node 转发流量默认继续使用正常分流规则。只有明确要把 Exit Node 转发流量强制指定到某个目标时，才开启 `forceExitNodeTraffic`。

## 默认工作流：headless 渲染（部署见 sshopt-private）

本仓只负责**生成**配置：

```bash
npm install
cp secrets.env.example secrets.env && chmod 600 secrets.env   # 不进 git
cp hosts/overseas-cloud.example.js hosts/myhost.js            # 真实 hosts/*.js 不进 git
node scripts/render-config.js --host myhost                   # → out/myhost.yaml，默认 mihomo -t
```

主机文件字段（`location`、`roles`、`runtime`、`selections`、`options.front` 等）与 Clash Party 覆写语义一致；出口用 `secret:KEY` 引用，协议字段完整透传。

本地路径、Windows 盘符与 `file://` 订阅、缓存隔离、凭证和输出权限说明见[配置生成](docs/配置生成.md)。`selections` 只是配置头部元数据，渲染器不会连接客户端或应用运行时选择。

**不进本仓**：`serve-configs.js`、`mihomo-pull.sh`、systemd/timer、本机 `clash-ensure`/`clash-regen`、真实主机清单与运维说明。这些在私有仓 [`sshopt-private`](https://github.com/ada20204/sshopt-private) → `scripts/mihomo/` 与 `docs/mihomo/CLASH_OVERRIDE_OPS.md`（含 🇨🇳 国内 / 🌐 国外 / 🐟 兜底、🔗 前置、测 IP 站与 grok-bot 约定）。有权限的维护者从那里部署；公开读者用上面的 Clash Party 导入即可。

## 导入顺序

按需导入，主脚本始终放在最后：

```text
出口IP凭证.js      （可选：家宽、自定义/前置节点、自定义业务规则）
完全覆写.js        （必选）
```

`出口IP凭证.js` 统一提供 `_homeProxy`、`_customProxies` 和 `_customRuleGroups` 数据，各项均可不配置；`完全覆写.js` 负责生成节点、策略组、DNS、TUN 与规则。前置是否启用在组里选择，专用节点的用途授权仍由主脚本 `USER_OPTIONS` 控制。

从旧文件迁移时，把配置合并进同一个 `main(config)`，每种数组只赋值一次；确认生效后停用旧覆写，避免同名节点重复或数组被后执行的文件覆盖。旧 `_frontProxy` 可原样迁入以保留默认选择，不会因删除样本而取消兼容。真实凭证只放本地，勿提交仓库。

## 验证是否真的生效

规则模式下，不同检测源对应不同链路，不能互相替代；全局模式由 GLOBAL 决定：

| 检测源 | 观察的策略 | 正确用途 |
|---|---|---|
| `ipip.net` | `DIRECT`（不经前置） | 确认本机环境的直连出口 |
| `ip.sb` | `🔗 前置`（无该组时退回旧前置节点或 `DIRECT`） | 确认前置出口（前置为 `DIRECT` 时即直连） |
| `ipwho.is` | `节点选择` | 确认普通代理最终出口 |
| `ipapi.is` | `🤖 AI Agent` | 确认 AI 最终出口 IP |
| `ip.net.coffee` | `🤖 AI Agent` | 观察 AI 出口、DNS、协议和端到端表现 |
| `ping0.cc`、`ipinfo.io` | `🤖 AI Agent` | AI 出口辅助检测，保持原有用途 |

检测站统一维护在 [完全覆写.js](src/完全覆写.js) 顶部的 `NETWORK_PROBES` 清单，按 `direct / front / node / ai` 标记观察对象；规则、DNS、嗅探和 QUIC 保护均从清单生成。不再把检测域名混入 AI 业务补充列表，也不增加新的策略组。[维护方法](docs/配置教程.md#检测站如何统一维护)。

除直连检测 `ipip.net` 外，清单中的检测站及其子域名默认先拒绝 UDP/443（QUIC），促使支持回退的客户端改用 TCP。否则 HTTP 或未启用 UDP 的 SOCKS5 出口可能被内核跳过，误入直连兜底。此保护独立于 AI QUIC 开关，不是全局禁用 UDP；不自动回退的客户端需要改用 TCP 检测。

在 Clash Party 中结合三处信息判断：

1. 代理组当前选择与测速。
2. 网络信息页的 IP、地区、DNS 与 WebRTC 结果。
3. 连接图或 Mihomo 日志中的实际规则命中。

脚本能生成规则，但只有重新导入/重载覆写并查看当前运行配置后，才能证明客户端已经生效。

## 本地校验

```bash
npm ci
npm test
node --check src/完全覆写.js
node scripts/sync-community-rules.js --check
python3 -m py_compile scripts/proxy-reliability-test.py
node scripts/check-claude-rules.js    # 可选的联网调查，不属于离线回归
```

`check-claude-rules.js` 会把当前内嵌 AI 规则和本地 Anthropic 补充与参考页的具体域名、CIDR 比对，保留精确/后缀匹配的区别。关键词、ASN 和 GeoSite 建议只输出提示，不会自动扩大匹配范围。

对家宽 IP、公司代理或自定义 HTTP/SOCKS5 出口，可使用 [`scripts/proxy-reliability-test.py`](./scripts/proxy-reliability-test.py) 独立压测连通率与延迟；它验证代理本身，不替代 Clash 的规则命中检查。

## 文件地图

```text
src/
  完全覆写.js             主覆写脚本
  出口IP凭证_样本.js       唯一配置样本：家宽、自定义/前置节点、专用业务规则
  无订阅基础配置.yaml      无订阅模式的空配置容器

tests/
  validate-direct.js       主覆写行为与回归测试
  validate-community.js    社区解析、分类边界与增量更新测试
  validate-headless.js     headless 渲染器回归（URI 解析、字段透传、runtime、ETag 稳定）
  validate-headless-cache.js 订阅缓存隔离与离线回退
  validate-docs.js         文档索引、本地链接与章节锚点

scripts/
  render-config.js         headless 渲染：每台主机一份 mihomo 配置（不需要 Clash Party）
  lib/proxy-uri.js         代理 URI 解析（http/socks5/ss/vless/trojan/hy2）
  update-interface-name.js 自动探测并写入 Tailscale 网卡名
  proxy-reliability-test.py 批量测试出口代理稳定性
  check-claude-rules.js    检查 Claude/Anthropic 域名与 CIDR 覆盖
  sync-community-rules.js 社区快照同步、规则生成与增量记录
  rule-routing-audit.js   显式规则首条命中的离线检查

rules/
  community-sources.json  来源、分类策略、过滤理由与边界样例
  community.snapshot.json 固定上游版本的完整规则快照
  community-update-history.json 追加式更新历史

hosts/
  *.example.js             主机文件样例（真实 hosts/*.js 不进 git）

docs/
  README.md                当前教程、设计稿与历史记录的索引
  配置教程.md              面向首次使用者的完整操作说明
  配置生成.md              无 Clash Party 的配置生成与凭证说明
  规则维护与调研记录.md    调查证据与后续增量维护步骤
  统一配置参考.md          尚未实现的重构方案，不是当前配置格式
  （部署/拉取/systemd → sshopt-private docs/mihomo/CLASH_OVERRIDE_OPS.md）
```

历史 MiyaIP 链式脚本及其专用测试已移除，旧版本可从 Git 历史查阅。当前只维护 `完全覆写.js`，`出口IP凭证.js` 按需使用。

## 进一步阅读

- 部署与运维（有权限）：私有仓 `sshopt-private` → `docs/mihomo/CLASH_OVERRIDE_OPS.md`。
- [低门槛配置教程](./docs/配置教程.md)：逐步导入、无订阅、前置代理、家宽 IP 和 Tailscale 子网代理。
- [规则维护与调研记录](./docs/规则维护与调研记录.md)：社区来源、服务分类边界、更新工具和本次调查结果。
- [出口凭证样本](./src/出口IP凭证_样本.js)：本地出口与自定义业务规则的统一入口。
