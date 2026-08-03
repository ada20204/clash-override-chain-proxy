# Clash 完全覆写脚本

一个 Clash Party 覆写脚本，自动生成代理组、分流规则和 DNS 配置。

新手配置请优先看完整教程：[Clash 完全覆写脚本低门槛配置教程](docs/配置教程.md)。

## 功能

- **声明式功能组**：国际媒体、Telegram、GitHub、微软服务、游戏平台、Apple 等，新增组只需加一条配置；微软服务默认直连
- **地区自动检测**：根据订阅节点自动创建香港、美国、日本、新加坡、台湾、韩国等地区 url-test 组
- **无订阅模式**：可用空 YAML 作为基础配置，出口节点统一写入 `出口IP凭证.js`
- **AI Agent 策略组**：AI 域名和进程统一走独立策略组；有家宽出口时可选家宽 IP，无家宽出口时可直接选择订阅节点
- **AI QUIC 防泄漏**：默认拒绝 AI 域名的 UDP/443，让浏览器立即回退 HTTPS/TCP，避免 HTTP 出口不支持 UDP 时继续匹配到直连
- **WebRTC UDP 防泄漏**：默认拒绝常用 STUN UDP 端口，避免不支持 UDP 的 HTTP 出口暴露本地公网 IP
- **家宽IP链路（可选）**：配置家宽出口后，会生成真直连 `家宽IP` 和可选 `家宽IP链式`，可在 AI Agent 组中选择
- **前置代理（可选）**：给订阅节点统一加一层一级跳板，缓解本机网络到订阅节点的污染和超时；也可在 GLOBAL 中选择它，让全局流量都先走一级代理
- **自定义出口（可选）**：注入自定义 HTTP/SOCKS5 代理节点
- **公司代理隔离（可选）**：`scope: "dedicated"` 节点只接受显式业务规则引用，不进入通用出口
- **通用出海兜底**：未分类国际流量通过隐藏的 `🌐 通用出海` 复用 `节点选择`，与公司内网代理解耦
- **分流 DNS**：国内域名使用国内 DNS；海外 DNS 默认随 `🤖 AI Agent` 建立 DoH 连接
- **Tailscale 共存（可调）**：Tailnet 目的地址固定直连，官方域名和进程目标可配置，并默认生成隐藏监控组
- **GeoSite/GeoIP 兜底**：国内域名和 IP 自动直连，无需手动维护
- **跨平台进程规则**：同时覆盖 macOS 和 Windows 进程名

## 代理组结构

```
 1. 自动选择           ← url-test，自动选最快节点
 2. 节点选择           ← select，可选组/地区/普通自定义节点/裸节点/DIRECT
 3. GLOBAL            ← select，含节点选择和全部普通选项
 4. 🌍 国际媒体        ← YouTube/Netflix/Twitter/Disney+/Spotify 等
 5. 📲 Telegram       ← Telegram + Discord
 6. 🐙 GitHub         ← GitHub 全套
 7. Ⓜ️ 微软服务        ← Office/Azure/Windows 等，默认 DIRECT
 8. 🎮 游戏平台        ← Steam/Epic/Nintendo/PlayStation/Blizzard，默认代理
 9. 🍎 Apple          ← iCloud/App Store 等
10. 🎯 直连            ← DIRECT
11. 🤖 AI Agent       ← AI 域名/进程的独立出口选择组
12. 🔗 家宽跳板        ← 家宽链式节点的上级跳板（有家宽凭证和可用跳板时）
13. 🏠 家宽IP          ← 家宽出口选择组（有家宽凭证时）
14+ 地区 url-test 组   ← 🇭🇰|香港、🇺🇸|美国、🇯🇵|日本 等（沉底）
```

`🌐 通用出海`、`🇯🇵 日本服务` 与 Tailscale 监控组均为隐藏内部组：前者只负责让 `MATCH` 复用 `节点选择`；日本服务保持 LINE、Yahoo Japan、Sony、Nintendo 等规则优先日本节点；Tailscale 监控组只用于连接信息观测。VS Code Marketplace、npm、NuGet、Bing 等开发服务不创建独立分组，直接走 `节点选择`。

`🤖 AI Agent` 的成员会按是否配置家宽 IP 自动变化：

```
有家宽IP时：
  🏠 家宽IP / 节点选择 / 地区组 / 普通自定义出口 / DIRECT

无家宽IP时：
  节点选择 / 地区组 / 普通自定义出口 / 订阅裸节点 / DIRECT

无订阅模式：
  🏠 家宽IP / 普通自定义出口 / 节点选择 / DIRECT
```

AI Agent 不直接放入总的自动选择组，避免 AI 出口选择过于含糊；地区组会保留。有家宽 IP 时不展开订阅裸节点，避免高阶场景下列表过长；无家宽 IP 时保留裸节点，方便单独给 AI 选择某个支持 AI 的订阅节点。

## 规则优先级

```
代理服务器地址         → DIRECT（避免下游 Clash 重复代理）
AI 域名 UDP/443       → REJECT（rejectAiQuic 开启时，立即回退 TCP）
WebRTC STUN UDP       → REJECT（3478、5349、19302，rejectWebRtcUdp 开启时）
YouTube 共享 Google API → 🌍 国际媒体（优先于通用 Google 域名）
AI 进程规则           → 🤖 AI Agent
明确 AI 域名          → 🤖 AI Agent（Gemini / AI Studio / Antigravity 等）
通用 Google 服务      → 节点选择
浏览器进程规则        → 🤖 AI Agent（enableChainRegionBrowserProcessProxy 开启时）
功能组域名规则        → 各功能组（媒体/Telegram/GitHub/日本服务/微软/游戏/Apple）
公司域名和网段        → dedicated 自定义规则组
Tailnet 目的地址和 MagicDNS → 🧩 Tailnet 内部直连 → DIRECT
Tailscale 控制面域名+进程  → Tailscale 监控组 → USER_OPTIONS.tailscale 配置的目标
国内域名/IP直连       → DIRECT（手动列表 + GEOSITE,cn + GEOIP,cn）
兜底                  → 隐藏的 🌐 通用出海 → 节点选择
```

## 与 Tailscale 共存

脚本默认按标准 Tailscale 方式共存。远程设备把本机作为 Exit Node 时，默认不会用一条 `SRC-IP-CIDR` 把转发流量提前截获，因此这类公网访问仍会继续走完整分流规则，最后才落到 `MATCH → 🌐 通用出海 → 节点选择`。

最终直连的 Tailnet 目的地址和 MagicDNS 域名：

```text
100.64.0.0/10 → 🧩 Tailnet 内部直连 → DIRECT
100.100.100.100/32 → 🧩 Tailnet 内部直连 → DIRECT
fd7a:115c:a1e0::/48 → 🧩 Tailnet 内部直连 → DIRECT
*.ts.net → 🧩 Tailnet 内部直连 → DIRECT
```

`*.ts.net` 是 MagicDNS 专用后缀。脚本将它排除 Fake-IP，不为它添加显式的上游 `nameserver-policy` 或 hosts；开启 MagicDNS 后，由 Tailscale 的 scoped resolver 直接查询 `100.100.100.100`。`100.64.0.0/10` 与 `100.100.100.100/32` 都已排除 TUN 路由，因此这条查询和最终 Tailnet 连接不会被 Mihomo 再次接管或形成 DNS 回环。

Tailscale 控制面域名和 App 进程默认直连，但规则会先进入隐藏监控组，便于在 Clash Party 的连接图里确认流向：

| 监控组 | 默认成员 | 用途 |
|---|---|---|
| `🧩 Tailnet 内部直连` | `DIRECT` | `100.64.0.0/10`、`*.ts.net` 与其他 Tailnet 目的地址 |
| `🧩 Tailscale 控制面` | `DIRECT` | `tailscale.com`、`tailscale.io` |
| `🧩 Tailscale 进程` | `DIRECT` | Tailscale App / 服务进程 |
| `🧩 Tailscale Exit Node` | `forceExitNodeTrafficTarget` | 仅在强制接管 Exit Node 转发流量时出现 |

可以在 `完全覆写.js` 顶部配置：

```javascript
tailscale: {
  enable: true,
  monitorGroups: true,
  hideMonitorGroups: true,
  subnetCidrs: [],
  controlPlaneTarget: "DIRECT",
  processTarget: "DIRECT",
  forceExitNodeTraffic: false,
  forceExitNodeTrafficTarget: "节点选择"
}
```

测速地址在 `完全覆写.js` 顶部按用途分层配置：

```javascript
urlTestProbeUrl: "http://connect.rom.miui.com/generate_204",
proxyProbeUrl: "https://www.gstatic.com/generate_204"
```

`urlTestProbeUrl` 用于直连、Tailscale 监控和自定义业务组的界面健康检查，避免 DIRECT 被 Google 测速误判超时。`proxyProbeUrl` 用于 `自动选择`、地区组、`节点选择`、`AI Agent`、家宽跳板等代理出海组。需要某个分组单独使用业务健康检查地址时，再在该分组里配置 `testUrl` 覆盖。

`directProxyServerRules` 默认开启：脚本会从最终代理节点列表读取 `server`，将字面量 IP 生成为 `IP-CIDR -> DIRECT`，将服务器域名生成为 `DOMAIN-SUFFIX -> DIRECT`。这只处理代理节点本身的上游连接，适合 Mac Clash 经过局域网到 XStation 时避免 XStation 再次代理节点服务器；如某个节点的 `server` 是域名，且下游 Clash 只能看到已解析 IP，再把实际 IP 写入 `proxyServerResolvedIps`，脚本会额外生成对应的 `/32` 或 `/128 DIRECT` 规则：

```javascript
proxyServerResolvedIps: {
  "edge.example.com": ["203.0.113.10", "2001:db8::10"]
}
```

域名的 IP 发生变化时需要同步更新这份映射；如某个环境不需要代理服务器直连豁免，可将 `directProxyServerRules` 改为 `false`。

`rejectAiQuic` 默认开启：脚本会复用 AI Agent 的域名清单，在普通 AI 代理规则之前自动生成 UDP/443 `REJECT`。这适合 HTTP 家宽代理等运行时显示 `udp=false` 的出口，可防止 Mihomo 跳过不支持 UDP 的策略后继续向下匹配到直连。`rejectWebRtcUdp` 也默认开启，会拒绝浏览器常用的 STUN UDP 端口 `3478`、`5349`、`19302`，避免 WebRTC 暴露本地公网 IP。需要实时语音/视频，且所选代理链已验证支持 UDP 时，再将相应开关改为 `false`。

DNS 默认开启 `respect-rules`。`geosite:cn` 和直连/代理节点启动解析使用 AliDNS / DNSPod；未知域名与海外策略默认使用 Google、Cloudflare、Quad9，并通过 `🤖 AI Agent` 建立 DoH 连接，所以会随你为 AI 选择的家宽或指定节点出站。将 `overseasDnsTarget` 改为 `"节点选择"`，则恢复使用普通出海线路。DNS 检测页展示的是 Google、Cloudflare 等递归 DNS 的地址，不会等于你的家宽出口 IP；关键是它不再显示中国大陆递归 DNS。

完全覆写会在 TUN 已存在时保留原有 DNS 劫持项，并补齐 UDP `any:53` 与 TCP `tcp://any:53`。不要同时启用 Clash Party 的独立「DNS 覆写」作为第二个 DNS 配置入口，它会在脚本之后覆盖 `respect-rules`、上游 DNS 和策略；需要统一行为时应关闭该功能并重载覆写。此设置只管理进入 Mihomo 的 DNS 请求；macOS 若仍将系统 DNS 绑定到物理网卡，仍须让 Clash Party 的「自动设置系统 DNS」实际生效。

如果本机网络访问 `tailscale.com` 官方域名也受污染，可以把 `controlPlaneTarget` 改成前置代理名称或 `节点选择`。如果启用了 Tailscale subnet route，并希望这些内网段也在连接图里归到 `🧩 Tailnet 内部直连`，把网段写入 `subnetCidrs`，例如 `["192.168.88.0/24"]`。`monitorGroups` 只影响界面可观测性，设为 `false` 后规则会直接指向配置目标。`hideMonitorGroups` 默认隐藏这些监控组，避免它们在代理组列表里显示 DIRECT 测速超时；临时排查时可改成 `false`。`processTarget` 默认不建议改；进程级代理可能影响 WireGuard、DERP 或 STUN 行为。只有明确需要一刀切接管 Exit Node 转发公网流量时，才把 `forceExitNodeTraffic` 改成 `true`。

## 快速开始

### 1. 准备凭证文件（可选）

复制 [`出口IP凭证_样本.js`](src/出口IP凭证_样本.js)，重命名为 `出口IP凭证.js`，按需取消注释：

```javascript
function main(config) {
  // 家宽IP（可选）
  config._homeProxy = {
    type: "http",
    server: "你的家宽IP",
    port: 1080
  };

  // 普通自定义出口（可选，数组；会进入通用选择组）
  config._customProxies = [
    {
      name: "自定义出口",
      type: "http",
      server: "10.0.0.1",
      port: 3128,
      // 可选：节点在 Tailscale subnet 内时，指定 Tailscale 网卡，例如 "utun4"
      interfaceName: ""
    }
  ];

  return config;
}
```

只允许公司域名或内网网段使用的代理应标记为 dedicated，并同时配置规则组：

```javascript
function main(config) {
  config._customProxies = [
    {
      name: "公司代理",
      scope: "dedicated",
      type: "http",
      server: "10.0.0.1",
      port: 3128,
      interfaceName: ""
    }
  ];
  config._customRuleGroups = [
    {
      name: "公司内网",
      proxies: ["公司代理"],
      rules: [
        "DOMAIN-SUFFIX,example.corp",
        { type: "IP-CIDR", value: "10.0.0.0/8", option: "no-resolve" }
      ]
    }
  ];
  return config;
}
```

`scope: "dedicated"` 节点不会进入 `节点选择`、`🌐 通用出海`、AI、媒体、GitHub、游戏平台、家宽跳板或 `GLOBAL`。未被 `_customRuleGroups.proxies` 引用时，脚本会直接报错。

如果自定义出口是 Tailscale subnet 内的地址，并且虚拟网卡模式下开启了「自动选择流量出口接口」，需要给该节点配置 `interfaceName`。macOS 可通过 `route -n get 代理IP` 查看当前接口名。

如果只想让固定域名或网段走某个目标，可以复制 [`自定义规则组_样本.js`](src/自定义规则组_样本.js)，重命名后按需配置：

```javascript
function main(config) {
  config._customRuleGroups = [
    {
      name: "自定义业务",
      proxy: {
        name: "自定义业务节点",
        type: "socks5",
        server: "127.0.0.1",
        port: 10880
      },
      rules: [
        "DOMAIN,service.example.test",
        "DOMAIN-SUFFIX,internal.example.test"
      ],
      testUrl: "http://connect.rom.miui.com/generate_204"
    }
  ];

  return config;
}
```

这会生成一个独立策略组，并把指定规则指向这个组；该组不会默认进入「节点选择」，避免被当作普通出口误选。如果目标节点已经存在，也可以删掉 `proxy`，改用 `proxies: ["已有节点名"]` 或 `proxies: ["DIRECT"]`。自定义规则组的测速地址按“分组 `testUrl` → 全局 `USER_OPTIONS.urlTestProbeUrl` → 脚本内置默认值”的顺序取值。

也可以使用仓库内的辅助脚本自动探测并写入：

```bash
node scripts/update-interface-name.js \
  --file "/path/to/出口IP凭证.js" \
  --server 10.96.0.100 \
  --write
```

不加 `--write` 时只预览，不会修改文件。

不配置任何凭证时，脚本仅做分流覆写（纯功能组 + 域名规则 + GeoSite/GeoIP 直连）。

如果你的本机网络到订阅节点经常超时，可以复制 [`前置代理_样本.js`](src/前置代理_样本.js)，重命名为 `前置代理.js`，配置一个一级代理：

```javascript
function main(config) {
  config._frontProxy = {
    name: "一级前置代理",
    type: "socks5",
    server: "你的一级代理服务器IP",
    port: 1080
  };

  return config;
}
```

配置后，订阅原始节点会先走这个前置代理；URLTest 测速地区节点时也会先走前置代理。自定义出口默认不会被前置代理覆盖；如需让某个自定义节点也先走前置代理，在节点配置里加 `useFrontProxy: true`。

如果希望全局所有流量都走一级代理，请在 `GLOBAL` 组里选择你配置的一级代理名称。`DIRECT` 是 Clash 内置直连，选择 `GLOBAL → DIRECT` 时仍然会真实直连。

### 2. 导入覆写

在 Clash Party 覆写列表中按顺序导入：

1. `前置代理.js`（如有）
2. `出口IP凭证.js`（如有）
3. `完全覆写.js`

顺序不能反——覆写脚本需要读取凭证文件注入的配置。

### 3. 调整参数

覆写脚本顶部的可调参数：

```javascript
var USER_OPTIONS = {
  autoSelectGroupName: "自动选择",              // 订阅中自动选择组的名称
  overseasDnsTarget: "🤖 AI Agent",             // 海外 DoH 连接随 AI Agent 出站；可改为“节点选择”
  proxyServerResolvedIps: {},                     // 域名代理服务器的已解析 IP 白名单
  rejectAiQuic: true,                            // AI 域名拒绝 UDP/443 并回退 TCP
  rejectWebRtcUdp: true,                         // 拒绝常用 STUN UDP，防止 WebRTC 暴露本地公网 IP
  enableChainRegionBrowserProcessProxy: false,  // 浏览器进程是否走家宽出口
  enableChainRegionAiCliProcessProxy: true,     // AI CLI 进程是否走家宽出口
  tailscale: {
    enable: true,
    monitorGroups: true,
    hideMonitorGroups: true,
    subnetCidrs: [],
    controlPlaneTarget: "DIRECT",
    processTarget: "DIRECT",
    forceExitNodeTraffic: false,
    forceExitNodeTrafficTarget: "节点选择"
  }
};
```

### 无订阅模式

如果没有机场订阅，也可以使用空 YAML 作为容器：

1. 导入 [`src/无订阅基础配置.yaml`](src/无订阅基础配置.yaml)
2. 复制 [`src/出口IP凭证_样本.js`](src/出口IP凭证_样本.js)，重命名为 `出口IP凭证.js`
3. 在 `出口IP凭证.js` 里填入 dedicated 公司节点、普通自定义节点或固定 IP
4. 覆写顺序：`出口IP凭证.js` → `完全覆写.js`

无订阅模式不会生成地区组，也不会强行创建 `自动选择`。如果空 YAML 里没有订阅节点，也没有 `_customProxies` 或 `_homeProxy`，脚本会直接报错。

### 4. 启用并验证

- 启用覆写 → 切回订阅配置 → 启动代理
- 确认使用**规则模式**和 **TUN 模式**
- 打开 Clash Party 的「网络信息」，用不同检测源判断不同出口是否生效

网络信息检测源会被脚本显式分流：

| 检测源 | 用来判断什么 | 规则目标 | 预期结果 |
|---|---|---|---|
| `ip.net.coffee` | AI Agent 的完整网络表现 | `🤖 AI Agent` | 显示 AI Agent 当前出口，并用于观察页面资源、DNS、协议等端到端结果 |
| `ipapi.is` | AI 专用出口 | `🤖 AI Agent` | 显示 AI Agent 当前选择的出口；如果选了 `🏠 家宽IP`，就显示家宽 IP |
| `ipwho.is` | 普通代理出口 | `节点选择` | 显示默认代理出口，不受 AI Agent 和公司内网代理影响 |
| `IP.SB` / `ip.sb` | 前置链路或直连出口 | 有前置代理时指向前置代理；无前置代理时 `DIRECT` | 开启前置代理时显示一级代理 IP；未开启时显示本机直连公网 IP |

简单判定方式：

```text
ip.net.coffee → 看 AI Agent 的完整网络行为
ipapi.is   → 看 AI 相关流量最终走哪里
ipwho.is   → 看节点选择的默认代理出口
ip.sb      → 看本机到订阅节点前的第一跳；没前置代理时就是直连公网 IP
```

如果配置了 `前置代理.js`，地区组和 URLTest 测速订阅节点时会先走前置代理，因此 `IP.SB` 应显示前置代理的 IP；但 `ipwho.is` 仍应显示普通代理节点的最终出口 IP。

如果要排查某个出口节点本身是否稳定，可以绕过 Clash 分流，直接用仓库脚本批量访问检测源：

```bash
python3 scripts/proxy-reliability-test.py \
  --scheme http \
  --host 你的出口IP或域名 \
  --port 代理端口 \
  --username 用户名 \
  --password 密码 \
  --url https://ipapi.is/ \
  --count 50 \
  --concurrency 2 \
  --tcp-check \
  --csv /tmp/proxy-reliability.csv
```

也可以直接传完整代理地址：

```bash
python3 scripts/proxy-reliability-test.py \
  --proxy http://user:pass@10.96.0.100:3456 \
  --url https://ipwho.is/ \
  --count 30 \
  --timeout 10 \
  --json
```

这个脚本用于验证 `家宽IP`、公司代理、自定义出口这类 HTTP/HTTPS 代理节点的连通率和延迟；Clash 里的分流是否命中，仍然以「网络信息」和连接图为准。

## 文件说明

```
src/
  完全覆写.js           ← 覆写脚本（唯一）
  无订阅基础配置.yaml    ← 无订阅模式的空基础配置
  前置代理_样本.js       ← 前置代理样本（给订阅节点统一加第一跳）
  出口IP凭证_样本.js     ← 统一出口配置样本（家宽IP + 普通出口 + dedicated 公司代理）
  自定义规则组_样本.js    ← 固定规则指向自定义策略组的样本
  家宽IP-链式代理.js     ← 原始脚本（保留参考）
  MiyaIP 凭证_样本.js    ← MiyaIP 凭证样本（保留参考）

tests/
  validate-direct.js    ← 测试用例

scripts/
  update-interface-name.js     ← 自动探测并写入 Tailscale 网卡名
  proxy-reliability-test.py    ← 批量测试 HTTP 出口代理可用率
  check-claude-rules.js        ← 对照参考页检查 Claude/Anthropic 规则遗漏
```

## 本地校验

```bash
node tests/validate-direct.js
python3 -m py_compile scripts/proxy-reliability-test.py
node scripts/check-claude-rules.js
```

`check-claude-rules.js` 会从 `https://ip.net.coffee/claude/site.html` 抽取 Claude/Anthropic 相关域名和 IP 段，并和 `完全覆写.js` 当前规则对比。明确遗漏的域名或 CIDR 会让脚本失败；关键词、ASN、NTP/GeoSite 这类宽规则只作为 advisory 输出，避免默认规则过宽造成误伤。

`自动选择` 组会自动过滤订阅里的状态信息节点，例如官网地址、剩余流量、套餐时间、到期/续费提醒等。这些节点不会参与测速，但仍保留在 `节点选择` 里，方便查看订阅状态。如需补充服务商特有关键词，可在 `USER_OPTIONS.autoSelectExcludeKeywords` 里追加。

## 覆盖的进程

### AI 应用（走 🤖 AI Agent）

以下应用和命令行工具会命中 `🤖 AI Agent`。如果 `🤖 AI Agent` 里选择了 `🏠 家宽IP`，这些流量才会继续走家宽 IP；也可以按需切到地区组、普通自定义出口或订阅节点。dedicated 公司代理不会出现在这里。

| 应用 | macOS | Windows |
|---|---|---|
| Claude | Claude, Claude Helper 等 | Claude.exe |
| Claude Code | Claude Code, claude | Claude Code.exe, claude.exe |
| ChatGPT | ChatGPT, ChatGPT Helper | ChatGPT.exe |
| Perplexity | Perplexity, Perplexity Helper | Perplexity.exe |
| Cursor | Cursor, Cursor Helper | Cursor.exe |
| Antigravity | Antigravity.app | Antigravity.exe, language_server_windows_x64.exe |
| Gemini CLI | gemini | gemini.exe |
| Codex CLI | codex | codex.exe |

### 浏览器（enableChainRegionBrowserProcessProxy 开启时走 🤖 AI Agent）

开启 `enableChainRegionBrowserProcessProxy` 后，以下浏览器进程会命中 `🤖 AI Agent`。默认关闭，避免普通浏览器流量过度影响 AI 出口选择。

| 浏览器 | macOS | Windows |
|---|---|---|
| Chrome | Google Chrome + Helper 系列 | chrome.exe |
| Edge | — | msedge.exe |
| Dia | Dia + Helper 系列 | Dia.exe |
| Atlas | Atlas + Helper 系列 | Atlas.exe |
| SunBrowser | SunBrowser + Helper 系列 | SunBrowser.exe |

```mermaid
flowchart LR
  USER["USER_OPTIONS\n地区 · 开关"]
  BASE["BASE\n运行期常量"]
  SRC["SOURCE_*\n模式字面量"]
  POL["POLICY\n策略表"]
  DER["DERIVED\n派生视图"]
  CFG[("Clash 配置")]
  EXP["EXPECTED_ROUTES\n路由样本"]
  VAL[["断言 + tests/validate.js"]]
```

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：macOS + Windows
