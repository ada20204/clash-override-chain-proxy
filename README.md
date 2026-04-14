# Clash 完全覆写脚本

一个 Clash Party 覆写脚本，自动生成代理组、分流规则和 DNS 配置。

## 功能

- **声明式功能组**：国际媒体、Telegram、GitHub、微软服务、游戏平台、Apple 等，新增组只需加一条配置
- **地区自动检测**：根据订阅节点自动创建香港、美国、日本、新加坡、台湾、韩国等地区 url-test 组
- **家宽IP链路（可选）**：配置家宽出口后，AI 和指定进程的流量走家宽 IP 出口
- **自定义出口（可选）**：注入自定义 HTTP/SOCKS5 代理节点
- **GeoSite/GeoIP 兜底**：国内域名和 IP 自动直连，无需手动维护
- **跨平台进程规则**：同时覆盖 macOS 和 Windows 进程名

## 代理组结构

```
 1. 自动选择           ← url-test，自动选最快节点
 2. 节点选择           ← select，可选组/地区/裸节点/DIRECT
 3. GLOBAL            ← select，含节点选择 + 全部选项
 4. 🌍 国际媒体        ← YouTube/Netflix/Twitter/Disney+/Spotify 等
 5. 📲 Telegram       ← Telegram + Discord
 6. 🐙 GitHub         ← GitHub 全套
 7. Ⓜ️ 微软服务        ← Office/Azure/Bing/Xbox/VS Code 等
 8. 🎮 游戏平台        ← Steam/Epic/Nintendo/PlayStation/Blizzard
 9. 🍎 Apple          ← iCloud/App Store 等
10. 🎯 直连            ← DIRECT
11. 🔗 家宽跳板        ← 家宽节点的上级跳板（有家宽凭证时）
12. 🏠家宽IP          ← 家宽出口节点（有家宽凭证时）
13+ 地区 url-test 组   ← 🇭🇰|香港、🇺🇸|美国、🇯🇵|日本 等（沉底）
```

## 规则优先级

```
AI 进程规则           → 🏠家宽IP（有家宽凭证时）
AI + 平台域名         → 🏠家宽IP（有家宽凭证时）
浏览器进程规则        → 🏠家宽IP（enableChainRegionBrowserProcessProxy 开启时）
功能组域名规则        → 各功能组（国际媒体/Telegram/GitHub/微软/游戏/Apple）
Tailscale 进程+IP    → DIRECT
国内域名/IP直连       → DIRECT（手动列表 + GEOSITE,cn + GEOIP,cn）
兜底                  → 节点选择
```

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

  // 自定义出口（可选，数组）
  config._customProxies = [
    { name: "自定义出口", type: "http", server: "10.0.0.1", port: 3128 }
  ];

  return config;
}
```

不配置任何凭证时，脚本仅做分流覆写（纯功能组 + 域名规则 + GeoSite/GeoIP 直连）。

### 2. 导入覆写

在 Clash Party 覆写列表中按顺序导入：

1. `出口IP凭证.js`（如有）
2. `完全覆写.js`

顺序不能反——覆写脚本需要读取凭证文件注入的配置。

### 3. 调整参数

覆写脚本顶部的可调参数：

```javascript
var USER_OPTIONS = {
  autoSelectGroupName: "自动选择",              // 订阅中自动选择组的名称
  enableChainRegionBrowserProcessProxy: false,  // 浏览器进程是否走家宽出口
  enableChainRegionAiCliProcessProxy: true      // AI CLI 进程是否走家宽出口
};
```

### 4. 启用并验证

- 启用覆写 → 切回订阅配置 → 启动代理
- 确认使用**规则模式**和 **TUN 模式**
- 访问 [ipapi.is](https://ipapi.is) 验证家宽 IP 是否生效

## 文件说明

```
src/
  完全覆写.js           ← 覆写脚本（唯一）
  出口IP凭证_样本.js     ← 凭证样本（家宽IP + 自定义出口，全可选）
  家宽IP-链式代理.js     ← 原始脚本（保留参考）
  MiyaIP 凭证_样本.js    ← MiyaIP 凭证样本（保留参考）

tests/
  validate-direct.js    ← 测试用例
```

## 本地校验

```bash
node tests/validate-direct.js
```

## 覆盖的进程

### AI 应用（走 🏠家宽IP）

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

### 浏览器（enableChainRegionBrowserProcessProxy 开启时走 🏠家宽IP）

| 浏览器 | macOS | Windows |
|---|---|---|
| Chrome | Google Chrome + Helper 系列 | chrome.exe |
| Edge | — | msedge.exe |
| Dia | Dia + Helper 系列 | Dia.exe |
| Atlas | Atlas + Helper 系列 | Atlas.exe |
| SunBrowser | SunBrowser + Helper 系列 | SunBrowser.exe |

```mermaid
flowchart LR
  USER["USER_OPTIONS<br/>地区 · 开关"]
  BASE["BASE<br/>运行期常量"]
  SRC["SOURCE_*<br/>模式字面量"]
  POL["POLICY<br/>策略表"]
  DER["DERIVED<br/>派生视图"]
  CFG[("Clash 配置")]
  EXP["EXPECTED_ROUTES<br/>路由样本"]
  VAL[["断言 + tests/validate.js"]]

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：macOS + Windows
