![封面图](img/封面图.png)

# 用家宽 IP 访问 Claude / ChatGPT，告别风控 · Clash 链式代理覆写方法

借助机场 + 家宽 IP 的链式代理，把域外 AI 服务（Claude、ChatGPT、Gemini 等）的出口 IP 切换为家庭宽带住宅 IP，降低风控风险。社交媒体与流媒体（YouTube、Netflix、X 等）同样支持锁定到指定区域。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)
>
> 当前 README 与进程分流规则明确按 **macOS / MacBook** 环境编写；Tailscale 和 AI App 的进程名也只维护 macOS 常见命名。

## 工作原理

```
请求 → Clash → 跳板节点（机场线路） → MiyaIP 家宽IP → 目标服务
                  ↑ dialer-proxy           ↑ HTTP 代理
```

脚本在覆写阶段做六件事：

1. **注入家宽IP代理节点**——自选跳板（机场线路中转）和官方中转，两种模式可选
2. **覆写 DNS**——fake-ip 模式，域外 AI / Office 相关域名 / 流媒体走域外 DoH（Google、Cloudflare），Apple / 域内 AI 走域内 DoH（阿里、腾讯）
3. **覆写域名嗅探（Sniffer）**——TLS（443/8443）、HTTP（80/8080/8880）、QUIC（443）三协议嗅探，还原 fake-ip 下的真实域名，让规则精确命中
4. **美国 AI 网站强制走链式代理**——Claude、ChatGPT、Gemini、Perplexity、xAI、OpenRouter 等美国系 AI 服务统一走现有链式代理逻辑，也就是「自选节点 + 自选家庭宽带静态IP」
5. **macOS AI App / 进程强制走链式代理**——Claude、ChatGPT、Perplexity、Cursor、Windsurf 等专用客户端按进程名强制命中现有链式代理
6. **强隔离 Tailscale**——`tailscale.com/io` 控制面域名直连，Tailnet 地址段和常见 macOS Tailscale 进程置顶直连，避免远程访问链路误入家宽出口

## 文件说明

- **`src/家宽IP-链式代理.js`**——主脚本，全部逻辑都在这里
- **`src/MiyaIP 凭证_样本.js`**——凭证模板，复制后填入你自己的信息

---

## 配置流程

四样东西先备齐：

1. **Clash Party**——[GitHub 下载](https://github.com/mihomo-party-org/clash-party)
2. **机场订阅**——推荐 [办公娱乐好帮手](https://xn--9kq10e0y7h.site/index.html?register=twb6RIec)
3. **静态家宽 IP**——[注册 MiyaIP](https://www.miyaip.com/?invitecode=7670643)，购买静态住宅代理，拿到用户名、密码、服务器地址
4. **本仓库文件**——`src/MiyaIP 凭证_样本.js` + `src/家宽IP-链式代理.js`

### 1. 导入机场订阅

打开 Clash Party →「配置」→ 粘贴订阅链接 → 导入。

导入的节点就是链式代理的「跳板」。脚本会按地区（如新加坡、美国）自动筛选；如果订阅里已经有可复用的地区代理组，会优先直接复用，否则再按地区节点自动生成。

### 2. 创建凭证文件

把 `MiyaIP 凭证_样本.js` 复制一份，重命名为 **`MiyaIP 凭证.js`**，打开填入真实信息：

```javascript
function main(config) {
  config._miya = {
    username: "你的用户名", // ← MiyaIP 用户名
    password: "你的密码", // ← MiyaIP 密码
    relay: {
      server: "12.34.56.78", // ← 自选跳板服务器 IP
      port: 8022,
    },
    transit: {
      server: "transit.miyaip.com", // ← 官方中转服务器地址
      port: 8001,
    },
  };
  return config;
}
```

> ⚠️ 凭证文件已在 `.gitignore` 中排除，不会提交到仓库。

### 3. 导入覆写脚本并排序

进入 Clash Party →「覆写」，把两个 `.js` 文件加进去，**拖拽成这个顺序**：

① **`MiyaIP 凭证.js`**——把凭证注入 `config._miya`
② **`家宽IP-链式代理.js`**——读取凭证，注入代理节点、DNS、规则等全部配置

顺序反了会报错——主脚本启动时需要读取 `config._miya`，凭证没注入自然读不到。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 4. 调整参数

打开 `家宽IP-链式代理.js`，顶部有三个参数可以改：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG", // 链式代理地区（自选节点 + 家宽IP 出口）
  mediaRegion: "US", // 社交媒体与流媒体锁区地区
  manualNode: "", // 手动指定跳板节点名（留空 = 自动选最快的）
};
```

- **`chainRegion`**（可选值：`US` `JP` `HK` `SG`）——链式代理流量从哪个地区出去；美国 AI 网站、macOS AI App、微软开发工具、GitHub 都统一跟随这个参数
- **`mediaRegion`**（可选值：`US` `JP` `HK` `SG`）——YouTube、Netflix 等锁定到哪个区域
- **`manualNode`**（节点名 / 留空）——指定跳板节点；留空则自动选该地区延迟最低的线路

### 5. 启用并验证

1. 两个覆写脚本的开关都打开
2. 切换到机场配置，启动代理
3. 进入「代理组」，确认以下角色已经到位：

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

① **节点选择**——默认「自动选择」，优先分配延迟最低的节点（如 HK），用于常规域外流量
② **新加坡跳板组**——如果订阅里已有可复用的新加坡地区代理组，脚本会直接复用；否则会生成 **`🇸🇬|新加坡线路-链式代理-跳板`**
③ **🇸🇬|新加坡-链式代理-家宽IP出口**——统一链式代理出口；美国 AI 网站、macOS AI App、微软 / GitHub 等都会通过这里出网
④ **美国流媒体组**——如果订阅里已有可复用的美国地区代理组，脚本会直接复用；否则会生成 **`🇺🇸|美国线路-流媒体`**

4. 验证是否生效：
   - [ping0.cc](https://ping0.cc/) 或 [ipinfo.io](https://ipinfo.io/)——应显示当前链式代理对应的住宅 IP，不是机房 IP
   - [claude.ai](https://claude.ai/) / ChatGPT macOS App——应命中你当前 `chainRegion` 对应的 **`*-链式代理-家宽IP出口`**

---

## 分流一览

- **美国 AI 网站** → 强制链式代理（跟随 `chainRegion` 的家宽IP出口）：Claude、ChatGPT、Gemini、Antigravity、Perplexity、OpenRouter、xAI
- **macOS AI App / 进程** → 强制链式代理（跟随 `chainRegion` 的家宽IP出口）：Claude、ChatGPT、Perplexity、Cursor、Windsurf、Codeium
- **微软开发工具 / GitHub** → 链式代理（跟随 `chainRegion`）：GitHub、VS Code、Office 365
- **社交媒体与流媒体** → 锁区节点：YouTube、Netflix、X / Twitter、Facebook / Instagram、Telegram、Discord
- **域内 AI** → 直连：通义千问、智谱、ChatGLM、SiliconFlow 等网络边界较明确的域名
- **Tailscale 控制面 / 数据面** → 强制直连：`tailscale.com` / `tailscale.io`、`100.64.0.0/10`、`100.100.100.100/32`、`fd7a:115c:a1e0::/48`
- **出口测试** → 固定美国链式代理（美国静态家宽IP出口）：ping0.cc、ipinfo.io

> 微软域名只覆盖 Office / VS Code / 鉴权相关范围，不再把整棵 Microsoft / Live 家族全部纳入链式代理。
>
> 浏览器进程（Chrome / Safari / Arc / Edge）不会被加入进程规则，避免你在浏览器里打开普通网站时也被一并带进链式代理。

---

## 常见问题

**报错「缺少 config._miya」**
覆写顺序反了——`MiyaIP 凭证.js` 必须排在 `家宽IP-链式代理.js` 前面

**出口 IP 不是住宅 IP**
MiyaIP 凭证填错了，或者账户余额不足

**流媒体没解锁到目标地区**
检查 `mediaRegion` 参数，同时确认机场有对应地区的节点

**想手动指定跳板节点**
把 `manualNode` 设为节点全名，要和 Clash Party 里显示的一字不差

**美国 AI 现在走哪条链路？**
不再额外注入美国 AI 专用组。美国 AI 网站和 macOS AI App 会直接并入你原先的链式代理逻辑，也就是统一走 **`自选节点 + 家宽IP`**；最终出口跟随 `chainRegion` 和 `manualNode`。

**担心 Tailscale 远程浏览把家宽出口污染了**
当前脚本已额外把 Tailscale 控制面域名、Tailnet 常见地址段，以及 macOS 上常见的 Tailscale 进程名置顶直连。只要远程浏览器本身运行在远端主机、并由远端主机直接出网，通常不会把网页流量混进 MiyaIP 家宽出口。

---

## 兼容性

脚本跑在 Clash Party 的 JavaScriptCore 环境里，全部使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串等 ES6+ 特性。

当前进程分流规则明确按 **macOS / MacBook** 维护；Windows / Linux 的 AI App 进程名暂未纳入。
