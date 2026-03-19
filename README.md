![封面图](img/封面图.png)

# 用家宽 IP 访问 Claude / ChatGPT，告别风控 · Clash 链式代理覆写方法

借助机场 + 家宽 IP 的链式代理，把域外 AI 服务（Claude、ChatGPT、Gemini 等）的出口 IP 切换为家庭宽带住宅 IP，降低风控风险。社交媒体与流媒体（YouTube、Netflix、X 等）也可统一并入同一条链式代理出口。

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
2. **覆写 DNS**——fake-ip 模式，AI 服务 / 基础平台 / 社交与流媒体按同一套分类走域外 DoH（Google、Cloudflare），Apple / 域内 AI 走域内 DoH（阿里、腾讯）
3. **覆写域名嗅探（Sniffer）**——TLS（443/8443）、HTTP（80/8080/8880）、QUIC（443）三协议嗅探，并与 DNS / 规则分类保持一致；直连保留项（如 Tailscale、Apple、本地域名）继续跳过嗅探
4. **统一注入链式代理规则**——AI 服务、浏览器、基础平台、社交与流媒体，以及指定的 macOS App / 进程，统一走现有链式代理逻辑，也就是「自选节点 + 自选家庭宽带静态IP」
5. **统一去重并消除冲突**——同一目标的域名 / 进程规则合并成单一链式代理规则集，避免重复注入和分类间的优先级冲突
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

打开 `家宽IP-链式代理.js`，顶部现在有两个参数可以改：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG", // 链式代理地区（自选节点 + 家宽IP 出口）
  manualNode: "", // 手动指定跳板节点名（留空 = 自动选最快的）
};
```

- **`chainRegion`**（可选值：`US` `JP` `HK` `SG`）——链式代理流量从哪个地区出去；AI 服务、浏览器、基础平台、社交与流媒体都统一跟随这个参数
- **`manualNode`**（节点名 / 留空）——指定跳板节点；留空则自动选该地区延迟最低的线路

### 5. 启用并验证

1. 两个覆写脚本的开关都打开
2. 切换到机场配置，启动代理
3. 进入「代理组」，确认以下角色已经到位：

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

① **节点选择**——默认「自动选择」，优先分配延迟最低的节点（如 HK），用于常规域外流量
② **新加坡跳板组**——如果订阅里已有可复用的新加坡地区代理组，脚本会直接复用；否则会生成 **`🇸🇬|新加坡线路-链式代理-跳板`**
③ **🇸🇬|新加坡-链式代理-家宽IP出口**——统一链式代理出口；AI 服务、浏览器、基础平台、社交与流媒体都会通过这里出网

4. 验证是否生效：
   - [ping0.cc](https://ping0.cc/) 或 [ipinfo.io](https://ipinfo.io/)——应显示当前链式代理对应的住宅 IP，不是机房 IP
   - [claude.ai](https://claude.ai/) / ChatGPT macOS App——应命中你当前 `chainRegion` 对应的 **`*-链式代理-家宽IP出口`**

---

## 分流一览

- **AI 服务** → 链式代理（跟随 `chainRegion` 的家宽IP出口）：Claude、ChatGPT、Gemini、Antigravity、Perplexity、OpenRouter、xAI，以及 Claude / ChatGPT / Perplexity / Cursor / Windsurf / Codeium 等 macOS AI App
- **浏览器** → 链式代理（跟随 `chainRegion` 的家宽IP出口）：Arc、Comet、Dia、ChatGPT Atlas、Google Chrome、Microsoft Edge 及其 helper 进程
- **基础平台** → 链式代理（跟随 `chainRegion`）：`google.com`、`googleapis.com`、`gstatic.com`、`microsoft.com`、`live.com`、`office.com`、`sharepoint.com`、GitHub，以及 Google Drive、Teams、Outlook、Word、Excel、PowerPoint、OneDrive、VS Code
- **社交与流媒体** → 链式代理（跟随 `chainRegion`）：YouTube、Netflix、X / Twitter、Facebook / Instagram、Telegram、Discord
- **直连保留项** → 直连：域内 AI、`tailscale.com` / `tailscale.io`、`100.64.0.0/10`、`100.100.100.100/32`、`fd7a:115c:a1e0::/48`
- **出口测试** → 链式代理（跟随 `chainRegion` 的家宽IP出口）：ping0.cc、ipinfo.io

> 浏览器单独成类，是为了明确暴露它们的副作用：你在这些浏览器里访问的普通网站，默认也会跟着走链式代理。
>
> `mediaRegion` 已并入链式代理，YouTube / Netflix / X / Telegram / Discord 等不再单独锁区，统一跟随 `chainRegion` 出口。
>
> 当前实现会先把所有指向同一链式代理组的规则统一去重，再整体置顶；DNS `nameserver-policy`、`fallback-filter` 和 Sniffer 的 `force-domain` / `skip-domain` 也与同一套分类同步。

---

## 常见问题

**报错「缺少 config._miya」**
覆写顺序反了——`MiyaIP 凭证.js` 必须排在 `家宽IP-链式代理.js` 前面

**出口 IP 不是住宅 IP**
MiyaIP 凭证填错了，或者账户余额不足

**流媒体为什么不再单独锁区？**
当前脚本已把 `mediaRegion` 合并到链式代理逻辑里。YouTube / Netflix / X 等媒体域名现在统一走 `chainRegion` 对应的家宽IP出口，不再单独维护独立媒体地区组。

**想手动指定跳板节点**
把 `manualNode` 设为节点全名，要和 Clash Party 里显示的一字不差

**链式代理对象现在怎么分类？**
当前按用途分类为五类：`AI 服务`、`浏览器`、`基础平台`、`社交与流媒体`、`直连保留项`。分类只影响可读性和维护方式，不改变它们当前是否走链式代理的实际行为。

**担心 Tailscale 远程浏览把家宽出口污染了**
当前脚本已额外把 Tailscale 控制面域名、Tailnet 常见地址段，以及 macOS 上常见的 Tailscale 进程名置顶直连。只要远程浏览器本身运行在远端主机、并由远端主机直接出网，通常不会把网页流量混进 MiyaIP 家宽出口。

---

## 兼容性

脚本跑在 Clash Party 的 JavaScriptCore 环境里，全部使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串等 ES6+ 特性。

当前进程分流规则明确按 **macOS / MacBook** 维护；Windows / Linux 的 AI App 进程名暂未纳入。
