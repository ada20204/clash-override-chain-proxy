![封面图](img/封面图.png)

# 解决 Clash 分流失控：让 ChatGPT / Claude 稳定走指定家宽出口

很多人用 `Clash` 跑 `ChatGPT` / `Claude` / `Gemini` 时，真正烦人的不是“能不能连上”，而是下面这些问题会不会失控：

- 有些请求莫名其妙走直连
- `DNS` 解析跑到了错误地区
- 规则看起来是对的，实际出口却不对
- 应用换了别的进程名，结果分流静默失效

结果就是登录异常、风控、速度波动，甚至直接不可用。

这个仓库就是为了解决这个问题：让关键流量始终走你指定的家宽出口，不再“偶尔对、偶尔错”。

如果你遇到的正是“表面能用，但出口经常不对”，这份脚本针对的就是这个场景。

> 当前主脚本版本：`v8.12`

## 一句话理解

- `AI / 开发相关流量` → `chainRegion`
- `社交 / 流媒体` → `mediaRegion`
- `域内 / 特定应用 / 特定网络地址` → `DIRECT`

## 这份脚本主要做四件事

- 把域外 `AI` 服务、支撑平台，以及受管浏览器和 `AI CLI` 进程，稳定绑定到 `chainRegion` 对应的链式代理出口。
- 把社交和流媒体域名单独绑定到 `mediaRegion` 对应的普通地区组，不再拖进家宽链路。
- 让 `DNS`、`Sniffer` 和规则尽量使用同一套分类，减少“规则看着对，实际出口已经偏了”的情况。
- 自动生成并维护所需的代理节点、代理组和规则，避免手工拼装越改越乱。

## 你会得到什么

- 默认情况下，`AI`、受管浏览器和 `AI CLI` 的出口收口到 `chainRegion`，更容易稳定控制地区
- 媒体流量单独放到 `mediaRegion`，不用再和家宽链路绑死
- 如果订阅里已有 `节点选择` 组，脚本会把生成的 `-链式代理-跳板` 组和 `-媒体` 组同步进去
- 缺少地区节点、规则目标不成立时直接报错，而不是静默回退
- 仓库自带 `validate.js`，改动后可以快速做本地校验

## 分流一览

这份配置最终只把流量送到三类目标：`chainRegion`、`mediaRegion`、`DIRECT`。

### 1. `chainRegion`

最需要收紧的一组。目标很明确：让关键流量稳定命中指定家宽出口。

- **域外 `AI` 与支撑平台**：强制命中当前 `chainRegion` 对应的链式代理出口。当前覆盖 `Claude`、`ChatGPT`、`Gemini`、`NotebookLM`、`Perplexity`，以及 `Google`、`Microsoft`、`GitHub` 等登录、下载、开发相关平台。
- **按进程名强制分流的 `AI` 应用**：当前维护 `Claude`、`ChatGPT`、`Perplexity`、`Cursor`，并覆盖已验证的相关 `Helper` / 精确进程名。
- **按应用名强制分流的 `AI CLI`**：当前覆盖已验证的 `Claude Code`、`Claude Code URL Handler`、`Claude Code` 的 Unix 可执行名 `claude`，以及 `Codex`、`Gemini CLI`。
- **按应用名强制分流的浏览器**：当前覆盖 `Dia`、`Atlas`、`Google Chrome`、`SunBrowser`，并显式覆盖 `Helper`、`Helper (Renderer)`、`Helper (GPU)`、`Helper (Plugin)`、`Helper (Alerts)`。

### 2. `mediaRegion`

媒体单独选区，和 `chainRegion` 脱钩。

- **社交与流媒体**：当前覆盖 `YouTube`、`Netflix`、`X` / `Twitter`、`Facebook`、`Instagram`、`Telegram`、`Discord` 相关域名，走 `mediaRegion` 对应的普通地区组，不进入家宽链路。

单独切 `mediaRegion` 时，只会影响媒体相关域名，不会改动 `AI`、`AI CLI` 和受管浏览器的出口。

### 3. `DIRECT`

必须稳定直连的一组。

- **域内直连**：固定 `DIRECT`，包括域内 `AI`，以及腾讯、阿里、字节、`WPS` 的主力办公、沟通、协作域名。
- **域外应用直连**：固定 `DIRECT + 域外 DoH + skip-domain`，当前包括 `Typeless`、`Tailscale` 等。
- **网络地址直连**：固定 `DIRECT`。

## 快速开始

### 1. 准备代理和家宽资源（可选）

你需要两类资源：

- 一个代理订阅
- 一个家宽 `IP` 服务，用于链式出口

如果你已经有自己的资源，直接替换即可。下面只是示例：

- 代理订阅示例：[办公娱乐好帮手](https://xn--9kq10e0y7h.site/index.html?register=twb6RIec)
- 家宽资源示例：[MiyaIP](https://www.miyaip.com/?invitecode=7670643)

### 2. 准备两份覆写脚本

你需要两份脚本：

1. [`MiyaIP 凭证.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81.js)
2. [`家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

其中，`MiyaIP 凭证.js` 负责向 `config._miya` 注入凭证；`家宽IP-链式代理.js` 负责生成链式节点、媒体组选区和分流规则。

### 3. 填好凭证脚本

新建 `MiyaIP 凭证.js`，把真实信息填进去：

```javascript
function main(config) {
  config._miya = {
    username: "你的用户名",
    password: "你的密码",
    relay: {
      server: "12.34.56.78",
      port: 8022
    },
    transit: {
      server: "transit.example.com",
      port: 8001
    }
  };
  return config;
}
```

### 4. 按顺序导入覆写

在 `Clash Party` 里按这个顺序导入：

1. `MiyaIP 凭证.js`
2. `家宽IP-链式代理.js`

顺序不能反。主脚本运行时会直接读取 `config._miya`，凭证脚本如果放在后面，脚本会直接报错。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 5. 按场景调整参数

大多数情况下，你只需要改下面四个入口参数：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG",
  mediaRegion: "US",
  enableChainRegionBrowserProcessProxy: true,
  enableChainRegionAiCliProcessProxy: true
};
```

常见使用方式：

- 想让 `ChatGPT` 看起来在美国 → `chainRegion: "US"`
- 想让 `Claude` 看起来在日本 → `chainRegion: "JP"`
- 想刷 `Netflix` 美区 → `mediaRegion: "US"`
- 想让 `AI` 用日本、媒体用美国 → `chainRegion: "JP"`，`mediaRegion: "US"`
- 不想让受管浏览器按应用名强制走 `chainRegion` → `enableChainRegionBrowserProcessProxy: false`
- 不想让 `AI CLI` 按应用名强制走 `chainRegion` → `enableChainRegionAiCliProcessProxy: false`

脚本仍兼容旧参数名 `enableBrowserProcessProxy` 和 `enableAiCliProcessProxy`。新配置建议直接使用带 `ChainRegion` 的新命名，含义更直观。

### 6. 启用并确认结果

- 在 `Clash Party` 里启用这两个覆写
- 切回机场配置并启动代理
- 确认使用规则模式和 `TUN` 模式
- 如果订阅里已有 `节点选择` 组，脚本会把当前 `chainRegion` 对应的 `-链式代理-跳板` 组，以及当前 `mediaRegion` 对应的 `-媒体` 组自动放进去
- 默认配置下，如果订阅里已有 `节点选择` 组，你会看到 `🇸🇬|新加坡-链式代理-跳板` 和 `🇺🇸|美国-媒体`
- 同时还会生成当前 `chainRegion` 对应的 `-链式代理-家宽IP出口` 组

这里显示的地区名称由 `chainRegion` 和 `mediaRegion` 决定，不是写死的。比如把 `chainRegion` 改成 `HK`、`mediaRegion` 保持 `US`，那么 `节点选择` 里会同时出现 `🇭🇰|香港-链式代理-跳板` 和 `🇺🇸|美国-媒体`。

日常使用时，建议在 `节点选择` 里手动选中当前地区对应的链式跳板组；媒体流量会由规则直接命中对应的 `-媒体` 组。

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

## 适合谁用

- 经常使用 `ChatGPT`、`Claude`、`Gemini` 等域外 `AI` 服务的用户
- 对代理稳定性要求较高，不接受“偶尔能用、偶尔跑偏”的用户
- 已经在使用 `Clash` 或 `Clash Party` 的用户
- 能接受简单配置，但不想手工维护大量规则的用户

## 不适合谁用

- 只想开全局代理，不关心具体出口地区的用户
- 没有家宽 `IP` 资源，也不打算做链式代理的用户
- 不使用 `Clash Party`，或者不准备维护脚本覆写的用户

## 本地校验

改完规则之后，先跑一遍本地校验：

```bash
node tests/validate.js
```

## 常见问题

- **报错“缺少 `config._miya`”**：先检查覆写导入顺序。`MiyaIP 凭证.js` 必须排在主脚本前面，而且文件里确实已经写入了凭证。
- **报错找不到可用地区跳板**：说明当前 `chainRegion` 没有匹配到可用地区节点。先确认订阅里确实有这个地区，再看节点命名能不能被脚本识别。
- **报错找不到可用媒体节点**：说明当前 `mediaRegion` 没有匹配到可用地区节点。先确认订阅里确实有这个地区，再看节点命名能不能被脚本识别。
- **节点选择里没有看到 `-链式代理-跳板` 或 `-媒体` 组**：先确认你用的是最新版本的 `家宽IP-链式代理.js`，然后重新加载覆写。脚本只会把当前 `chainRegion` 对应的跳板组和当前 `mediaRegion` 对应的媒体组同步到已存在的 `节点选择` 组；如果你的订阅没有这个组，脚本不会额外新建。
- **出口不符合预期**：先看凭证和中转信息，再看当前地区的家宽出口组、跳板组和媒体组有没有生成正确。偏差大多出在这几层。
- **为什么还保留部分域外应用直连**：这类对象本来就不适合走家宽链式代理，但解析也不能随手落回域内，所以会固定成 `DIRECT + 域外 DoH + skip-domain`。
- **为什么 `Claude Code` 要同时维护多个进程名**：本地实测里，`/Users/az/.local/bin/claude` 最终指向同一份 `Claude Code` 二进制；`Claude Code URL Handler.app` 只是另一层启动入口，负责声明 `claude-cli:` URL scheme。`LaunchServices` 会把它注册成 `Claude Code URL Handler`，而高频轮询运行态时稳定可见的 Unix 进程名仍是 `claude`，深链触发时还能短暂看到版本化二进制路径本身。脚本因此同时保留 `Claude Code`、`Claude Code URL Handler` 和 `claude` 三种入口，而不额外维护没有运行态证据的别名。

## 兼容性

- 运行环境：`Clash Party` 的 `JavaScriptCore`
- 语法范围：`ES5`
- 进程分流覆盖：当前只维护 `macOS` 常见命名
