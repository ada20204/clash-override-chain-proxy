![封面图](img/封面图.png)

# Clash 家宽 IP 链式代理覆写

这个仓库解决的问题很明确：当你需要在一个手动选择的地区稳定使用域外 AI 服务时，尽量不要因为分流遗漏、DNS 解析跑偏，或者规则静默回退，把关键流量送到直连或错误地区。

脚本的思路并不复杂。它会把域外 AI 服务及其支撑平台，稳定绑定到你当前选定地区的家宽出口；同时让 DNS、Sniffer、规则三层使用同一套分类，尽量减少“表面走代理，实际某一层已经偏掉”的情况。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)
>
> 当前主脚本版本：`v8.6`

## 分流一览

- **域外 AI 与支撑平台**：强制命中当前 `chainRegion` 的家宽出口，包括 Claude、ChatGPT、Gemini、NotebookLM、Perplexity，以及 Google、Microsoft、GitHub 等登录、下载、开发相关平台。
- **按应用名强制分流的 AI 应用**：当前覆盖 `Claude`、`ChatGPT`、`Perplexity`、`Cursor`，以及 `Claude Code`、`Codex`、`Antigravity`、`Gemini CLI`。
- **按应用名强制分流的浏览器**：可选进入普通链式代理，默认关闭；当前维护 `Comet`、`Dia`、`Atlas`、`Google Chrome` 及其明显 helper。
- **社交与流媒体**：走普通链式代理，跟随 `chainRegion`。
- **域内直连**：固定 `DIRECT`，包括域内 AI，以及腾讯、阿里、字节、WPS 的主力办公、沟通、协作域名。
- **域外应用直连**：固定 `DIRECT + 域外 DoH + skip-domain`，包括 `Typeless`、`Tailscale` 等。
- **网络地址直连**：固定 `DIRECT`。

## 如何使用

### 1. 准备代理和家宽资源

- 代理订阅：[办公娱乐好帮手](https://xn--9kq10e0y7h.site/index.html?register=twb6RIec)
- 家宽资源：[MiyaIP](https://www.miyaip.com/?invitecode=7670643)

### 2. 准备覆写脚本

你需要两份脚本：

1. [`MiyaIP 凭证.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81.js)
2. [`家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

其中，`MiyaIP 凭证.js` 负责往 `config._miya` 注入凭证。

### 3. 填好凭证脚本

新建 `MiyaIP 凭证.js`，填入真实信息：

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

在 Clash Party 里按下面的顺序导入：

1. `MiyaIP 凭证.js`
2. `家宽IP-链式代理.js`

凭证脚本必须排在前面，否则主脚本拿不到 `config._miya`。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 5. 只改你需要的场景

大多数情况下，你只需要改 `chainRegion`：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG",
  enableBrowserProcessProxy: false,
  enableAiCliProcessProxy: true
};
```

- 想切到别的地区：改 `chainRegion`，可选 `US / JP / HK / SG`。
- 想让浏览器也进入普通链式代理：打开 `enableBrowserProcessProxy`。
- 不想让 AI CLI 按应用名强制分流：关闭 `enableAiCliProcessProxy`。

### 6. 启用

- 在 Clash Party 里开启这两个覆写
- 切回机场配置并启动代理
- 确认使用规则模式和 TUN 模式
- 确认当前地区的家宽出口组已经出现

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

## 本地校验

改完规则之后，先跑一遍本地校验：

```bash
node tests/validate.js
```

## 常见问题

- **报错“缺少 `config._miya`”**：大多是覆写顺序不对。先确认 `MiyaIP 凭证.js` 在主脚本前面，而且文件里确实已经写入了凭证。
- **报错找不到可用地区跳板**：说明当前 `chainRegion` 没有匹配到可复用节点。先检查你选的地区在订阅里是否真的存在，再看节点命名是否能被脚本识别。
- **出口不符合预期**：先看凭证和中转信息，再看当前地区的家宽出口组有没有正确生成。大多数偏差都出在这两层。
- **为什么会有域外应用直连**：这类对象本来就不适合走家宽链式代理，但解析又不能随便落到域内，所以会固定成 `DIRECT + 域外 DoH + skip-domain`。

## 兼容性

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：当前只维护 macOS 常见命名
