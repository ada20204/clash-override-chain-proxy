![封面图](img/封面图.png)

# Clash 家宽 IP 链式代理覆写

这个仓库解决的是一个很具体的问题：当你想在固定地区稳定使用域外 AI 服务时，关键流量不该因为分流漏项、DNS 解析跑偏，或者规则静默回退，悄悄走到直连或错误出口。

这份覆写脚本主要做三件事：

- 把域外 AI 服务及其支撑平台，稳定绑定到当前 `chainRegion` 对应的家宽出口。
- 让 DNS、Sniffer、规则三层尽量使用同一套分类，减少“规则看着对，出口其实已经偏了”的情况。
- 给常见 AI 应用、CLI 和浏览器补上进程级分流，尽量少留漏网流量。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)
>
> 当前主脚本版本：`v8.11`

## 分流一览

- **域外 AI 与支撑平台**：强制命中当前 `chainRegion` 的家宽出口，包括 Claude、ChatGPT、Gemini、NotebookLM、Perplexity，以及 Google、Microsoft、GitHub 等登录、下载、开发相关平台。
- **按应用名强制分流的 AI 应用**：当前覆盖 `Claude`、`ChatGPT`、`Perplexity`、`Cursor`、`Antigravity.app`、`Quotio.app`，以及 `Claude Code`、`Codex`、`Gemini CLI`。
- **按应用名强制分流的浏览器**：默认进入普通链式代理；当前维护 `Dia`、`Atlas`、`Google Chrome`、`SunBrowser`，并显式覆盖 `Helper`、`Helper (Renderer)`、`Helper (GPU)`、`Helper (Plugin)`、`Helper (Alerts)` 进程名。
- **社交与流媒体**：走普通链式代理，跟随 `chainRegion`。
- **域内直连**：固定 `DIRECT`，包括域内 AI，以及腾讯、阿里、字节、WPS 的主力办公、沟通、协作域名。
- **域外应用直连**：固定 `DIRECT + 域外 DoH + skip-domain`，包括 `Typeless`、`Tailscale` 等。
- **网络地址直连**：固定 `DIRECT`。

可以把它理解成两条主线：一条是“该走家宽的流量不要掉出去”，另一条是“该直连的对象也别被错误拖进链式代理”。

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

在 Clash Party 里按这个顺序导入：

1. `MiyaIP 凭证.js`
2. `家宽IP-链式代理.js`

凭证脚本必须放在前面。主脚本运行时会直接读取 `config._miya`，顺序反了就会报错。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 5. 只改你需要的场景

大多数情况下，你只需要改一个参数：`chainRegion`

```javascript
var USER_OPTIONS = {
  chainRegion: "SG",
  enableBrowserProcessProxy: true,
  enableAiCliProcessProxy: true
};
```

- 想切地区：改 `chainRegion`，可选 `US / JP / HK / SG`。
- 不想让浏览器按应用名进入普通链式代理：关闭 `enableBrowserProcessProxy`。
- 不想让 AI CLI 按应用名强制分流：关闭 `enableAiCliProcessProxy`。

### 6. 启用

- 在 Clash Party 里开启这两个覆写
- 切回机场配置并启动代理
- 脚本会把当前 `chainRegion` 对应的 `-链式代理-跳板` 组自动放进 `节点选择`
- 例如 `chainRegion: "SG"` 时，你会看到 `🇸🇬|新加坡-链式代理-跳板`
- 确认使用规则模式和 TUN 模式
- 确认当前地区的家宽出口组已经出现

这里显示的地区名称由 `家宽IP-链式代理.js` 里的 `chainRegion` 决定，不是固定新加坡。比如改成 `US` 之后，自动放进 `节点选择` 的就会变成 `🇺🇸|美国-链式代理-跳板`。实际使用时，建议在 `节点选择` 里手动选中当前地区对应的这个跳板组。

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

## 本地校验

改完规则之后，先跑一遍本地校验：

```bash
node tests/validate.js
```

## 常见问题

- **报错“缺少 `config._miya`”**：先检查覆写导入顺序。`MiyaIP 凭证.js` 必须排在主脚本前面，而且文件里确实已经写入了凭证。
- **报错找不到可用地区跳板**：说明当前 `chainRegion` 没有匹配到可用地区节点。先确认订阅里确实有这个地区，再看节点命名能不能被脚本识别。
- **节点选择里没有看到 `-链式代理-跳板` 组**：先确认你用的是最新版本的 `家宽IP-链式代理.js`，然后重新加载覆写。脚本会把当前 `chainRegion` 对应的跳板组自动放进 `节点选择`。
- **出口不符合预期**：先看凭证和中转信息，再看当前地区的家宽出口组和跳板组有没有生成正确。大多数偏差都出在这两层。
- **为什么会有域外应用直连**：这类对象本来就不适合走家宽链式代理，但解析也不能随手落回域内，所以会固定成 `DIRECT + 域外 DoH + skip-domain`。

## 兼容性

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：当前只维护 macOS 常见命名
