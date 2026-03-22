![封面图](img/封面图.png)

# Clash 家宽 IP 链式代理覆写

这个仓库用来降低异常画像和错误分流导致的风险。

它的核心做法是：把你手动选择地区的域外 AI 服务流量，稳定送到同一个家宽出口；同时把 DNS、Sniffer、规则三层收成同一套分类，避免因为规则遗漏、解析跑偏或错误回退，把关键流量送到直连或错误地区。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)
>
> 当前主脚本版本：`v8.6`
>
> 当前默认实现依赖 `MiyaIP 凭证.js`

## 分流一览

- **域外 AI 与支撑平台**：强制命中当前 `chainRegion` 的家宽出口。包括 Claude、ChatGPT、Sora、Gemini、NotebookLM、Perplexity、OpenRouter、Grok / xAI，以及 Google、Microsoft、GitHub 等登录、下载、开发相关平台
- **按应用名强制分流的 AI 应用**：当前覆盖 `Claude`、`ChatGPT`、`Perplexity`、`Cursor`，以及 `claude`、`gemini`、`codex`
- **按应用名强制分流的浏览器**：可选进入普通链式代理，默认关闭；当前只维护 `Comet`、`Dia`、`Atlas`、`Google Chrome` 及其明显 helper
- **社交与流媒体**：走普通链式代理，跟随 `chainRegion`
- **域内直连**：固定 `DIRECT`，包括域内 AI，以及腾讯、阿里、字节、WPS 的主力办公 / 沟通 / 协作域名
- **域外应用直连**：固定 `DIRECT + 域外 DoH + skip-domain`
- **网络地址直连**：固定 `DIRECT`

## 如何使用

### 1. 准备覆写脚本

需要两份脚本：

1. `MiyaIP 凭证.js`
2. [`src/家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

当前默认实现依赖 `MiyaIP 凭证.js` 往 `config._miya` 注入凭证。

可以从样本开始：

- [`src/MiyaIP 凭证_样本.js`](src/MiyaIP%20%E5%87%AD%E8%AF%81_%E6%A0%B7%E6%9C%AC.js)

### 2. 填好凭证脚本

把样本复制成 `MiyaIP 凭证.js`，填入真实信息：

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

### 3. 按顺序导入覆写

在 Clash Party 里按这个顺序导入：

1. `MiyaIP 凭证.js`
2. [`家宽IP-链式代理.js`](src/%E5%AE%B6%E5%AE%BDIP-%E9%93%BE%E5%BC%8F%E4%BB%A3%E7%90%86.js)

凭证脚本必须排在前面，否则主脚本读不到 `config._miya`。

![Clash Party 覆写页面](img/Clash%20Party%20覆写.png)

### 4. 只改你需要的场景

最常见的是只改 `chainRegion`：

```javascript
var USER_OPTIONS = {
  chainRegion: "SG",
  manualNode: "",
  enableBrowserProcessProxy: false,
  enableAiCliProcessProxy: true
};
```

- 想切到别的地区：改 `chainRegion`，可选 `US / JP / HK / SG`
- 自动找不到可用跳板：填 `manualNode`
- 想让浏览器也进入普通链式代理：打开 `enableBrowserProcessProxy`
- 不想让 AI CLI 按应用名强制分流：关闭 `enableAiCliProcessProxy`

### 5. 启用

- 在 Clash Party 里开启这两个覆写
- 切回机场配置并启动代理
- 确认使用规则模式和 TUN 模式
- 确认当前地区的家宽出口组已经出现

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

## 本地校验

```bash
node tests/validate.js
```

## 常见问题

- **报错“缺少 `config._miya`”**：凭证脚本顺序不对，`MiyaIP 凭证.js` 必须排在主脚本前面
- **报错找不到可用地区跳板**：当前 `chainRegion` 没有可复用节点，改 `chainRegion` 或填写 `manualNode`
- **出口不符合预期**：先检查凭证、中转信息和当前地区代理组是否正确生成
- **为什么会有域外应用直连**：这类对象需要保持 `DIRECT`，但解析仍要固定走域外 DoH

## 兼容性

- 运行环境：Clash Party 的 JavaScriptCore
- 语法范围：ES5
- 进程分流覆盖：当前只维护 macOS 常见命名
