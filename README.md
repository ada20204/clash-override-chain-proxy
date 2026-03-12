![封面图](img/封面图.png)

# 用家宽 IP 访问 Claude / ChatGPT，告别风控 · Clash 链式代理覆写方法

借助机场 + 家宽 IP 的链式代理，把域外 AI 服务（Claude、ChatGPT、Gemini 等）的出口 IP 切换为家庭宽带住宅 IP，降低风控风险。社交媒体与流媒体（YouTube、Netflix、X 等）同样支持锁定到指定区域。

> 开源仓库：[github.com/andrew-zyf/clash-override-chain-proxy](https://github.com/andrew-zyf/clash-override-chain-proxy)

## 工作原理

```
请求 → Clash → 跳板节点（机场线路） → MiyaIP 家宽IP → 目标服务
                  ↑ dialer-proxy           ↑ HTTP 代理
```

基于 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核，运行于 [Clash Party](https://github.com/mihomo-party-org/clash-party)。

脚本在覆写阶段做四件事：

1. **注入家宽IP代理节点**——自选跳板（机场线路中转）和官方中转，两种模式可选
2. **覆写 DNS**——fake-ip 模式，域外 AI / 微软 / 流媒体走域外 DoH（Google、Cloudflare），Apple / 域内 AI 走域内 DoH（阿里、腾讯）
3. **覆写域名嗅探（Sniffer）**——TLS（443/8443）、HTTP（80/8080/8880）、QUIC（443）三协议嗅探，还原 fake-ip 下的真实域名，让规则精确命中
4. **注入路由规则（置顶）**——域外 AI、微软开发工具走链式代理；社交与流媒体锁区；域内 AI 直连

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

导入的节点就是链式代理的「跳板」。脚本会按地区（如新加坡、美国）自动筛选，不用手动挑。

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
  chainRegion: "SG", // 链式代理地区（AI 服务出口 IP 归属地）
  mediaRegion: "US", // 社交媒体与流媒体锁区地区
  manualNode: "", // 手动指定跳板节点名（留空 = 自动选最快的）
};
```

- **`chainRegion`**（可选值：`US` `JP` `HK` `SG`）——域外 AI 服务（Claude、ChatGPT 等）从哪个地区出去
- **`mediaRegion`**（可选值：`US` `JP` `HK` `SG`）——YouTube、Netflix 等锁定到哪个区域
- **`manualNode`**（节点名 / 留空）——指定跳板节点；留空则自动选该地区延迟最低的线路

### 5. 启用并验证

1. 两个覆写脚本的开关都打开
2. 切换到机场配置，启动代理
3. 进入「代理组」，确认生成了以下四个组：

![Clash Party 代理组页面](img/Clash%20Party%20代理组.png)

① **节点选择**——默认「自动选择」，优先分配延迟最低的节点（如 HK），用于常规域外流量
② **🇸🇬|新加坡线路-链式代理-跳板**——从新加坡节点中自动选延迟最低的一个，作为链式代理的第一跳
③ **🇸🇬|新加坡-链式代理-家宽IP出口**——静态家宽 IP 出口，链式代理的第二跳——域外 AI 服务的流量最终从这里出去
④ **🇺🇸|美国线路-流媒体**——从美区节点中自动选延迟最低的一个，社交媒体和流媒体锁定在这个区域

4. 验证是否生效：
   - [ping0.cc](https://ping0.cc/) 或 [ipinfo.io](https://ipinfo.io/)——应显示家宽住宅 IP，不是机房 IP
   - [claude.ai](https://claude.ai/)——正常访问，不触发风控

---

## 域名分流一览

- **域外 AI + 开发工具** → 链式代理（家宽IP出口）：Claude、ChatGPT、Gemini、Antigravity、Perplexity、OpenRouter、GitHub、VS Code、Office 365
- **社交媒体与流媒体** → 锁区节点：YouTube、Netflix、Google、X / Twitter、Facebook / Instagram、Telegram、Discord
- **域内 AI** → 直连：通义千问、Kimi、智谱、MiniMax 等
- **出口测试** → 链式代理（家宽IP出口）：ping0.cc、ipinfo.io

> 微软域名（Office 365、VS Code 等）走链式代理，是为了确保 Claude in Excel / PowerPoint 等插件在同一 IP 出口下正常工作。

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

---

## 兼容性

脚本跑在 Clash Party 的 JavaScriptCore 环境里，全部使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串等 ES6+ 特性。
