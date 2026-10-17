# 文档索引

当前只维护 `src/完全覆写.js`。Clash Party 直接执行它，独立生成器准备输入后调用同一个 `main(config)`；两种运行方式不各自维护一套业务规则。

## 当前可用

| 文档 | 何时阅读 |
|---|---|
| [项目 README](../README.md) | 快速开始、策略组和链路概览 |
| [配置教程](./配置教程.md) | Clash Party 导入、可选凭证、前置、家宽和 Tailscale |
| [检测站维护](./配置教程.md#检测站如何统一维护) | 修改 NETWORK_PROBES，核对直连、前置、普通节点与 AI 出口 |
| [配置生成](./配置生成.md) | 无 Clash Party 环境下生成 YAML、配置 secrets 和本地验证 |
| [规则维护与调研记录](./规则维护与调研记录.md) | 更新社区来源、排查分流、查看增量调查证据 |

`出口IP凭证.js` 统一配置家宽、多个自定义出口（含前置候选）和自定义业务规则，各部分均可按需省略。普通节点默认跟随前置组，选 DIRECT 不加前置；专用节点用 `dedicated: true`，再通过业务组、`domesticExit` 或 `front.include` 明确授权。唯一配置样本是[出口IP凭证_样本.js](../src/出口IP凭证_样本.js)，无需单独的前置或规则组文件。

## 设计与历史

| 文档 | 状态 |
|---|---|
| [统一配置参考](./统一配置参考.md) | 重构提案。USER_OPTIONS.nodes/roles/defaults 尚未实现，不要当作可导入配置 |
| [节点清单设计](./节点清单设计.md) | 更早的设计归档，未启用标签选择器或自动链路推导 |
| [2026-10-17 合并与修复清单](./2026-10-17合并与修复清单.md) | 当日状态的历史记录；检测站用途等以当前教程及最新调查记录为准 |

历史 MiyaIP 脚本及其专用测试已经退役，需要查阅时使用 Git 历史。调查记录按日期追加，不用当前行为覆盖过去的结论。本仓只维护分流、配置生成和验证，不收录个人运维信息；历史记录也只保留与项目有关的技术结论。

## 维护检查

在仓库根目录执行：

```bash
npm ci
npm test
node --check src/完全覆写.js
node scripts/sync-community-rules.js --check
git diff --check
```

`npm test` 需要 Node.js 和 Python 3（可通过 `PYTHON` 指定解释器）。覆盖主覆写、社区规则、独立生成器、订阅缓存、辅助工具、ES5 语法、文档本地链接/章节锚点和教程参数默认值。文档检查不访问外部网站，不证明第三方服务仍在线；静态测试也不代替客户端重新加载后的实际连接验证。

## 回归保护与隔离校验

维护时先在公开入口复现失败，再修复同一问题，最后运行完整 `npm test`；不能用源码私有函数的返回值计算测试期望。

- `validate-regressions.js` 通过 `main(config)` 检查国内/海外、有无家宽、自定义业务组和进程开关；保护私网/Tailnet 优先级、业务网段例外、共享 CDN 边界、组依赖与字段透传。无关业务组不得改变已有规则相对顺序。
- `validate-headless.js` 通过节点 URI 解析和配置生成 CLI 检查协议字段最终落入 YAML，包含 VLESS、Trojan、Hysteria2 的 SNI 与网卡绑定。
- `validate-tools.js` 通过 CLI 修改临时凭证文件，检查注释、尾逗号、字段别名、重复地址和失败不写入；使用 loopback HTTP 服务验证 407、目标 404、5xx 和 HTTPS CONNECT 失败，不访问真实出口。
- `validate-kernel.js` 是独立可选检查，需要自备 Mihomo 和离线 `geosite.dat`、`geoip.dat`、`country.mmdb`、`ASN.mmdb`。它复制数据到临时目录，只执行配置检查，不启动监听、不加载真实凭证、不重载当前客户端。

```powershell
node tests/validate-kernel.js --mihomo "C:/path/to/mihomo.exe" --geodata-dir "C:/path/to/geodata"
```

静态首条匹配工具不模拟 GeoSite/GeoIP 数据和 UDP 能力跳过。`-t` 验证配置可被内核接受，也不等于业务请求实测；实际出口、DNS、UDP 回退仍需用户应用覆写后检查新连接。当前测试不宣称覆盖所有代码路径或全部客户端。
