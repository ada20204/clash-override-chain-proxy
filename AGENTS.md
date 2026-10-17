# 项目维护约定

本项目的推荐入口是 `src/完全覆写.js`，运行环境为 Clash Party / Mihomo 的 JavaScriptCore。主覆写脚本及其生成数据使用 ES5 语法；Node.js 维护工具可以使用现代语法和标准库。

## 更新或排查分流规则前

1. 先阅读 `docs/规则维护与调研记录.md`、`rules/community-sources.json`，并查看 `rules/community-update-history.json` 最近一次记录。
2. 检查 `git status -sb`，保留用户已有改动。以当前文件和规则快照为准，不依赖聊天历史中的旧分组名称或旧实现。
3. AI 按服务用途分类：Muse / Meta AI、Claude、Gemini、Copilot 等进入 `🤖 AI Agent`；Facebook / Instagram / WhatsApp / YouTube 的普通业务进入 `🌍 国际媒体`。
4. `src/完全覆写.js` 的 `BEGIN GENERATED COMMUNITY RULES` 至 `END GENERATED COMMUNITY RULES` 区段由工具生成，不能手工改。调整来源、排除策略或分类边界应修改 `rules/community-sources.json`，然后运行同步工具。
5. 社区条目必须保留 `DOMAIN` 与 `DOMAIN-SUFFIX` 的区别；不能将共享登录、CDN、整个云平台或整个厂商 ASN 归入 AI Agent。
6. 社区数据的路由、DNS、Sniffer 和 QUIC 应一起更新。原有本地补充和 Tailscale、内网、进程、家宽链路的特殊策略仍需保留。

## 增量更新与验证

```bash
node scripts/sync-community-rules.js --dry-run
node scripts/sync-community-rules.js --refresh
node scripts/sync-community-rules.js --check
node --check src/完全覆写.js
node tests/validate-community.js
node tests/validate-direct.js
node tests/validate.js
```

没有网络或仅修改本地分类策略时，使用 `--render` 从已提交快照重新生成，随后执行检查和测试。遇到未知格式、必需域名消失、目标冲突或分流边界失败，应先调查并增加对应回归测试；不要通过放宽全部匹配、清空规则或跳过验证来解决。

每次发现新服务、共享端点、误分类或上游格式变化，都在 `docs/规则维护与调研记录.md` 追加带日期的调查记录，保留证据链接、实际首条命中规则、修改理由和验证结果。同步工具自动记录上游提交、规则增删、实际生效分类增删和排除原因；继续增量维护，不要覆盖既有历史。

静态规则内嵌不等于已完成 Shadowrocket 全配置转换。自动测试验证生成配置，客户端生效还需要重载并查看实际连接。
