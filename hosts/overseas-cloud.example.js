// 主机文件样例：境外云电脑（美国家宽 IP 出 AI、阿里云回国、其余直连）。
// 复制为 hosts/<主机名>.js 使用；hosts/*.js（除 *.example.js）不进 git。
// 写 "secret:KEY" 的地方在渲染时从环境变量或 secrets.env 读取，主机文件本身不含秘密。
module.exports = {
  location: "overseas",                        // cn | overseas
  subscriptions: [
    { name: "机场", url: "secret:SUB_URL_MAIN", ua: "clash-verge/v1.7.7" }   // 可多个；第一个为基础，其余合并节点
  ],
  roles: {
    home: { secret: "HOME_PROXY_URL", optional: true },                 // → 🏠 家宽IP / 家宽IP链式（http 或 socks5 URI）
    cnReturn: [{ name: "阿里云回国", secret: "CN_EXIT_URL", optional: true }], // → 🇨🇳 国内 候选（overseas 默认选第一个）
    relay: { excludePorts: [80, 443], excludeKeywords: ["遊戲專用"], prefer: ["^🇺🇸 Lil 美国09"] } // 🔗 前置：80/443 端口节点需中转
  },
  options: {},                                   // 覆盖 完全覆写.js 的 USER_OPTIONS 任意键（不改共享脚本）
  runtime: {
    mixedPort: 7890, bindAddress: "127.0.0.1", allowLan: false,
    controller: "127.0.0.1:9090", secret: "secret:CONTROLLER_SECRET_OVERSEAS_CLOUD",
    tun: false
  },
  // 主机首次拉取（或旧选择失效）时套用的分组选择；数组表示按顺序取第一个存在的
  selections: {
    "🔗 前置": "⚡ 前置自动",
    "🏠 家宽IP": "家宽IP链式",
    "🤖 AI Agent": "🏠 家宽IP",
    "🇨🇳 国内": "阿里云回国",
    "🌐 国外": "DIRECT",
    "🐟 兜底": "🌐 国外"
  }
};
