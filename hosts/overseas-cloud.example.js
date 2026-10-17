// 通用样例：境外环境；家宽用于 AI，国内出口用于国内业务，两者均可选。
// 复制为 hosts/<主机名>.js 使用；hosts/*.js（除 *.example.js）不进 git。
// 写 "secret:KEY" 的地方在渲染时从环境变量或 secrets.env 读取，主机文件本身不含秘密。
module.exports = {
  location: "overseas",                        // cn | overseas
  subscriptions: [
    { name: "机场", url: "secret:SUB_URL_MAIN" } // 可多个；第一个为基础，其余合并节点
  ],
  roles: {
    home: { secret: "HOME_PROXY_URL", optional: true },
    cnReturn: [{ name: "国内出口", secret: "CN_EXIT_URL", optional: true, dedicated: true }]
  },
  // 参数由完全覆写.js 解释；include 让国内专用节点也成为前置候选，默认仍选 DIRECT。
  options: { front: { include: ["国内出口"] } },
  runtime: {
    mixedPort: 7890, bindAddress: "127.0.0.1", allowLan: false,
    controller: "127.0.0.1:9090", secret: "secret:CONTROLLER_SECRET",
    tun: false
  }
};
