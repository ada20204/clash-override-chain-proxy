// 通用样例：国内电脑；订阅必填，家宽和前置候选可选。
module.exports = {
  location: "cn",
  subscriptions: [{ name: "机场", url: "secret:SUB_URL_MAIN" }],
  roles: {
    home: { secret: "HOME_PROXY_URL", optional: true }
  },
  customProxies: [
    { name: "前置出口", secret: "FRONT_PROXY_URL", optional: true, dedicated: true }
  ],
  options: { front: { include: ["前置出口"] } }, // 只追加候选，默认仍选 DIRECT
  runtime: {
    mixedPort: 7890, bindAddress: "127.0.0.1", allowLan: false,
    controller: "127.0.0.1:9090", secret: "secret:CONTROLLER_SECRET",
    tun: true                                    // 由这台机器自己决定；渲染器只写进配置
  }
};
