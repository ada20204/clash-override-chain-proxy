// 主机文件样例：国内电脑（阿里云前置、家宽 IP 链式出 AI、国内直连），本机开 TUN。
module.exports = {
  location: "cn",
  subscriptions: [{ name: "机场", url: "secret:SUB_URL_MAIN" }],
  roles: {
    front: { name: "阿里云前置", secret: "ALIYUN_FRONT_URL", optional: true }, // 订阅节点先经阿里云
    home: { secret: "HOME_PROXY_URL", optional: true }
  },
  runtime: {
    mixedPort: 7890, bindAddress: "*", allowLan: true,
    controller: "127.0.0.1:9090", secret: "secret:CONTROLLER_SECRET_CN_DESKTOP",
    tun: true                                    // 由这台机器自己决定；渲染器只写进配置
  },
  selections: { "🤖 AI Agent": "🏠 家宽IP" }
};
