/**
 * 自定义规则组样本
 *
 * 用途：
 * - 给固定域名 / 网段单独创建一个策略组。
 * - 该组不会默认进入「节点选择」，只被 rules 命中时使用。
 * - 适合把少量业务域名转发给指定 SOCKS/HTTP 节点，或在特定机器上直连。
 */

function main(config) {
  config._customRuleGroups = [
    {
      name: "自定义业务",

      // 可选：为这个规则组注入一个专用节点。
      // 如果目标节点已经由其他覆写或订阅提供，也可以删掉 proxy，改用 proxies: ["已有节点名"]。
      proxy: {
        name: "自定义业务节点",
        type: "socks5",
        server: "127.0.0.1",
        port: 10880
      },

      // 可选：覆盖这个分组的测速地址；不写时使用 USER_OPTIONS.urlTestProbeUrl。
      testUrl: "http://connect.rom.miui.com/generate_204",

      // 可选：显式指定组内成员；不写时会使用上面的 proxy，且自动追加 DIRECT 作为备选。
      // proxies: ["自定义业务节点", "DIRECT"],

      // 规则支持两种写法：
      // 1. "TYPE,value"
      // 2. { type: "TYPE", value: "value", option: "no-resolve" }
      rules: [
        "DOMAIN,service.example.test",
        "DOMAIN-SUFFIX,internal.example.test",
        { type: "IP-CIDR", value: "10.0.0.0/8", option: "no-resolve" }
      ]
    },

    {
      name: "本机直连业务",
      proxies: ["DIRECT"],
      rules: [
        "DOMAIN-SUFFIX,local.example.test"
      ]
    }
  ];

  return config;
}
