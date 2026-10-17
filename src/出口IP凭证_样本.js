/**
 * 出口IP凭证注入脚本
 * 将家宽IP和自定义出口的凭证注入到 config，供完全覆写脚本读取。
 * 所有配置项均为可选，按需取消注释即可。
 * 有订阅和无订阅模式都使用这个文件维护出口节点。
 *
 * 使用方式：
 *   1. 复制本文件并重命名为「出口IP凭证.js」
 *   2. 按需取消注释并填入实际地址和端口
 *   3. 在 Mihomo Party 覆写列表中启用，且排序必须在「完全覆写.js」之前
 */
function main(config) {

  // ── 家宽IP（可选）─────────────────────────────────────────────────────────
  // 配置后，脚本会注入「家宽IP」真直连节点。
  // 如果订阅或自定义出口可作为跳板，还会额外生成「家宽IP链式」节点，
  // 并创建「🏠 家宽IP」组供 AI Agent 选择。
  // 不配置则脚本仅做分流覆写，不注入家宽链路。

  // config._homeProxy = {
  //   type: "http",   // http 或 socks5
  //   server: "",     // 家宽 IP 地址（公网 IP 或内网 IP）
  //   port: 1080,     // 代理端口
  //   // 如需认证，取消注释以下两行：
  //   // username: "",
  //   // password: ""
  // };

  // ── 普通自定义出口（可选，数组）──────────────────────────────────────────
  // 注入后，所有节点会出现在「节点选择」和各功能组中，可按组单独选择出口。
  // 只允许固定公司域名或网段使用的代理不要放在这里，见下方 dedicated 样本。
  // 支持单个节点或多个节点。
  //
  // useFrontProxy:
  //   - 默认不写或 false：这个节点直接拨号
  //   - true：这个节点先走「前置代理.js」里配置的 config._frontProxy
  //   - 只有同时导入「前置代理.js」时才能设为 true
  //
  // interfaceName:
  //   - 可选：指定这个节点从哪个网卡发起连接
  //   - 如果普通出口在 Tailscale subnet 内，且虚拟网卡模式下全局开启
  //     「自动选择流量出口接口」会导致该节点超时，可以填 Tailscale 网卡名
  //   - macOS 可用 `route -n get 代理IP` 查看 interface，例如 utun4

  // config._customProxies = [
  //   {
  //     name: "普通备用出口",  // 节点显示名称，可自定义
  //     type: "http",          // http 或 socks5
  //     server: "",            // 代理服务器地址（IP 或域名）
  //     port: 3128,            // 代理端口
  //     useFrontProxy: false,  // 默认直连拨号，不经过前置代理
  //     interfaceName: ""      // 可选：例如 "utun4"，仅需给 Tailscale subnet 节点配置
  //     // 如需认证，取消注释以下两行：
  //     // username: "",
  //     // password: ""
  //   }
  //   // 如需添加更多节点，继续在此追加：
  //   // ,{
  //   //   name: "需要前置代理的上游节点",
  //   //   type: "socks5",
  //   //   server: "",
  //   //   port: 1080,
  //   //   useFrontProxy: true
  //   // }
  // ];

  // ── 境外回国出口（可选，配合 USER_OPTIONS.location = "overseas"）──────────
  // 本机在境外时，国内流量走「🇨🇳 回国」组。把国内 VPS 写成 dedicated 节点，
  // 再在完全覆写.js 的 USER_OPTIONS.domesticExit 填入同名，它就只会出现在回国组。

  // config._customProxies = [
  //   {
  //     name: "阿里云回国",
  //     scope: "dedicated",
  //     type: "socks5",
  //     server: "",
  //     port: 1080,
  //     udp: true
  //   }
  // ];

  // ── 公司内网专用代理（可选）──────────────────────────────────────────────
  // dedicated 节点不会进入节点选择、通用出海、AI、媒体、GitHub 或家宽跳板。
  // 它必须由 _customRuleGroups.proxies 显式引用，否则主脚本会拒绝生成配置。

  // config._customProxies = [
  //   {
  //     name: "公司代理",
  //     scope: "dedicated",
  //     type: "http",
  //     server: "",
  //     port: 3128,
  //     interfaceName: ""
  //   }
  // ];
  //
  // config._customRuleGroups = [
  //   {
  //     name: "公司内网",
  //     proxies: ["公司代理"],
  //     rules: [
  //       "DOMAIN-SUFFIX,example.corp",
  //       { type: "IP-CIDR", value: "10.0.0.0/8", option: "no-resolve" }
  //     ]
  //   }
  // ];

  return config;
}
