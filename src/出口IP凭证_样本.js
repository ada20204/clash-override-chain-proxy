/**
 * 出口IP凭证注入脚本
 * 将家宽IP、公司节点和自定义出口的凭证注入到 config，供完全覆写脚本读取。
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

  // ── 自定义出口 / 公司节点（可选，数组）──────────────────────────────────
  // 注入后，所有节点会出现在「节点选择」和各功能组中，可按组单独选择出口。
  // 支持单个节点或多个节点。
  //
  // useFrontProxy:
  //   - 默认不写或 false：这个节点直接拨号
  //   - true：这个节点先走「前置代理.js」里配置的 config._frontProxy
  //   - 只有同时导入「前置代理.js」时才能设为 true
  //
  // interfaceName:
  //   - 可选：指定这个节点从哪个网卡发起连接
  //   - 如果公司代理在 Tailscale subnet 内，且虚拟网卡模式下全局开启
  //     「自动选择流量出口接口」会导致该节点超时，可以填 Tailscale 网卡名
  //   - macOS 可用 `route -n get 代理IP` 查看 interface，例如 utun4

  // config._customProxies = [
  //   {
  //     name: "公司代理",      // 节点显示名称，可自定义
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

  return config;
}
