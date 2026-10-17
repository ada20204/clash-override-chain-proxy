/**
 * 出口IP凭证注入脚本
 * 统一维护家宽IP、自定义出口（含前置候选）和自定义业务规则。
 * 所有配置项均为可选，按需取消注释即可。
 * 有订阅和无订阅模式都使用这个文件维护出口节点。
 *
 * 使用方式：
 *   1. 复制本文件并重命名为「出口IP凭证.js」
 *   2. 按需取消注释并填入实际地址和端口
 *   3. 在 Mihomo Party 覆写列表中启用，且排序必须在「完全覆写.js」之前
 * 无需再导入独立的前置代理或自定义规则组样本。
 * 将旧文件内容迁入同一个 main(config) 时，合并数组，不要重复赋值覆盖；迁移后停用旧文件。
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
  // 注入后，普通节点会出现在「节点选择」和各功能组中，可按组单独选择出口。
  // 普通、国内和 Tailscale 子网节点都放在这一个数组里；只供指定用途的节点设置 dedicated: true。
  // 支持单个节点或多个节点；所有自定义节点放在同一个数组中，不要重复赋值覆盖。
  // 启用数组的开始和结束行，只取消需要的节点对象的注释，并填写该节点的地址。
  //
  // dedicated:
  //   - 默认不写或 false：普通节点，进入通用候选
  //   - true：专用节点，只供明确引用的业务或前置使用
  //   - 兼容旧 scope: "ordinary" / "dedicated"；同时填写时必须一致
  //
  // 前置只在「🔗 前置」组里切换：DIRECT 不加前置，选节点则增加一跳。
  // 普通节点自动跟随，并生成仅供前置组使用的「⤴ 原名」直连副本。
  // 不再需要填写 useFrontProxy / allowAsFront；旧字段仍兼容。
  // 特殊情况可用 via: "DIRECT" 固定直连，或 via: "节点名" 固定上级。
  // 仅供前置使用：节点设 dedicated: true，在主脚本 USER_OPTIONS.front.include 填它的名称。
  // 兼容旧配置：已有 config._frontProxy 可原样移入此 main(config)，仍会默认选中；不要与数组重复定义同名节点。
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
  //     dedicated: false,      // 普通节点；可省略
  //     interfaceName: "",     // 可选：Windows 可填 "Tailscale"，macOS 按实际网卡填写
  //     // 如需认证，取消注释以下两行：
  //     // username: "",
  //     // password: ""
  //   },

  // ── 境外回国出口（可选，配合 USER_OPTIONS.location = "overseas"）──────────
  // 本机在境外时，国内流量走「🇨🇳 国内」组。把国内 VPS 写成 dedicated 节点，
  // 再在完全覆写.js 的 USER_OPTIONS.domesticExit 填入同名。
  // 同一节点也能作为前置：在 USER_OPTIONS.front.include 填 ["阿里云回国"]。
  // 前置默认仍为 DIRECT，需手动选择；不必再通过 _frontProxy 重复填写节点凭证。

  //   {
  //     name: "阿里云回国",
  //     dedicated: true,
  //     type: "socks5",
  //     server: "",
  //     port: 1080,
  //     udp: true
  //   },

  // ── Tailscale 子网内的代理节点（可选）─────────────────────────────────────
  // 路径：本机 → Tailscale 子网路由器 → 子网内 HTTP/SOCKS5 代理 → 目标服务。
  // server 填代理服务器的子网 IP，不是子网路由器的 Tailscale IP（除非代理就在该地址监听）。
  // 本机须先能通过 Tailscale 访问该 IP/端口；此文件不会发布子网路由或修改访问权限。
  // via: "DIRECT" 表示通过本机路由连接代理，不跟随「🔗 前置」，不代表绕过 Tailscale。
  // interfaceName 按实际网卡填写；Windows 常见为 "Tailscale"，不要照搬其他系统的网卡名。
  // 节点位于子网内不等于只能代理内网业务，也不意味着整个子网都要经过该代理。
  // dedicated 节点不会自动进入节点选择、国外、AI、媒体、GitHub 或家宽跳板。
  // 此处保留专用示例，由下面 _customRuleGroups.proxies 引用；也可由 domesticExit 或 front.include 显式使用。
  // 若要作为普通可选出口，改为 dedicated: false；保留 via: "DIRECT"，不需要额外业务规则组。

  //   {
  //     name: "Tailscale子网代理",
  //     dedicated: true,
  //     type: "http",
  //     server: "",           // 例如 192.168.88.10，替换为实际代理服务器 IP
  //     port: 3128,
  //     via: "DIRECT",
  //     interfaceName: ""
  //   }
  // ];

  // ── 自定义业务规则（可选，数组）──────────────────────────────────────────
  // 引用上面已定义的节点或订阅节点，不重复保存凭证；也可仅使用 DIRECT。
  // 删除子网代理节点时，也应删除引用它的规则组。只有直连规则时不需要自定义代理。
  // 规则写法："TYPE,value"，或 { type: "TYPE", value: "value", option: "no-resolve" }。
  // 这些业务组只供规则使用，不自动加入节点选择。
  // 以下域名和 198.51.100.0/24 均为文档占位目标，须按实际业务替换，不是代理所在子网。
  // config._customRuleGroups = [
  //   {
  //     name: "指定业务",
  //     proxies: ["Tailscale子网代理"],
  //     // 可选：仅覆盖这个组的测速地址；省略时按主脚本及 location 默认值。
  //     // testUrl: "http://connect.rom.miui.com/generate_204",
  //     rules: [
  //       "DOMAIN,service.example.test",
  //       "DOMAIN-SUFFIX,internal.example.test",
  //       { type: "IP-CIDR", value: "198.51.100.0/24", option: "no-resolve" }
  //     ]
  //   },
  //   {
  //     name: "本机直连业务",
  //     proxies: ["DIRECT"],
  //     rules: ["DOMAIN-SUFFIX,local.example.test"]
  //   }
  // ];

  return config;
}
