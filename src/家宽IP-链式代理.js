/**
 * Clash 家宽IP-链式代理覆写脚本
 *
 * 功能：
 * 1. 注入 MiyaIP 链式代理节点。
 * 2. 覆写 DNS 与域名嗅探配置。
 * 3. 注入 AI 服务、浏览器、基础平台和社交与流媒体规则。
 * 4. 生成链式代理所需代理组。
 *
 * 依赖：
 * - 需先执行 `MiyaIP 凭证.js`，向 `config._miya` 注入凭证。
 *
 * 兼容性：
 * - 运行环境为 Clash Party 的 JavaScriptCore。
 * - 使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串、
 *   展开语法、`Object.values()`、`Object.fromEntries()` 等 ES6+ 特性。
 *
 * @version 8.2
 */

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

// 控制通用链式代理地区和手动跳板节点。
var USER_OPTIONS = {
  // 通用链式代理中转地区，可选 US / JP / HK / SG，统一影响链式代理流量。
  chainRegion: "SG",
  // 手动指定跳板节点名，留空则按 chainRegion 自动匹配。
  manualNode: "",
  // 是否将浏览器主进程和 helper 进程一并纳入链式代理。
  enableBrowserProcessProxy: true,
};

// ---------------------------------------------------------------------------
// 节点与地区常量
// ---------------------------------------------------------------------------

// 按节点名特征识别地区，并提供地区标签与旗帜。
var REGION_MAP = {
  US: { regex: /🇺🇸|美国|^US[\|丨\- ]/i, label: "美国", flag: "🇺🇸" },
  JP: { regex: /🇯🇵|日本|^JP[\|丨\- ]/i, label: "日本", flag: "🇯🇵" },
  HK: { regex: /🇭🇰|香港|^HK[\|丨\- ]/i, label: "香港", flag: "🇭🇰" },
  SG: { regex: /🇸🇬|新加坡|^SG[\|丨\- ]/i, label: "新加坡", flag: "🇸🇬" },
};

// 脚本注入的两个 MiyaIP 节点名称。
var NODE_NAMES = {
  relay: "自选节点 + 家宽IP",
  transit: "MiyaIP（官方中转）",
};

// 自动匹配地区组时需要跳过的汇总代理组。
var EXCLUDED_GROUPS = ["节点选择"];

// 域名模式里使用的通配前缀。
var DOMAIN_WILDCARD_PREFIX = "+.";

// 直连规则统一使用的目标名称。
var RULE_TARGET_DIRECT = "DIRECT";

// `url-test` 代理组使用的探测地址。
var URL_TEST_PROBE_URL = "http://www.gstatic.com/generate_204";

// 识别 MiyaIP 自身节点时使用的名称关键字。
var MIYA_PROXY_NAME_KEYWORD = "MiyaIP";

// 脚本生成的各类代理组名称后缀。
var GROUP_NAME_SUFFIXES = {
  relay: "线路-链式代理-跳板",
  chain: "-链式代理-家宽IP出口",
};

// ---------------------------------------------------------------------------
// DNS 域名组常量
// ---------------------------------------------------------------------------

// 域外服务优先使用的 DoH 服务器列表。
var DOH_OVERSEAS = [
  "https://dns.google/dns-query",
  "https://cloudflare-dns.com/dns-query",
];

// 域内服务优先使用的 DoH 服务器列表。
var DOH_DOMESTIC = [
  "https://dns.alidns.com/dns-query",
  "https://doh.pub/dns-query",
];

// 主解析失败或命中过滤条件时使用的后备 DoH 列表。
var DOH_FALLBACK = DOH_OVERSEAS.concat(["https://dns.quad9.net/dns-query"]);

// Apple 生态相关域名分类。
var DOMAINS_APPLE = {
  core: ["+.apple.com", "+.icloud.com"],
  content: [
    "+.icloud-content.com",
    "+.mzstatic.com",
    "+.cdn-apple.com",
    "+.aaplimg.com",
  ],
  services: ["+.apple-cloudkit.com"],
};

// 需要统一走链式代理的基础平台域名。
var DOMAINS_CHAIN_PLATFORM = {
  google_core: ["+.google.com", "+.googleapis.com", "+.googleusercontent.com"],
  google_static: ["+.gstatic.com", "+.ggpht.com", "+.gvt1.com", "+.gvt2.com"],
  // `withgoogle.com` 为 Google 官方活动与推广站点；`googleworkspace.com`
  // 公开一方证据不足，避免作为默认规则注入。
  google_workspace: ["+.withgoogle.com"],
  google_cloud: ["+.cloud.google.com"],
  microsoft_core: ["+.microsoft.com", "+.live.com", "+.windows.net"],
  microsoft_productivity: [
    "+.office.com",
    "+.office.net",
    "+.office365.com",
    "+.m365.cloud.microsoft",
    "+.sharepoint.com",
    "+.onenote.com",
    "+.onedrive.com",
  ],
  microsoft_auth: [
    "+.microsoftonline.com",
    "+.msftauth.net",
    "+.msauth.net",
    "+.msecnd.net",
  ],
  microsoft_developer: [
    "+.visualstudio.com",
    "+.vsassets.io",
    "+.vsmarketplacebadges.dev",
  ],
  developer: ["+.github.com"],
};

// 需要统一走链式代理的 AI 服务域名。
var DOMAINS_CHAIN_AI = {
  anthropic: [
    "+.claude.ai",
    "+.claude.com",
    "+.anthropic.com",
    "+.claudeusercontent.com",
    // 公开一方文档证据较弱，但在实际规则集中较常见，先作为经验域名保留。
    "+.claudemcpclient.com",
    // Anthropic 站点静态资源经验域名，优先级低于主域名理解。
    "+.servd-anthropic-website.b-cdn.net",
    // Anthropic 官方场景使用过的短链。
    "+.clau.de",
  ],

  openai: [
    "+.openai.com",
    "+.chatgpt.com",
    "+.sora.com",
    "+.oaiusercontent.com",
    "+.oaistatic.com",
  ],

  google_ai: [
    "+.gemini.google.com",
    "+.aistudio.google.com",
    "+.ai.google.dev",
    "+.generativelanguage.googleapis.com",
    "+.ai.google",
    "+.notebooklm.google",
    // 历史兼容入口，Google 已迁移到 AI Studio。
    "+.makersuite.google.com",
    "+.deepmind.google",
    "+.labs.google",
    "+.antigravity.google",
    "+.antigravity-ide.com",
  ],

  perplexity: ["+.perplexity.ai", "+.perplexitycdn.com"],

  router_and_tools: ["+.openrouter.ai"],

  xai: ["+.x.ai", "+.grok.com", "+.console.x.ai", "+.api.x.ai"],
};

// 需要统一走链式代理的 macOS AI 服务 App / 进程名。
var PROCESS_NAMES_CHAIN_AI_MACOS = [
  "Claude",
  "Claude Helper",
  "ChatGPT",
  "ChatGPT Helper",
  "Perplexity",
  "Perplexity Helper",
  "Cursor",
  "Cursor Helper",
  "Windsurf",
  "Windsurf Helper",
  "Codeium",
  "Codeium Helper",
];

// 官方资料可直接确认的 macOS 浏览器主进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS_CONFIRMED = [
  "Arc",
  "Comet",
  "Dia",
  "Atlas",
  "Google Chrome",
  "Microsoft Edge",
];

// 基于 Chromium 进程命名模式推断的浏览器 helper 进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS_CHROMIUM_INFERRED = [
  "Arc Helper",
  "Arc Helper (GPU)",
  "Arc Helper (Plugin)",
  "Arc Helper (Renderer)",
  "Comet Helper",
  "Comet Helper (GPU)",
  "Comet Helper (Plugin)",
  "Comet Helper (Renderer)",
  "Dia Helper",
  "Dia Helper (GPU)",
  "Dia Helper (Plugin)",
  "Dia Helper (Renderer)",
  "Google Chrome Helper",
  "Google Chrome Helper (GPU)",
  "Google Chrome Helper (Plugin)",
  "Google Chrome Helper (Renderer)",
  "Atlas Helper",
  "Atlas Helper (GPU)",
  "Atlas Helper (Plugin)",
  "Atlas Helper (Renderer)",
  "Microsoft Edge Helper",
  "Microsoft Edge Helper (GPU)",
  "Microsoft Edge Helper (Plugin)",
  "Microsoft Edge Helper (Renderer)",
];

// 需要统一走链式代理的 macOS 浏览器 App / 进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS = mergeStringGroups([
  PROCESS_NAMES_CHAIN_BROWSER_MACOS_CONFIRMED,
  PROCESS_NAMES_CHAIN_BROWSER_MACOS_CHROMIUM_INFERRED,
]);

// 需要统一走链式代理的 macOS 基础平台 App / 进程名。
var PROCESS_NAMES_CHAIN_PLATFORM_MACOS = [
  "Google Drive",
  "Google Drive Helper",
  "Microsoft Teams",
  "Microsoft Teams Helper",
  "Microsoft Outlook",
  "Microsoft Word",
  "Microsoft Excel",
  "Microsoft PowerPoint",
  "OneDrive",
  "Visual Studio Code",
  "Code",
  "Code Helper",
];

// 需要统一走链式代理的流媒体和域外社交域名。
var DOMAINS_CHAIN_MEDIA = {
  youtube: [
    "+.youtube.com",
    "+.googlevideo.com",
    "+.ytimg.com",
    "+.youtube-nocookie.com",
    "+.yt.be",
  ],
  netflix: [
    "+.netflix.com",
    "+.netflix.net",
    "+.nflxvideo.net",
    "+.nflxso.net",
    "+.nflximg.net",
    "+.nflximg.com",
    "+.nflxext.com",
  ],
  twitter: ["+.twitter.com", "+.x.com", "+.twimg.com", "+.t.co"],
  facebook: [
    "+.facebook.com",
    "+.fbcdn.net",
    "+.fb.com",
    "+.facebook.net",
    "+.instagram.com",
    "+.cdninstagram.com",
  ],
  telegram: ["+.telegram.org", "+.t.me", "+.telegra.ph", "+.telesco.pe"],
  discord: [
    "+.discord.com",
    "+.discord.gg",
    "+.discordapp.com",
    "+.discordapp.net",
    "+.discord.media",
  ],
};

// 网络边界相对明确、适合稳定直连的域内 AI 域名。
var DOMAINS_AI_DOMESTIC = {
  tongyi: [
    "+.tongyi.aliyun.com",
    "+.qianwen.aliyun.com",
    "+.dashscope.aliyuncs.com",
  ],
  moonshot: ["+.moonshot.cn"],
  zhipu: ["+.chatglm.cn", "+.zhipuai.cn", "+.bigmodel.cn"],
  siliconflow: ["+.siliconflow.cn"],
};

// 需要直连的其他域名（VPN、内网工具等）。
var DOMAINS_DIRECT_EXTRA = {
  tailscale: ["+.tailscale.com", "+.tailscale.io"],
};

// 需要强制直连的 Tailnet 地址段，避免 Tailscale 数据面进入家宽链式代理。
var DIRECT_IP_CIDR_RULES = [
  { type: "IP-CIDR", value: "100.64.0.0/10", target: RULE_TARGET_DIRECT },
  { type: "IP-CIDR", value: "100.100.100.100/32", target: RULE_TARGET_DIRECT },
  { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48", target: RULE_TARGET_DIRECT },
];

// macOS 上常见的 Tailscale 相关进程名，置顶直连以减少被 TUN 接管的概率。
var DIRECT_PROCESS_RULES = [
  { type: "PROCESS-NAME", value: "Tailscale", target: RULE_TARGET_DIRECT },
  { type: "PROCESS-NAME", value: "tailscaled", target: RULE_TARGET_DIRECT },
  { type: "PROCESS-NAME", value: "IPNExtension", target: RULE_TARGET_DIRECT },
  {
    type: "PROCESS-NAME",
    value: "io.tailscale.ipn.macos.network-extension",
    target: RULE_TARGET_DIRECT,
  },
];

// 对字符串列表做稳定去重，保留首次出现的顺序。
function uniqueStrings(values) {
  var uniqueValues = [];
  var seen = {};
  for (var i = 0; i < values.length; i++) {
    var value = values[i];
    if (seen[value]) continue;
    seen[value] = true;
    uniqueValues.push(value);
  }
  return uniqueValues;
}

// 合并多组字符串列表并保持稳定去重。
function mergeStringGroups(groups) {
  var mergedValues = [];
  for (var i = 0; i < groups.length; i++) {
    mergedValues.push.apply(mergedValues, groups[i]);
  }
  return uniqueStrings(mergedValues);
}

// 把按类别分组的域名对象展平成单个数组并去重。
function flattenGroupedDomains(groupedDomains) {
  var flattenedDomains = [];
  Object.keys(groupedDomains).forEach(function (groupName) {
    flattenedDomains.push.apply(flattenedDomains, groupedDomains[groupName]);
  });
  return uniqueStrings(flattenedDomains);
}

// 展平后的 Apple 域名列表，供 DNS 和规则注入复用。
var ALL_APPLE_DOMAINS = flattenGroupedDomains(DOMAINS_APPLE);

// 展平后的链式代理基础平台域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_PLATFORM_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_PLATFORM);

// 展平后的链式代理 AI 服务域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_AI_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_AI);

// 展平后的链式代理媒体和社交域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_MEDIA_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_MEDIA);

// 展平后的全部链式代理域名列表，供 DNS 覆写和嗅探配置复用。
var ALL_CHAIN_DOMAINS = mergeStringGroups([
  ALL_CHAIN_AI_DOMAINS,
  ALL_CHAIN_PLATFORM_DOMAINS,
  ALL_CHAIN_MEDIA_DOMAINS,
]);

// 展平后的域内 AI 域名列表，供 DNS 和规则注入复用。
var ALL_AI_DOMESTIC_DOMAINS = flattenGroupedDomains(DOMAINS_AI_DOMESTIC);

// 展平后的额外直连域名列表，供规则注入复用。
var ALL_DIRECT_EXTRA_DOMAINS = flattenGroupedDomains(DOMAINS_DIRECT_EXTRA);

// 链式代理出口测试与通用静态资源域名。
var CHAIN_PROXY_SUPPORT_SUFFIXES = uniqueStrings([
  "cdn.cloudflare.net",
  "ping0.cc",
  "ipinfo.io",
]);

// DNS `fallback-filter` 额外补充的域名模式。
var DNS_FALLBACK_EXTRA_DOMAINS = uniqueStrings([
  "+.cdn.cloudflare.net",
  "ping0.cc",
  "ipinfo.io",
]);

// Sniffer 强制保留域名语义的域名模式。
var SNIFFER_FORCE_DOMAINS = uniqueStrings([
  "+.cloudflare.com",
  "+.cdn.cloudflare.net",
]);

// Sniffer 应跳过的直连和本地域名模式。
var SNIFFER_SKIP_DOMAINS = uniqueStrings(
  [
    "+.push.apple.com",
    "+.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
  ].concat(ALL_DIRECT_EXTRA_DOMAINS),
);

// 需要统一生成链式代理规则的主域名分组，按用途排序。
var CHAIN_PROXY_DOMAIN_GROUPS = [
  ALL_CHAIN_AI_DOMAINS,
  ALL_CHAIN_MEDIA_DOMAINS,
  ALL_CHAIN_PLATFORM_DOMAINS,
];

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.replace(DOMAIN_WILDCARD_PREFIX, "");
}

// 按固定顺序执行凭证读取、DNS/Sniffer 注入、代理链路注入和规则注入。
function main(config) {
  var miyaCredentials = takeMiyaCredentials(config);

  applyDnsAndSniffer(config);
  ensureProxyContainers(config);
  injectMiyaProxies(config, miyaCredentials);

  var relayTarget = resolveRelayTarget(
    config,
    USER_OPTIONS.chainRegion,
    USER_OPTIONS.manualNode,
  );
  bindDialerProxy(config, relayTarget);

  var chainGroupName = ensureChainGroup(config, USER_OPTIONS.chainRegion);
  injectManagedRules(config, chainGroupName);

  return config;
}

// ---------------------------------------------------------------------------
// 凭证读取
// ---------------------------------------------------------------------------

// 读取并移除注入到 `config._miya` 的 MiyaIP 凭证。
function takeMiyaCredentials(config) {
  if (!config._miya) {
    throw new Error(
      "[家宽IP-链式代理] 缺少 config._miya，请确保 MiyaIP 凭证.js 已启用且排序在本脚本之前",
    );
  }
  var miyaCredentials = config._miya;
  delete config._miya; // 防止凭证输出到最终配置
  return miyaCredentials;
}

// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

// 把脚本生成的 DNS 和域名嗅探配置写入主配置。
function applyDnsAndSniffer(config) {
  config.dns = buildDnsConfig();
  config.sniffer = buildSnifferConfig();
}

// 把一组域名统一绑定到同一套 DoH 服务器。
function assignNameserverPolicyDomains(policy, domains, dohServers) {
  for (var i = 0; i < domains.length; i++) {
    policy[domains[i]] = dohServers;
  }
}

// 构建不同域名分类对应的 `nameserver-policy` 映射。
function buildNameserverPolicy() {
  var policy = {
    "geosite:openai": DOH_OVERSEAS,
  };

  // 基础平台走域外 DoH，Apple 走域内 DoH。
  assignNameserverPolicyDomains(policy, ALL_CHAIN_PLATFORM_DOMAINS, DOH_OVERSEAS);
  assignNameserverPolicyDomains(policy, ALL_APPLE_DOMAINS, DOH_DOMESTIC);
  // Tailscale 控制面属于域外直连域名，单独指定域外 DoH。
  assignNameserverPolicyDomains(policy, ALL_DIRECT_EXTRA_DOMAINS, DOH_OVERSEAS);

  // AI 服务走域外 DoH。
  assignNameserverPolicyDomains(policy, ALL_CHAIN_AI_DOMAINS, DOH_OVERSEAS);
  // 域内 AI 走域内 DoH。
  assignNameserverPolicyDomains(policy, ALL_AI_DOMESTIC_DOMAINS, DOH_DOMESTIC);
  // 流媒体与域外社交走域外 DoH。
  assignNameserverPolicyDomains(policy, ALL_CHAIN_MEDIA_DOMAINS, DOH_OVERSEAS);

  return policy;
}

// 构建需要绕过 `fake-ip` 的域名白名单。
function buildDnsFakeIpFilter() {
  var localNetworkDomains = [
    "*.lan",
    "*.local",
    "*.localhost",
    "localhost.ptlogin2.qq.com",
  ];
  var timeSyncDomains = [
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "ntp1.aliyun.com",
    "pool.ntp.org",
    "*.pool.ntp.org",
  ];
  var connectivityTestDomains = [
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "*.msftconnecttest.com",
    "*.msftncsi.com",
  ];
  // Apple 生态对真实 IP 更敏感，统一排除 `fake-ip`。
  var appleDomains = ALL_APPLE_DOMAINS.slice();
  var realtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
    "*.battlenet.com.cn",
    "*.blzstatic.cn",
    "stun.*.*",
    "stun.*.*.*",
    "+.stun.*.*",
    "+.stun.*.*.*",
  ];
  var homeNetworkDomains = [
    "*.mcdn.bilivideo.cn",
    "+.music.163.com",
    "+.126.net",
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "*.xiaoqiang.net",
  ];

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(appleDomains)
    .concat(realtimeDomains)
    .concat(homeNetworkDomains)
    .concat(ALL_DIRECT_EXTRA_DOMAINS);
}

// 构建 `fallback-filter` 使用的域名匹配列表。
function buildDnsFallbackFilterDomains() {
  return mergeStringGroups([ALL_CHAIN_DOMAINS, DNS_FALLBACK_EXTRA_DOMAINS]);
}

// 构建 Clash DNS 的 `fallback-filter` 配置对象。
function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: buildDnsFallbackFilterDomains(),
  };
}

// 构建不含动态列表项的基础 DNS 配置。
function buildDnsBaseConfig() {
  return {
    enable: true,
    listen: "0.0.0.0:1053",
    ipv6: true,
    "respect-rules": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    nameserver: DOH_DOMESTIC,
    "proxy-server-nameserver": DOH_DOMESTIC,
    "direct-nameserver": DOH_DOMESTIC.slice(),
    "direct-nameserver-follow-policy": true,
    fallback: DOH_FALLBACK,
  };
}

// 组装完整的 DNS 配置。
function buildDnsConfig() {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter();
  dnsConfig["fallback-filter"] = buildDnsFallbackFilter();
  dnsConfig["nameserver-policy"] = buildNameserverPolicy();
  return dnsConfig;
}

// 构建域名嗅探配置。
function buildSnifferConfig() {
  return {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      QUIC: { ports: [443] },
    },
    "force-domain": SNIFFER_FORCE_DOMAINS,
    "skip-domain": SNIFFER_SKIP_DOMAINS,
  };
}

// ---------------------------------------------------------------------------
// MiyaIP 代理链路
// ---------------------------------------------------------------------------

// 确保主配置里存在代理、代理组和规则三个容器。
function ensureProxyContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 把地区输入统一转成大写字符串键。
function normalizeRegionKey(region) {
  return String(region || "").toUpperCase();
}

// 根据地区键解析地区元数据，并按需提供兜底标签。
function resolveRegionMeta(region, allowFallbackRegionLabel) {
  var regionKey = normalizeRegionKey(region);
  if (REGION_MAP[regionKey]) return REGION_MAP[regionKey];
  if (!allowFallbackRegionLabel) return null;
  return { label: region, flag: "🌐" };
}

// 按旗帜、地区标签和后缀拼出代理组名称。
function buildRegionGroupName(regionMeta, groupNameSuffix) {
  return regionMeta.flag + "|" + regionMeta.label + groupNameSuffix;
}

// 根据凭证和端点信息生成一个 MiyaIP HTTP 代理节点。
function buildMiyaProxy(miyaCredentials, proxyName, endpoint) {
  return {
    name: proxyName,
    type: "http",
    server: endpoint.server,
    port: endpoint.port,
    username: miyaCredentials.username,
    password: miyaCredentials.password,
    udp: true,
  };
}

// 按名称查找单个代理节点。
function findProxyByName(proxies, proxyName) {
  for (var i = 0; i < proxies.length; i++) {
    if (proxies[i].name === proxyName) return proxies[i];
  }
  return null;
}

// 按名称查找单个代理组。
function findProxyGroupByName(proxyGroups, groupName) {
  for (var i = 0; i < proxyGroups.length; i++) {
    if (proxyGroups[i].name === groupName) return proxyGroups[i];
  }
  return null;
}

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 查找可直接复用的订阅地区组名称。
function findReusableRegionGroupName(proxyGroups, regionRegex) {
  for (var i = 0; i < proxyGroups.length; i++) {
    var proxyGroup = proxyGroups[i];
    if (
      regionRegex.test(proxyGroup.name) &&
      EXCLUDED_GROUPS.indexOf(proxyGroup.name) < 0
    ) {
      return proxyGroup.name;
    }
  }
  return null;
}

// 收集匹配地区特征且非 MiyaIP 的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(MIYA_PROXY_NAME_KEYWORD) < 0
    ) {
      regionNodeNames.push(proxy.name);
    }
  }
  return regionNodeNames;
}

// 把地区节点列表包装成一个 `url-test` 代理组。
function addRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames) {
  proxyGroups.push({
    name: groupName,
    type: "url-test",
    proxies: regionNodeNames,
    url: URL_TEST_PROBE_URL,
    interval: 300,
    tolerance: 50,
  });
}

// 向主配置注入家宽出口和官方中转两个 MiyaIP 节点。
function injectMiyaProxies(config, miyaCredentials) {
  var miyaProxies = [
    buildMiyaProxy(miyaCredentials, NODE_NAMES.relay, miyaCredentials.relay),
    buildMiyaProxy(
      miyaCredentials,
      NODE_NAMES.transit,
      miyaCredentials.transit,
    ),
  ];

  for (var i = 0; i < miyaProxies.length; i++) {
    var miyaProxy = miyaProxies[i];
    if (!findProxyByName(config.proxies, miyaProxy.name)) {
      config.proxies.push(miyaProxy);
    }
  }
}

// 查找、复用或创建指定地区的 `url-test` 代理组。
function ensureRegionGroup(config, region, groupNameSuffix, reuseExisting) {
  var regionMeta = resolveRegionMeta(region, false);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  // 优先复用订阅里已有的地区代理组。
  if (reuseExisting) {
    var reusableGroupName = findReusableRegionGroupName(
      proxyGroups,
      regionRegex,
    );
    if (reusableGroupName) return reusableGroupName;
  }

  // 检查是否已存在同名组。
  if (findProxyGroupByName(proxyGroups, groupName)) return groupName;

  // 筛选地区节点，并排除 MiyaIP 自身节点。
  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  addRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames);

  return groupName;
}

// 解析家宽链式代理前一跳应使用的跳板节点或地区组。
function resolveRelayTarget(config, region, manualNode) {
  var relayTarget = null;
  if (manualNode) {
    relayTarget = manualNode;
    if (!hasProxyOrGroup(config, relayTarget)) {
      throw new Error(
        "[家宽IP-链式代理] manualNode 未命中现有节点或代理组: " + relayTarget,
      );
    }
    return relayTarget;
  }

  relayTarget = ensureRegionGroup(config, region, GROUP_NAME_SUFFIXES.relay, true);
  if (!relayTarget) {
    throw new Error(
      "[家宽IP-链式代理] 未找到可用的 " +
        region +
        " 跳板节点或代理组，请检查 chainRegion 或改用 manualNode",
    );
  }
  return relayTarget;
}

// 给家宽出口节点绑定拨号前置代理，并清理官方中转节点的拨号代理。
function bindDialerProxy(config, relayTarget) {
  var relayProxy = findProxyByName(config.proxies, NODE_NAMES.relay);
  if (relayProxy) {
    if (relayTarget) relayProxy["dialer-proxy"] = relayTarget;
    else delete relayProxy["dialer-proxy"];
  }

  // 官方中转节点不挂 `dialer-proxy`。
  var transitProxy = findProxyByName(config.proxies, NODE_NAMES.transit);
  if (transitProxy) delete transitProxy["dialer-proxy"];
}

// 确保存在一个承载 MiyaIP 官方中转与家宽出口的链式代理组。
function ensureChainGroup(config, region) {
  var regionMeta = resolveRegionMeta(region, true);
  var chainGroupName = buildRegionGroupName(
    regionMeta,
    GROUP_NAME_SUFFIXES.chain,
  );

  if (!findProxyGroupByName(config["proxy-groups"], chainGroupName)) {
    config["proxy-groups"].push({
      name: chainGroupName,
      type: "select",
      proxies: [NODE_NAMES.transit, NODE_NAMES.relay],
    });
  }

  return chainGroupName;
}
// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

// 提取规则的 `"TYPE,value"` 标识。
function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;

  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;

  return ruleLine.substring(0, secondCommaIndex);
}

// 按固定优先级拼出直连保留项和链式代理两类管理规则。
function buildManagedRules(chainGroupName) {
  return buildDirectAiRules()
    .concat(buildChainProxyRules(chainGroupName));
}

// 把规则数组转换成便于查询的规则标识表。
function buildRuleIdentityLookup(ruleLines) {
  var ruleIdentityLookup = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity) ruleIdentityLookup[ruleIdentity] = true;
  }
  return ruleIdentityLookup;
}

// 过滤掉与管理规则命中同一标识的原始订阅规则。
function filterConflictingRules(ruleLines, blockedRuleIdentities) {
  var filteredRules = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity === null || !blockedRuleIdentities[ruleIdentity]) {
      filteredRules.push(ruleLines[i]);
    }
  }
  return filteredRules;
}

// 保持原顺序把一批规则插入到规则数组头部。
function prependRules(targetRules, rulesToPrepend) {
  for (var i = rulesToPrepend.length - 1; i >= 0; i--) {
    targetRules.unshift(rulesToPrepend[i]);
  }
}

// 注入管理规则并整体置顶。
function injectManagedRules(
  config,
  chainGroupName,
) {
  var managedRules = buildManagedRules(chainGroupName);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);

  config.rules = filterConflictingRules(config.rules, managedRuleIdentities);
  prependRules(config.rules, managedRules);
}

// 按规则标识去重后追加单条管理规则。
function addRuleIfNotExists(
  ruleLines,
  seenRuleIdentities,
  type,
  value,
  target,
) {
  var ruleIdentity = type + "," + value;
  if (seenRuleIdentities[ruleIdentity]) return;
  seenRuleIdentities[ruleIdentity] = true;
  ruleLines.push(type + "," + value + "," + target);
}

// 追加一批原生规则项，可附带额外参数，例如 `no-resolve`。
function addRawRulesIfNotExists(ruleLines, seenRuleIdentities, rawRules) {
  for (var i = 0; i < rawRules.length; i++) {
    var rawRule = rawRules[i];
    var ruleIdentity = rawRule.type + "," + rawRule.value;
    if (seenRuleIdentities[ruleIdentity]) continue;
    seenRuleIdentities[ruleIdentity] = true;

    var ruleLine = rawRule.type + "," + rawRule.value + "," + rawRule.target;
    if (rawRule.option) ruleLine += "," + rawRule.option;
    ruleLines.push(ruleLine);
  }
}

// 批量生成 `DOMAIN-SUFFIX` 规则并完成批内去重。
function addSuffixRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  domains,
  target,
) {
  for (var i = 0; i < domains.length; i++) {
    addRuleIfNotExists(
      ruleLines,
      seenRuleIdentities,
      "DOMAIN-SUFFIX",
      toSuffix(domains[i]),
      target,
    );
  }
}

// 批量生成 `PROCESS-NAME` 规则并完成批内去重。
function addProcessRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  processNames,
  target,
) {
  for (var i = 0; i < processNames.length; i++) {
    addRuleIfNotExists(
      ruleLines,
      seenRuleIdentities,
      "PROCESS-NAME",
      processNames[i],
      target,
    );
  }
}

// 按当前用户选项返回应纳入链式代理的进程分组。
function buildChainProxyProcessGroups() {
  var processGroups = [PROCESS_NAMES_CHAIN_AI_MACOS];
  if (USER_OPTIONS.enableBrowserProcessProxy) {
    processGroups.push(PROCESS_NAMES_CHAIN_BROWSER_MACOS);
  }
  processGroups.push(PROCESS_NAMES_CHAIN_PLATFORM_MACOS);
  return processGroups;
}

// 统一生成链式代理规则，按用途分类收拢输入，避免重复或冲突。
function buildChainProxyRules(chainGroupName) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildChainProxyProcessGroups();
  var i;

  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      processGroups[i],
      chainGroupName,
    );
  }

  for (i = 0; i < CHAIN_PROXY_DOMAIN_GROUPS.length; i++) {
    addSuffixRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      CHAIN_PROXY_DOMAIN_GROUPS[i],
      chainGroupName,
    );
  }

  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    CHAIN_PROXY_SUPPORT_SUFFIXES,
    chainGroupName,
  );
  return ruleLines;
}

// 生成域内 AI 域名及额外直连域名的直连规则。
function buildDirectAiRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var directNetworkRules = [];
  var i;

  for (i = 0; i < DIRECT_IP_CIDR_RULES.length; i++) {
    directNetworkRules.push({
      type: DIRECT_IP_CIDR_RULES[i].type,
      value: DIRECT_IP_CIDR_RULES[i].value,
      target: DIRECT_IP_CIDR_RULES[i].target,
      option: "no-resolve",
    });
  }

  addRawRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    DIRECT_PROCESS_RULES.concat(directNetworkRules),
  );
  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    ALL_AI_DOMESTIC_DOMAINS,
    RULE_TARGET_DIRECT,
  );
  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    ALL_DIRECT_EXTRA_DOMAINS,
    RULE_TARGET_DIRECT,
  );
  return ruleLines;
}
