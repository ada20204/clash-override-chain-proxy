/**
 * Clash 家宽IP-链式代理覆写脚本
 *
 * 功能：
 * 1. 注入 MiyaIP 链式代理节点。
 * 2. 覆写 DNS 与域名嗅探配置。
 * 3. 注入 AI 严格链式代理、浏览器链式代理和三类 DIRECT 规则。
 * 4. 生成链式代理所需代理组并校验关键目标是否正确写入。
 *
 * 总体分组说明：
 * 1. 用户参数：只放用户手动可改的入口。
 * 2. 基础常量：地区、节点、错误前缀、代理组命名等稳定常量。
 * 3. 原始分类数据源：按域外 AI、浏览器、域内直连、域外应用直连、网络直连拆开维护。
 * 4. 通用数据处理工具：只做去重、展平、排除、错误构建等纯工具操作。
 * 5. 派生分类与统一入口：把原始数据源收敛成 DNS、Sniffer、规则生成共享的单一入口。
 * 6. 执行函数：按初始化、DNS/Sniffer、代理链路、规则注入、最终校验的阅读顺序排列。
 *
 * 依赖：
 * - 需先执行 `MiyaIP 凭证.js`，向 `config._miya` 注入凭证。
 *
 * 兼容性：
 * - 运行环境为 Clash Party 的 JavaScriptCore。
 * - 使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串、
 *   展开语法、`Object.values()`、`Object.fromEntries()` 等 ES6+ 特性。
 *
 * @version 8.6
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
  enableBrowserProcessProxy: false,
  // 是否将常见 AI CLI 可执行文件纳入链式代理。
  enableAiCliProcessProxy: true
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// 按节点名特征识别地区，并提供地区标签与旗帜。
var REGION_MAP = {
  US: { regex: /🇺🇸|美国|^US[\|丨\- ]/i, label: "美国", flag: "🇺🇸" },
  JP: { regex: /🇯🇵|日本|^JP[\|丨\- ]/i, label: "日本", flag: "🇯🇵" },
  HK: { regex: /🇭🇰|香港|^HK[\|丨\- ]/i, label: "香港", flag: "🇭🇰" },
  SG: { regex: /🇸🇬|新加坡|^SG[\|丨\- ]/i, label: "新加坡", flag: "🇸🇬" }
};

// 脚本注入的两个 MiyaIP 节点名称。
var NODE_NAMES = {
  relay: "自选节点 + 家宽IP",
  transit: "MiyaIP（官方中转）"
};

// 自动匹配地区组时需要跳过的汇总代理组。
var EXCLUDED_GROUPS = ["节点选择"];

// 直连规则统一使用的目标名称。
var RULE_TARGET_DIRECT = "DIRECT";

// `url-test` 代理组使用的探测地址。
var URL_TEST_PROBE_URL = "http://www.gstatic.com/generate_204";

// 识别 MiyaIP 自身节点时使用的名称关键字。
var MIYA_PROXY_NAME_KEYWORD = "MiyaIP";

// 用户可见错误统一前缀。
var ERROR_PREFIX = "[家宽IP-链式代理] ";

// 脚本生成的各类代理组名称后缀。
var GROUP_NAME_SUFFIXES = {
  relay: "线路-链式代理-跳板",
  chain: "-链式代理-家宽IP出口"
};

// 兼容旧版本时需要清理的废弃代理组名称。
var LEGACY_PROXY_GROUP_NAMES = ["AI 严格链式代理"];

// ---------------------------------------------------------------------------
// 原始分类数据源
// ---------------------------------------------------------------------------

// 域外服务优先使用的 DoH 服务器列表。
var DOH_OVERSEAS = [
  "https://dns.google/dns-query",
  "https://cloudflare-dns.com/dns-query"
];

// 域内服务优先使用的 DoH 服务器列表。
var DOH_DOMESTIC = [
  "https://dns.alidns.com/dns-query",
  "https://doh.pub/dns-query"
];

// 主解析失败或命中过滤条件时使用的后备 DoH 列表。
var DOH_FALLBACK = DOH_OVERSEAS.concat(["https://dns.quad9.net/dns-query"]);

// Apple 生态相关域名分类。
var DOMAINS_APPLE = {
  core: [
    "+.apple.com",
    "+.icloud.com"
  ],
  content: [
    "+.icloud-content.com",
    "+.mzstatic.com",
    "+.cdn-apple.com",
    "+.aaplimg.com"
  ],
  services: ["+.apple-cloudkit.com"]
};

// 需要统一走链式代理的基础平台域名。
var DOMAINS_CHAIN_PLATFORM = {
  // Google 官方主域与官方 API / 内容分发基础设施。
  google_core: [
    "+.google.com",
    "+.googleapis.com",
    "+.googleusercontent.com"
  ],
  // Google 官方静态资源与下载分发基础设施。
  google_static: [
    "+.gstatic.com",
    "+.ggpht.com",
    "+.gvt1.com",
    "+.gvt2.com"
  ],
  // `withgoogle.com` 为 Google 官方活动与推广站点；`googleworkspace.com`
  // 公开一方证据不足，避免作为默认规则注入。
  google_workspace: [
    "+.withgoogle.com"
  ],
  google_cloud: [
    "+.cloud.google.com"
  ],
  // Microsoft 官方主域与官方基础设施入口；`windows.net` 属于官方基础设施宽域名。
  microsoft_core: [
    "+.microsoft.com",
    "+.live.com",
    "+.windows.net"
  ],
  microsoft_productivity: [
    "+.office.com",
    "+.office.net",
    "+.office365.com",
    "+.m365.cloud.microsoft",
    "+.sharepoint.com",
    "+.onenote.com",
    "+.onedrive.com"
  ],
  microsoft_auth: [
    "+.microsoftonline.com",
    "+.msftauth.net",
    "+.msauth.net",
    "+.msecnd.net"
  ],
  // Microsoft 开发者与 VS Code 生态基础设施。
  microsoft_developer: [
    "+.visualstudio.com",
    "+.vsassets.io",
    "+.vsmarketplacebadges.dev"
  ],
  developer: [
    "+.github.com"
  ]
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
    "+.clau.de"
  ],

  openai: [
    "+.openai.com",
    "+.chatgpt.com",
    "+.sora.com",
    // OpenAI 官方静态资源与内容分发基础设施。
    "+.oaiusercontent.com",
    "+.oaistatic.com"
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
    "+.antigravity-ide.com"
  ],

  // `perplexitycdn.com` 为 Perplexity 资源分发域名。
  perplexity: [
    "+.perplexity.ai",
    "+.perplexitycdn.com"
  ],

  router_and_tools: [
    "+.openrouter.ai"
  ],

  xai: [
    "+.x.ai",
    "+.grok.com",
    "+.console.x.ai",
    "+.api.x.ai"
  ]
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
  "Cursor Helper"
];

// 可选纳入链式代理的 AI CLI 可执行文件名，默认开启。
var PROCESS_NAMES_CHAIN_AI_CLI = ["claude", "gemini", "codex"];

// 官方资料可直接确认的 macOS 浏览器主进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS_CONFIRMED = [
  "Comet", "Dia", "Atlas", "Google Chrome"
];

// 基于 Chromium 进程命名模式推断的浏览器 helper 进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS_CHROMIUM_INFERRED = [
  "Comet Helper", "Dia Helper", "Google Chrome Helper", "Atlas Helper"
];

// 需要统一走链式代理的 macOS 浏览器 App / 进程名。
var PROCESS_NAMES_CHAIN_BROWSER_MACOS = mergeStringGroups([
  PROCESS_NAMES_CHAIN_BROWSER_MACOS_CONFIRMED,
  PROCESS_NAMES_CHAIN_BROWSER_MACOS_CHROMIUM_INFERRED
]);

// 需要统一走链式代理的流媒体和域外社交域名。
var DOMAINS_CHAIN_MEDIA = {
  youtube: [
    "+.youtube.com",
    "+.googlevideo.com",
    "+.ytimg.com",
    "+.youtube-nocookie.com",
    "+.yt.be"
  ],
  netflix: [
    "+.netflix.com",
    "+.netflix.net",
    "+.nflxvideo.net",
    "+.nflxso.net",
    "+.nflximg.net",
    "+.nflximg.com",
    "+.nflxext.com"
  ],
  twitter: [
    "+.twitter.com",
    "+.x.com",
    "+.twimg.com",
    "+.t.co"
  ],
  facebook: [
    "+.facebook.com",
    "+.fbcdn.net",
    "+.fb.com",
    "+.facebook.net",
    "+.instagram.com",
    "+.cdninstagram.com"
  ],
  telegram: [
    "+.telegram.org",
    "+.t.me",
    "+.telegra.ph",
    "+.telesco.pe"
  ],
  discord: [
    "+.discord.com",
    "+.discord.gg",
    "+.discordapp.com",
    "+.discordapp.net",
    "+.discord.media"
  ]
};

// 网络边界相对明确、适合稳定直连的域内 AI 域名。
var DOMAINS_AI_DOMESTIC = {
  tongyi: [
    "+.tongyi.aliyun.com",
    "+.qianwen.aliyun.com",
    "+.dashscope.aliyuncs.com"
  ],
  moonshot: [
    "+.moonshot.cn"
  ],
  zhipu: [
    "+.chatglm.cn",
    "+.zhipuai.cn",
    "+.bigmodel.cn"
  ],
  siliconflow: [
    "+.siliconflow.cn"
  ]
};

// 域内办公软件与协作平台域名，固定保持 DIRECT。
var DOMAINS_OFFICE_DOMESTIC = {
  tencent_messaging_and_collab: [
    "+.qq.com",
    "+.qqmail.com",
    "+.exmail.qq.com",
    "+.weixin.qq.com",
    "+.work.weixin.qq.com",
    "+.docs.qq.com",
    "+.meeting.tencent.com",
    "+.tencentcloud.com",
    "+.cloud.tencent.com"
  ],
  alibaba_productivity: [
    "+.dingtalk.com",
    "+.dingtalkapps.com",
    "+.aliyundrive.com",
    "+.quark.cn",
    "+.teambition.com",
    "+.aliyun.com",
    "+.aliyuncs.com",
    "+.alibabacloud.com"
  ],
  bytedance_productivity: [
    "+.feishu.cn",
    "+.feishu.net",
    "+.feishucdn.com",
    "+.larksuite.com",
    "+.larkoffice.com"
  ],
  wps_productivity: [
    "+.wps.cn",
    "+.wps.com",
    "+.kdocs.cn",
    "+.kdocs.com"
  ]
};

// 域外应用直连域名，当前先实装 Tailscale；Typeless 预留到后续补充。
var DOMAINS_APPS_OVERSEAS_DIRECT = {
  tailscale: [
    "+.tailscale.com",
    "+.tailscale.io",
    "+.ts.net"
  ],
  typeless: [
    "+.typeless.com"
  ]
};

// 网络地址直连，当前主要用于 Tailnet 地址段。
var NETWORK_DIRECT_CIDR_RULES = [
  { type: "IP-CIDR", value: "100.64.0.0/10", target: RULE_TARGET_DIRECT },
  { type: "IP-CIDR", value: "100.100.100.100/32", target: RULE_TARGET_DIRECT },
  { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48", target: RULE_TARGET_DIRECT }
];

// ---------------------------------------------------------------------------
// 通用数据处理工具
// ---------------------------------------------------------------------------

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

// 为字符串数组构建便于查询的哈希表。
function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
}

// 从字符串数组中排除另一组字符串，保留原顺序。
function excludeStrings(values, excludedValues) {
  var filteredValues = [];
  var excludedLookup = buildStringLookup(excludedValues);
  for (var i = 0; i < values.length; i++) {
    if (excludedLookup[values[i]]) continue;
    filteredValues.push(values[i]);
  }
  return uniqueStrings(filteredValues);
}

// 从原生规则对象里提取指定类型的值列表。
function extractRawRuleValues(rawRules, targetType) {
  var values = [];
  for (var i = 0; i < rawRules.length; i++) {
    if (rawRules[i].type === targetType) values.push(rawRules[i].value);
  }
  return uniqueStrings(values);
}

// 把按类别分组的域名对象展平成单个数组并去重。
function flattenGroupedDomains(groupedDomains) {
  var flattenedDomains = [];
  Object.keys(groupedDomains).forEach(function (groupName) {
    flattenedDomains.push.apply(flattenedDomains, groupedDomains[groupName]);
  });
  return uniqueStrings(flattenedDomains);
}

// 为统一错误文案构建 Error 对象。
function createUserError(message) {
  return new Error(ERROR_PREFIX + message);
}

// ---------------------------------------------------------------------------
// 派生分类与统一入口
// ---------------------------------------------------------------------------

// 展平后的 Apple 域名列表，供 DNS 和规则注入复用。
var ALL_APPLE_DOMAINS = flattenGroupedDomains(DOMAINS_APPLE);

// 展平后的链式代理基础平台域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_PLATFORM_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_PLATFORM);

// 展平后的链式代理 AI 服务域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_AI_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_AI);

// 展平后的链式代理媒体和社交域名列表，供 DNS 和规则注入复用。
var ALL_CHAIN_MEDIA_DOMAINS = flattenGroupedDomains(DOMAINS_CHAIN_MEDIA);

// 展平后的域内 AI 域名列表，供 DNS 和规则注入复用。
var ALL_AI_DOMESTIC_DOMAINS = flattenGroupedDomains(DOMAINS_AI_DOMESTIC);

// 展平后的域内办公软件域名列表，供 DNS 和规则注入复用。
var ALL_OFFICE_DOMESTIC_DOMAINS = flattenGroupedDomains(DOMAINS_OFFICE_DOMESTIC);

// 展平后的域外应用直连域名列表，供 DNS 和规则注入复用。
var ALL_OVERSEAS_APP_DIRECT_DOMAINS = flattenGroupedDomains(
  DOMAINS_APPS_OVERSEAS_DIRECT
);

// 需要直连的域名分类，分别对应域内直连与域外应用直连。
var DIRECT_DOMAIN_SOURCES = {
  domestic: [ALL_AI_DOMESTIC_DOMAINS, ALL_OFFICE_DOMESTIC_DOMAINS],
  overseasApps: [ALL_OVERSEAS_APP_DIRECT_DOMAINS]
};

// DNS `fallback-filter` 额外补充的域名模式。
var DNS_FALLBACK_EXTRA_DOMAINS = uniqueStrings([
  "+.cdn.cloudflare.net",
  "ping0.cc",
  "ipinfo.io"
]);

// Sniffer 强制保留域名语义的域名模式。
var SNIFFER_FORCE_DOMAINS = uniqueStrings([
  "+.cloudflare.com",
  "+.cdn.cloudflare.net"
]);

// Sniffer 应跳过的直连和本地域名模式。
var SNIFFER_SKIP_DOMAINS = uniqueStrings(
  [
    "+.push.apple.com",
    "+.apple.com",
    "+.lan",
    "+.local",
    "+.localhost"
  ].concat(ALL_OVERSEAS_APP_DIRECT_DOMAINS)
);

// 统一收拢直连对象，作为冲突裁决和后续生成的单一来源。
var ALL_DOMESTIC_DIRECT_DOMAIN_PATTERNS = mergeStringGroups(
  DIRECT_DOMAIN_SOURCES.domestic
);
var ALL_OVERSEAS_APP_DIRECT_DOMAIN_PATTERNS = mergeStringGroups(
  DIRECT_DOMAIN_SOURCES.overseasApps
);
var ALL_DIRECT_DOMAIN_PATTERNS = mergeStringGroups([
  ALL_DOMESTIC_DIRECT_DOMAIN_PATTERNS,
  ALL_OVERSEAS_APP_DIRECT_DOMAIN_PATTERNS
]);
var ALL_DIRECT_PROCESS_NAMES = [];
var ALL_DIRECT_NETWORK_RULES = NETWORK_DIRECT_CIDR_RULES.slice();

// 严格 AI 路由对象：AI 主服务、支撑平台与出口验证域名。
var ALL_STRICT_AI_DOMAIN_PATTERNS = excludeStrings(
  ALL_CHAIN_AI_DOMAINS,
  ALL_DIRECT_DOMAIN_PATTERNS
);
var ALL_STRICT_SUPPORT_PLATFORM_DOMAIN_PATTERNS = excludeStrings(
  ALL_CHAIN_PLATFORM_DOMAINS,
  ALL_DIRECT_DOMAIN_PATTERNS
);
var ALL_STRICT_VALIDATION_DOMAIN_PATTERNS = excludeStrings(
  DNS_FALLBACK_EXTRA_DOMAINS,
  ALL_DIRECT_DOMAIN_PATTERNS
);
var ALL_STRICT_DOMAIN_PATTERNS = mergeStringGroups([
  ALL_STRICT_AI_DOMAIN_PATTERNS,
  ALL_STRICT_SUPPORT_PLATFORM_DOMAIN_PATTERNS,
  ALL_STRICT_VALIDATION_DOMAIN_PATTERNS
]);

// 非严格链式代理对象保持原有行为，当前只保留媒体和社交。
var ALL_NON_STRICT_CHAIN_DOMAIN_PATTERNS = excludeStrings(
  ALL_CHAIN_MEDIA_DOMAINS,
  ALL_DIRECT_DOMAIN_PATTERNS
);

// 严格 AI 路由对象对应的进程集合。
var ALL_STRICT_PROCESS_NAMES_BASE = excludeStrings(
  PROCESS_NAMES_CHAIN_AI_MACOS,
  ALL_DIRECT_PROCESS_NAMES
);
var ALL_BROWSER_CHAIN_PROCESS_NAMES = excludeStrings(
  PROCESS_NAMES_CHAIN_BROWSER_MACOS,
  ALL_DIRECT_PROCESS_NAMES
);
var ALL_STRICT_SNIFFER_FORCE_DOMAINS = mergeStringGroups([
  SNIFFER_FORCE_DOMAINS,
  ALL_STRICT_DOMAIN_PATTERNS
]);

// 规则与 DNS/Sniffer 统一读取这几个总入口，避免各处分散引用。
var ROUTING_DOMAIN_SOURCES = {
  direct: DIRECT_DOMAIN_SOURCES,
  strict: {
    ai: ALL_STRICT_AI_DOMAIN_PATTERNS,
    support: ALL_STRICT_SUPPORT_PLATFORM_DOMAIN_PATTERNS,
    validation: ALL_STRICT_VALIDATION_DOMAIN_PATTERNS,
    all: ALL_STRICT_DOMAIN_PATTERNS
  },
  generalChain: ALL_NON_STRICT_CHAIN_DOMAIN_PATTERNS
};

var ROUTING_PROCESS_SOURCES = {
  strictBase: ALL_STRICT_PROCESS_NAMES_BASE,
  strictOptionalAiCli: PROCESS_NAMES_CHAIN_AI_CLI,
  generalBrowser: ALL_BROWSER_CHAIN_PROCESS_NAMES
};

var MANAGED_RULE_ASSERTIONS = [
  { type: "DOMAIN-SUFFIX", value: "claude.ai" },
  { type: "DOMAIN-SUFFIX", value: "google.com" },
  { type: "PROCESS-NAME", value: "Claude" }
];

// ---------------------------------------------------------------------------
// 执行装配与初始化
// ---------------------------------------------------------------------------

// 在所有修改前确保主配置存在脚本依赖的基础容器，并清理旧残留。
function initializeManagedConfig(config) {
  ensureProxyContainers(config);
  removeLegacyProxyGroups(config["proxy-groups"]);
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
    "geosite:openai": DOH_OVERSEAS
  };

  // 严格 AI 域名与支撑平台走域外 DoH，Apple 走域内 DoH。
  assignNameserverPolicyDomains(
    policy,
    ROUTING_DOMAIN_SOURCES.strict.support,
    DOH_OVERSEAS
  );
  assignNameserverPolicyDomains(policy, ALL_APPLE_DOMAINS, DOH_DOMESTIC);
  // 域外应用直连对象固定使用域外 DoH，避免被域内解析污染。
  assignNameserverPolicyDomains(
    policy,
    ALL_OVERSEAS_APP_DIRECT_DOMAIN_PATTERNS,
    DOH_OVERSEAS
  );

  // AI 服务与出口验证域名走域外 DoH。
  assignNameserverPolicyDomains(policy, ROUTING_DOMAIN_SOURCES.strict.ai, DOH_OVERSEAS);
  assignNameserverPolicyDomains(
    policy,
    ROUTING_DOMAIN_SOURCES.strict.validation,
    DOH_OVERSEAS
  );
  // 域内 AI 走域内 DoH。
  assignNameserverPolicyDomains(policy, ALL_AI_DOMESTIC_DOMAINS, DOH_DOMESTIC);
  // 域内办公软件走域内 DoH。
  assignNameserverPolicyDomains(policy, ALL_OFFICE_DOMESTIC_DOMAINS, DOH_DOMESTIC);
  // 流媒体与域外社交走域外 DoH。
  assignNameserverPolicyDomains(
    policy,
    ROUTING_DOMAIN_SOURCES.generalChain,
    DOH_OVERSEAS
  );

  return policy;
}

// 构建需要绕过 `fake-ip` 的域名白名单。
function buildDnsFakeIpFilter() {
  var localNetworkDomains = [
    "*.lan",
    "*.local",
    "*.localhost",
    "localhost.ptlogin2.qq.com"
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
    "*.pool.ntp.org"
  ];
  var connectivityTestDomains = [
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "*.msftconnecttest.com",
    "*.msftncsi.com"
  ];
  // 游戏主机联机和游戏平台入口通常依赖真实 IP。
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
    "*.battlenet.com.cn",
    "*.blzstatic.cn"
  ];
  // 通用 STUN 域名常见于 WebRTC、语音和点对点实时连接。
  var stunRealtimeDomains = [
    "stun.*.*",
    "stun.*.*.*"
  ];
  // 本地路由器和家庭网络设备入口应直接返回真实 IP。
  var homeRouterDomains = [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "*.xiaoqiang.net"
  ];

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(ALL_APPLE_DOMAINS)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

// 构建 `fallback-filter` 使用的域名匹配列表。
function buildDnsFallbackFilterDomains() {
  return mergeStringGroups([
    ALL_STRICT_DOMAIN_PATTERNS,
    ALL_NON_STRICT_CHAIN_DOMAIN_PATTERNS,
    ALL_OVERSEAS_APP_DIRECT_DOMAIN_PATTERNS
  ]);
}

// 构建 Clash DNS 的 `fallback-filter` 配置对象。
function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: buildDnsFallbackFilterDomains()
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
    fallback: DOH_FALLBACK
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
      QUIC: { ports: [443] }
    },
    "force-domain": ALL_STRICT_SNIFFER_FORCE_DOMAINS,
    "skip-domain": SNIFFER_SKIP_DOMAINS
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
    udp: true
  };
}

// 在按 `name` 命名的数组项中查找单个条目。
function findNamedItem(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return items[i];
  }
  return null;
}

// 按名称查找单个代理节点。
function findProxyByName(proxies, proxyName) {
  return findNamedItem(proxies, proxyName);
}

// 按名称查找单个代理组。
function findProxyGroupByName(proxyGroups, groupName) {
  return findNamedItem(proxyGroups, groupName);
}

// 从代理组列表中移除同名代理组。
function removeProxyGroupByName(proxyGroups, groupName) {
  for (var i = proxyGroups.length - 1; i >= 0; i--) {
    if (proxyGroups[i].name === groupName) proxyGroups.splice(i, 1);
  }
}

// 清理旧版遗留代理组，避免旧配置残留影响当前行为。
function removeLegacyProxyGroups(proxyGroups) {
  for (var i = 0; i < LEGACY_PROXY_GROUP_NAMES.length; i++) {
    removeProxyGroupByName(proxyGroups, LEGACY_PROXY_GROUP_NAMES[i]);
  }
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
    tolerance: 50
  });
}

// 向主配置注入家宽出口和官方中转两个 MiyaIP 节点。
function injectMiyaProxies(config, miyaCredentials) {
  var miyaProxies = [
    buildMiyaProxy(miyaCredentials, NODE_NAMES.relay, miyaCredentials.relay),
    buildMiyaProxy(
      miyaCredentials,
      NODE_NAMES.transit,
      miyaCredentials.transit
    )
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
      regionRegex
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
      throw createUserError(
        "manualNode 未命中现有节点或代理组: " +
          relayTarget +
          "，请改成 Clash Party 中实际存在的节点名或留空自动选择"
      );
    }
    return relayTarget;
  }

  relayTarget = ensureRegionGroup(config, region, GROUP_NAME_SUFFIXES.relay, true);
  if (!relayTarget) {
    throw createUserError(
      "未找到可用的 " +
        region +
        " 跳板节点或代理组，请检查 chainRegion 是否与订阅地区一致，或显式填写 manualNode"
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
    GROUP_NAME_SUFFIXES.chain
  );

  if (!findProxyGroupByName(config["proxy-groups"], chainGroupName)) {
    config["proxy-groups"].push({
      name: chainGroupName,
      type: "select",
      proxies: [NODE_NAMES.transit, NODE_NAMES.relay]
    });
  }

  return chainGroupName;
}

// 统一解析本轮注入所需的关键目标，减少主流程里的状态分散。
function resolveRoutingTargets(config, region, manualNode) {
  var relayTarget = resolveRelayTarget(config, region, manualNode);
  var chainGroupName = ensureChainGroup(config, region);
  return {
    relayTarget: relayTarget,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName
  };
}

// 把代理链路绑定与管理规则注入收口到一个装配步骤。
function applyManagedRouting(config, routingTargets) {
  bindDialerProxy(config, routingTargets.relayTarget);
  injectManagedRules(
    config,
    routingTargets.strictAiTarget,
    routingTargets.chainGroupName
  );
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
function buildManagedRules(strictAiTarget, chainGroupName) {
  return buildStrictChainRules(strictAiTarget)
    .concat(buildGeneralChainRules(chainGroupName))
    .concat(buildDirectRules());
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
  strictAiTarget,
  chainGroupName
) {
  var managedRules = buildManagedRules(strictAiTarget, chainGroupName);
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
  target
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
function addTypedRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  values,
  ruleType,
  target
) {
  for (var i = 0; i < values.length; i++) {
    addRuleIfNotExists(
      ruleLines,
      seenRuleIdentities,
      ruleType,
      values[i],
      target
    );
  }
}

// 批量生成 `DOMAIN-SUFFIX` 规则并完成批内去重。
function addSuffixRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  domains,
  target
) {
  var suffixes = [];
  for (var i = 0; i < domains.length; i++) {
    suffixes.push(toSuffix(domains[i]));
  }
  addTypedRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    suffixes,
    "DOMAIN-SUFFIX",
    target
  );
}

// 批量生成 `PROCESS-NAME` 规则并完成批内去重。
function addProcessRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  processNames,
  target
) {
  addTypedRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    processNames,
    "PROCESS-NAME",
    target
  );
}

// 按当前用户选项返回应纳入严格 AI 路由的进程分组。
function buildStrictProcessGroups() {
  var processGroups = [ROUTING_PROCESS_SOURCES.strictBase];
  if (USER_OPTIONS.enableAiCliProcessProxy) {
    processGroups.push(
      excludeStrings(
        ROUTING_PROCESS_SOURCES.strictOptionalAiCli,
        ALL_DIRECT_PROCESS_NAMES
      )
    );
  }
  return processGroups;
}

// 按当前用户选项返回应继续使用普通链式代理的进程分组。
function buildGeneralChainProcessGroups() {
  if (!USER_OPTIONS.enableBrowserProcessProxy) return [];
  return [ROUTING_PROCESS_SOURCES.generalBrowser];
}

// 统一生成严格 AI 路由规则，按用途分类收拢输入，避免重复或冲突。
function buildStrictChainRules(strictAiTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildStrictProcessGroups();
  var i;

  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      processGroups[i],
      strictAiTarget
    );
  }

  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    ROUTING_DOMAIN_SOURCES.strict.all,
    strictAiTarget
  );
  return ruleLines;
}

// 生成非严格链式代理规则，保持既有浏览器与媒体行为。
function buildGeneralChainRules(chainGroupName) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildGeneralChainProcessGroups();
  var i;

  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      processGroups[i],
      chainGroupName
    );
  }

  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    ROUTING_DOMAIN_SOURCES.generalChain,
    chainGroupName
  );

  return ruleLines;
}

// 生成域内直连、域外应用直连和网络地址直连规则。
function buildDirectRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var directNetworkRules = [];
  var directDomainGroups = ROUTING_DOMAIN_SOURCES.direct.domestic.concat(
    ROUTING_DOMAIN_SOURCES.direct.overseasApps
  );
  var i;

  for (i = 0; i < ALL_DIRECT_NETWORK_RULES.length; i++) {
    directNetworkRules.push({
      type: ALL_DIRECT_NETWORK_RULES[i].type,
      value: ALL_DIRECT_NETWORK_RULES[i].value,
      target: ALL_DIRECT_NETWORK_RULES[i].target,
      option: "no-resolve"
    });
  }

  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, directNetworkRules);
  for (i = 0; i < directDomainGroups.length; i++) {
    addSuffixRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      directDomainGroups[i],
      RULE_TARGET_DIRECT
    );
  }
  return ruleLines;
}

// 断言单条管理规则已经按预期目标写入最终配置。
function assertManagedRuleTarget(ruleLines, type, value, target) {
  var ruleLine = type + "," + value + "," + target;
  if (ruleLines.indexOf(ruleLine) >= 0) return;
  throw createUserError(
    "关键规则未正确写入: " + ruleLine + "，请检查 chainRegion、manualNode 和订阅代理组"
  );
}

// 验证关键 AI 规则目标，避免静默泄漏或错误地区回退。
function validateManagedRouting(config, routingTargets) {
  var i;

  for (i = 0; i < LEGACY_PROXY_GROUP_NAMES.length; i++) {
    if (findProxyGroupByName(config["proxy-groups"], LEGACY_PROXY_GROUP_NAMES[i])) {
      throw createUserError(
        "遗留旧版代理组未被清理: " +
          LEGACY_PROXY_GROUP_NAMES[i] +
          "，请检查当前覆写脚本是否仍在重复注入旧规则"
      );
    }
  }

  if (routingTargets.strictAiTarget !== routingTargets.chainGroupName) {
    throw createUserError(
      "域外 AI 与支撑平台未直接指向当前 chainRegion 出口，请检查 chainRegion 或代理组注入逻辑"
    );
  }

  for (i = 0; i < MANAGED_RULE_ASSERTIONS.length; i++) {
    assertManagedRuleTarget(
      config.rules,
      MANAGED_RULE_ASSERTIONS[i].type,
      MANAGED_RULE_ASSERTIONS[i].value,
      routingTargets.strictAiTarget
    );
  }
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.replace("+.", "");
}

// 读取并移除注入到 `config._miya` 的 MiyaIP 凭证。
function takeMiyaCredentials(config) {
  if (!config._miya) {
    throw createUserError(
      "缺少 config._miya，请确保 MiyaIP 凭证.js 已启用且排序在本脚本之前"
    );
  }
  var miyaCredentials = config._miya;
  delete config._miya; // 防止凭证输出到最终配置
  return miyaCredentials;
}

// 按初始化、DNS/Sniffer、代理链路、规则注入、最终校验的顺序装配输出配置。
function main(config) {
  var miyaCredentials = takeMiyaCredentials(config);
  var routingTargets;

  initializeManagedConfig(config);
  applyDnsAndSniffer(config);
  injectMiyaProxies(config, miyaCredentials);

  routingTargets = resolveRoutingTargets(
    config,
    USER_OPTIONS.chainRegion,
    USER_OPTIONS.manualNode
  );
  applyManagedRouting(config, routingTargets);
  validateManagedRouting(config, routingTargets);

  return config;
}
