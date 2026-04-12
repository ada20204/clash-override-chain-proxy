/**
 * Clash 家宽IP-链式代理覆写脚本
 *
 * 作用：
 * 1. 注入 MiyaIP 链式代理节点、AI 家宽出口组，以及媒体地区组。
 * 2. 让域外 AI、支撑平台和受管浏览器进程稳定命中 `chainRegion` 对应的链式代理出口。
 * 3. 让媒体域名命中 `mediaRegion` 对应的普通地区组。
 * 4. 覆写 DNS、Sniffer 和 DIRECT 保留规则，并校验关键目标是否命中预期出口。
 *
 * 结构：
 * 1. 用户参数
 * 2. 基础常量
 * 3. 原始分类数据源
 * 4. 通用数据处理工具
 * 5. 派生分类与统一入口
 * 6. DNS / 代理链路 / 规则注入 / 主流程
 *
 * 依赖：
 * - 需先执行 `MiyaIP 凭证.js`，向 `config._miya` 注入凭证。
 *
 * 兼容性：
 * - 运行环境为 Clash Party 的 JavaScriptCore。
 * - 使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串、
 *   展开语法、`Object.values()`、`Object.fromEntries()` 等 ES6+ 特性。
 *
 * @version 8.12
 */

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

// 这一层只放用户手动可改的入口参数。
var USER_OPTIONS = {
  chainRegion: "SG", // AI 家宽出口前一跳地区，可选 US / JP / HK / SG
  mediaRegion: "US", // 媒体默认地区，可选 US / JP / HK / SG
  enableChainRegionBrowserProcessProxy: true, // 是否让受管浏览器按应用名继续强制走 chainRegion
  enableChainRegionAiCliProcessProxy: true // 是否让常见 AI CLI 按应用名继续强制走 chainRegion
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// 这一层只放运行期稳定常量，后续逻辑统一从 `BASE` 读取。
// 这样可以避免地区、代理组命名和 DNS 默认值在文件中多处散落。
var BASE = {
  regions: {
    US: { regex: /🇺🇸|美国|^US[\|丨\- ]/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|^JP[\|丨\- ]/i, label: "日本", flag: "🇯🇵" },
    HK: { regex: /🇭🇰|香港|^HK[\|丨\- ]/i, label: "香港", flag: "🇭🇰" },
    SG: { regex: /🇸🇬|新加坡|^SG[\|丨\- ]/i, label: "新加坡", flag: "🇸🇬" }
  },
  nodeNames: {
    relay: "自选节点 + 家宽IP",
    transit: "MiyaIP（官方中转）"
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  miyaProxyNameKeyword: "MiyaIP",
  errorPrefix: "[家宽IP-链式代理] ",
  groupNameSuffixes: {
    relay: "-链式代理-跳板",
    chain: "-链式代理-家宽IP出口",
    media: "-媒体"
  },
  dns: {
    overseas: [
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ],
    domestic: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]
  }
};

// `fallback` 依赖已定义的 `overseas`，单独成行可避免重复写同一组域外 DoH。
BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 原始分类数据源
// ---------------------------------------------------------------------------

// 这一层只放原始业务分类，不在这里混入派生路由语义。
// 带 `"+."` 的统一叫 `patterns`，转成规则时再显式转换为 suffixes。
var SOURCE_PATTERNS = {
  apple: {
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
  },
  chain: {
    platform: {
      google_core: [
        "+.google.com",
        "+.googleapis.com",
        "+.googleusercontent.com"
      ],
      google_static: [
        "+.gstatic.com",
        "+.ggpht.com",
        "+.gvt1.com",
        "+.gvt2.com"
      ],
      google_workspace: ["+.withgoogle.com"], // `googleworkspace.com` 证据不足，先不默认注入
      google_cloud: [
        "+.cloud.google.com"
      ],
      microsoft_core: [
        "+.microsoft.com",
        "+.live.com",
        "+.windows.net"
      ], // `windows.net` 作为 Microsoft 官方基础设施宽域名保留
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
      microsoft_developer: [
        "+.visualstudio.com",
        "+.vsassets.io",
        "+.vsmarketplacebadges.dev"
      ], // Microsoft 开发者与 VS Code 生态基础设施
      developer: [
        "+.github.com"
      ]
    },
    ai: {
      anthropic: [
        "+.claude.ai",
        "+.claude.com",
        "+.anthropic.com",
        "+.claudeusercontent.com",
        "+.claudemcpclient.com", // 公开证据较弱，先作为经验域名保留
        "+.servd-anthropic-website.b-cdn.net", // Anthropic 站点静态资源经验域名
        "+.clau.de" // Anthropic 官方场景使用过的短链
      ],
      openai: [
        "+.openai.com",
        "+.chatgpt.com",
        "+.sora.com",
        "+.oaiusercontent.com", // OpenAI 官方静态资源与内容分发基础设施
        "+.oaistatic.com"
      ],
      google_ai: [
        "+.gemini.google.com",
        "+.aistudio.google.com",
        "+.ai.google.dev",
        "+.generativelanguage.googleapis.com",
        "+.ai.google",
        "+.notebooklm.google",
        "+.makersuite.google.com", // 历史兼容入口，Google 已迁移到 AI Studio
        "+.deepmind.google",
        "+.labs.google",
        "+.antigravity.google",
        "+.antigravity-ide.com"
      ],
      perplexity: [
        "+.perplexity.ai",
        "+.perplexitycdn.com" // Perplexity 资源分发域名
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
    },
    media: {
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
    }
  },
  direct: {
    domestic: {
      ai: {
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
      },
      office: {
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
      }
    },
    overseasApps: {
      tailscale: [
        "+.tailscale.com",
        "+.tailscale.io",
        "+.ts.net"
      ],
      typeless: [
        "+.typeless.com"
      ]
    }
  },
  policy: {
    dnsFallbackExtra: [
      "+.cdn.cloudflare.net",
      "ping0.cc",
      "ipinfo.io"
    ],
    snifferForceBase: [
      "+.cloudflare.com",
      "+.cdn.cloudflare.net"
    ],
    snifferSkipBase: [
      "+.push.apple.com",
      "+.apple.com",
      "+.lan",
      "+.local",
      "+.localhost"
    ]
  }
};

// 这一层只放原始进程分类，当前只保留 AI 与浏览器两类。
// AI 与浏览器进程后续都会走链式代理出口。
var SOURCE_PROCESSES = {
  chain: {
    aiApps: {
      apps: [
        "Claude",
        "ChatGPT",
        "Perplexity",
        "Cursor"
      ],
      helperSuffixes: [
        "Helper"
      ],
      exact: [
        "ChatGPTHelper",
        "Claude Helper (Renderer)",
        "Claude Helper (GPU)",
        "Claude Helper (Plugin)",
        // Claude Code 在本机可见的 App / Bundle 名。
        // `claude-cli:` 深链会先命中 URL Handler，再落到同一份 `claude` 二进制。
        "Claude Code",
        "Claude Code URL Handler",
        "Antigravity.app",
        "Quotio.app",
        // "CC Switch.app"
      ]
    },
    aiCli: ["claude", "gemini", "codex"],
    browser: {
      apps: [
        // "Comet", // 不走脚本托管的媒体组选区
        "Dia",
        "Atlas",
        "Google Chrome",
        "SunBrowser"
      ],
      helperSuffixes: [
        "Helper",
        "Helper (Renderer)",
        "Helper (GPU)",
        "Helper (Plugin)",
        "Helper (Alerts)"
      ]
    }
  }
};

// 这一层只放原始网络地址规则，当前只有直连对象。
var SOURCE_NETWORK_RULES = {
  direct: [
    { type: "IP-CIDR", value: "100.64.0.0/10", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "100.100.100.100/32", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48", target: BASE.ruleTargets.direct }
  ]
};

// ---------------------------------------------------------------------------
// 通用数据处理工具
// ---------------------------------------------------------------------------

// 这一层只放纯工具函数，不承载业务分组语义。

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

// 为应用展开主进程、显式 helper，以及精确进程名。
function expandProcessNamesWithHelpers(appNames, helperSuffixes, exactProcessNames) {
  var processNames = [];
  var i;
  var j;
  var exactNames = exactProcessNames || [];

  for (i = 0; i < appNames.length; i++) {
    processNames.push(appNames[i]);
    for (j = 0; j < helperSuffixes.length; j++) {
      processNames.push(appNames[i] + " " + helperSuffixes[j]);
    }
  }

  processNames.push.apply(processNames, exactNames);
  return uniqueStrings(processNames);
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

// 把按类别分组的域名模式对象展平成单个数组并去重。
function flattenGroupedPatterns(groupedPatterns) {
  var flattenedPatterns = [];
  Object.keys(groupedPatterns).forEach(function (groupName) {
    flattenedPatterns.push.apply(flattenedPatterns, groupedPatterns[groupName]);
  });
  return uniqueStrings(flattenedPatterns);
}

// 为统一错误文案构建 Error 对象。
function createUserError(message) {
  return new Error(BASE.errorPrefix + message);
}

// 解析布尔型用户参数，优先使用新键，必要时兼容旧键。
function resolveBooleanOption(preferredValue, legacyValue, defaultValue) {
  if (typeof preferredValue === "boolean") return preferredValue;
  if (typeof legacyValue === "boolean") return legacyValue;
  return defaultValue;
}

// 是否让常见 AI CLI 继续按应用名强制走 chainRegion。
function isChainRegionAiCliProcessProxyEnabled() {
  return resolveBooleanOption(
    USER_OPTIONS.enableChainRegionAiCliProcessProxy,
    USER_OPTIONS.enableAiCliProcessProxy,
    true
  );
}

// 是否让受管浏览器继续按应用名强制走 chainRegion。
function isChainRegionBrowserProcessProxyEnabled() {
  return resolveBooleanOption(
    USER_OPTIONS.enableChainRegionBrowserProcessProxy,
    USER_OPTIONS.enableBrowserProcessProxy,
    true
  );
}

// ---------------------------------------------------------------------------
// 派生分类与统一入口
// ---------------------------------------------------------------------------

// 这一层把原始数据源收敛成共享入口，供 DNS、Sniffer、规则生成和校验复用。
// 阅读顺序保持和文件头部说明一致：先展平 patterns，再派生路由入口，最后派生进程与网络规则。

// 先把原始域名模式展平，保留业务分类，不在这一层混入路由语义。
function buildDerivedPatternsBase() {
  return {
    apple: flattenGroupedPatterns(SOURCE_PATTERNS.apple),
    chain: {
      platform: flattenGroupedPatterns(SOURCE_PATTERNS.chain.platform),
      ai: flattenGroupedPatterns(SOURCE_PATTERNS.chain.ai),
      media: flattenGroupedPatterns(SOURCE_PATTERNS.chain.media)
    },
    direct: {
      domestic: {
        ai: flattenGroupedPatterns(SOURCE_PATTERNS.direct.domestic.ai),
        office: flattenGroupedPatterns(SOURCE_PATTERNS.direct.domestic.office)
      },
      overseasApps: flattenGroupedPatterns(SOURCE_PATTERNS.direct.overseasApps)
    },
    policy: {
      dnsFallbackExtra: uniqueStrings(SOURCE_PATTERNS.policy.dnsFallbackExtra.slice()),
      snifferForceBase: uniqueStrings(SOURCE_PATTERNS.policy.snifferForceBase.slice()),
      snifferSkipBase: uniqueStrings(SOURCE_PATTERNS.policy.snifferSkipBase.slice())
    }
  };
}

// 在展平后的模式之上补齐直连、AI 家宽、媒体组选区和 Sniffer 入口。
function buildDerivedPatterns() {
  var patterns = buildDerivedPatternsBase();
  var directDomesticGroups = [
    patterns.direct.domestic.ai,
    patterns.direct.domestic.office
  ];
  var directDomesticAll = mergeStringGroups(directDomesticGroups);
  var directGroups = directDomesticGroups.concat([patterns.direct.overseasApps]);
  var directAll = mergeStringGroups([
    directDomesticAll,
    patterns.direct.overseasApps
  ]);
  var strictPatterns = {
    ai: excludeStrings(patterns.chain.ai, directAll),
    support: excludeStrings(patterns.chain.platform, directAll),
    validation: excludeStrings(
      patterns.policy.dnsFallbackExtra,
      directAll
    )
  };
  var strictAll = mergeStringGroups([
    strictPatterns.ai,
    strictPatterns.support,
    strictPatterns.validation
  ]);
  var mediaPatterns = excludeStrings(patterns.chain.media, directAll);

  patterns.direct.domestic.groups = directDomesticGroups;
  patterns.direct.groups = directGroups;
  patterns.strict = strictPatterns;
  patterns.strict.all = strictAll;
  patterns.general = {
    media: mediaPatterns
  };

  patterns.sniffer = {
    force: mergeStringGroups([
      patterns.policy.snifferForceBase,
      strictAll
    ]),
    skip: uniqueStrings(
      patterns.policy.snifferSkipBase.concat(patterns.direct.overseasApps)
    )
  };

  return patterns;
}

// 进程派生单独收口，避免和域名模式的路由语义混在一起。
// 这里统一产出“严格 AI”与“链式浏览器”两类进程入口。
function buildDerivedProcessNames() {
  var processNames = {
    ai: {
      apps: expandProcessNamesWithHelpers(
        SOURCE_PROCESSES.chain.aiApps.apps,
        SOURCE_PROCESSES.chain.aiApps.helperSuffixes,
        SOURCE_PROCESSES.chain.aiApps.exact
      ),
      cli: uniqueStrings(SOURCE_PROCESSES.chain.aiCli.slice())
    },
    browser: {
      all: expandProcessNamesWithHelpers(
        SOURCE_PROCESSES.chain.browser.apps,
        SOURCE_PROCESSES.chain.browser.helperSuffixes
      )
    }
  };

  processNames.strict = {
    base: processNames.ai.apps,
    optionalAiCli: processNames.ai.cli
  };
  processNames.general = {
    browser: processNames.browser.all
  };

  return processNames;
}

// DERIVED 是后续执行函数唯一应直接消费的派生入口。
var DERIVED = {
  patterns: buildDerivedPatterns(),
  processNames: buildDerivedProcessNames(),
  networkRules: {
    direct: SOURCE_NETWORK_RULES.direct.slice()
  }
};

// 校验目标单独成层，避免 AI 家宽与媒体组选区断言散落在函数内部。
function buildStrictValidationTargets() {
  var validationTargets = [
    { type: "DOMAIN-SUFFIX", value: "claude.ai" },
    { type: "DOMAIN-SUFFIX", value: "chatgpt.com" },
    { type: "DOMAIN-SUFFIX", value: "gemini.google.com" },
    { type: "DOMAIN-SUFFIX", value: "perplexity.ai" },
    { type: "DOMAIN-SUFFIX", value: "google.com" },
    { type: "PROCESS-NAME", value: "Claude" }
  ];

  if (isChainRegionAiCliProcessProxyEnabled()) {
    validationTargets.push({ type: "PROCESS-NAME", value: "claude" });
    // Claude Code 同时校验 Unix 可执行名与 App / URL Handler 名，避免 macOS 启动路径差异导致漏配。
    validationTargets.push({ type: "PROCESS-NAME", value: "Claude Code" });
    validationTargets.push({ type: "PROCESS-NAME", value: "Claude Code URL Handler" });
    validationTargets.push({ type: "PROCESS-NAME", value: "codex" });
  }

  return validationTargets;
}

// 校验媒体域名是否命中独立媒体组选区。
function buildMediaValidationTargets() {
  var validationTargets = [
    { type: "DOMAIN-SUFFIX", value: "youtube.com" },
    { type: "DOMAIN-SUFFIX", value: "x.com" }
  ];

  return validationTargets;
}

// 校验受管浏览器进程是否继续命中链式代理出口。
function buildBrowserValidationTargets() {
  if (!isChainRegionBrowserProcessProxyEnabled()) return [];
  return [{ type: "PROCESS-NAME", value: "Google Chrome" }];
}

// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

// 这一段负责 DNS 与 Sniffer 的组装和写入。

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
    "geosite:openai": BASE.dns.overseas
  };

  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.strict.support,
    BASE.dns.overseas
  ); // 严格支撑平台走域外 DoH
  assignNameserverPolicyDomains(policy, DERIVED.patterns.apple, BASE.dns.domestic); // Apple 走域内 DoH
  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.direct.overseasApps,
    BASE.dns.overseas
  ); // 域外应用直连固定走域外 DoH

  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.strict.ai,
    BASE.dns.overseas
  ); // AI 服务走域外 DoH
  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.strict.validation,
    BASE.dns.overseas
  ); // 出口验证域名走域外 DoH
  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.direct.domestic.ai,
    BASE.dns.domestic
  ); // 域内 AI 走域内 DoH
  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.direct.domestic.office,
    BASE.dns.domestic
  ); // 域内办公软件走域内 DoH
  assignNameserverPolicyDomains(
    policy,
    DERIVED.patterns.general.media,
    BASE.dns.overseas
  ); // 媒体组选区相关域名走域外 DoH

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
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
    "*.battlenet.com.cn",
    "*.blzstatic.cn"
  ]; // 游戏主机和游戏平台入口通常依赖真实 IP
  var stunRealtimeDomains = [
    "stun.*.*",
    "stun.*.*.*"
  ]; // 通用 STUN 常见于 WebRTC、语音和点对点连接
  var homeRouterDomains = [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "*.xiaoqiang.net"
  ]; // 本地路由器和家庭网络设备入口应返回真实 IP

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(DERIVED.patterns.apple)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

// 构建 `fallback-filter` 使用的域名匹配列表，覆盖 AI 家宽、媒体组选区和域外直连应用。
function buildDnsFallbackFilterDomains() {
  return mergeStringGroups([
    DERIVED.patterns.strict.all,
    DERIVED.patterns.general.media,
    DERIVED.patterns.direct.overseasApps
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
    nameserver: BASE.dns.domestic,
    "proxy-server-nameserver": BASE.dns.domestic,
    "direct-nameserver": BASE.dns.domestic.slice(),
    "direct-nameserver-follow-policy": true,
    fallback: BASE.dns.fallback
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

// 构建域名嗅探配置，继续复用 AI 严格分类与直连跳过项。
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
    "force-domain": DERIVED.patterns.sniffer.force,
    "skip-domain": DERIVED.patterns.sniffer.skip
  };
}

// ---------------------------------------------------------------------------
// MiyaIP 代理链路与地区组选区
// ---------------------------------------------------------------------------

// 这一段负责 MiyaIP 代理链路、链式跳板和媒体组选区的解析、组装与绑定。

// 确保主配置里存在代理、代理组和规则三个容器。
function ensureProxyContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 清空订阅原有的代理组和规则，只保留节点列表。
// 后续由脚本完整重建代理组和规则，避免订阅残留组干扰分流。
function resetSubscriptionGroupsAndRules(config) {
  config["proxy-groups"] = [];
  config.rules = [];
}

// 生成一个包含所有订阅节点（排除 MiyaIP 节点）的 `节点选择` select 组，用于兜底流量。
function ensureNodeSelectionGroup(config) {
  var allNodeNames = [];
  var managedNodeNames = [BASE.nodeNames.relay, BASE.nodeNames.transit];
  for (var i = 0; i < config.proxies.length; i++) {
    var proxy = config.proxies[i];
    if (
      proxy.name.indexOf(BASE.miyaProxyNameKeyword) < 0 &&
      managedNodeNames.indexOf(proxy.name) < 0
    ) {
      allNodeNames.push(proxy.name);
    }
  }
  upsertNamedItem(config["proxy-groups"], {
    name: "节点选择",
    type: "select",
    proxies: allNodeNames
  });
  upsertNamedItem(config["proxy-groups"], {
    name: "GLOBAL",
    type: "select",
    proxies: allNodeNames.slice()
  });
}

// 把地区输入统一转成大写字符串键。
function normalizeRegionKey(region) {
  return String(region || "").toUpperCase();
}

// 根据地区键解析地区元数据，并按需提供兜底标签。
function resolveRegionMeta(region, allowFallbackRegionLabel) {
  var regionKey = normalizeRegionKey(region);
  if (BASE.regions[regionKey]) return BASE.regions[regionKey];
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

// 在按 `name` 命名的数组项中查找条目下标。
function findNamedItemIndex(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return i;
  }
  return -1;
}

// 按名称更新或插入一个完整条目，避免沿用同名旧对象。
function upsertNamedItem(items, itemDefinition) {
  var itemIndex = findNamedItemIndex(items, itemDefinition.name);
  if (itemIndex >= 0) items[itemIndex] = itemDefinition;
  else items.push(itemDefinition);
  return itemDefinition;
}

// 按名称查找单个代理节点。
function findProxyByName(proxies, proxyName) {
  return findNamedItem(proxies, proxyName);
}

// 按名称查找单个代理组。
function findProxyGroupByName(proxyGroups, groupName) {
  return findNamedItem(proxyGroups, groupName);
}

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 收集匹配地区特征且非 MiyaIP 的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(BASE.miyaProxyNameKeyword) < 0
    ) {
      regionNodeNames.push(proxy.name);
    }
  }
  return regionNodeNames;
}

// 把地区节点列表包装成一个 `url-test` 代理组，并覆盖同名旧组。
function upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames) {
  upsertNamedItem(proxyGroups, {
    name: groupName,
    type: "url-test",
    proxies: regionNodeNames,
    url: BASE.urlTestProbeUrl,
    interval: 300,
    tolerance: 50
  });
}

// 把当前脚本生成的地区代理组同步进 `节点选择`，并剔除旧同类组。
function syncManagedGroupIntoNodeSelection(config, managedGroupName, managedGroupSuffix) {
  var nodeSelectionGroup = findProxyGroupByName(config["proxy-groups"], "节点选择");
  if (!nodeSelectionGroup || !nodeSelectionGroup.proxies) return;

  var nextProxyNames = [];
  var i;
  var proxyName;
  var managedSuffixIndex;

  for (i = 0; i < nodeSelectionGroup.proxies.length; i++) {
    proxyName = nodeSelectionGroup.proxies[i];
    managedSuffixIndex = proxyName.lastIndexOf(managedGroupSuffix);
    if (proxyName === managedGroupName) continue;
    if (
      managedSuffixIndex >= 0 &&
      managedSuffixIndex === proxyName.length - managedGroupSuffix.length
    ) {
      continue;
    }
    nextProxyNames.push(proxyName);
  }

  nextProxyNames.push(managedGroupName);
  nodeSelectionGroup.proxies = uniqueStrings(nextProxyNames);
}

// 把当前地区的链式代理跳板组同步进 `节点选择`。
function syncRelayGroupIntoNodeSelection(config, relayGroupName) {
  syncManagedGroupIntoNodeSelection(
    config,
    relayGroupName,
    BASE.groupNameSuffixes.relay
  );
}

// 把当前地区的媒体组选区同步进 `节点选择`。
function syncMediaGroupIntoNodeSelection(config, mediaGroupName) {
  syncManagedGroupIntoNodeSelection(
    config,
    mediaGroupName,
    BASE.groupNameSuffixes.media
  );
}

// 向主配置注入家宽出口和官方中转两个 MiyaIP 节点。
function injectMiyaProxies(config, miyaCredentials) {
  var miyaProxies = [
    buildMiyaProxy(miyaCredentials, BASE.nodeNames.relay, miyaCredentials.relay),
    buildMiyaProxy(
      miyaCredentials,
      BASE.nodeNames.transit,
      miyaCredentials.transit
    )
  ];

  for (var i = 0; i < miyaProxies.length; i++) {
    upsertNamedItem(config.proxies, miyaProxies[i]);
  }
}

// 仅根据订阅节点创建或修正指定地区的 `url-test` 代理组。
// 当前既用于链式跳板，也用于媒体组选区。
function ensureRegionGroup(config, region, groupNameSuffix) {
  var regionMeta = resolveRegionMeta(region, false);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames); // 用订阅地区节点创建或修正目标组

  return groupName;
}

// 解析家宽链式代理前一跳应使用的脚本跳板组。
function resolveRelayTarget(config, region) {
  var relayTarget = ensureRegionGroup(config, region, BASE.groupNameSuffixes.relay);
  if (!relayTarget) {
    throw createUserError(
      "未找到可用的 " +
        region +
        " 节点，请检查 chainRegion 是否与订阅地区一致"
    );
  }
  return relayTarget;
}

// 解析媒体应使用的普通地区组。
function resolveMediaTarget(config, region) {
  var mediaTarget = ensureRegionGroup(config, region, BASE.groupNameSuffixes.media);
  if (!mediaTarget) {
    throw createUserError(
      "未找到可用的 " +
        region +
        " 媒体节点，请检查 mediaRegion 是否与订阅地区一致"
    );
  }
  return mediaTarget;
}

// 给家宽出口节点绑定拨号前置代理，并清理官方中转节点的拨号代理。
function bindDialerProxy(config, relayTarget) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (relayProxy) {
    if (relayTarget) relayProxy["dialer-proxy"] = relayTarget;
    else delete relayProxy["dialer-proxy"];
  }

  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (transitProxy) delete transitProxy["dialer-proxy"]; // 官方中转节点不挂 dialer-proxy
}

// 确保存在一个承载 MiyaIP 官方中转与家宽出口的 AI 家宽出口组。
function ensureChainGroup(config, region) {
  var regionMeta = resolveRegionMeta(region, true);
  var chainGroupName = buildRegionGroupName(
    regionMeta,
    BASE.groupNameSuffixes.chain
  );

  upsertNamedItem(config["proxy-groups"], {
    name: chainGroupName,
    type: "select",
    proxies: [BASE.nodeNames.transit, BASE.nodeNames.relay]
  });

  return chainGroupName;
}

// 统一解析本轮注入所需的关键目标，减少主流程里的状态分散。
// 这里会同时收敛链式跳板、AI 家宽出口和媒体组选区。
function resolveRoutingTargets(config, chainRegion, mediaRegion) {
  var relayTarget = resolveRelayTarget(config, chainRegion);
  syncRelayGroupIntoNodeSelection(config, relayTarget);
  var chainGroupName = ensureChainGroup(config, chainRegion);
  var mediaTarget = resolveMediaTarget(config, mediaRegion);
  syncMediaGroupIntoNodeSelection(config, mediaTarget);
  return {
    relayTarget: relayTarget,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName,
    mediaTarget: mediaTarget
  };
}

// 把拨号代理绑定和受管规则注入收口到一个装配步骤。
function applyManagedRouting(config, routingTargets) {
  bindDialerProxy(config, routingTargets.relayTarget);
  injectManagedRules(
    config,
    routingTargets.strictAiTarget,
    routingTargets.mediaTarget
  );
}

// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

// 这一段负责受管规则的生成、去重、置顶和校验。

// 提取规则的 `"TYPE,value"` 标识。
function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;

  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;

  return ruleLine.substring(0, secondCommaIndex);
}

// 按固定优先级拼出直连保留项、严格 AI 规则、链式浏览器规则和媒体组选区规则。
function buildManagedRules(strictAiTarget, mediaTarget) {
  return buildStrictChainRules(strictAiTarget)
    .concat(buildBrowserChainRules(strictAiTarget))
    .concat(buildMediaRules(mediaTarget))
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
  mediaTarget
) {
  var managedRules = buildManagedRules(strictAiTarget, mediaTarget);
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
  var processGroups = [DERIVED.processNames.strict.base];
  if (isChainRegionAiCliProcessProxyEnabled()) {
    processGroups.push(DERIVED.processNames.strict.optionalAiCli);
  }
  return processGroups;
}

// 按当前用户选项返回应纳入链式代理的浏览器进程分组。
function buildBrowserChainProcessGroups() {
  if (!isChainRegionBrowserProcessProxyEnabled()) return [];
  return [DERIVED.processNames.general.browser];
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
    DERIVED.patterns.strict.all,
    strictAiTarget
  );
  return ruleLines;
}

// 生成链式浏览器规则，承载按应用名强制分流的浏览器进程。
function buildBrowserChainRules(browserTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildBrowserChainProcessGroups();
  var i;

  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      processGroups[i],
      browserTarget
    );
  }

  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(mediaTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};

  addSuffixRulesIfNotExists(
    ruleLines,
    seenRuleIdentities,
    DERIVED.patterns.general.media,
    mediaTarget
  );

  return ruleLines;
}

// 生成域内直连、域外应用直连和网络地址直连规则。
function buildDirectRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var directNetworkRules = [];
  var directPatternGroups = DERIVED.patterns.direct.groups;
  var i;

  for (i = 0; i < DERIVED.networkRules.direct.length; i++) {
    directNetworkRules.push({
      type: DERIVED.networkRules.direct[i].type,
      value: DERIVED.networkRules.direct[i].value,
      target: DERIVED.networkRules.direct[i].target,
      option: "no-resolve"
    });
  }

  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, directNetworkRules);
  for (i = 0; i < directPatternGroups.length; i++) {
    addSuffixRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      directPatternGroups[i],
      BASE.ruleTargets.direct
    );
  }
  ruleLines.push("MATCH,节点选择");
  return ruleLines;
}

// 断言单条管理规则已经按预期目标写入最终配置。
function assertManagedRuleTarget(ruleLines, type, value, target) {
  var ruleLine = type + "," + value + "," + target;
  if (ruleLines.indexOf(ruleLine) >= 0) return;
  throw createUserError(
    "关键规则未正确写入: " + ruleLine + "，请检查 chainRegion / mediaRegion 和订阅代理组"
  );
}

// 判断两个字符串数组是否完全一致，保留顺序敏感语义。
function haveSameStrings(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  for (var i = 0; i < values.length; i++) {
    if (values[i] !== expectedValues[i]) return false;
  }
  return true;
}

// 验证关键 AI 家宽、链式浏览器与媒体组选区规则目标，避免静默泄漏或错误地区回退。
function validateManagedRouting(config, routingTargets) {
  var i;
  var relayProxy;
  var transitProxy;
  var chainGroup;
  var mediaGroup;
  var expectedChainMembers = [BASE.nodeNames.transit, BASE.nodeNames.relay];
  var strictValidationTargets = buildStrictValidationTargets();
  var browserValidationTargets = buildBrowserValidationTargets();
  var mediaValidationTargets = buildMediaValidationTargets();

  if (routingTargets.strictAiTarget !== routingTargets.chainGroupName) {
    throw createUserError(
      "域外 AI 与支撑平台未直接指向当前 chainRegion 出口，请检查 chainRegion 或代理组注入逻辑"
    );
  }
  if (routingTargets.mediaTarget === routingTargets.chainGroupName) {
    throw createUserError(
      "媒体组选区错误复用了家宽出口组，请检查 mediaRegion 或媒体组选区注入逻辑"
    );
  }
  if (routingTargets.relayTarget === routingTargets.chainGroupName) {
    throw createUserError(
      "当前 chainRegion 跳板错误复用了家宽出口组，请检查地区代理组复用逻辑"
    );
  }
  if (!hasProxyOrGroup(config, routingTargets.relayTarget)) {
    throw createUserError(
      "当前 chainRegion 跳板不存在，请检查 chainRegion 和订阅代理组"
    );
  }
  if (!hasProxyOrGroup(config, routingTargets.mediaTarget)) {
    throw createUserError(
      "当前 mediaRegion 媒体组选区不存在，请检查 mediaRegion 和订阅代理组"
    );
  }

  relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (!relayProxy || relayProxy["dialer-proxy"] !== routingTargets.relayTarget) {
    throw createUserError(
      "家宽出口节点未正确绑定到当前 chainRegion 跳板，请检查代理链路注入逻辑"
    );
  }

  transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (!transitProxy || transitProxy["dialer-proxy"]) {
    throw createUserError(
      "官方中转节点状态异常，请检查 MiyaIP 凭证.js 和节点注入逻辑"
    );
  }

  chainGroup = findProxyGroupByName(config["proxy-groups"], routingTargets.chainGroupName);
  if (
    !chainGroup ||
    chainGroup.type !== "select" ||
    !haveSameStrings(chainGroup.proxies || [], expectedChainMembers)
  ) {
    throw createUserError(
      "当前 chainRegion 的家宽出口组内容异常，请检查代理组注入逻辑"
    );
  }

  mediaGroup = findProxyGroupByName(config["proxy-groups"], routingTargets.mediaTarget);
  if (
    !mediaGroup ||
    mediaGroup.type !== "url-test" ||
    !mediaGroup.proxies ||
    mediaGroup.proxies.length === 0 ||
    mediaGroup.proxies.indexOf(BASE.nodeNames.relay) >= 0 ||
    mediaGroup.proxies.indexOf(BASE.nodeNames.transit) >= 0
  ) {
    throw createUserError(
      "当前 mediaRegion 的媒体组选区内容异常，请检查媒体组选区注入逻辑"
    );
  }

  for (i = 0; i < strictValidationTargets.length; i++) {
    assertManagedRuleTarget(
      config.rules,
      strictValidationTargets[i].type,
      strictValidationTargets[i].value,
      routingTargets.strictAiTarget
    );
  }

  for (i = 0; i < browserValidationTargets.length; i++) {
    assertManagedRuleTarget(
      config.rules,
      browserValidationTargets[i].type,
      browserValidationTargets[i].value,
      routingTargets.strictAiTarget
    );
  }

  for (i = 0; i < mediaValidationTargets.length; i++) {
    assertManagedRuleTarget(
      config.rules,
      mediaValidationTargets[i].type,
      mediaValidationTargets[i].value,
      routingTargets.mediaTarget
    );
  }
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

// 这一段负责主流程装配，按初始化、DNS、链路、规则、校验的顺序执行。
// 主流程同时覆盖 AI 家宽出口和媒体组选区两条路径。

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
  var miyaCredentials = takeMiyaCredentials(config); // 先取出并隐藏凭证
  var routingTargets;

  ensureProxyContainers(config); // 初始化基础容器
  resetSubscriptionGroupsAndRules(config); // 清空订阅代理组和规则，由脚本完整重建
  ensureNodeSelectionGroup(config); // 生成兜底节点选择组
  applyDnsAndSniffer(config); // 先写 DNS 与 Sniffer
  injectMiyaProxies(config, miyaCredentials); // 注入 MiyaIP 节点

  routingTargets = resolveRoutingTargets(
    config,
    USER_OPTIONS.chainRegion,
    USER_OPTIONS.mediaRegion
  ); // 解析链路目标
  applyManagedRouting(config, routingTargets); // 写入拨号与规则
  validateManagedRouting(config, routingTargets); // 校验关键目标

  return config;
}
