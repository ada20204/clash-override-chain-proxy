/**
 * Clash 家宽IP-链式代理覆写脚本
 *
 * 作用：
 * 1. 注入 MiyaIP 链式代理节点、AI 家宽出口组，以及媒体地区组。
 * 2. 把域外 AI、支撑平台、AI CLI 与受管浏览器稳定绑定到 `chainRegion` 出口。
 * 3. 把社交和流媒体绑定到 `mediaRegion`，与家宽链路脱钩。
 * 4. 覆写 DNS、Sniffer 和 DIRECT 保留规则，并在收尾阶段校验关键目标。
 *
 * 架构（自顶向下）：
 *   USER_OPTIONS     用户可调参数
 *   BASE             运行期常量（地区、节点名、组名后缀、DNS、规则前缀）
 *   SOURCE_*         原始分类的裸 `+.domain` 列表。按路由意图拆成顶层常量：
 *                    - SOURCE_APPLE
 *                    - SOURCE_CHAIN_PLATFORM / SOURCE_CHAIN_AI
 *                    - SOURCE_MEDIA
 *                    - SOURCE_DIRECT_DOMESTIC_AI / SOURCE_DIRECT_DOMESTIC_OFFICE
 *                    - SOURCE_DIRECT_OVERSEAS_APPS
 *                    - SOURCE_AI_EGRESS_VALIDATION
 *                    - SOURCE_SNIFFER_FORCE_BASE / SOURCE_SNIFFER_SKIP_BASE
 *   SOURCE_PROCESSES / SOURCE_NETWORK_RULES  进程与网络地址
 *   EXPECTED_ROUTES  路由样本表（toChain/toMedia），派生校验目标与测试期望
 *   POLICY           策略表：pattern + route/dnsZone/sniffer/fakeIp/fallbackFilter
 *                    所有派生视图（strict/general/direct/sniffer）均从 POLICY 投影
 *   DERIVED          从 POLICY 投影出的数据视图（patterns + processNames + networkRules），
 *                    供下面的 build-/write- 系函数直接读取
 *   builder/writer/resolver/assert  按动词前缀系统化：
 *     build*         纯产出（返回值，无副作用）
 *     resolve*       读取并计算（可能触发幂等写入作为副产物）
 *     write*         写入 config（副作用为主）
 *     assert*        运行期断言
 *   main(config)     装配顺序：容器初始化 → DNS/Sniffer → MiyaIP 节点 →
 *                    路由目标解析 → 规则写入 → 校验
 *
 * 依赖：
 * - 需先执行 `MiyaIP 凭证.js`，向 `config._miya` 注入凭证。
 *
 * 兼容性：
 * - 运行环境为 Clash Party 的 JavaScriptCore。
 * - 使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串、
 *   展开语法、`Object.values()`、`Object.fromEntries()` 等 ES6+ 特性。
 *
 * @version 9.0
 */

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

var USER_OPTIONS = {
  chainRegion: "SG", // AI 家宽出口前一跳地区，可选 US / JP / HK / SG
  mediaRegion: "US", // 媒体默认地区，可选 US / JP / HK / SG
  routeBrowserToChain: true, // 是否让受管浏览器按应用名继续强制走 chainRegion
  routeAiCliToChain: true // 是否让常见 AI CLI 按应用名继续强制走 chainRegion
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// 所有运行期稳定常量的单一来源：地区、节点名、组名后缀、DoH 服务器、规则前缀。
var BASE = {
  regions: {
    US: { regex: /🇺🇸|美国|^US[|丨\- ]/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|^JP[|丨\- ]/i, label: "日本", flag: "🇯🇵" },
    HK: { regex: /🇭🇰|香港|^HK[|丨\- ]/i, label: "香港", flag: "🇭🇰" },
    SG: { regex: /🇸🇬|新加坡|^SG[|丨\- ]/i, label: "新加坡", flag: "🇸🇬" }
  },
  nodeNames: {
    relay: "自选节点 + 家宽IP",
    transit: "MiyaIP（官方中转）"
  },
  groupNames: {
    nodeSelection: "节点选择" // 订阅里托管的全局选择组
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  rulePrefixes: {
    match: "MATCH," // Clash 兜底规则固定前缀
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  miyaProxyNameKeyword: "MiyaIP",
  groupNameSuffixes: {
    relay: "-链式代理.跳板",
    chain: "-链式代理.家宽IP出口",
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
    ],
    openaiGeosite: "geosite:openai" // nameserver-policy 专用 geosite 键
  }
};

// `fallback` 依赖已定义的 `overseas`，单独成行可避免重复写同一组域外 DoH。
BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 模式字面量（SOURCE_*）
// ---------------------------------------------------------------------------

// 按路由意图拆成若干顶层常量，每块就是一个语义桶。
// 路由 / DNS / sniffer 等行为在下面的 POLICY 层统一注入，这里只维护"谁属于哪个业务桶"。
// 转成规则时由 `toSuffix` 去掉 `+.` 前缀。

// ---------- Apple（fake-ip 绕过 + 境内 DoH，无路由规则） ----------
var SOURCE_APPLE = {
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

// ---------- Chain · 支撑平台（AI 登录 / 开发 / 文档） ----------
var SOURCE_CHAIN_PLATFORM = {
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
};

// ---------- Chain · AI 服务本身 ----------
var SOURCE_CHAIN_AI = {
  anthropic: [
    "+.claude.ai",
    "+.claude.com",
    "+.anthropic.com",
    "+.claudeusercontent.com",
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
    "+.labs.google"
  ],
  google_antigravity: [
    "+.antigravity.google",
    "+.antigravity-ide.com" // Antigravity IDE 的非 google 子域资源站
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
    "+.grok.com"
  ],
  immersivetranslate: [
    "+.immersivetranslate.com"
  ]
};

// ---------- Media（独立地区组，不走家宽链路） ----------
var SOURCE_MEDIA = {
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

// ---------- Direct · 境内 AI（域内 DoH + 直连） ----------
var SOURCE_DIRECT_DOMESTIC_AI = {
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

// ---------- Direct · 境内办公协作（域内 DoH + 直连） ----------
var SOURCE_DIRECT_DOMESTIC_OFFICE = {
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

// ---------- Direct · 域外应用（直连 + 域外 DoH + skip-domain） ----------
var SOURCE_DIRECT_OVERSEAS_APPS = {
  tailscale: [
    "+.tailscale.com",
    "+.tailscale.io",
    "+.ts.net"
  ],
  typeless: [
    "+.typeless.com"
  ]
};

// ---------- Policy · AI 出口验证 ----------
// 这些域名被刻意路由到 AI 家宽出口，用于核验出口 IP（ping0.cc / ipinfo.io）
// 或覆盖 AI 常用的 CF CDN 子域（cdn.cloudflare.net）。它们同时通过 strict.all 参与
// DNS overseas 解析与 fake-ip fallback 过滤。
//
// 注意：`+.cdn.cloudflare.net` 只覆盖 Cloudflare 官方基础设施子域（如 workers.dev 回源、R2），
// 不会波及普通 CF 前置的第三方网站——第三方站点通常以自有域名 fronted，DNS 不命中
// `cdn.cloudflare.net`。这是"为 AI 出口让路"的小范围策略，不会显著影响域内访问普通 CF 站点。
var SOURCE_AI_EGRESS_VALIDATION = [
  "+.cdn.cloudflare.net",
  "+.ping0.cc",
  "+.ipinfo.io"
];

// ---------- Policy · Sniffer 强制 / 跳过 ----------
var SOURCE_SNIFFER_FORCE_BASE = [
  "+.cloudflare.com",
  "+.cdn.cloudflare.net"
];
var SOURCE_SNIFFER_SKIP_BASE = [
  "+.push.apple.com",
  "+.apple.com",
  "+.lan",
  "+.local",
  "+.localhost"
];

// 原始进程分类，目前只维护 AI 与浏览器两类——两者最终都会路由到链式代理出口。
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
        // macOS PROCESS-NAME 匹配 Bundle 可执行名，不含 `.app` 后缀。
        // 未列入此处的应用：
        //   - Claude Code / URL Handler 都以 `claude` 运行，统一通过 aiCli 命中。
        //   - Antigravity 的 Bundle 可执行名是 `Electron`，无法按进程名精确匹配，改走域名规则。
        "Quotio"
      ]
    },
    aiCli: ["claude", "gemini", "codex"],
    browser: {
      apps: [
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

// 路由样本：声明"这些具体的域名 / 进程必须落到这个出口"。运行期 assertRuleTargetBatch
// 逐条核对规则命中；加载期 assertExpectedRoutesCoverage 核对样本没有脱离 SOURCE_* 源数据；
// `tests/validate.js` 直接读 sandbox.EXPECTED_ROUTES 作为端到端期望。
// 更新时只改这一处，校验与测试同步跟进。
//
// 字段：
//   domains       以 DOMAIN-SUFFIX 命中的裸域名
//   processNames  始终注入的进程名（受管 App）
//   cliNames      CLI 可执行名，仅当 shouldRouteAiCliToChain() 启用时校验
var EXPECTED_ROUTES = {
  toChain: {
    domains: [
      "claude.ai",
      "chatgpt.com",
      "gemini.google.com",
      "perplexity.ai",
      "google.com"
    ],
    processNames: ["Claude"],
    cliNames: ["claude", "codex"]
  },
  toMedia: {
    domains: ["youtube.com", "x.com"]
  }
};

// 原始网络地址规则，目前只覆盖直连（Tailscale CGNAT 网段、DNS 节点、Tailscale IPv6）。
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

// 约束：`+.` 前缀 + 一或多个标签（字母/数字/连字符，不以 `-` 起止），标签间用单个 `.` 分隔，
// 禁止 `*`、连续点、首尾点等通配或畸形写法。单标签（如 +.lan）允许。
var PATTERN_SHAPE = /^\+\.[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

// 断言所有模式符合 `+.domain` 形状，拦截漏写前缀或通配符滥用。
function assertPatternsHavePlusPrefix(patterns) {
  for (var i = 0; i < patterns.length; i++) {
    if (!PATTERN_SHAPE.test(patterns[i])) {
      throw createUserError("pattern 形状非法（应为 +.domain）: " + patterns[i]);
    }
  }
}

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.indexOf("+.") === 0
    ? domainPattern.substring(2)
    : domainPattern;
}

// 把按类别分组的域名模式对象展平成单个数组并去重。
function flattenGroupedPatterns(groupedPatterns) {
  var flattenedPatterns = [];
  Object.keys(groupedPatterns).forEach(function (groupName) {
    flattenedPatterns.push.apply(flattenedPatterns, groupedPatterns[groupName]);
  });
  return uniqueStrings(flattenedPatterns);
}

function createUserError(message) {
  return new Error(message);
}

// 是否让常见 AI CLI 继续按应用名强制走 chainRegion。
function shouldRouteAiCliToChain() {
  return USER_OPTIONS.routeAiCliToChain !== false;
}

// 是否让受管浏览器继续按应用名强制走 chainRegion。
function shouldRouteBrowserToChain() {
  return USER_OPTIONS.routeBrowserToChain !== false;
}

// ---------------------------------------------------------------------------
// 策略表（POLICY）与派生分类
// ---------------------------------------------------------------------------

// POLICY 是所有域名模式的**单一权威来源**：每条 entry 同时声明路由、DNS 分区、
// sniffer 行为、fake-ip 绕过、fallback-filter 归属。所有派生视图都从 POLICY 投影，
// 避免"某域名在哪里被路由/走哪个 DoH/是否强制嗅探"的决策散落在多个 builder 里。
//
// 条目字段：
//   key          调试与断言用的稳定标识（唯一）
//   patterns     `+.domain` 模式数组（已去重）
//   route        "chain" | "media" | "direct"，省略表示无路由规则（仅 sniffer/DNS）
//   routeBucket  可选子桶（如 "ai" / "support" / "validation" / "direct.domestic.ai"），
//                保持 DNS 策略与规则段的细粒度
//   dnsZone      "overseas" | "domestic"，省略则不进 nameserver-policy
//   sniffer      "force" | "skip"，省略表示不参与 sniffer 配置
//   fakeIpBypass true 表示进入 fake-ip-filter（解析真实 IP）
//   fallbackFilter true 表示进入 DNS fallback-filter.domain
//
// 冲突解决：同一 pattern 若同时出现在 direct 条目与 chain/media 条目中，direct 胜出
// （route 规则生成时 chain/media 会 excludeStrings(directAll)）。
function buildPolicy() {
  return [
    {
      key: "apple", patterns: flattenGroupedPatterns(SOURCE_APPLE),
      dnsZone: "domestic", fakeIpBypass: true
    },

    {
      key: "chain.support", patterns: flattenGroupedPatterns(SOURCE_CHAIN_PLATFORM),
      route: "chain", routeBucket: "support",
      dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.ai", patterns: flattenGroupedPatterns(SOURCE_CHAIN_AI),
      route: "chain", routeBucket: "ai",
      dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.validation",
      patterns: uniqueStrings(SOURCE_AI_EGRESS_VALIDATION.slice()),
      route: "chain", routeBucket: "validation",
      dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },

    {
      key: "media", patterns: flattenGroupedPatterns(SOURCE_MEDIA),
      route: "media", dnsZone: "overseas", fallbackFilter: true
    },

    {
      key: "direct.overseasApps",
      patterns: flattenGroupedPatterns(SOURCE_DIRECT_OVERSEAS_APPS),
      route: "direct", routeBucket: "direct.overseasApps",
      dnsZone: "overseas", sniffer: "skip", fallbackFilter: true
    },
    {
      key: "direct.domestic.ai",
      patterns: flattenGroupedPatterns(SOURCE_DIRECT_DOMESTIC_AI),
      route: "direct", routeBucket: "direct.domestic.ai", dnsZone: "domestic"
    },
    {
      key: "direct.domestic.office",
      patterns: flattenGroupedPatterns(SOURCE_DIRECT_DOMESTIC_OFFICE),
      route: "direct", routeBucket: "direct.domestic.office", dnsZone: "domestic"
    },

    {
      key: "sniffer.force.base",
      patterns: uniqueStrings(SOURCE_SNIFFER_FORCE_BASE.slice()),
      sniffer: "force"
    },
    {
      key: "sniffer.skip.base",
      patterns: uniqueStrings(SOURCE_SNIFFER_SKIP_BASE.slice()),
      sniffer: "skip"
    }
  ];
}

var POLICY = buildPolicy();

// 加载期断言：每条 POLICY 条目的 patterns 都符合 `+.domain` 形状。
(function () {
  for (var i = 0; i < POLICY.length; i++) {
    assertPatternsHavePlusPrefix(POLICY[i].patterns);
  }
})();

// 投影工具：对每条 POLICY 跑断言函数，把命中的 patterns 合并去重返回。
function projectPolicyPatterns(predicate) {
  var result = [];
  for (var i = 0; i < POLICY.length; i++) {
    if (predicate(POLICY[i])) result.push.apply(result, POLICY[i].patterns);
  }
  return uniqueStrings(result);
}

// 常用断言工厂，命名化以替代匿名函数。
function matchRouteBucket(bucket) {
  return function (entry) { return entry.routeBucket === bucket; };
}
function matchRoute(route) {
  return function (entry) { return entry.route === route; };
}
function matchSniffer(mode) {
  return function (entry) { return entry.sniffer === mode; };
}
function matchSnifferOnly(mode) {
  return function (entry) { return entry.sniffer === mode && !entry.route; };
}
function matchFakeIpBypass(entry) { return entry.fakeIpBypass === true; }
function matchFallbackFilter(entry) { return entry.fallbackFilter === true; }

// 从 POLICY 投影派生 `patterns` 视图。保留既有消费者的字段路径以免改动调用侧。
function buildDerivedPatterns() {
  var directAll = projectPolicyPatterns(matchRoute("direct"));

  function strictBucket(bucket) {
    return excludeStrings(projectPolicyPatterns(matchRouteBucket(bucket)), directAll);
  }
  var strict = {
    ai: strictBucket("ai"),
    support: strictBucket("support"),
    validation: strictBucket("validation")
  };
  strict.all = mergeStringGroups([strict.ai, strict.support, strict.validation]);

  var general = {
    media: excludeStrings(projectPolicyPatterns(matchRoute("media")), directAll)
  };

  var directDomesticAi = projectPolicyPatterns(matchRouteBucket("direct.domestic.ai"));
  var directDomesticOffice = projectPolicyPatterns(matchRouteBucket("direct.domestic.office"));
  var directOverseasApps = projectPolicyPatterns(matchRouteBucket("direct.overseasApps"));
  var directDomesticGroups = [directDomesticAi, directDomesticOffice];
  var directGroups = directDomesticGroups.concat([directOverseasApps]);

  // sniffer.force 与 strict.all 有语义重叠：chain 条目默认参与强制嗅探，但这些
  // 模式已被 direct 排除后存在于 strict.all 中。额外再并入"仅 sniffer"条目。
  var sniffer = {
    force: mergeStringGroups([projectPolicyPatterns(matchSnifferOnly("force")), strict.all]),
    skip: projectPolicyPatterns(matchSniffer("skip"))
  };

  return {
    apple: projectPolicyPatterns(matchFakeIpBypass),
    direct: {
      domestic: { ai: directDomesticAi, office: directDomesticOffice, groups: directDomesticGroups },
      overseasApps: directOverseasApps,
      groups: directGroups
    },
    strict: strict,
    general: general,
    sniffer: sniffer
  };
}

// 从 SOURCE_PROCESSES 展开出"严格 AI"和"链式浏览器"两类进程入口。
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

// 判断裸域是否被一组 `+.xxx` 模式覆盖（等值或作为子域）。
function isDomainCoveredBySuffixPatterns(domain, suffixPatterns) {
  for (var i = 0; i < suffixPatterns.length; i++) {
    var suffix = toSuffix(suffixPatterns[i]);
    if (domain === suffix) return true;
    var tail = "." + suffix;
    if (
      domain.length > tail.length &&
      domain.lastIndexOf(tail) === domain.length - tail.length
    ) {
      return true;
    }
  }
  return false;
}

// 断言每个样本域名 / 进程都能在对应的 DERIVED 源集合中找到覆盖，防止样本与源头漂移。
function assertExpectedRoutesCoverage() {
  var i;
  var sample;

  for (i = 0; i < EXPECTED_ROUTES.toChain.domains.length; i++) {
    sample = EXPECTED_ROUTES.toChain.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.strict.all)) {
      throw createUserError("route 样本未被 strict 源覆盖: " + sample);
    }
  }

  for (i = 0; i < EXPECTED_ROUTES.toMedia.domains.length; i++) {
    sample = EXPECTED_ROUTES.toMedia.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.general.media)) {
      throw createUserError("route 样本未被 media 源覆盖: " + sample);
    }
  }

  var strictProcLookup = buildStringLookup(
    DERIVED.processNames.strict.base.concat(DERIVED.processNames.strict.optionalAiCli)
  );
  var procSamples = EXPECTED_ROUTES.toChain.processNames
    .concat(EXPECTED_ROUTES.toChain.cliNames);
  for (i = 0; i < procSamples.length; i++) {
    if (!strictProcLookup[procSamples[i]]) {
      throw createUserError("route 样本进程未在 strict 源中: " + procSamples[i]);
    }
  }
}

assertExpectedRoutesCoverage();

// 把字符串数组映射为 { type, value } 规则目标列表。
function buildValidationTargets(ruleType, values) {
  var targets = [];
  for (var i = 0; i < values.length; i++) {
    targets.push({ type: ruleType, value: values[i] });
  }
  return targets;
}

// 校验目标从 `EXPECTED_ROUTES.toChain` 派生，避免校验与源数据脱钩。
function buildStrictValidationTargets() {
  var samples = EXPECTED_ROUTES.toChain;
  var validationTargets = buildValidationTargets("DOMAIN-SUFFIX", samples.domains)
    .concat(buildValidationTargets("PROCESS-NAME", samples.processNames));
  if (shouldRouteAiCliToChain()) {
    // Claude Code CLI 与 URL Handler 都以 `claude` 可执行名运行，开关一旦关闭校验也随之撤销。
    validationTargets = validationTargets.concat(
      buildValidationTargets("PROCESS-NAME", samples.cliNames)
    );
  }
  return validationTargets;
}

// 校验媒体域名是否命中独立媒体组选区。
function buildMediaValidationTargets() {
  return buildValidationTargets("DOMAIN-SUFFIX", EXPECTED_ROUTES.toMedia.domains);
}

// 校验受管浏览器进程是否继续命中链式代理出口，每个受管 App 都校验主进程名。
function buildBrowserValidationTargets() {
  if (!shouldRouteBrowserToChain()) return [];
  var targets = [];
  var apps = SOURCE_PROCESSES.chain.browser.apps;
  for (var i = 0; i < apps.length; i++) {
    targets.push({ type: "PROCESS-NAME", value: apps[i] });
  }
  return targets;
}

// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

// 把脚本生成的 DNS 和域名嗅探配置写入主配置。
function writeDnsAndSniffer(config, derived) {
  config.dns = buildDnsConfig(derived);
  config.sniffer = buildSnifferConfig(derived);
}

// 把一组域名统一绑定到同一套 DoH 服务器。
function assignNameserverPolicyDomains(policy, domains, dohServers) {
  for (var i = 0; i < domains.length; i++) {
    policy[domains[i]] = dohServers;
  }
}

// 把派生字段路径按 DNS 分区收拢到一张表；新增类别只需在这里加一行，无需动循环逻辑。
// zone: "overseas" = 域外 DoH，"domestic" = 域内 DoH。
function buildNameserverPolicyTable(patterns) {
  return [
    { source: patterns.strict.support, zone: "overseas", note: "严格支撑平台" },
    { source: patterns.strict.ai, zone: "overseas", note: "AI 服务" },
    { source: patterns.strict.validation, zone: "overseas", note: "出口验证域名" },
    { source: patterns.general.media, zone: "overseas", note: "媒体组选区" },
    { source: patterns.direct.overseasApps, zone: "overseas", note: "域外直连应用" },
    { source: patterns.apple, zone: "domestic", note: "Apple 服务" },
    { source: patterns.direct.domestic.ai, zone: "domestic", note: "域内 AI" },
    { source: patterns.direct.domestic.office, zone: "domestic", note: "域内办公软件" }
  ];
}

// 构建不同域名分类对应的 `nameserver-policy` 映射。
function buildNameserverPolicy(derived) {
  var dohByZone = { overseas: BASE.dns.overseas, domestic: BASE.dns.domestic };
  var policy = {};
  policy[BASE.dns.openaiGeosite] = dohByZone.overseas;

  var table = buildNameserverPolicyTable(derived.patterns);
  for (var i = 0; i < table.length; i++) {
    var entry = table[i];
    var dohServers = dohByZone[entry.zone];
    if (!dohServers) throw createUserError("nameserver-policy 未知 zone: " + entry.zone);
    assignNameserverPolicyDomains(policy, entry.source, dohServers);
  }

  return policy;
}

// 构建需要绕过 `fake-ip` 的域名白名单。
// 风格约定：能用 `+.` 前缀的统一用 `+.`（匹配域名本身与全部子域）；
// 仅中部通配（如 `time.*.com`、`xbox.*.microsoft.com`、`stun.*.*`）才保留 glob，
// 因为 `+.` 不支持中段通配。
function buildDnsFakeIpFilter(derived) {
  var localNetworkDomains = [
    "+.lan",
    "+.local",
    "+.localhost",
    "localhost.ptlogin2.qq.com"
  ];
  var timeSyncDomains = [
    "time.*.com", // 中部通配：保留 glob
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "ntp1.aliyun.com",
    "pool.ntp.org",
    "+.pool.ntp.org"
  ];
  var connectivityTestDomains = [
    "+.msftconnecttest.com", // 覆盖裸域与所有子域（含 www.）
    "+.msftncsi.com"
  ];
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com", // 中部通配：保留 glob
    "+.xboxlive.com",
    "+.battlenet.com.cn",
    "+.blzstatic.cn"
  ]; // 游戏主机和游戏平台入口通常依赖真实 IP
  var stunRealtimeDomains = [
    "stun.*.*", // 中部通配：保留 glob
    "stun.*.*.*"
  ]; // 通用 STUN 常见于 WebRTC、语音和点对点连接
  var homeRouterDomains = [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "+.xiaoqiang.net"
  ]; // 本地路由器和家庭网络设备入口应返回真实 IP

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(derived.patterns.apple)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

// 构建 `fallback-filter` 使用的域名匹配列表，覆盖 AI 家宽、媒体组选区和域外直连应用。
function buildDnsFallbackFilterDomains(derived) {
  return mergeStringGroups([
    derived.patterns.strict.all,
    derived.patterns.general.media,
    derived.patterns.direct.overseasApps
  ]);
}

// 构建 Clash DNS 的 `fallback-filter` 配置对象。
function buildDnsFallbackFilter(derived) {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: buildDnsFallbackFilterDomains(derived)
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
function buildDnsConfig(derived) {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter(derived);
  dnsConfig["fallback-filter"] = buildDnsFallbackFilter(derived);
  dnsConfig["nameserver-policy"] = buildNameserverPolicy(derived);
  return dnsConfig;
}

// 构建域名嗅探配置，继续复用 AI 严格分类与直连跳过项。
function buildSnifferConfig(derived) {
  return {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      QUIC: { ports: [443] }
    },
    "force-domain": derived.patterns.sniffer.force,
    "skip-domain": derived.patterns.sniffer.skip
  };
}

// ---------------------------------------------------------------------------
// MiyaIP 代理链路与地区组选区
// ---------------------------------------------------------------------------

// 确保主配置里存在代理、代理组和规则三个容器。
function writeContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 把地区输入统一转成大写字符串键；非字符串或空串直接拒绝，便于尽早暴露配置错误。
function normalizeRegionKey(region) {
  if (typeof region !== "string" || region === "") {
    throw createUserError("chainRegion / mediaRegion 必须是非空字符串，实际: " + region);
  }
  return region.toUpperCase();
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

// 在按 `name` 命名的数组项中查找条目下标；未命中返回 -1。
function findNamedItemIndex(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return i;
  }
  return -1;
}

// 在按 `name` 命名的数组项中查找单个条目，复用下标查找避免重复遍历。
function findNamedItem(items, targetName) {
  var index = findNamedItemIndex(items, targetName);
  return index >= 0 ? items[index] : null;
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
function writeManagedGroupIntoNodeSelection(config, managedGroupName, managedGroupSuffix) {
  var nodeSelectionGroup = findProxyGroupByName(config["proxy-groups"], BASE.groupNames.nodeSelection);
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
function writeRelayIntoNodeSelection(config, relayGroupName) {
  writeManagedGroupIntoNodeSelection(
    config,
    relayGroupName,
    BASE.groupNameSuffixes.relay
  );
}

// 把当前地区的媒体组选区同步进 `节点选择`。
function writeMediaIntoNodeSelection(config, mediaGroupName) {
  writeManagedGroupIntoNodeSelection(
    config,
    mediaGroupName,
    BASE.groupNameSuffixes.media
  );
}

// 向主配置注入家宽出口和官方中转两个 MiyaIP 节点。
function writeMiyaProxies(config, miyaCredentials) {
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
function writeRegionGroup(config, region, groupNameSuffix) {
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
  var relayTarget = writeRegionGroup(config, region, BASE.groupNameSuffixes.relay);
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
  var mediaTarget = writeRegionGroup(config, region, BASE.groupNameSuffixes.media);
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
function writeDialerProxy(config, relayTarget) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (relayProxy) {
    if (relayTarget) relayProxy["dialer-proxy"] = relayTarget;
    else delete relayProxy["dialer-proxy"];
  }

  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (transitProxy) delete transitProxy["dialer-proxy"]; // 官方中转节点不挂 dialer-proxy
}

// 确保存在一个承载 MiyaIP 官方中转与家宽出口的 AI 家宽出口组。
function writeChainGroup(config, region) {
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
  writeRelayIntoNodeSelection(config, relayTarget);
  var chainGroupName = writeChainGroup(config, chainRegion);
  var mediaTarget = resolveMediaTarget(config, mediaRegion);
  writeMediaIntoNodeSelection(config, mediaTarget);
  return {
    relayTarget: relayTarget,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName,
    mediaTarget: mediaTarget
  };
}

// 把拨号代理绑定和受管规则注入收口到一个装配步骤。
function writeManagedRouting(config, routingTargets, derived) {
  writeDialerProxy(config, routingTargets.relayTarget);
  writeManagedRules(
    config,
    routingTargets.strictAiTarget,
    routingTargets.mediaTarget,
    derived
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

// 按规则标识（TYPE,value）首次出现即保留，丢弃后续同标识行，解决跨段重复。
function dedupeRulesByIdentity(ruleLines) {
  var deduped = [];
  var seen = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var identity = getRuleIdentity(ruleLines[i]);
    if (identity === null) {
      deduped.push(ruleLines[i]);
      continue;
    }
    if (seen[identity]) continue;
    seen[identity] = true;
    deduped.push(ruleLines[i]);
  }
  return deduped;
}

// 按固定优先级拼出直连保留项、严格 AI 规则、链式浏览器规则和媒体组选区规则。
// 段内各自去重，段间顺序即优先级——首次出现的目标胜出。
function buildManagedRules(strictAiTarget, mediaTarget, derived) {
  var concatenated = buildStrictChainRules(strictAiTarget, derived)
    .concat(buildBrowserChainRules(strictAiTarget, derived))
    .concat(buildMediaRules(mediaTarget, derived))
    .concat(buildDirectRules(derived));
  return dedupeRulesByIdentity(concatenated);
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

// 将原始规则拆成"非 MATCH 兜底"与"MATCH 兜底"两段，保留后者在末尾以不破坏 Clash 兜底语义。
function splitMatchFallback(ruleLines) {
  var nonMatch = [];
  var matchTail = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var line = ruleLines[i];
    if (line.indexOf(BASE.rulePrefixes.match) === 0) {
      matchTail.push(line);
    } else {
      nonMatch.push(line);
    }
  }
  return { nonMatch: nonMatch, matchTail: matchTail };
}

// 注入管理规则并整体置顶，同时保证 MATCH 兜底始终在末尾。
function writeManagedRules(
  config,
  strictAiTarget,
  mediaTarget,
  derived
) {
  var managedRules = buildManagedRules(strictAiTarget, mediaTarget, derived);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);
  var remainingRules = filterConflictingRules(config.rules, managedRuleIdentities);
  var split = splitMatchFallback(remainingRules);

  // 管理规则置顶 → 剩余非兜底规则 → MATCH 兜底永远在最后。
  config.rules = managedRules.concat(split.nonMatch).concat(split.matchTail);
}

// 追加一批原生规则项，可附带额外参数，例如 `no-resolve`。最终去重由 `dedupeRulesByIdentity` 在段后统一处理。
function appendRawRules(ruleLines, rawRules) {
  for (var i = 0; i < rawRules.length; i++) {
    var rawRule = rawRules[i];
    var ruleLine = rawRule.type + "," + rawRule.value + "," + rawRule.target;
    if (rawRule.option) ruleLine += "," + rawRule.option;
    ruleLines.push(ruleLine);
  }
}

// 批量追加指定类型规则。
function appendTypedRules(ruleLines, values, ruleType, target) {
  for (var i = 0; i < values.length; i++) {
    ruleLines.push(ruleType + "," + values[i] + "," + target);
  }
}

// 批量追加 `DOMAIN-SUFFIX` 规则。
function appendSuffixRules(ruleLines, domains, target) {
  var suffixes = [];
  for (var i = 0; i < domains.length; i++) {
    suffixes.push(toSuffix(domains[i]));
  }
  appendTypedRules(ruleLines, suffixes, "DOMAIN-SUFFIX", target);
}

// 批量追加 `PROCESS-NAME` 规则。
function appendProcessRules(ruleLines, processNames, target) {
  appendTypedRules(ruleLines, processNames, "PROCESS-NAME", target);
}

// 按当前用户选项返回应纳入严格 AI 路由的进程分组。
function buildStrictProcessGroups(derived) {
  var processGroups = [derived.processNames.strict.base];
  if (shouldRouteAiCliToChain()) {
    processGroups.push(derived.processNames.strict.optionalAiCli);
  }
  return processGroups;
}

// 按当前用户选项返回应纳入链式代理的浏览器进程分组。
function buildBrowserChainProcessGroups(derived) {
  if (!shouldRouteBrowserToChain()) return [];
  return [derived.processNames.general.browser];
}

// 统一生成严格 AI 路由规则。段内不去重——跨段去重由 `buildManagedRules` 末端统一完成。
function buildStrictChainRules(strictAiTarget, derived) {
  var ruleLines = [];
  var processGroups = buildStrictProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], strictAiTarget);
  }
  appendSuffixRules(ruleLines, derived.patterns.strict.all, strictAiTarget);
  return ruleLines;
}

// 生成链式浏览器规则，承载按应用名强制分流的浏览器进程。
function buildBrowserChainRules(browserTarget, derived) {
  var ruleLines = [];
  var processGroups = buildBrowserChainProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], browserTarget);
  }
  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(mediaTarget, derived) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.general.media, mediaTarget);
  return ruleLines;
}

// 生成域内直连、域外应用直连和网络地址直连规则。
function buildDirectRules(derived) {
  var ruleLines = [];
  var directNetworkRules = [];
  var directPatternGroups = derived.patterns.direct.groups;
  var i;

  for (i = 0; i < derived.networkRules.direct.length; i++) {
    directNetworkRules.push({
      type: derived.networkRules.direct[i].type,
      value: derived.networkRules.direct[i].value,
      target: derived.networkRules.direct[i].target,
      option: "no-resolve"
    });
  }

  appendRawRules(ruleLines, directNetworkRules);
  for (i = 0; i < directPatternGroups.length; i++) {
    appendSuffixRules(ruleLines, directPatternGroups[i], BASE.ruleTargets.direct);
  }
  return ruleLines;
}

// 基于预构建的规则行查找表 O(1) 断言管理规则是否命中预期目标。
function assertManagedRuleTarget(ruleLineLookup, type, value, target) {
  var ruleLine = type + "," + value + "," + target;
  if (ruleLineLookup[ruleLine]) return;
  throw createUserError(
    "关键规则未正确写入: " + ruleLine + "，请检查 chainRegion / mediaRegion 和订阅代理组"
  );
}

// 判断两个字符串数组集合相等（无视顺序、不允许重复）。
function haveSameStringSet(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  var lookup = buildStringLookup(values);
  for (var i = 0; i < expectedValues.length; i++) {
    if (!lookup[expectedValues[i]]) return false;
  }
  return true;
}

// 断言三元目标关系：strictAi = chain，media ≠ chain，relay ≠ chain。
function assertRoutingTargetCoherence(routingTargets) {
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
}

// 断言跳板组与媒体组在节点/代理组中均存在。
function assertRoutingTargetsExist(config, routingTargets) {
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
}

// 断言家宽出口与官方中转节点的 dialer-proxy 状态。
function assertDialerBindings(config, routingTargets) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (!relayProxy || relayProxy["dialer-proxy"] !== routingTargets.relayTarget) {
    throw createUserError(
      "家宽出口节点未正确绑定到当前 chainRegion 跳板，请检查代理链路注入逻辑"
    );
  }
  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (!transitProxy || transitProxy["dialer-proxy"]) {
    throw createUserError(
      "官方中转节点状态异常，请检查 MiyaIP 凭证.js 和节点注入逻辑"
    );
  }
}

// 断言链式出口组 shape 与成员集合。
function assertChainGroupShape(config, chainGroupName) {
  var expectedMembers = [BASE.nodeNames.transit, BASE.nodeNames.relay];
  var chainGroup = findProxyGroupByName(config["proxy-groups"], chainGroupName);
  if (
    !chainGroup ||
    chainGroup.type !== "select" ||
    !haveSameStringSet(chainGroup.proxies || [], expectedMembers)
  ) {
    throw createUserError(
      "当前 chainRegion 的家宽出口组内容异常，请检查代理组注入逻辑"
    );
  }
}

// 断言媒体组 shape：必须是 url-test、非空、且不含 MiyaIP 节点。
function assertMediaGroupShape(config, mediaTarget) {
  var mediaGroup = findProxyGroupByName(config["proxy-groups"], mediaTarget);
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
}

// 逐条断言一批校验目标在最终规则里命中预期 target。
function assertRuleTargetBatch(ruleLineLookup, validationTargets, expectedTarget) {
  for (var i = 0; i < validationTargets.length; i++) {
    assertManagedRuleTarget(
      ruleLineLookup,
      validationTargets[i].type,
      validationTargets[i].value,
      expectedTarget
    );
  }
}

// 验证关键 AI 家宽、链式浏览器与媒体组选区规则目标，避免静默泄漏或错误地区回退。
function validateManagedRouting(config, routingTargets) {
  assertRoutingTargetCoherence(routingTargets);
  assertRoutingTargetsExist(config, routingTargets);
  assertDialerBindings(config, routingTargets);
  assertChainGroupShape(config, routingTargets.chainGroupName);
  assertMediaGroupShape(config, routingTargets.mediaTarget);

  var ruleLineLookup = buildStringLookup(config.rules);
  assertRuleTargetBatch(ruleLineLookup, buildStrictValidationTargets(), routingTargets.strictAiTarget);
  assertRuleTargetBatch(ruleLineLookup, buildBrowserValidationTargets(), routingTargets.strictAiTarget);
  assertRuleTargetBatch(ruleLineLookup, buildMediaValidationTargets(), routingTargets.mediaTarget);
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

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
// `derivedOverride` 可选；测试可传入 stub 以隔离源数据依赖，生产路径默认使用模块级 `DERIVED`。
function main(config, derivedOverride) {
  var derived = derivedOverride || DERIVED;
  var miyaCredentials = takeMiyaCredentials(config); // 先取出并隐藏凭证
  var routingTargets;

  writeContainers(config); // 初始化基础容器
  writeDnsAndSniffer(config, derived); // 先写 DNS 与 Sniffer
  writeMiyaProxies(config, miyaCredentials); // 注入 MiyaIP 节点

  routingTargets = resolveRoutingTargets(
    config,
    USER_OPTIONS.chainRegion,
    USER_OPTIONS.mediaRegion
  ); // 解析链路目标
  writeManagedRouting(config, routingTargets, derived); // 写入拨号与规则
  validateManagedRouting(config, routingTargets); // 校验关键目标

  return config;
}
