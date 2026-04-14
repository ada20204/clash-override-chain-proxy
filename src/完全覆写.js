/**
 * Clash 家宽IP-直连覆写脚本
 *
 * 作用：
 * 1. 注入家宽IP代理节点（单节点链式），以及媒体地区组。
 * 2. 让域外 AI、支撑平台和受管浏览器进程稳定命中家宽IP出口。
 * 3. 让媒体域名命中 `mediaRegion` 对应的普通地区组。
 * 4. 覆写 DNS、Sniffer 和 DIRECT 保留规则，并校验关键目标是否命中预期出口。
 *
 * 与「链式代理」版本的区别：
 * - 单个家宽IP节点（通过 dialer-proxy → 自动选择组跳转），无 transit 节点。
 * - 适合自有家宽 HTTP/SOCKS5 代理、无需 MiyaIP 服务的场景。
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
 * - 需先执行 `家宽IP凭证.js`，向 `config._homeProxy` 注入凭证。
 *
 * 兼容性：
 * - 运行环境为 Clash Party 的 JavaScriptCore。
 * - 使用 ES5 语法，不依赖箭头函数、解构赋值、模板字符串、
 *   展开语法、`Object.values()`、`Object.fromEntries()` 等 ES6+ 特性。
 *
 * @version 1.0
 */

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

var USER_OPTIONS = {
  autoSelectGroupName: "自动选择", // 订阅中的自动选择组名（url-test），Smart 内核会自动追加 "(Smart Group)" 后缀
  enableChainRegionBrowserProcessProxy: false, // 是否让受管浏览器按应用名强制走家宽出口
  enableChainRegionAiCliProcessProxy: true    // 是否让常见 AI CLI 按应用名强制走家宽出口
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

var BASE = {
  regions: {
    HK: { regex: /🇭🇰|香港|^HK[\|丨\- ]/i, label: "香港", flag: "🇭🇰" },
    US: { regex: /🇺🇸|美国|^US[\|丨\- ]/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|^JP[\|丨\- ]/i, label: "日本", flag: "🇯🇵" },
    SG: { regex: /🇸🇬|新加坡|^SG[\|丨\- ]/i, label: "新加坡", flag: "🇸🇬" },
    TW: { regex: /🇹🇼|台湾|台灣|^TW[\|丨\- ]/i, label: "台湾", flag: "🇹🇼" },
    KR: { regex: /🇰🇷|韩国|韓国|韓國|^KR[\|丨\- ]/i, label: "韩国", flag: "🇰🇷" }
  },
  regionOrder: ["HK", "US", "JP", "SG", "TW", "KR"],
  nodeNames: {
    home: "家宽IP"
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  errorPrefix: "[家宽IP-直连] ",
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

BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 原始分类数据源
// ---------------------------------------------------------------------------

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
  microsoft: {
    core: [
      "+.microsoft.com",
      "+.live.com",
      "+.live.net",
      "+.windows.com",
      "+.windows.net",
      "+.aka.ms",
      "+.msn.com",
      "+.msn.cn"
    ],
    mail: [
      "+.outlook.com",
      "+.outlook.cn",
      "+.hotmail.com",
      "+.office.com",
      "+.office.net",
      "+.office365.com",
      "+.m365.cloud.microsoft"
    ],
    productivity: [
      "+.sharepoint.com",
      "+.onenote.com",
      "+.onenote.net",
      "+.onedrive.com",
      "+.1drv.com",
      "+.microsoft365.com",
      "+.microsoftstream.com",
      "+.microsoftteams.com",
      "+.yammer.com",
      "+.sway.com"
    ],
    auth: [
      "+.microsoftonline.com",
      "+.microsoftonline.cn",
      "+.msftauth.net",
      "+.msauth.net",
      "+.msecnd.net",
      "+.msidentity.com",
      "+.login.microsoftonline.com"
    ],
    cloud: [
      "+.azure.com",
      "+.azure.cn",
      "+.azure.net",
      "+.azurewebsites.net",
      "+.azureedge.net",
      "+.azurefd.net",
      "+.azurecontainer.io",
      "+.trafficmanager.net"
    ],
    developer: [
      "+.visualstudio.com",
      "+.vscode.dev",
      "+.vscode-cdn.net",
      "+.vsassets.io",
      "+.vsmarketplacebadges.dev",
      "+.nuget.org",
      "+.dotnet.microsoft.com",
      "+.npmjs.com",             // npm 注册中心（Microsoft/GitHub 旗下）
      "+.npmjs.org"
    ],
    communication: [
      "+.skype.com",
      "+.skype.net",
      "+.skypeassets.com"
    ],
    search: [
      "+.bing.com",
      "+.bing.net",
      "+.bingapis.com"
    ],
    store: [
      "+.microsoftstore.com",
      "+.microsoftstore.com.cn",
      "+.windowsupdate.com",
      "+.wns.windows.com",         // Windows 推送通知
      "+.store.rg-adguard.net"     // Microsoft Store 第三方下载源
    ],
    gaming: [
      "+.xbox.com",
      "+.xboxlive.com",
      "+.xboxlive.cn",
      "+.gamepass.com",
      "+.minecraft.net",
      "+.mojang.com"
    ]
  },
  chain: {
    platform: {
      google_core: [
        "+.google.com",
        "+.googleapis.com",
        "+.googleusercontent.com",
        "+.gmail.com",
        "+.googlemail.com"
      ],
      google_static: [
        "+.gstatic.com",
        "+.ggpht.com",
        "+.gvt1.com",
        "+.gvt2.com",
        "+.recaptcha.net"
      ],
      google_workspace: ["+.withgoogle.com"],
      google_cloud: [
        "+.cloud.google.com"
      ],
      google_services: [
        "+.blogspot.com",
        "+.googleplay.com",
        "+.waze.com"
      ]
    },
    github: {
      core: [
        "+.github.com",
        "+.github.io",
        "+.github.dev",
        "+.githubcopilot.com"
      ],
      content: [
        "+.githubusercontent.com",
        "+.githubassets.com"
      ],
      packages: [
        "+.ghcr.io",
        "+.pkg.github.com"
      ]
    },
    ai: {
      anthropic: [
        "+.claude.ai",
        "+.claude.com",
        "+.anthropic.com",
        "+.claudeusercontent.com",
        "+.claudemcpclient.com",
        "+.servd-anthropic-website.b-cdn.net",
        "+.clau.de",
        "+.intercom.io",         // Claude 应用内嵌客服
        "+.intercomcdn.com",
        "+.datadoghq.com",       // Claude 应用内嵌监控
        "+.statsigapi.net",      // AI 应用常用的 feature flag 服务
        "+.statsig.com"
      ],
      openai: [
        "+.openai.com",
        "+.chatgpt.com",
        "+.sora.com",
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
        "+.makersuite.google.com",
        "+.deepmind.google",
        "+.deepmind.com",
        "+.labs.google",
        "+.antigravity.google",
        "+.antigravity-ide.com"
      ],
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
    },
    media: {
      youtube: [
        "+.youtube.com",
        "+.googlevideo.com",
        "+.ytimg.com",
        "+.youtube-nocookie.com",
        "+.yt.be",
        "+.youtu.be",
        "+.withyoutube.com",
        "+.youtubekids.com",
        "+.youtubegaming.com",
        "+.youtubeeducation.com"
      ],
      netflix: [
        "+.netflix.com",
        "+.netflix.net",
        "+.nflxvideo.net",
        "+.nflxso.net",
        "+.nflximg.net",
        "+.nflximg.com",
        "+.nflxext.com",
        "+.nflxsearch.net",
        "+.fast.com"
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
        "+.cdninstagram.com",
        "+.messenger.com",
        "+.meta.com",
        "+.whatsapp.com",
        "+.whatsapp.net",
        "+.oculus.com",
        "+.oculuscdn.com"
      ],
      telegram: [
        "+.telegram.org",
        "+.t.me",
        "+.telegra.ph",
        "+.telesco.pe",
        "+.tdesktop.com",
        "+.telegram.dog",
        "+.tg.dev",
        "+.cdn-telegram.org",
        "+.telegram-cdn.org",
        "+.graph.org",
        "+.tx.me"
      ],
      discord: [
        "+.discord.com",
        "+.discord.gg",
        "+.discordapp.com",
        "+.discordapp.net",
        "+.discord.media",
        "+.discordcdn.com",
        "+.discordapp.io",
        "+.discordstatus.com",
        "+.discord.co",
        "+.discord.gift",
        "+.discord.gifts"
      ],
      disney: [
        "+.disneyplus.com",    // Disney+ 核心
        "+.disney.com",
        "+.disney-plus.net",   // CDN
        "+.bamgrid.com",       // Disney+ 基础设施
        "+.dssott.com",        // Disney+ 基础设施
        "+.disneystreaming.com",
        "+.espn.com",          // ESPN
        "+.espn.net",
        "+.espncdn.com",
        "+.hotstar.com",       // Disney+ 印度
        "+.starplus.com",      // Disney+ 拉丁美洲
        "+.marvel.com",        // Marvel
        "+.starwars.com",      // Star Wars
        "+.nationalgeographic.com",
        "+.ngeo.com"           // Nat Geo CDN
      ],
      spotify: [
        "+.spotify.com",
        "+.scdn.co",           // Spotify CDN
        "+.spoti.fi",          // 短链
        "+.spotifycdn.com",
        "+.spotifycdn.net",
        "+.byspotify.com"
      ]
    },
    gaming: {
      steam: [
        "+.steampowered.com",
        "+.steamcommunity.com",
        "+.store.steampowered.com",
        "+.steamstatic.com",
        "+.steamcdn-a.akamaihd.net",
        "+.steam-chat.com",
        "+.steamgames.com",
        "+.steam.tv",
        "+.steamdeck.com",
        "+.valvesoftware.com",
        "+.s.team"
      ],
      epicgames: [
        "+.epicgames.com",
        "+.epicgames.dev",
        "+.unrealengine.com",
        "+.unrealtournament.com",
        "+.fortnite.com",
        "+.easyanticheat.net",
        "+.eac-cdn.com"
      ],
      nintendo: [
        "+.nintendo.com",
        "+.nintendo.net",
        "+.nintendoswitch.com",
        "+.pokemon.com",
        "+.pokemonhome.com",
        "+.supermariorun.com"
      ],
      playstation: [
        "+.playstation.com",
        "+.playstation.net",
        "+.playstationnetwork.com",
        "+.sonyentertainmentnetwork.com"
      ],
      blizzard: [
        "+.battle.net",
        "+.battlenet.com",
        "+.blizzard.com",
        "+.diablo3.com",
        "+.diabloimmortal.com",
        "+.playhearthstone.com",
        "+.playoverwatch.com",
        "+.worldofwarcraft.com",
        "+.starcraft.com",
        "+.starcraft2.com",
        "+.heroesofthestorm.com"
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
      typeless: [
        "+.typeless.com"
      ]
    }
  },
  policy: {
    dnsFallbackExtra: [
      "+.cdn.cloudflare.net",
      "ping0.cc",
      "ipinfo.io",
      "ipapi.is"
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
        "Claude Code",
        "Claude Code URL Handler",
        "Antigravity.app",
        "Antigravity.exe",
        "language_server_windows_x64.exe",
        "Quotio.app",
        "Quotio.exe",
        // Windows
        "Claude.exe",
        "ChatGPT.exe",
        "Perplexity.exe",
        "Cursor.exe",
        "Claude Code.exe"
      ]
    },
    aiCli: ["claude", "gemini", "codex", "claude.exe", "gemini.exe", "codex.exe"],
    browser: {
      apps: [
        // macOS（会自动展开 Helper 后缀）
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
      ],
      exact: [
        // Windows（不展开 Helper）
        "chrome.exe",
        "msedge.exe",
        "Dia.exe",
        "Atlas.exe",
        "SunBrowser.exe"
      ]
    }
  }
};

var SOURCE_NETWORK_RULES = {
  direct: [
    // 私有局域网网段（RFC 1918）
    { type: "IP-CIDR",  value: "10.0.0.0/8",          target: BASE.ruleTargets.direct },
    { type: "IP-CIDR",  value: "172.16.0.0/12",        target: BASE.ruleTargets.direct },
    { type: "IP-CIDR",  value: "192.168.0.0/16",       target: BASE.ruleTargets.direct },
    // 链路本地地址（APIPA / mDNS）
    { type: "IP-CIDR",  value: "169.254.0.0/16",       target: BASE.ruleTargets.direct },
    // 回环地址
    { type: "IP-CIDR",  value: "127.0.0.0/8",          target: BASE.ruleTargets.direct },
    // IPv6 私有/特殊地址
    { type: "IP-CIDR6", value: "::1/128",               target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fc00::/7",              target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fe80::/10",             target: BASE.ruleTargets.direct },
    // Tailscale 进程直连（WireGuard 隧道走纯 IP，不命中域名规则）
    { type: "PROCESS-NAME", value: "tailscaled.exe", target: BASE.ruleTargets.direct },
    { type: "PROCESS-NAME", value: "tailscaled",     target: BASE.ruleTargets.direct },
    // Tailscale IP 网段（CGNAT + MagicDNS + IPv6）
    { type: "IP-CIDR",  value: "100.64.0.0/10",       target: BASE.ruleTargets.direct },
    { type: "IP-CIDR",  value: "100.100.100.100/32",   target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48",  target: BASE.ruleTargets.direct }
  ]
};

// ---------------------------------------------------------------------------
// 通用数据处理工具
// ---------------------------------------------------------------------------

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

function mergeStringGroups(groups) {
  var mergedValues = [];
  for (var i = 0; i < groups.length; i++) {
    mergedValues.push.apply(mergedValues, groups[i]);
  }
  return uniqueStrings(mergedValues);
}

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

function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
}

function excludeStrings(values, excludedValues) {
  var filteredValues = [];
  var excludedLookup = buildStringLookup(excludedValues);
  for (var i = 0; i < values.length; i++) {
    if (excludedLookup[values[i]]) continue;
    filteredValues.push(values[i]);
  }
  return uniqueStrings(filteredValues);
}

function flattenGroupedPatterns(groupedPatterns) {
  var flattenedPatterns = [];
  Object.keys(groupedPatterns).forEach(function (groupName) {
    flattenedPatterns.push.apply(flattenedPatterns, groupedPatterns[groupName]);
  });
  return uniqueStrings(flattenedPatterns);
}

function createUserError(message) {
  return new Error(BASE.errorPrefix + message);
}

function resolveBooleanOption(preferredValue, legacyValue, defaultValue) {
  if (typeof preferredValue === "boolean") return preferredValue;
  if (typeof legacyValue === "boolean") return legacyValue;
  return defaultValue;
}

function isChainRegionAiCliProcessProxyEnabled() {
  return resolveBooleanOption(
    USER_OPTIONS.enableChainRegionAiCliProcessProxy,
    USER_OPTIONS.enableAiCliProcessProxy,
    true
  );
}

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

function buildDerived() {
  var directDomesticAi     = flattenGroupedPatterns(SOURCE_PATTERNS.direct.domestic.ai);
  var directDomesticOffice = flattenGroupedPatterns(SOURCE_PATTERNS.direct.domestic.office);
  var directOverseasApps   = flattenGroupedPatterns(SOURCE_PATTERNS.direct.overseasApps);
  var directAll            = mergeStringGroups([directDomesticAi, directDomesticOffice, directOverseasApps]);

  var aiPatterns       = flattenGroupedPatterns(SOURCE_PATTERNS.chain.ai);
  var platformPatterns = flattenGroupedPatterns(SOURCE_PATTERNS.chain.platform);
  var validationExtra  = uniqueStrings(SOURCE_PATTERNS.policy.dnsFallbackExtra.slice());
  var strictAi         = excludeStrings(aiPatterns, directAll);
  var strictSupport    = excludeStrings(platformPatterns, directAll);
  var strictValidation = excludeStrings(validationExtra, directAll);
  var strictAll        = mergeStringGroups([strictAi, strictSupport, strictValidation]);

  var specs = [
    {
      name: "🌍 国际媒体",
      preference: "proxy",
      domains: excludeStrings(mergeStringGroups([
        SOURCE_PATTERNS.chain.media.youtube,
        SOURCE_PATTERNS.chain.media.netflix,
        SOURCE_PATTERNS.chain.media.twitter,
        SOURCE_PATTERNS.chain.media.facebook,
        SOURCE_PATTERNS.chain.media.disney,
        SOURCE_PATTERNS.chain.media.spotify
      ]), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "📲 Telegram",
      preference: "proxy",
      domains: excludeStrings(mergeStringGroups([
        SOURCE_PATTERNS.chain.media.telegram,
        SOURCE_PATTERNS.chain.media.discord
      ]), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "🐙 GitHub",
      preference: "proxy",
      domains: excludeStrings(flattenGroupedPatterns(SOURCE_PATTERNS.chain.github), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "Ⓜ️ 微软服务",
      preference: "proxy",
      domains: excludeStrings(flattenGroupedPatterns(SOURCE_PATTERNS.microsoft), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "🎮 游戏平台",
      preference: "direct",
      domains: excludeStrings(flattenGroupedPatterns(SOURCE_PATTERNS.chain.gaming), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "🍎 Apple",
      preference: "direct",
      domains: flattenGroupedPatterns(SOURCE_PATTERNS.apple),
      dnsPolicy: "domestic"
    },
    {
      name: "🎯 直连",
      preference: "fixed",
      domains: [],
      dnsPolicy: null,
      fixedProxies: ["DIRECT"],
      testUrl: "https://www.baidu.com/generate_204"
    }
  ];

  var snifferForce = mergeStringGroups([
    uniqueStrings(SOURCE_PATTERNS.policy.snifferForceBase.slice()),
    strictAll
  ]);
  var snifferSkip = uniqueStrings(
    SOURCE_PATTERNS.policy.snifferSkipBase.concat(directOverseasApps)
  );

  return {
    specs: specs,
    patterns: {
      strict: { ai: strictAi, support: strictSupport, validation: strictValidation, all: strictAll },
      direct: {
        domestic: {
          ai: directDomesticAi,
          office: directDomesticOffice,
          groups: [directDomesticAi, directDomesticOffice]
        },
        overseasApps: directOverseasApps,
        groups: [directDomesticAi, directDomesticOffice, directOverseasApps]
      },
      apple: flattenGroupedPatterns(SOURCE_PATTERNS.apple),
      sniffer: { force: snifferForce, skip: snifferSkip }
    }
  };
}

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
        SOURCE_PROCESSES.chain.browser.helperSuffixes,
        SOURCE_PROCESSES.chain.browser.exact
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

var _derived = buildDerived();
var DERIVED = {
  specs: _derived.specs,
  patterns: _derived.patterns,
  processNames: buildDerivedProcessNames(),
  networkRules: { direct: SOURCE_NETWORK_RULES.direct.slice() }
};

function buildStrictValidationTargets() {
  var validationTargets = [
    { type: "DOMAIN-SUFFIX", value: "claude.ai" },
    { type: "DOMAIN-SUFFIX", value: "chatgpt.com" },
    { type: "DOMAIN-SUFFIX", value: "gemini.google.com" },
    { type: "DOMAIN-SUFFIX", value: "perplexity.ai" },
    { type: "DOMAIN-SUFFIX", value: "google.com" },
    { type: "PROCESS-NAME",  value: "Claude" }
  ];
  if (isChainRegionAiCliProcessProxyEnabled()) {
    validationTargets.push({ type: "PROCESS-NAME", value: "claude" });
    validationTargets.push({ type: "PROCESS-NAME", value: "Claude Code" });
    validationTargets.push({ type: "PROCESS-NAME", value: "Claude Code URL Handler" });
    validationTargets.push({ type: "PROCESS-NAME", value: "codex" });
  }
  return validationTargets;
}

function buildMediaValidationTargets() {
  return [
    { type: "DOMAIN-SUFFIX", value: "youtube.com" },
    { type: "DOMAIN-SUFFIX", value: "x.com" }
  ];
}

function buildBrowserValidationTargets() {
  if (!isChainRegionBrowserProcessProxyEnabled()) return [];
  return [
    { type: "PROCESS-NAME", value: "Google Chrome" },
    { type: "PROCESS-NAME", value: "chrome.exe" }
  ];
}

// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

function applyDnsAndSniffer(config) {
  config.dns = buildDnsConfig();
  config.sniffer = buildSnifferConfig();
}

function assignNameserverPolicyDomains(policy, domains, dohServers) {
  for (var i = 0; i < domains.length; i++) {
    policy[domains[i]] = dohServers;
  }
}

function buildNameserverPolicy() {
  var policy = { "geosite:openai": BASE.dns.overseas };
  var i;
  var spec;
  var dnsServers;
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.ai,              BASE.dns.overseas);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.support,         BASE.dns.overseas);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.validation,      BASE.dns.overseas);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.direct.domestic.ai,     BASE.dns.domestic);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.direct.domestic.office, BASE.dns.domestic);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.direct.overseasApps,    BASE.dns.overseas);
  for (i = 0; i < DERIVED.specs.length; i++) {
    spec = DERIVED.specs[i];
    if (!spec.domains || spec.domains.length === 0 || !spec.dnsPolicy) continue;
    dnsServers = spec.dnsPolicy === "overseas" ? BASE.dns.overseas : BASE.dns.domestic;
    assignNameserverPolicyDomains(policy, spec.domains, dnsServers);
  }
  return policy;
}

function buildDnsFakeIpFilter() {
  var localNetworkDomains = [
    "*.lan", "*.local", "*.localhost", "localhost.ptlogin2.qq.com"
  ];
  var timeSyncDomains = [
    "time.*.com", "time.*.gov", "time.*.edu.cn", "time.*.apple.com",
    "time-ios.apple.com", "time-macos.apple.com",
    "ntp.*.com", "ntp1.aliyun.com", "pool.ntp.org", "*.pool.ntp.org"
  ];
  var connectivityTestDomains = [
    "www.msftconnecttest.com", "www.msftncsi.com",
    "*.msftconnecttest.com", "*.msftncsi.com"
  ];
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net", "+.stun.playstation.net",
    "xbox.*.microsoft.com", "+.xboxlive.com",
    "*.battlenet.com.cn", "*.blzstatic.cn"
  ];
  var stunRealtimeDomains = ["stun.*.*", "stun.*.*.*"];
  var homeRouterDomains = [
    "+.router.asus.com", "+.linksys.com", "+.tplinkwifi.net", "*.xiaoqiang.net"
  ];
  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(DERIVED.patterns.apple)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

function buildDnsFallbackFilterDomains() {
  var groups = [DERIVED.patterns.strict.all, DERIVED.patterns.direct.overseasApps];
  for (var i = 0; i < DERIVED.specs.length; i++) {
    if (DERIVED.specs[i].domains && DERIVED.specs[i].domains.length > 0) {
      groups.push(DERIVED.specs[i].domains);
    }
  }
  return mergeStringGroups(groups);
}

function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: buildDnsFallbackFilterDomains()
  };
}

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

function buildDnsConfig() {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter();
  dnsConfig["fallback-filter"] = buildDnsFallbackFilter();
  dnsConfig["nameserver-policy"] = buildNameserverPolicy();
  return dnsConfig;
}

function buildSnifferConfig() {
  return {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    sniff: {
      TLS:  { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      QUIC: { ports: [443] }
    },
    "force-domain": DERIVED.patterns.sniffer.force,
    "skip-domain":  DERIVED.patterns.sniffer.skip
  };
}

// ---------------------------------------------------------------------------
// 家宽IP节点与地区组选区
// ---------------------------------------------------------------------------

function ensureProxyContainers(config) {
  if (!config.proxies)          config.proxies = [];
  if (!config["proxy-groups"])  config["proxy-groups"] = [];
  if (!config.rules)            config.rules = [];
}

// 清空订阅原有代理组和规则，保留 Smart Group 或原始 url-test 组。
// Smart 内核会将 url-test 转为 smart 类型并追加 "(Smart Group)" 后缀；
// 未启用 Smart 内核时保留原始 url-test 组供 dialer-proxy 引用。
// 清空订阅原有代理组和规则，保留 Smart Group 或原始 url-test 组的定义。
// 保留的组不立即插入（由 appendTailGroups 放到底部），仅暂存到 config._savedAutoGroup。
function resetSubscriptionGroupsAndRules(config) {
  var smartName = USER_OPTIONS.autoSelectGroupName + "(Smart Group)";
  var baseName  = USER_OPTIONS.autoSelectGroupName;
  var savedGroup = null;
  for (var i = 0; i < config["proxy-groups"].length; i++) {
    var group = config["proxy-groups"][i];
    if (group.name === smartName) { savedGroup = group; break; }
    if (group.name === baseName && !savedGroup) { savedGroup = group; }
  }
  config["proxy-groups"] = [];
  config.rules = [];
  config._savedAutoGroup = savedGroup; // 暂存，appendTailGroups 使用后删除
}

function findNamedItem(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return items[i];
  }
  return null;
}

function findNamedItemIndex(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return i;
  }
  return -1;
}

function upsertNamedItem(items, itemDefinition) {
  var itemIndex = findNamedItemIndex(items, itemDefinition.name);
  if (itemIndex >= 0) items[itemIndex] = itemDefinition;
  else items.push(itemDefinition);
  return itemDefinition;
}

function findProxyByName(proxies, proxyName) {
  return findNamedItem(proxies, proxyName);
}

function findProxyGroupByName(proxyGroups, groupName) {
  return findNamedItem(proxyGroups, groupName);
}

function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

function collectRegionNodeNames(proxies, regionRegex) {
  var names = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (regionRegex.test(proxy.name) && proxy.name !== BASE.nodeNames.home) {
      names.push(proxy.name);
    }
  }
  return names;
}

// 生成锚点组（节点选择）并按 BASE.regionOrder 顺序收集可用的地区节点。
// 节点选择的成员为 [自动选择, 地区组..., 自定义节点..., DIRECT]，选组而不是选裸节点。
// 地区组和 GLOBAL 由 appendTailGroups 插入底部。
function ensureAnchorGroups(config) {
  var allNodeNames = [];
  for (var i = 0; i < config.proxies.length; i++) {
    allNodeNames.push(config.proxies[i].name);
  }

  // 收集地区组定义（暂不插入 proxy-groups）
  var regionGroups = [];
  var regionGroupNames = [];
  for (var j = 0; j < BASE.regionOrder.length; j++) {
    var regionKey = BASE.regionOrder[j];
    var regionMeta = BASE.regions[regionKey];
    if (!regionMeta) continue;
    var regionNodes = collectRegionNodeNames(config.proxies, regionMeta.regex);
    if (regionNodes.length === 0) continue;
    var rgName = regionMeta.flag + "|" + regionMeta.label;
    regionGroups.push({
      name: rgName, type: "url-test", proxies: regionNodes,
      url: BASE.urlTestProbeUrl, interval: 300, tolerance: 50
    });
    regionGroupNames.push(rgName);
  }

  // 自动选择组已在 ensureAutoSelectGroup 中确保存在，直接查找名字
  var smartName = USER_OPTIONS.autoSelectGroupName + "(Smart Group)";
  var baseName  = USER_OPTIONS.autoSelectGroupName;
  var autoSelectName = hasProxyOrGroup(config, smartName) ? smartName : baseName;

  // 节点选择 = [自动选择, 地区组..., 全部裸节点..., DIRECT]
  var nodeSelProxies = [autoSelectName].concat(regionGroupNames).concat(allNodeNames).concat(["DIRECT"]);
  upsertNamedItem(config["proxy-groups"], { name: "节点选择", type: "select", proxies: nodeSelProxies });

  return { allNodeNames: allNodeNames, regionGroups: regionGroups, regionGroupNames: regionGroupNames };
}

// 按 DERIVED.specs 创建所有功能代理组。
// 地区 url-test 组和自定义出口节点均按 preference 插入到合适位置。
function buildFunctionalGroups(config, regionGroupNames) {
  var i;
  var spec;
  var proxies;
  var groupDef;
  var extra = regionGroupNames;
  for (i = 0; i < DERIVED.specs.length; i++) {
    spec = DERIVED.specs[i];
    if (spec.fixedProxies) {
      proxies = spec.fixedProxies;
    } else if (spec.preference === "proxy") {
      proxies = ["节点选择"].concat(extra).concat(["DIRECT"]);
    } else {
      proxies = ["DIRECT", "节点选择"].concat(extra);
    }
    groupDef = { name: spec.name, type: "select", proxies: proxies };
    if (spec.testUrl) groupDef.url = spec.testUrl;
    upsertNamedItem(config["proxy-groups"], groupDef);
  }
}

// 将不需要频繁操作的组插入到底部：GLOBAL → 地区 url-test 组 → 自动选择组
// 将不需要频繁操作的组插入到底部：地区 url-test 组
function appendTailGroups(config, regionGroupDefs) {
  for (var i = 0; i < regionGroupDefs.length; i++) {
    upsertNamedItem(config["proxy-groups"], regionGroupDefs[i]);
  }
}

// 确保自动选择组存在并排在 proxy-groups 最前面。
// 订阅有 Smart Group 或 url-test → 直接用；都没有 → 用全部节点自建 url-test。
function ensureAutoSelectGroup(config) {
  var smartName = USER_OPTIONS.autoSelectGroupName + "(Smart Group)";
  var baseName  = USER_OPTIONS.autoSelectGroupName;

  // 优先使用 resetSubscriptionGroupsAndRules 暂存的组
  if (config._savedAutoGroup) {
    upsertNamedItem(config["proxy-groups"], config._savedAutoGroup);
    var savedName = config._savedAutoGroup.name;
    delete config._savedAutoGroup;
    return savedName;
  }

  // proxy-groups 中已存在
  if (hasProxyOrGroup(config, smartName)) return smartName;
  if (hasProxyOrGroup(config, baseName))  return baseName;

  // 都没有 → 自建 url-test
  var allNodeNames = [];
  var homeNodeName = BASE.nodeNames.home;
  for (var i = 0; i < config.proxies.length; i++) {
    if (config.proxies[i].name !== homeNodeName) {
      allNodeNames.push(config.proxies[i].name);
    }
  }
  if (allNodeNames.length === 0) {
    throw createUserError("没有可用的订阅节点，无法创建自动选择组");
  }
  upsertNamedItem(config["proxy-groups"], {
    name: baseName, type: "url-test", proxies: allNodeNames,
    url: BASE.urlTestProbeUrl, interval: 300, tolerance: 50
  });
  return baseName;
}

// 读取并移除注入到 `config._homeProxy` 的家宽IP凭证（可选）。
// 不存在时返回 null，脚本仅做分流覆写，不注入家宽链路。
function takeHomeProxyCredentials(config) {
  if (!config._homeProxy) return null;
  var credentials = config._homeProxy;
  delete config._homeProxy;
  return credentials;
}

// 把家宽IP凭证转成 Clash 代理节点对象（单节点，无 dialer-proxy）。
function buildHomeProxy(credentials) {
  var node = {
    name: BASE.nodeNames.home,
    type: credentials.type || "http",
    server: credentials.server,
    port: credentials.port,
    udp: true
  };
  if (credentials.username) node.username = credentials.username;
  if (credentials.password) node.password = credentials.password;
  return node;
}

// 将家宽IP节点注入主配置。
function injectHomeProxy(config, credentials) {
  upsertNamedItem(config.proxies, buildHomeProxy(credentials));
}

// 解析家宽节点前一跳应使用的跳板组。
// 自动选择组已由 ensureAutoSelectGroup 在 main() 最早阶段确保存在。
function resolveRelayTarget(config) {
  var smartName = USER_OPTIONS.autoSelectGroupName + "(Smart Group)";
  var baseName  = USER_OPTIONS.autoSelectGroupName;
  if (hasProxyOrGroup(config, smartName)) return smartName;
  if (hasProxyOrGroup(config, baseName))  return baseName;
  throw createUserError("自动选择组不存在，请检查脚本逻辑");
}

// 给家宽IP节点绑定 dialer-proxy 到「🔗 家宽跳板」组。
function bindDialerProxy(config, relayGroupName) {
  var homeProxy = findProxyByName(config.proxies, BASE.nodeNames.home);
  if (homeProxy) {
    if (relayGroupName) homeProxy["dialer-proxy"] = relayGroupName;
    else delete homeProxy["dialer-proxy"];
  }
}

// 返回家宽IP出口组的固定名称。
function ensureChainGroup() {
  return "🏠家宽IP";
}

// 解析本轮注入所需的关键目标。
// 新增「🔗 家宽跳板」select 组，成员为 [自动选择, 地区组..., 自定义节点...]，
// 用户可在界面上手动选择家宽IP走哪条跳板线路。
function resolveRoutingTargets(config, regionGroupNames) {
  // 确保自动选择组存在（供跳板组引用）
  var relayTarget = resolveRelayTarget(config);

  // 跳板组成员：自动选择 + 地区组 + 自定义节点
  var relayGroupName = "🔗 家宽跳板";
  var relayGroupProxies = [relayTarget].concat(regionGroupNames || []);
  upsertNamedItem(config["proxy-groups"], {
    name: relayGroupName, type: "select", proxies: relayGroupProxies
  });

  // 家宽IP 的 dialer-proxy 指向跳板组
  var chainGroupName = ensureChainGroup();
  upsertNamedItem(config["proxy-groups"], {
    name: chainGroupName, type: "select", proxies: [BASE.nodeNames.home]
  });

  return {
    relayTarget: relayTarget,
    relayGroupName: relayGroupName,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName
  };
}

// 读取并移除注入到 `config._customProxies` 的自定义出口配置（可选）。
function takeCustomProxies(config) {
  if (!config._customProxies) return null;
  var raw = config._customProxies;
  delete config._customProxies;
  return Array.isArray(raw) ? raw : [raw];
}

function buildCustomProxyNode(proxyConfig) {
  var node = {
    name: proxyConfig.name,
    type: proxyConfig.type || "http",
    server: proxyConfig.server,
    port: proxyConfig.port,
    udp: true
  };
  if (proxyConfig.username) node.username = proxyConfig.username;
  if (proxyConfig.password) node.password = proxyConfig.password;
  return node;
}

function injectCustomProxies(config, proxyConfigs) {
  for (var i = 0; i < proxyConfigs.length; i++) {
    var proxyConfig = proxyConfigs[i];
    if (!proxyConfig.server || !proxyConfig.port) {
      throw createUserError(
        "自定义出口配置不完整（第 " + (i + 1) + " 条），请检查 server 和 port 字段"
      );
    }
    if (!proxyConfig.name) {
      proxyConfig.name = "自定义出口" + (i + 1);
    }
    upsertNamedItem(config.proxies, buildCustomProxyNode(proxyConfig));
  }
}

// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;
  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;
  return ruleLine.substring(0, secondCommaIndex);
}

function buildFunctionalRules() {
  var rules = [];
  var seen = {};
  for (var i = 0; i < DERIVED.specs.length; i++) {
    var spec = DERIVED.specs[i];
    if (spec.domains && spec.domains.length > 0) {
      addSuffixRulesIfNotExists(rules, seen, spec.domains, spec.name);
    }
  }
  return rules;
}

// strictAiTarget 为 null 时跳过 AI 进程和浏览器进程规则（纯分流模式）。
function buildManagedRules(strictAiTarget) {
  var rules = [];
  if (strictAiTarget) {
    rules = rules.concat(buildStrictChainRules(strictAiTarget));
    rules = rules.concat(buildBrowserChainRules(strictAiTarget));
  }
  return rules
    .concat(buildFunctionalRules())
    .concat(buildDirectRules());
}

function buildRuleIdentityLookup(ruleLines) {
  var ruleIdentityLookup = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity) ruleIdentityLookup[ruleIdentity] = true;
  }
  return ruleIdentityLookup;
}

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

function prependRules(targetRules, rulesToPrepend) {
  for (var i = rulesToPrepend.length - 1; i >= 0; i--) {
    targetRules.unshift(rulesToPrepend[i]);
  }
}

function injectManagedRules(config, strictAiTarget) {
  var managedRules = buildManagedRules(strictAiTarget);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);
  config.rules = filterConflictingRules(config.rules, managedRuleIdentities);
  prependRules(config.rules, managedRules);
}

function addRuleIfNotExists(ruleLines, seenRuleIdentities, type, value, target) {
  var ruleIdentity = type + "," + value;
  if (seenRuleIdentities[ruleIdentity]) return;
  seenRuleIdentities[ruleIdentity] = true;
  ruleLines.push(type + "," + value + "," + target);
}

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

function addTypedRulesIfNotExists(ruleLines, seenRuleIdentities, values, ruleType, target) {
  for (var i = 0; i < values.length; i++) {
    addRuleIfNotExists(ruleLines, seenRuleIdentities, ruleType, values[i], target);
  }
}

function addSuffixRulesIfNotExists(ruleLines, seenRuleIdentities, domains, target) {
  var suffixes = [];
  for (var i = 0; i < domains.length; i++) {
    suffixes.push(toSuffix(domains[i]));
  }
  addTypedRulesIfNotExists(ruleLines, seenRuleIdentities, suffixes, "DOMAIN-SUFFIX", target);
}

function addProcessRulesIfNotExists(ruleLines, seenRuleIdentities, processNames, target) {
  addTypedRulesIfNotExists(ruleLines, seenRuleIdentities, processNames, "PROCESS-NAME", target);
}

function buildStrictProcessGroups() {
  var processGroups = [DERIVED.processNames.strict.base];
  if (isChainRegionAiCliProcessProxyEnabled()) {
    processGroups.push(DERIVED.processNames.strict.optionalAiCli);
  }
  return processGroups;
}

function buildBrowserChainProcessGroups() {
  if (!isChainRegionBrowserProcessProxyEnabled()) return [];
  return [DERIVED.processNames.general.browser];
}

function buildStrictChainRules(strictAiTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildStrictProcessGroups();
  var i;
  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(ruleLines, seenRuleIdentities, processGroups[i], strictAiTarget);
  }
  addSuffixRulesIfNotExists(ruleLines, seenRuleIdentities, DERIVED.patterns.strict.all, strictAiTarget);
  return ruleLines;
}

function buildBrowserChainRules(browserTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var processGroups = buildBrowserChainProcessGroups();
  var i;
  for (i = 0; i < processGroups.length; i++) {
    addProcessRulesIfNotExists(ruleLines, seenRuleIdentities, processGroups[i], browserTarget);
  }
  return ruleLines;
}


function buildDirectRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var directNetworkRules = [];
  var directPatternGroups = DERIVED.patterns.direct.groups;
  var i;
  for (i = 0; i < DERIVED.networkRules.direct.length; i++) {
    directNetworkRules.push({
      type:   DERIVED.networkRules.direct[i].type,
      value:  DERIVED.networkRules.direct[i].value,
      target: DERIVED.networkRules.direct[i].target,
      option: "no-resolve"
    });
  }
  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, directNetworkRules);
  for (i = 0; i < directPatternGroups.length; i++) {
    addSuffixRulesIfNotExists(ruleLines, seenRuleIdentities, directPatternGroups[i], BASE.ruleTargets.direct);
  }

  // GeoSite/GeoIP 兜底：国内域名和 IP 直连
  ruleLines.push("GEOSITE,cn,DIRECT");
  ruleLines.push("GEOIP,cn,DIRECT,no-resolve");

  ruleLines.push("MATCH,节点选择");
  return ruleLines;
}

function assertManagedRuleTarget(ruleLines, type, value, target) {
  var ruleLine = type + "," + value + "," + target;
  if (ruleLines.indexOf(ruleLine) >= 0) return;
  throw createUserError(
    "关键规则未正确写入: " + ruleLine + "，请检查 mediaRegion 和订阅代理组"
  );
}

function haveSameStrings(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  for (var i = 0; i < values.length; i++) {
    if (values[i] !== expectedValues[i]) return false;
  }
  return true;
}

// 校验家宽IP出口组、dialer-proxy 绑定、媒体组和关键规则目标。
function validateManagedRouting(config, routingTargets) {
  var i;
  var homeProxy;
  var chainGroup;
  var mediaGroupName = "🌍 国际媒体";
  var strictValidationTargets  = buildStrictValidationTargets();
  var browserValidationTargets = buildBrowserValidationTargets();
  var mediaValidationTargets   = buildMediaValidationTargets();

  if (routingTargets.strictAiTarget !== routingTargets.chainGroupName) {
    throw createUserError("域外 AI 与支撑平台未直接指向家宽IP出口组，请检查代理组注入逻辑");
  }
  if (!hasProxyOrGroup(config, routingTargets.relayGroupName)) {
    throw createUserError(
      "家宽跳板组 \"" + routingTargets.relayGroupName + "\" 不存在，请检查代理组注入逻辑"
    );
  }

  homeProxy = findProxyByName(config.proxies, BASE.nodeNames.home);
  if (!homeProxy) {
    throw createUserError("家宽IP节点不存在，请检查 出口IP凭证.js 和节点注入逻辑");
  }
  if (!homeProxy["dialer-proxy"] || homeProxy["dialer-proxy"] !== routingTargets.relayGroupName) {
    throw createUserError("家宽IP节点未正确绑定到家宽跳板组，请检查代理链路注入逻辑");
  }

  chainGroup = findProxyGroupByName(config["proxy-groups"], routingTargets.chainGroupName);
  if (!chainGroup || chainGroup.type !== "select" ||
      !haveSameStrings(chainGroup.proxies || [], [BASE.nodeNames.home])) {
    throw createUserError("家宽IP出口组内容异常，请检查代理组注入逻辑");
  }

  for (i = 0; i < strictValidationTargets.length; i++) {
    assertManagedRuleTarget(config.rules, strictValidationTargets[i].type,
      strictValidationTargets[i].value, routingTargets.strictAiTarget);
  }
  for (i = 0; i < browserValidationTargets.length; i++) {
    assertManagedRuleTarget(config.rules, browserValidationTargets[i].type,
      browserValidationTargets[i].value, routingTargets.strictAiTarget);
  }
  for (i = 0; i < mediaValidationTargets.length; i++) {
    assertManagedRuleTarget(config.rules, mediaValidationTargets[i].type,
      mediaValidationTargets[i].value, mediaGroupName);
  }
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

function toSuffix(domainPattern) {
  return domainPattern.replace("+.", "");
}

// 按初始化、DNS/Sniffer、代理节点、规则注入、最终校验的顺序装配输出配置。
// _homeProxy 和 _customProxies 均为可选；都不配置时脚本仅做分流覆写。
function main(config) {
  var credentials    = takeHomeProxyCredentials(config); // 可选：取出家宽IP凭证
  var customProxies  = takeCustomProxies(config);        // 可选：取出自定义出口配置
  var anchorResult;
  var regionGroupNames;
  var routingTargets;
  var hasHomeProxy = !!credentials;

  ensureProxyContainers(config);
  if (customProxies) injectCustomProxies(config, customProxies);
  resetSubscriptionGroupsAndRules(config);

  // ① 自动选择组（最上面）：订阅有就用，没有就自建 url-test
  var autoSelectName = ensureAutoSelectGroup(config);

  // ② 节点选择（第二位）
  anchorResult = ensureAnchorGroups(config);
  regionGroupNames = anchorResult.regionGroupNames;

  // ③ GLOBAL（第三位，成员 = [节点选择] + 节点选择的全部成员）
  var nodeSelGroup = findProxyGroupByName(config["proxy-groups"], "节点选择");
  var globalProxies = ["节点选择"].concat(nodeSelGroup ? nodeSelGroup.proxies.slice() : []);
  upsertNamedItem(config["proxy-groups"], { name: "GLOBAL", type: "select", proxies: globalProxies });

  // ④ 功能组
  buildFunctionalGroups(config, regionGroupNames);

  // ⑤ 家宽出口 + 跳板组（有凭证时）
  var chainGroupName = null;
  if (hasHomeProxy) {
    injectHomeProxy(config, credentials);
    routingTargets = resolveRoutingTargets(config, regionGroupNames);
    bindDialerProxy(config, routingTargets.relayGroupName);
    chainGroupName = routingTargets.chainGroupName;
    // 将 🏠家宽IP 添加到节点选择和 GLOBAL 中（在 DIRECT 之前）
    var groups = [nodeSelGroup, findProxyGroupByName(config["proxy-groups"], "GLOBAL")];
    for (var gi = 0; gi < groups.length; gi++) {
      if (!groups[gi]) continue;
      var directIdx = groups[gi].proxies.indexOf("DIRECT");
      if (directIdx >= 0) groups[gi].proxies.splice(directIdx, 0, chainGroupName);
      else groups[gi].proxies.push(chainGroupName);
    }
  }

  // ⑥ 地区 url-test 组（沉底）
  appendTailGroups(config, anchorResult.regionGroups);

  // ⑤ DNS / Sniffer / 规则注入
  applyDnsAndSniffer(config);
  if (hasHomeProxy) {
    injectManagedRules(config, routingTargets.strictAiTarget);
    validateManagedRouting(config, routingTargets);
  } else {
    // 无家宽凭证：仅注入功能组域名规则 + 直连规则（纯分流模式）
    injectManagedRules(config, null);
  }

  return config;
}
