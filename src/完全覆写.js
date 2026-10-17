/**
 * Clash 家宽IP-直连覆写脚本
 *
 * 作用：
 * 1. 注入家宽IP代理节点（真直连 + 可选链式），以及媒体地区组。
 * 2. 让域外 AI、支撑平台和受管浏览器进程稳定命中家宽IP出口。
 * 3. 让媒体域名命中 `mediaRegion` 对应的普通地区组。
 * 4. 覆写 DNS、Sniffer 和 DIRECT 保留规则，并校验关键目标是否命中预期出口。
 *
 * 与「链式代理」版本的区别：
 * - 家宽IP真直连节点不挂 dialer-proxy；有可用跳板时额外生成家宽IP链式节点。
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
  enableIPv6: false, // 是否启用 IPv6；同时控制 Mihomo 全局与 DNS 的 ipv6，默认关闭
  location: "cn", // 本机所在位置："cn" 在中国大陆（默认）；"overseas" 在境外。规则对所有主机相同，只有 🇨🇳 国内 / 🌐 国外 / 🐟 兜底 三个策略组的默认选项跟着变
  domesticExit: [], // 🇨🇳 国内 组的回国出口候选：_customProxies 名称、订阅节点或策略组名。overseas 默认选第一个；cn 默认 DIRECT
  // 🔗 前置：本机能直连的节点都可以当前置。excludePorts 端口上的节点视为“需中转”（自定义节点/家宽IP 自动 dialer-proxy 到 🔗 前置，且不进前置候选）；
  // 🔗 前置 是固定选择的 select，默认 DIRECT（不走前置）；excludeKeywords 过滤不想当前置的节点；prefer 为正则字符串，命中的节点排在 DIRECT 之后。节点可写 via: "名称" 指定专门的前置，direct: false 强制标为需中转。
  relay: { enable: true, excludePorts: [], excludeKeywords: [], prefer: [] },
  autoSelectGroupName: "自动选择", // 订阅中的自动选择组名（url-test），Smart 内核会自动追加 "(Smart Group)" 后缀
  autoSelectExcludeKeywords: ["公司代理"], // 只过滤自动选择组；公司代理仍会保留在节点选择里供手动使用
  urlTestProbeUrl: "", // 直连/界面健康检查默认测速地址；留空按 location 选择（cn: connect.rom.miui.com，overseas: cp.cloudflare.com）；单个分组可用 testUrl 覆盖
  proxyProbeUrl: "https://www.gstatic.com/generate_204", // 代理/地区/出海能力默认测速地址
  overseasDnsTarget: "🤖 AI Agent", // 海外及未知域名的 DoH 连接出口；改为“节点选择”可使用普通出海线路
  googleTrafficConsistency: true, // 统一 Google 账号与 AI 出口；YouTube、Play 和 FCM 仍按协议能力分流
  directProxyServerRules: true, // 将最终代理节点的服务器地址在本机规则层直连，避免局域网下游 Clash 再代理一层
  proxyServerResolvedIps: {}, // 域名代理服务器在下游 Clash 场景下使用的已解析 IP，例如 { "edge.example.com": ["203.0.113.10"] }
  rejectAiQuic: true, // 拒绝 AI 域名 UDP/443，防止不支持 UDP 的出口被跳过后直连；浏览器会回退 HTTPS/TCP
  rejectAppStoreQuic: true, // 拒绝 App Store 启动接口 UDP/443，避免 QUIC 在 TUN 中超时；系统会回退 HTTPS/TCP
  rejectWebRtcUdp: true, // 拒绝常用 STUN UDP 端口，避免 HTTP 出口不支持 UDP 时 WebRTC 暴露本地公网 IP
  fullProtocolFallback: null, // HTTP 出口保留给 TCP/443；其余流量回退到支持完整隧道的订阅节点；null 按 location（cn 开启，overseas 关闭，非 443 流量直接走通用出海）
  enableChainRegionBrowserProcessProxy: false, // 是否让受管浏览器按应用名强制走家宽出口
  enableChainRegionAiCliProcessProxy: true,   // 是否让常见 AI CLI 按应用名强制走家宽出口
  tailscale: {
    enable: true,
    monitorGroups: true,
    hideMonitorGroups: true,
    subnetCidrs: [],
    excludeProxyServerFromTun: true,
    routeExcludeCidrs: ["100.64.0.0/10", "100.100.100.100/32"],
    controlPlaneTarget: "DIRECT",
    processTarget: "DIRECT",
    forceExitNodeTraffic: false,
    forceExitNodeTrafficTarget: "节点选择"
  }
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
    TW: { regex: /🇹🇼|台湾|台灣|^TW[\|丨\- ]/i, label: "台湾", flag: "🇨🇳" },
    KR: { regex: /🇰🇷|韩国|韓国|韓國|^KR[\|丨\- ]/i, label: "韩国", flag: "🇰🇷" }
  },
  regionOrder: ["HK", "US", "JP", "SG", "TW", "KR"],
  nodeNames: {
    aiAgent: "🤖 AI Agent",
    fullProtocolFallback: "🔌 全协议回退",
    japanServices: "🇯🇵 日本服务",
    front: "前置代理",
    home: "家宽IP",
    homeChained: "家宽IP链式",
    tailscaleControl: "🧩 Tailscale 控制面",
    tailscaleProcess: "🧩 Tailscale 进程",
    tailnetDirect: "🧩 Tailnet 内部直连",
    tailscaleExit: "🧩 Tailscale Exit Node",
    relay: "🔗 前置"
  },
  // 策略组：决定“哪类流量走哪里”，对所有主机相同；默认选项按 location 切换。
  policyNames: {
    domestic: "🇨🇳 国内",
    overseas: "🌐 国外",
    fallback: "🐟 兜底"
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  urlTestProbeUrl: "https://www.gstatic.com/generate_204",
  errorPrefix: "[家宽IP-直连] ",
  webRtcStunPorts: [3478, 5349, 19302],
  dns: {
    overseas: [
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ],
    domestic: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],
    domesticBootstrap: ["223.5.5.5", "119.29.29.29"],
    overseasBootstrap: ["1.1.1.1", "8.8.8.8"]
  },
  // 按本机所在位置切换的默认值。cn 与引入 location 之前的行为完全一致。
  locationProfiles: {
    cn: {
      directProbeUrl: "http://connect.rom.miui.com/generate_204",
      domesticProbeUrl: "http://connect.rom.miui.com/generate_204",
      fullProtocolFallback: true,
      inChina: true,             // 🇨🇳 国内 默认 DIRECT，🌐 国外 默认节点选择，🐟 兜底 默认国内
      domesticDnsViaGroup: false, // 国内 DoH 本机直连
      localDnsIsDomestic: true,  // 本地直连 DNS 即国内 DoH
      directFirstEgress: false,  // 代理型功能组默认走节点选择
      homeChainFirst: true       // 🏠 家宽IP 默认选链式节点（国内直连美国家宽不稳）
    },
    overseas: {
      directProbeUrl: "http://cp.cloudflare.com/generate_204",
      domesticProbeUrl: "http://connect.rom.miui.com/generate_204",
      fullProtocolFallback: false,
      inChina: false,            // 🇨🇳 国内 默认回国出口，🌐 国外 默认 DIRECT，🐟 兜底 默认国外
      domesticDnsViaGroup: true, // 国内 DoH 经 🇨🇳 国内 组解析
      localDnsIsDomestic: false,
      directFirstEgress: true,
      homeChainFirst: false
    }
  }
};

function getLocationName() {
  var location = typeof USER_OPTIONS.location === "undefined" ? "cn" : USER_OPTIONS.location;
  if (location !== "cn" && location !== "overseas") {
    throw createUserError("USER_OPTIONS.location 无效：" + location + "，仅支持 cn 或 overseas");
  }
  return location;
}

function getLocationProfile() {
  return BASE.locationProfiles[getLocationName()];
}

function getDomesticTarget() {
  return BASE.policyNames.domestic;
}

function getDomesticExitNames() {
  var names = USER_OPTIONS.domesticExit;
  var normalized = [];
  if (names === null || typeof names === "undefined") return normalized;
  if (typeof names === "string") names = [names];
  if (!Array.isArray(names)) {
    throw createUserError("USER_OPTIONS.domesticExit 必须为节点/组名称或名称数组");
  }
  for (var i = 0; i < names.length; i++) {
    if (typeof names[i] !== "string" || !names[i].trim()) {
      throw createUserError("USER_OPTIONS.domesticExit 第 " + (i + 1) + " 项必须为非空名称");
    }
    var name = names[i].trim();
    if (name !== BASE.ruleTargets.direct && normalized.indexOf(name) < 0) normalized.push(name);
  }
  return normalized;
}

function getDefaultProbeUrl() {
  return USER_OPTIONS.urlTestProbeUrl || getLocationProfile().directProbeUrl || BASE.urlTestProbeUrl;
}

function getProxyProbeUrl() {
  return USER_OPTIONS.proxyProbeUrl || BASE.urlTestProbeUrl;
}

function getGroupProbeUrl(groupConfig) {
  if (groupConfig && groupConfig.testUrl) return groupConfig.testUrl;
  if (groupConfig && (groupConfig.probePolicy === "proxy" || groupConfig.preference === "proxy")) {
    return getProxyProbeUrl();
  }
  return getDefaultProbeUrl();
}

function isFullProtocolFallbackEnabled() {
  if (typeof USER_OPTIONS.fullProtocolFallback === "boolean") return USER_OPTIONS.fullProtocolFallback;
  return getLocationProfile().fullProtocolFallback !== false;
}

function isGoogleTrafficConsistencyEnabled() {
  return USER_OPTIONS.googleTrafficConsistency !== false;
}

function resolveProxyUdp(proxyConfig) {
  return proxyConfig.udp === true;
}

// 注入节点时，管理字段由脚本自行处理；其余协议字段（ss 的 cipher/plugin、vless 的 uuid/tls/reality-opts 等）原样透传。
var PROXY_MANAGEMENT_KEYS = {
  name: true, type: true, server: true, port: true, udp: true, username: true, password: true,
  scope: true, useFrontProxy: true, interfaceName: true, "interface-name": true, "dialer-proxy": true,
  via: true, direct: true
};

function copyProtocolFields(source, node) {
  for (var key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (PROXY_MANAGEMENT_KEYS[key] || key.charAt(0) === "_") continue;
    if (source[key] === undefined || source[key] === null) continue;
    if (Object.prototype.hasOwnProperty.call(node, key)) continue;
    node[key] = source[key];
  }
  return node;
}

BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

var AUTO_SELECT_INFO_NODE_KEYWORDS = [
  "官网",
  "网址",
  "网站",
  "地址",
  "剩余流量",
  "流量",
  "套餐",
  "到期",
  "过期",
  "有效期",
  "续费",
  "应急",
  "重置",
  "更新订阅",
  "订阅",
  "公告",
  "通知",
  "traffic",
  "expire",
  "subscription",
  "renew"
];

// ---------------------------------------------------------------------------
// 原始分类数据源
// ---------------------------------------------------------------------------

// BEGIN GENERATED COMMUNITY RULES
// Generated by scripts/sync-community-rules.js; edit sources/policy, not this block.
var COMMUNITY_RULES = {
  "ai": [
    ["DOMAIN-SUFFIX","agentclientprotocol.com"],
    ["DOMAIN-SUFFIX","ai.studio"],
    ["DOMAIN-SUFFIX","aicode.googleapis.com"],
    ["DOMAIN-SUFFIX","aida.googleapis.com"],
    ["DOMAIN-SUFFIX","aisandbox-pa.googleapis.com"],
    ["DOMAIN-SUFFIX","aistudio.google.com"],
    ["DOMAIN-SUFFIX","anthropic.com"],
    ["DOMAIN-SUFFIX","antigravity-unleash.goog"],
    ["DOMAIN-SUFFIX","antigravity.google"],
    ["DOMAIN-SUFFIX","anythingllm.com"],
    ["DOMAIN-SUFFIX","arena.ai"],
    ["DOMAIN-SUFFIX","bard.google.com"],
    ["DOMAIN-SUFFIX","cerebras.ai"],
    ["DOMAIN-SUFFIX","chat.com"],
    ["DOMAIN-SUFFIX","chatgpt.com"],
    ["DOMAIN-SUFFIX","chatgpt.livekit.cloud"],
    ["DOMAIN-SUFFIX","chatgpt.site"],
    ["DOMAIN-SUFFIX","chutes.ai"],
    ["DOMAIN-SUFFIX","cici.com"],
    ["DOMAIN-SUFFIX","ciciai.com"],
    ["DOMAIN-SUFFIX","ciciaicdn.com"],
    ["DOMAIN-SUFFIX","clau.de"],
    ["DOMAIN-SUFFIX","claude.ai"],
    ["DOMAIN-SUFFIX","claude.com"],
    ["DOMAIN-SUFFIX","claude.dev"],
    ["DOMAIN-SUFFIX","claudemcpclient.com"],
    ["DOMAIN-SUFFIX","claudemcpcontent.com"],
    ["DOMAIN-SUFFIX","claudeusercontent.com"],
    ["DOMAIN-SUFFIX","clawhub.ai"],
    ["DOMAIN-SUFFIX","clipdrop.co"],
    ["DOMAIN-SUFFIX","codeium.com"],
    ["DOMAIN-SUFFIX","codeiumdata.com"],
    ["DOMAIN-SUFFIX","coderabbit.ai"],
    ["DOMAIN-SUFFIX","coderabbit.gallery.vsassets.io"],
    ["DOMAIN-SUFFIX","cohere.ai"],
    ["DOMAIN-SUFFIX","cohere.com"],
    ["DOMAIN-SUFFIX","comfy.org"],
    ["DOMAIN-SUFFIX","comfyci.org"],
    ["DOMAIN-SUFFIX","comfyregistry.org"],
    ["DOMAIN-SUFFIX","copilot-stg.com"],
    ["DOMAIN-SUFFIX","copilot.cloud.microsoft"],
    ["DOMAIN-SUFFIX","copilot.com"],
    ["DOMAIN-SUFFIX","copilot.microsoft.com"],
    ["DOMAIN-SUFFIX","coze.com"],
    ["DOMAIN-SUFFIX","crewai.com"],
    ["DOMAIN-SUFFIX","crixet.com"],
    ["DOMAIN-SUFFIX","cursor-cdn.com"],
    ["DOMAIN-SUFFIX","cursor.com"],
    ["DOMAIN-SUFFIX","cursor.sh"],
    ["DOMAIN-SUFFIX","cursorapi.com"],
    ["DOMAIN-SUFFIX","deepmind.com"],
    ["DOMAIN-SUFFIX","deepmind.google"],
    ["DOMAIN-SUFFIX","deepwiki.com"],
    ["DOMAIN-SUFFIX","deepwiki.org"],
    ["DOMAIN-SUFFIX","devin.ai"],
    ["DOMAIN-SUFFIX","diabrowser.com"],
    ["DOMAIN-SUFFIX","diabrowser.engineering"],
    ["DOMAIN-SUFFIX","dify.ai"],
    ["DOMAIN-SUFFIX","dola.com"],
    ["DOMAIN-SUFFIX","dreamgen.com"],
    ["DOMAIN-SUFFIX","duck.ai"],
    ["DOMAIN-SUFFIX","elevenlabs.com"],
    ["DOMAIN-SUFFIX","elevenlabs.io"],
    ["DOMAIN-SUFFIX","flow.google"],
    ["DOMAIN-SUFFIX","flow.google.com"],
    ["DOMAIN-SUFFIX","gateway.ai.cloudflare.com"],
    ["DOMAIN-SUFFIX","geller-pa.googleapis.com"],
    ["DOMAIN-SUFFIX","gemini.google"],
    ["DOMAIN-SUFFIX","gemini.google.com"],
    ["DOMAIN-SUFFIX","gemini.gstatic.com"],
    ["DOMAIN-SUFFIX","generativeai.google"],
    ["DOMAIN-SUFFIX","generativelanguage.googleapis.com"],
    ["DOMAIN-SUFFIX","githubcopilot.com"],
    ["DOMAIN-SUFFIX","grazie.ai"],
    ["DOMAIN-SUFFIX","grazie.aws.intellij.net"],
    ["DOMAIN-SUFFIX","grok.com"],
    ["DOMAIN-SUFFIX","grok.x.com"],
    ["DOMAIN-SUFFIX","grokipedia.com"],
    ["DOMAIN-SUFFIX","groq.com"],
    ["DOMAIN-SUFFIX","h2o.ai"],
    ["DOMAIN-SUFFIX","hf.co"],
    ["DOMAIN-SUFFIX","hf.space"],
    ["DOMAIN-SUFFIX","huggingface.co"],
    ["DOMAIN-SUFFIX","jasper.ai"],
    ["DOMAIN-SUFFIX","jetbrains.ai"],
    ["DOMAIN-SUFFIX","jules.google"],
    ["DOMAIN-SUFFIX","jules.google.com"],
    ["DOMAIN-SUFFIX","kimi.ai"],
    ["DOMAIN-SUFFIX","kiro.dev"],
    ["DOMAIN-SUFFIX","labs.google"],
    ["DOMAIN-SUFFIX","labs.google.com"],
    ["DOMAIN-SUFFIX","labstailwind.pa.googleapis.com"],
    ["DOMAIN-SUFFIX","langchain.com"],
    ["DOMAIN-SUFFIX","liveperson.net"],
    ["DOMAIN-SUFFIX","llama.com"],
    ["DOMAIN-SUFFIX","llamameta.net"],
    ["DOMAIN-SUFFIX","lmstudio.ai"],
    ["DOMAIN-SUFFIX","lovart.ai"],
    ["DOMAIN-SUFFIX","lpsnmedia.net"],
    ["DOMAIN-SUFFIX","makersuite.google.com"],
    ["DOMAIN-SUFFIX","manus.im"],
    ["DOMAIN-SUFFIX","manuscdn.com"],
    ["DOMAIN-SUFFIX","marscode.com"],
    ["DOMAIN-SUFFIX","meta.ai"],
    ["DOMAIN-SUFFIX","metaaivm.com"],
    ["DOMAIN-SUFFIX","midjourney.com"],
    ["DOMAIN-SUFFIX","minimax.io"],
    ["DOMAIN-SUFFIX","mistral.ai"],
    ["DOMAIN-SUFFIX","moonshot.ai"],
    ["DOMAIN-SUFFIX","mozilla.ai"],
    ["DOMAIN-SUFFIX","muse.ai"],
    ["DOMAIN-SUFFIX","notebook.google"],
    ["DOMAIN-SUFFIX","notebook.google.com"],
    ["DOMAIN-SUFFIX","notebooklm.google"],
    ["DOMAIN-SUFFIX","notebooklm.google.com"],
    ["DOMAIN-SUFFIX","notegpt.io"],
    ["DOMAIN-SUFFIX","novelai.net"],
    ["DOMAIN-SUFFIX","oaistatic.com"],
    ["DOMAIN-SUFFIX","oaistatsig.com"],
    ["DOMAIN-SUFFIX","oaiusercontent.com"],
    ["DOMAIN-SUFFIX","ollama.com"],
    ["DOMAIN-SUFFIX","opal.google"],
    ["DOMAIN-SUFFIX","opal.google.com"],
    ["DOMAIN-SUFFIX","openai.com"],
    ["DOMAIN-SUFFIX","openai.com.cdn.cloudflare.net"],
    ["DOMAIN-SUFFIX","openart.ai"],
    ["DOMAIN-SUFFIX","openclaw.ai"],
    ["DOMAIN-SUFFIX","opencode.ai"],
    ["DOMAIN-SUFFIX","openrouter.ai"],
    ["DOMAIN-SUFFIX","openspec.dev"],
    ["DOMAIN-SUFFIX","oystermercury.top"],
    ["DOMAIN-SUFFIX","perplexity.ai"],
    ["DOMAIN-SUFFIX","perplexity.com"],
    ["DOMAIN-SUFFIX","plannotator.ai"],
    ["DOMAIN-SUFFIX","poe.com"],
    ["DOMAIN-SUFFIX","poecdn.net"],
    ["DOMAIN-SUFFIX","pplx.ai"],
    ["DOMAIN-SUFFIX","proactivebackend-pa.googleapis.com"],
    ["DOMAIN-SUFFIX","qoder.com"],
    ["DOMAIN-SUFFIX","robinfrontend-pa.googleapis.com"],
    ["DOMAIN-SUFFIX","sider.ai"],
    ["DOMAIN-SUFFIX","sora.com"],
    ["DOMAIN-SUFFIX","spicywriter.com"],
    ["DOMAIN-SUFFIX","stitch.withgoogle.com"],
    ["DOMAIN-SUFFIX","talkai.info"],
    ["DOMAIN-SUFFIX","tapnow.ai"],
    ["DOMAIN-SUFFIX","trae.ai"],
    ["DOMAIN-SUFFIX","tripo3d.ai"],
    ["DOMAIN-SUFFIX","windsurf.build"],
    ["DOMAIN-SUFFIX","windsurf.com"],
    ["DOMAIN-SUFFIX","x.ai"],
    ["DOMAIN-SUFFIX","youmind.ai"],
    ["DOMAIN-SUFFIX","youmind.com"],
    ["DOMAIN-SUFFIX","youmind.site"],
    ["DOMAIN","ai.developer.meta.com"],
    ["DOMAIN","ai.google.dev"],
    ["DOMAIN","ai.meta.com"],
    ["DOMAIN","aidemos.meta.com"],
    ["DOMAIN","alkalicore-pa.clients6.google.com"],
    ["DOMAIN","alkalimakersuite-pa.clients6.google.com"],
    ["DOMAIN","antigravity-pa.googleapis.com"],
    ["DOMAIN","antigravity.googleapis.com"],
    ["DOMAIN","cloudaicompanion.googleapis.com"],
    ["DOMAIN","cloudcode-pa.googleapis.com"],
    ["DOMAIN","copilot-proxy.githubusercontent.com"],
    ["DOMAIN","copilot-telemetry-service.githubusercontent.com"],
    ["DOMAIN","copilot-telemetry.githubusercontent.com"],
    ["DOMAIN","copilot-workspace.githubnext.com"],
    ["DOMAIN","copilotprodattachments.blob.core.windows.net"],
    ["DOMAIN","daily-cloudcode-pa.googleapis.com"],
    ["DOMAIN","developer.meta.com"],
    ["DOMAIN","geminiweb-pa.clients.google.com"],
    ["DOMAIN","geminiweb-pa.clients6.google.com"],
    ["DOMAIN","llama.developer.meta.com"],
    ["DOMAIN","notebooklm-pa.googleapis.com"],
    ["DOMAIN","notebooklm.googleapis.com"],
    ["DOMAIN","openai.qualtrics.com"],
    ["DOMAIN","openaiapi-site.azureedge.net"],
    ["DOMAIN","openaiassets.blob.core.windows.net"],
    ["DOMAIN","openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net"],
    ["DOMAIN","openaicom.imgix.net"],
    ["DOMAIN","openaicomproductionae4b.blob.core.windows.net"],
    ["DOMAIN","ppl-ai-file-upload.s3.amazonaws.com"],
    ["DOMAIN","pplx-res.cloudinary.com"],
    ["DOMAIN","production-openaicom-storage.azureedge.net"],
    ["DOMAIN","servd-anthropic-website.b-cdn.net"],
    ["DOMAIN","webchannel-alkalimakersuite-pa.clients6.google.com"]
  ],
  "media": [
    ["DOMAIN-SUFFIX","112263.com"],
    ["DOMAIN-SUFFIX","20thcenturystudios.com"],
    ["DOMAIN-SUFFIX","20thcenturystudios.com.au"],
    ["DOMAIN-SUFFIX","20thcenturystudios.com.br"],
    ["DOMAIN-SUFFIX","20thcenturystudios.jp"],
    ["DOMAIN-SUFFIX","abc-studios.com"],
    ["DOMAIN-SUFFIX","abc.com"],
    ["DOMAIN-SUFFIX","abcnews.com"],
    ["DOMAIN-SUFFIX","aboutfacebook.com"],
    ["DOMAIN-SUFFIX","accessfacebookfromschool.com"],
    ["DOMAIN-SUFFIX","accountkit.com"],
    ["DOMAIN-SUFFIX","acebooik.com"],
    ["DOMAIN-SUFFIX","acebook.com"],
    ["DOMAIN-SUFFIX","achat-followers-instagram.com"],
    ["DOMAIN-SUFFIX","acheter-followers-instagram.com"],
    ["DOMAIN-SUFFIX","acheterdesfollowersinstagram.com"],
    ["DOMAIN-SUFFIX","acheterfollowersinstagram.com"],
    ["DOMAIN-SUFFIX","ads-twitter.com"],
    ["DOMAIN-SUFFIX","ads.youtube.com"],
    ["DOMAIN-SUFFIX","advancediddetection.com"],
    ["DOMAIN-SUFFIX","adventuresbydisney.com"],
    ["DOMAIN-SUFFIX","analytics.facebook.com"],
    ["DOMAIN-SUFFIX","analytics.tiktok.com"],
    ["DOMAIN-SUFFIX","askfacebook.net"],
    ["DOMAIN-SUFFIX","askfacebook.org"],
    ["DOMAIN-SUFFIX","atdmt2.com"],
    ["DOMAIN-SUFFIX","atlasdmt.com"],
    ["DOMAIN-SUFFIX","atlasonepoint.com"],
    ["DOMAIN-SUFFIX","atmeta.com"],
    ["DOMAIN-SUFFIX","atscaleconference.com"],
    ["DOMAIN-SUFFIX","babble.com"],
    ["DOMAIN-SUFFIX","babyzone.com"],
    ["DOMAIN-SUFFIX","bamgrid.com"],
    ["DOMAIN-SUFFIX","bamtech.net"],
    ["DOMAIN-SUFFIX","bbc"],
    ["DOMAIN-SUFFIX","bbc-reporting-api.app"],
    ["DOMAIN-SUFFIX","bbc.co.uk"],
    ["DOMAIN-SUFFIX","bbc.com"],
    ["DOMAIN-SUFFIX","bbc.in"],
    ["DOMAIN-SUFFIX","bbc.mp-pxcdn.com"],
    ["DOMAIN-SUFFIX","bbc.net.uk"],
    ["DOMAIN-SUFFIX","bbcfmt.s.llnwi.net"],
    ["DOMAIN-SUFFIX","bbci.co.uk"],
    ["DOMAIN-SUFFIX","bbcmedia.co.uk"],
    ["DOMAIN-SUFFIX","bbcpersian.com"],
    ["DOMAIN-SUFFIX","bbcverticals.com"],
    ["DOMAIN-SUFFIX","beautyandthebeastmusical.co.uk"],
    ["DOMAIN-SUFFIX","bidi.net.uk"],
    ["DOMAIN-SUFFIX","binoculus.com"],
    ["DOMAIN-SUFFIX","bookstagram.com"],
    ["DOMAIN-SUFFIX","botorch.org"],
    ["DOMAIN-SUFFIX","buck.build"],
    ["DOMAIN-SUFFIX","buckbuild.com"],
    ["DOMAIN-SUFFIX","buyingfacebooklikes.com"],
    ["DOMAIN-SUFFIX","buyoculus.com"],
    ["DOMAIN-SUFFIX","byspotify.com"],
    ["DOMAIN-SUFFIX","bytedapm.com"],
    ["DOMAIN-SUFFIX","callhulu.com"],
    ["DOMAIN-SUFFIX","careersatfb.com"],
    ["DOMAIN-SUFFIX","carstagram.com"],
    ["DOMAIN-SUFFIX","cdninstagram.com"],
    ["DOMAIN-SUFFIX","celebgramme.com"],
    ["DOMAIN-SUFFIX","chickstagram.com"],
    ["DOMAIN-SUFFIX","china-facebook.com"],
    ["DOMAIN-SUFFIX","click-url.com"],
    ["DOMAIN-SUFFIX","cms-twdigitalassets.com"],
    ["DOMAIN-SUFFIX","como-hackearfacebook.com"],
    ["DOMAIN-SUFFIX","componentkit.org"],
    ["DOMAIN-SUFFIX","crowdtangle.com"],
    ["DOMAIN-SUFFIX","dacebook.com"],
    ["DOMAIN-SUFFIX","detpress.com"],
    ["DOMAIN-SUFFIX","dilcdn.com"],
    ["DOMAIN-SUFFIX","disney-asia.com"],
    ["DOMAIN-SUFFIX","disney-discount.com"],
    ["DOMAIN-SUFFIX","disney-plus.net"],
    ["DOMAIN-SUFFIX","disney-portal.my.onetrust.com"],
    ["DOMAIN-SUFFIX","disney-studio.com"],
    ["DOMAIN-SUFFIX","disney-studio.net"],
    ["DOMAIN-SUFFIX","disney.asia"],
    ["DOMAIN-SUFFIX","disney.be"],
    ["DOMAIN-SUFFIX","disney.bg"],
    ["DOMAIN-SUFFIX","disney.ca"],
    ["DOMAIN-SUFFIX","disney.ch"],
    ["DOMAIN-SUFFIX","disney.co.il"],
    ["DOMAIN-SUFFIX","disney.co.jp"],
    ["DOMAIN-SUFFIX","disney.co.kr"],
    ["DOMAIN-SUFFIX","disney.co.th"],
    ["DOMAIN-SUFFIX","disney.co.uk"],
    ["DOMAIN-SUFFIX","disney.co.za"],
    ["DOMAIN-SUFFIX","disney.com"],
    ["DOMAIN-SUFFIX","disney.com.au"],
    ["DOMAIN-SUFFIX","disney.com.br"],
    ["DOMAIN-SUFFIX","disney.com.hk"],
    ["DOMAIN-SUFFIX","disney.com.tw"],
    ["DOMAIN-SUFFIX","disney.cz"],
    ["DOMAIN-SUFFIX","disney.de"],
    ["DOMAIN-SUFFIX","disney.dk"],
    ["DOMAIN-SUFFIX","disney.es"],
    ["DOMAIN-SUFFIX","disney.fi"],
    ["DOMAIN-SUFFIX","disney.fr"],
    ["DOMAIN-SUFFIX","disney.gr"],
    ["DOMAIN-SUFFIX","disney.hu"],
    ["DOMAIN-SUFFIX","disney.id"],
    ["DOMAIN-SUFFIX","disney.in"],
    ["DOMAIN-SUFFIX","disney.io"],
    ["DOMAIN-SUFFIX","disney.it"],
    ["DOMAIN-SUFFIX","disney.my"],
    ["DOMAIN-SUFFIX","disney.nl"],
    ["DOMAIN-SUFFIX","disney.no"],
    ["DOMAIN-SUFFIX","disney.ph"],
    ["DOMAIN-SUFFIX","disney.pl"],
    ["DOMAIN-SUFFIX","disney.pt"],
    ["DOMAIN-SUFFIX","disney.ro"],
    ["DOMAIN-SUFFIX","disney.ru"],
    ["DOMAIN-SUFFIX","disney.se"],
    ["DOMAIN-SUFFIX","disney.sg"],
    ["DOMAIN-SUFFIX","disneyaccount.com"],
    ["DOMAIN-SUFFIX","disneyadsales.com"],
    ["DOMAIN-SUFFIX","disneyanimation.com"],
    ["DOMAIN-SUFFIX","disneyarena.com"],
    ["DOMAIN-SUFFIX","disneyaulani.com"],
    ["DOMAIN-SUFFIX","disneybaby.com"],
    ["DOMAIN-SUFFIX","disneycareers.com"],
    ["DOMAIN-SUFFIX","disneychannelonstage.com"],
    ["DOMAIN-SUFFIX","disneychannelroadtrip.com"],
    ["DOMAIN-SUFFIX","disneycruisebrasil.com"],
    ["DOMAIN-SUFFIX","disneyenconcert.com"],
    ["DOMAIN-SUFFIX","disneyiejobs.com"],
    ["DOMAIN-SUFFIX","disneyinflight.com"],
    ["DOMAIN-SUFFIX","disneyinternational.com"],
    ["DOMAIN-SUFFIX","disneyinternationalhd.com"],
    ["DOMAIN-SUFFIX","disneyjunior.com"],
    ["DOMAIN-SUFFIX","disneyjuniortreataday.com"],
    ["DOMAIN-SUFFIX","disneylandparis.com"],
    ["DOMAIN-SUFFIX","disneylatino.com"],
    ["DOMAIN-SUFFIX","disneymagicmoments.co.il"],
    ["DOMAIN-SUFFIX","disneymagicmoments.co.uk"],
    ["DOMAIN-SUFFIX","disneymagicmoments.co.za"],
    ["DOMAIN-SUFFIX","disneymagicmoments.de"],
    ["DOMAIN-SUFFIX","disneymagicmoments.es"],
    ["DOMAIN-SUFFIX","disneymagicmoments.fr"],
    ["DOMAIN-SUFFIX","disneymagicmoments.gen.tr"],
    ["DOMAIN-SUFFIX","disneymagicmoments.gr"],
    ["DOMAIN-SUFFIX","disneymagicmoments.it"],
    ["DOMAIN-SUFFIX","disneymagicmoments.pl"],
    ["DOMAIN-SUFFIX","disneymagicmomentsme.com"],
    ["DOMAIN-SUFFIX","disneyme.com"],
    ["DOMAIN-SUFFIX","disneymeetingsandevents.com"],
    ["DOMAIN-SUFFIX","disneymovieinsiders.com"],
    ["DOMAIN-SUFFIX","disneymusicpromotion.com"],
    ["DOMAIN-SUFFIX","disneynewseries.com"],
    ["DOMAIN-SUFFIX","disneynow.com"],
    ["DOMAIN-SUFFIX","disneypeoplesurveys.com"],
    ["DOMAIN-SUFFIX","disneyplus.bn5x.net"],
    ["DOMAIN-SUFFIX","disneyplus.com"],
    ["DOMAIN-SUFFIX","disneyprivacycenter.com"],
    ["DOMAIN-SUFFIX","disneyredirects.com"],
    ["DOMAIN-SUFFIX","disneysrivieraresort.com"],
    ["DOMAIN-SUFFIX","disneystore.com"],
    ["DOMAIN-SUFFIX","disneystreaming.com"],
    ["DOMAIN-SUFFIX","disneysubscription.com"],
    ["DOMAIN-SUFFIX","disneytermsofuse.com"],
    ["DOMAIN-SUFFIX","disneytickets.co.uk"],
    ["DOMAIN-SUFFIX","disneyturkiye.com.tr"],
    ["DOMAIN-SUFFIX","disneytvajobs.com"],
    ["DOMAIN-SUFFIX","disneyworld-go.com"],
    ["DOMAIN-SUFFIX","dlfacebook.com"],
    ["DOMAIN-SUFFIX","dmed.technology"],
    ["DOMAIN-SUFFIX","dotfacebook.com"],
    ["DOMAIN-SUFFIX","dotfacebook.net"],
    ["DOMAIN-SUFFIX","draftjs.org"],
    ["DOMAIN-SUFFIX","dssott.com"],
    ["DOMAIN-SUFFIX","dtci.co"],
    ["DOMAIN-SUFFIX","dtci.technology"],
    ["DOMAIN-SUFFIX","edgedatg.com"],
    ["DOMAIN-SUFFIX","espn.co.uk"],
    ["DOMAIN-SUFFIX","espn.com"],
    ["DOMAIN-SUFFIX","espn.net"],
    ["DOMAIN-SUFFIX","espncdn.com"],
    ["DOMAIN-SUFFIX","espnqa.com"],
    ["DOMAIN-SUFFIX","expresswifi.com"],
    ["DOMAIN-SUFFIX","f8.com"],
    ["DOMAIN-SUFFIX","faacebok.com"],
    ["DOMAIN-SUFFIX","faacebook.com"],
    ["DOMAIN-SUFFIX","faasbook.com"],
    ["DOMAIN-SUFFIX","facbebook.com"],
    ["DOMAIN-SUFFIX","facbeok.com"],
    ["DOMAIN-SUFFIX","facboo.com"],
    ["DOMAIN-SUFFIX","facbook.com"],
    ["DOMAIN-SUFFIX","facbool.com"],
    ["DOMAIN-SUFFIX","facboox.com"],
    ["DOMAIN-SUFFIX","faccebook.com"],
    ["DOMAIN-SUFFIX","faccebookk.com"],
    ["DOMAIN-SUFFIX","facdbook.com"],
    ["DOMAIN-SUFFIX","facdebook.com"],
    ["DOMAIN-SUFFIX","face-book.com"],
    ["DOMAIN-SUFFIX","faceabook.com"],
    ["DOMAIN-SUFFIX","facebboc.com"],
    ["DOMAIN-SUFFIX","facebbook.com"],
    ["DOMAIN-SUFFIX","facebboook.com"],
    ["DOMAIN-SUFFIX","facebcook.com"],
    ["DOMAIN-SUFFIX","facebdok.com"],
    ["DOMAIN-SUFFIX","facebgook.com"],
    ["DOMAIN-SUFFIX","facebhook.com"],
    ["DOMAIN-SUFFIX","facebkkk.com"],
    ["DOMAIN-SUFFIX","facebo-ok.com"],
    ["DOMAIN-SUFFIX","faceboak.com"],
    ["DOMAIN-SUFFIX","facebock.com"],
    ["DOMAIN-SUFFIX","facebocke.com"],
    ["DOMAIN-SUFFIX","facebof.com"],
    ["DOMAIN-SUFFIX","faceboik.com"],
    ["DOMAIN-SUFFIX","facebok.com"],
    ["DOMAIN-SUFFIX","facebokbook.com"],
    ["DOMAIN-SUFFIX","facebokc.com"],
    ["DOMAIN-SUFFIX","facebokk.com"],
    ["DOMAIN-SUFFIX","facebokok.com"],
    ["DOMAIN-SUFFIX","faceboks.com"],
    ["DOMAIN-SUFFIX","facebol.com"],
    ["DOMAIN-SUFFIX","facebolk.com"],
    ["DOMAIN-SUFFIX","facebomok.com"],
    ["DOMAIN-SUFFIX","faceboo.com"],
    ["DOMAIN-SUFFIX","facebooa.com"],
    ["DOMAIN-SUFFIX","faceboob.com"],
    ["DOMAIN-SUFFIX","faceboobok.com"],
    ["DOMAIN-SUFFIX","facebooc.com"],
    ["DOMAIN-SUFFIX","faceboock.com"],
    ["DOMAIN-SUFFIX","facebood.com"],
    ["DOMAIN-SUFFIX","facebooe.com"],
    ["DOMAIN-SUFFIX","faceboof.com"],
    ["DOMAIN-SUFFIX","facebooi.com"],
    ["DOMAIN-SUFFIX","facebooik.com"],
    ["DOMAIN-SUFFIX","facebooik.org"],
    ["DOMAIN-SUFFIX","facebooj.com"],
    ["DOMAIN-SUFFIX","facebook-corp.com"],
    ["DOMAIN-SUFFIX","facebook-covid-19.com"],
    ["DOMAIN-SUFFIX","facebook-ebook.com"],
    ["DOMAIN-SUFFIX","facebook-forum.com"],
    ["DOMAIN-SUFFIX","facebook-hardware.com"],
    ["DOMAIN-SUFFIX","facebook-inc.com"],
    ["DOMAIN-SUFFIX","facebook-login.com"],
    ["DOMAIN-SUFFIX","facebook-newsroom.com"],
    ["DOMAIN-SUFFIX","facebook-newsroom.org"],
    ["DOMAIN-SUFFIX","facebook-pmdcenter.com"],
    ["DOMAIN-SUFFIX","facebook-pmdcenter.net"],
    ["DOMAIN-SUFFIX","facebook-pmdcenter.org"],
    ["DOMAIN-SUFFIX","facebook-privacy.com"],
    ["DOMAIN-SUFFIX","facebook-program.com"],
    ["DOMAIN-SUFFIX","facebook-studio.com"],
    ["DOMAIN-SUFFIX","facebook-support.org"],
    ["DOMAIN-SUFFIX","facebook-texas-holdem.com"],
    ["DOMAIN-SUFFIX","facebook-texas-holdem.net"],
    ["DOMAIN-SUFFIX","facebook.br"],
    ["DOMAIN-SUFFIX","facebook.ca"],
    ["DOMAIN-SUFFIX","facebook.cc"],
    ["DOMAIN-SUFFIX","facebook.com"],
    ["DOMAIN-SUFFIX","facebook.design"],
    ["DOMAIN-SUFFIX","facebook.hu"],
    ["DOMAIN-SUFFIX","facebook.in"],
    ["DOMAIN-SUFFIX","facebook.net"],
    ["DOMAIN-SUFFIX","facebook.nl"],
    ["DOMAIN-SUFFIX","facebook.org"],
    ["DOMAIN-SUFFIX","facebook.se"],
    ["DOMAIN-SUFFIX","facebook.shop"],
    ["DOMAIN-SUFFIX","facebook.tv"],
    ["DOMAIN-SUFFIX","facebook.us"],
    ["DOMAIN-SUFFIX","facebook.wang"],
    ["DOMAIN-SUFFIX","facebook123.org"],
    ["DOMAIN-SUFFIX","facebook30.com"],
    ["DOMAIN-SUFFIX","facebook30.net"],
    ["DOMAIN-SUFFIX","facebook30.org"],
    ["DOMAIN-SUFFIX","facebook4business.com"],
    ["DOMAIN-SUFFIX","facebookads.com"],
    ["DOMAIN-SUFFIX","facebookadvertisingsecrets.com"],
    ["DOMAIN-SUFFIX","facebookappcenter.info"],
    ["DOMAIN-SUFFIX","facebookappcenter.net"],
    ["DOMAIN-SUFFIX","facebookappcenter.org"],
    ["DOMAIN-SUFFIX","facebookatschool.com"],
    ["DOMAIN-SUFFIX","facebookawards.com"],
    ["DOMAIN-SUFFIX","facebookblueprint.net"],
    ["DOMAIN-SUFFIX","facebookbrand.com"],
    ["DOMAIN-SUFFIX","facebookbrand.net"],
    ["DOMAIN-SUFFIX","facebookcanadianelectionintegrityinitiative.com"],
    ["DOMAIN-SUFFIX","facebookcareer.com"],
    ["DOMAIN-SUFFIX","facebookcheats.com"],
    ["DOMAIN-SUFFIX","facebookck.com"],
    ["DOMAIN-SUFFIX","facebookclub.com"],
    ["DOMAIN-SUFFIX","facebookcom.com"],
    ["DOMAIN-SUFFIX","facebookconnect.com"],
    ["DOMAIN-SUFFIX","facebookconsultant.org"],
    ["DOMAIN-SUFFIX","facebookcoronavirus.com"],
    ["DOMAIN-SUFFIX","facebookcovers.org"],
    ["DOMAIN-SUFFIX","facebookcredits.info"],
    ["DOMAIN-SUFFIX","facebookdating.net"],
    ["DOMAIN-SUFFIX","facebookdevelopergarage.com"],
    ["DOMAIN-SUFFIX","facebookdusexe.org"],
    ["DOMAIN-SUFFIX","facebookemail.com"],
    ["DOMAIN-SUFFIX","facebookenespanol.com"],
    ["DOMAIN-SUFFIX","facebookexchange.com"],
    ["DOMAIN-SUFFIX","facebookexchange.net"],
    ["DOMAIN-SUFFIX","facebookfacebook.com"],
    ["DOMAIN-SUFFIX","facebookflow.com"],
    ["DOMAIN-SUFFIX","facebookgames.com"],
    ["DOMAIN-SUFFIX","facebookgraphsearch.com"],
    ["DOMAIN-SUFFIX","facebookgraphsearch.info"],
    ["DOMAIN-SUFFIX","facebookgroups.com"],
    ["DOMAIN-SUFFIX","facebookhome.cc"],
    ["DOMAIN-SUFFIX","facebookhome.com"],
    ["DOMAIN-SUFFIX","facebookhome.info"],
    ["DOMAIN-SUFFIX","facebookhub.com"],
    ["DOMAIN-SUFFIX","facebooki.com"],
    ["DOMAIN-SUFFIX","facebookinc.com"],
    ["DOMAIN-SUFFIX","facebookland.com"],
    ["DOMAIN-SUFFIX","facebooklikeexchange.com"],
    ["DOMAIN-SUFFIX","facebooklive.com"],
    ["DOMAIN-SUFFIX","facebooklivestaging.net"],
    ["DOMAIN-SUFFIX","facebooklivestaging.org"],
    ["DOMAIN-SUFFIX","facebooklogin.com"],
    ["DOMAIN-SUFFIX","facebooklogin.info"],
    ["DOMAIN-SUFFIX","facebookloginhelp.net"],
    ["DOMAIN-SUFFIX","facebooklogs.com"],
    ["DOMAIN-SUFFIX","facebookmail.com"],
    ["DOMAIN-SUFFIX","facebookmail.tv"],
    ["DOMAIN-SUFFIX","facebookmanager.info"],
    ["DOMAIN-SUFFIX","facebookmarketing.info"],
    ["DOMAIN-SUFFIX","facebookmarketingpartner.com"],
    ["DOMAIN-SUFFIX","facebookmarketingpartners.com"],
    ["DOMAIN-SUFFIX","facebookmobile.com"],
    ["DOMAIN-SUFFIX","facebookmsn.com"],
    ["DOMAIN-SUFFIX","facebooknews.com"],
    ["DOMAIN-SUFFIX","facebooknfl.com"],
    ["DOMAIN-SUFFIX","facebooknude.com"],
    ["DOMAIN-SUFFIX","facebookofsex.com"],
    ["DOMAIN-SUFFIX","facebookook.com"],
    ["DOMAIN-SUFFIX","facebookpaper.com"],
    ["DOMAIN-SUFFIX","facebookpay.com"],
    ["DOMAIN-SUFFIX","facebookphonenumber.net"],
    ["DOMAIN-SUFFIX","facebookphoto.com"],
    ["DOMAIN-SUFFIX","facebookphotos.com"],
    ["DOMAIN-SUFFIX","facebookpmdcenter.com"],
    ["DOMAIN-SUFFIX","facebookpoke.net"],
    ["DOMAIN-SUFFIX","facebookpoke.org"],
    ["DOMAIN-SUFFIX","facebookpoker.info"],
    ["DOMAIN-SUFFIX","facebookpokerchips.info"],
    ["DOMAIN-SUFFIX","facebookporn.net"],
    ["DOMAIN-SUFFIX","facebookporn.org"],
    ["DOMAIN-SUFFIX","facebookporno.net"],
    ["DOMAIN-SUFFIX","facebookportal.com"],
    ["DOMAIN-SUFFIX","facebooks.com"],
    ["DOMAIN-SUFFIX","facebooksafety.com"],
    ["DOMAIN-SUFFIX","facebooksecurity.net"],
    ["DOMAIN-SUFFIX","facebookshop.com"],
    ["DOMAIN-SUFFIX","facebooksignup.net"],
    ["DOMAIN-SUFFIX","facebooksite.net"],
    ["DOMAIN-SUFFIX","facebookstories.com"],
    ["DOMAIN-SUFFIX","facebookstudios.net"],
    ["DOMAIN-SUFFIX","facebookstudios.org"],
    ["DOMAIN-SUFFIX","facebooksupplier.com"],
    ["DOMAIN-SUFFIX","facebooksuppliers.com"],
    ["DOMAIN-SUFFIX","facebookswagemea.com"],
    ["DOMAIN-SUFFIX","facebookswagstore.com"],
    ["DOMAIN-SUFFIX","facebooksz.com"],
    ["DOMAIN-SUFFIX","facebookthreads.net"],
    ["DOMAIN-SUFFIX","facebooktv.net"],
    ["DOMAIN-SUFFIX","facebooktv.org"],
    ["DOMAIN-SUFFIX","facebookvacation.com"],
    ["DOMAIN-SUFFIX","facebookw.com"],
    ["DOMAIN-SUFFIX","facebookwork.com"],
    ["DOMAIN-SUFFIX","facebookworld.com"],
    ["DOMAIN-SUFFIX","facebool.com"],
    ["DOMAIN-SUFFIX","facebool.info"],
    ["DOMAIN-SUFFIX","facebooll.com"],
    ["DOMAIN-SUFFIX","faceboom.com"],
    ["DOMAIN-SUFFIX","faceboon.com"],
    ["DOMAIN-SUFFIX","faceboonk.com"],
    ["DOMAIN-SUFFIX","faceboooik.com"],
    ["DOMAIN-SUFFIX","faceboook.com"],
    ["DOMAIN-SUFFIX","faceboop.com"],
    ["DOMAIN-SUFFIX","faceboot.com"],
    ["DOMAIN-SUFFIX","faceboox.com"],
    ["DOMAIN-SUFFIX","facebopk.com"],
    ["DOMAIN-SUFFIX","facebpook.com"],
    ["DOMAIN-SUFFIX","facebuk.com"],
    ["DOMAIN-SUFFIX","facebuok.com"],
    ["DOMAIN-SUFFIX","facebvook.com"],
    ["DOMAIN-SUFFIX","facebyook.com"],
    ["DOMAIN-SUFFIX","facebzook.com"],
    ["DOMAIN-SUFFIX","facecbgook.com"],
    ["DOMAIN-SUFFIX","facecbook.com"],
    ["DOMAIN-SUFFIX","facecbook.org"],
    ["DOMAIN-SUFFIX","facecook.com"],
    ["DOMAIN-SUFFIX","facecook.org"],
    ["DOMAIN-SUFFIX","facedbook.com"],
    ["DOMAIN-SUFFIX","faceebok.com"],
    ["DOMAIN-SUFFIX","faceebook.com"],
    ["DOMAIN-SUFFIX","faceebot.com"],
    ["DOMAIN-SUFFIX","facegbok.com"],
    ["DOMAIN-SUFFIX","facegbook.com"],
    ["DOMAIN-SUFFIX","faceobk.com"],
    ["DOMAIN-SUFFIX","faceobok.com"],
    ["DOMAIN-SUFFIX","faceobook.com"],
    ["DOMAIN-SUFFIX","faceook.com"],
    ["DOMAIN-SUFFIX","facerbooik.com"],
    ["DOMAIN-SUFFIX","facerbook.com"],
    ["DOMAIN-SUFFIX","facesbooc.com"],
    ["DOMAIN-SUFFIX","facesounds.com"],
    ["DOMAIN-SUFFIX","facetook.com"],
    ["DOMAIN-SUFFIX","facevbook.com"],
    ["DOMAIN-SUFFIX","facewbook.co"],
    ["DOMAIN-SUFFIX","facewook.com"],
    ["DOMAIN-SUFFIX","facfacebook.com"],
    ["DOMAIN-SUFFIX","facfebook.com"],
    ["DOMAIN-SUFFIX","faciometrics.com"],
    ["DOMAIN-SUFFIX","fackebook.com"],
    ["DOMAIN-SUFFIX","facnbook.com"],
    ["DOMAIN-SUFFIX","facrbook.com"],
    ["DOMAIN-SUFFIX","facvebook.com"],
    ["DOMAIN-SUFFIX","facwebook.com"],
    ["DOMAIN-SUFFIX","facxebook.com"],
    ["DOMAIN-SUFFIX","fadebook.com"],
    ["DOMAIN-SUFFIX","faebok.com"],
    ["DOMAIN-SUFFIX","faebook.com"],
    ["DOMAIN-SUFFIX","faebookc.com"],
    ["DOMAIN-SUFFIX","faeboook.com"],
    ["DOMAIN-SUFFIX","faecebok.com"],
    ["DOMAIN-SUFFIX","faesebook.com"],
    ["DOMAIN-SUFFIX","fafacebook.com"],
    ["DOMAIN-SUFFIX","faicbooc.com"],
    ["DOMAIN-SUFFIX","fasebokk.com"],
    ["DOMAIN-SUFFIX","fasebook.com"],
    ["DOMAIN-SUFFIX","faseboox.com"],
    ["DOMAIN-SUFFIX","fast.com"],
    ["DOMAIN-SUFFIX","fasttext.cc"],
    ["DOMAIN-SUFFIX","favebook.com"],
    ["DOMAIN-SUFFIX","faycbok.com"],
    ["DOMAIN-SUFFIX","fb.careers"],
    ["DOMAIN-SUFFIX","fb.com"],
    ["DOMAIN-SUFFIX","fb.gg"],
    ["DOMAIN-SUFFIX","fb.me"],
    ["DOMAIN-SUFFIX","fb.watch"],
    ["DOMAIN-SUFFIX","fbacebook.com"],
    ["DOMAIN-SUFFIX","fbbmarket.com"],
    ["DOMAIN-SUFFIX","fbboostyourbusiness.com"],
    ["DOMAIN-SUFFIX","fbcdn.com"],
    ["DOMAIN-SUFFIX","fbcdn.net"],
    ["DOMAIN-SUFFIX","fbf8.com"],
    ["DOMAIN-SUFFIX","fbfeedback.com"],
    ["DOMAIN-SUFFIX","fbhome.com"],
    ["DOMAIN-SUFFIX","fbidb.io"],
    ["DOMAIN-SUFFIX","fbinc.com"],
    ["DOMAIN-SUFFIX","fbinfer.com"],
    ["DOMAIN-SUFFIX","fbinnovation.com"],
    ["DOMAIN-SUFFIX","fblitho.com"],
    ["DOMAIN-SUFFIX","fbmarketing.com"],
    ["DOMAIN-SUFFIX","fbmessenger.com"],
    ["DOMAIN-SUFFIX","fbredex.com"],
    ["DOMAIN-SUFFIX","fbreg.com"],
    ["DOMAIN-SUFFIX","fbrell.com"],
    ["DOMAIN-SUFFIX","fbrpms.com"],
    ["DOMAIN-SUFFIX","fbsbx.com"],
    ["DOMAIN-SUFFIX","fbsbx.net"],
    ["DOMAIN-SUFFIX","fbsupport-covid.net"],
    ["DOMAIN-SUFFIX","fbthirdpartypixel.com"],
    ["DOMAIN-SUFFIX","fbthirdpartypixel.net"],
    ["DOMAIN-SUFFIX","fbthirdpartypixel.org"],
    ["DOMAIN-SUFFIX","fburl.com"],
    ["DOMAIN-SUFFIX","fbwat.ch"],
    ["DOMAIN-SUFFIX","fbworkmail.com"],
    ["DOMAIN-SUFFIX","fcacebook.com"],
    ["DOMAIN-SUFFIX","fcaebook.com"],
    ["DOMAIN-SUFFIX","fcebook.com"],
    ["DOMAIN-SUFFIX","fcebookk.com"],
    ["DOMAIN-SUFFIX","fcfacebook.com"],
    ["DOMAIN-SUFFIX","fdacebook.info"],
    ["DOMAIN-SUFFIX","feacboo.com"],
    ["DOMAIN-SUFFIX","feacbook.com"],
    ["DOMAIN-SUFFIX","feacbooke.com"],
    ["DOMAIN-SUFFIX","feacebook.com"],
    ["DOMAIN-SUFFIX","fecbbok.com"],
    ["DOMAIN-SUFFIX","fecbooc.com"],
    ["DOMAIN-SUFFIX","fecbook.com"],
    ["DOMAIN-SUFFIX","feceboock.com"],
    ["DOMAIN-SUFFIX","fecebook.net"],
    ["DOMAIN-SUFFIX","feceboox.com"],
    ["DOMAIN-SUFFIX","fececbook.com"],
    ["DOMAIN-SUFFIX","feook.com"],
    ["DOMAIN-SUFFIX","ferabook.com"],
    ["DOMAIN-SUFFIX","fescebook.com"],
    ["DOMAIN-SUFFIX","fesebook.com"],
    ["DOMAIN-SUFFIX","ffacebook.com"],
    ["DOMAIN-SUFFIX","fgacebook.com"],
    ["DOMAIN-SUFFIX","ficeboock.com"],
    ["DOMAIN-SUFFIX","findyourlimits.com"],
    ["DOMAIN-SUFFIX","flow.dev"],
    ["DOMAIN-SUFFIX","flow.org"],
    ["DOMAIN-SUFFIX","flowtype.org"],
    ["DOMAIN-SUFFIX","fmcebook.com"],
    ["DOMAIN-SUFFIX","fnacebook.com"],
    ["DOMAIN-SUFFIX","fosebook.com"],
    ["DOMAIN-SUFFIX","fpacebook.com"],
    ["DOMAIN-SUFFIX","fqcebook.com"],
    ["DOMAIN-SUFFIX","fracebook.com"],
    ["DOMAIN-SUFFIX","freeb.com"],
    ["DOMAIN-SUFFIX","freebasics.com"],
    ["DOMAIN-SUFFIX","freebasics.net"],
    ["DOMAIN-SUFFIX","freebs.com"],
    ["DOMAIN-SUFFIX","freefacebook.com"],
    ["DOMAIN-SUFFIX","freefacebook.net"],
    ["DOMAIN-SUFFIX","freefacebookads.net"],
    ["DOMAIN-SUFFIX","freefblikes.com"],
    ["DOMAIN-SUFFIX","freeform.com"],
    ["DOMAIN-SUFFIX","freehulu.com"],
    ["DOMAIN-SUFFIX","freindfeed.com"],
    ["DOMAIN-SUFFIX","frescolib.org"],
    ["DOMAIN-SUFFIX","friendbook.info"],
    ["DOMAIN-SUFFIX","friendfed.com"],
    ["DOMAIN-SUFFIX","friendfeed-api.com"],
    ["DOMAIN-SUFFIX","friendfeed-media.com"],
    ["DOMAIN-SUFFIX","friendfeed.com"],
    ["DOMAIN-SUFFIX","friendfeedmedia.com"],
    ["DOMAIN-SUFFIX","fsacebok.com"],
    ["DOMAIN-SUFFIX","fscebook.com"],
    ["DOMAIN-SUFFIX","fundraisingwithfacebook.com"],
    ["DOMAIN-SUFFIX","funnyfacebook.org"],
    ["DOMAIN-SUFFIX","futureofbusinesssurvey.org"],
    ["DOMAIN-SUFFIX","fxnetwork.com"],
    ["DOMAIN-SUFFIX","fxnetworks.com"],
    ["DOMAIN-SUFFIX","gacebook.com"],
    ["DOMAIN-SUFFIX","gameroom.com"],
    ["DOMAIN-SUFFIX","gfacecbook.com"],
    ["DOMAIN-SUFFIX","ggpht.cn"],
    ["DOMAIN-SUFFIX","ggpht.com"],
    ["DOMAIN-SUFFIX","go-disneyworldgo.com"],
    ["DOMAIN-SUFFIX","go.com"],
    ["DOMAIN-SUFFIX","googlevideo.com"],
    ["DOMAIN-SUFFIX","graph-fallback.instagram.com"],
    ["DOMAIN-SUFFIX","graph.instagram.com"],
    ["DOMAIN-SUFFIX","graph.whatsapp.com"],
    ["DOMAIN-SUFFIX","graph.whatsapp.net"],
    ["DOMAIN-SUFFIX","groups.com"],
    ["DOMAIN-SUFFIX","hackerfacebook.com"],
    ["DOMAIN-SUFFIX","hackfacebook.com"],
    ["DOMAIN-SUFFIX","hackfacebookid.com"],
    ["DOMAIN-SUFFIX","hacklang.org"],
    ["DOMAIN-SUFFIX","hhvm.com"],
    ["DOMAIN-SUFFIX","hifacebook.info"],
    ["DOMAIN-SUFFIX","hongkongdisneyland.com"],
    ["DOMAIN-SUFFIX","hooloo.tv"],
    ["DOMAIN-SUFFIX","hoolu.com"],
    ["DOMAIN-SUFFIX","hoolu.tv"],
    ["DOMAIN-SUFFIX","hotstar-cdn.net"],
    ["DOMAIN-SUFFIX","hotstar-labs.com"],
    ["DOMAIN-SUFFIX","hotstar.com"],
    ["DOMAIN-SUFFIX","hotstarext.com"],
    ["DOMAIN-SUFFIX","howtohackfacebook-account.com"],
    ["DOMAIN-SUFFIX","hsfacebook.com"],
    ["DOMAIN-SUFFIX","hsprepack.akamaized.net"],
    ["DOMAIN-SUFFIX","httpfacebook.com"],
    ["DOMAIN-SUFFIX","httpsfacebook.com"],
    ["DOMAIN-SUFFIX","httpwwwfacebook.com"],
    ["DOMAIN-SUFFIX","hu1u.com"],
    ["DOMAIN-SUFFIX","huloo.cc"],
    ["DOMAIN-SUFFIX","huloo.tv"],
    ["DOMAIN-SUFFIX","hulu.com"],
    ["DOMAIN-SUFFIX","hulu.jp"],
    ["DOMAIN-SUFFIX","hulu.tv"],
    ["DOMAIN-SUFFIX","hulu.us"],
    ["DOMAIN-SUFFIX","huluaction.com"],
    ["DOMAIN-SUFFIX","huluad.com"],
    ["DOMAIN-SUFFIX","huluapp.com"],
    ["DOMAIN-SUFFIX","huluasks.com"],
    ["DOMAIN-SUFFIX","hulucall.com"],
    ["DOMAIN-SUFFIX","hulufree.com"],
    ["DOMAIN-SUFFIX","hulugans.com"],
    ["DOMAIN-SUFFIX","hulugermany.com"],
    ["DOMAIN-SUFFIX","hulugo.com"],
    ["DOMAIN-SUFFIX","huluim.com"],
    ["DOMAIN-SUFFIX","huluinstantmessenger.com"],
    ["DOMAIN-SUFFIX","huluitaly.com"],
    ["DOMAIN-SUFFIX","hulunet.com"],
    ["DOMAIN-SUFFIX","hulunetwork.com"],
    ["DOMAIN-SUFFIX","huluplus.com"],
    ["DOMAIN-SUFFIX","hulupremium.com"],
    ["DOMAIN-SUFFIX","hulupurchase.com"],
    ["DOMAIN-SUFFIX","huluqa.com"],
    ["DOMAIN-SUFFIX","hulurussia.com"],
    ["DOMAIN-SUFFIX","huluspain.com"],
    ["DOMAIN-SUFFIX","hulusports.com"],
    ["DOMAIN-SUFFIX","hulustream.com"],
    ["DOMAIN-SUFFIX","huluteam.com"],
    ["DOMAIN-SUFFIX","hulutv.com"],
    ["DOMAIN-SUFFIX","huluusa.com"],
    ["DOMAIN-SUFFIX","i.org"],
    ["DOMAIN-SUFFIX","ig.me"],
    ["DOMAIN-SUFFIX","igcdn.com"],
    ["DOMAIN-SUFFIX","igsonar.com"],
    ["DOMAIN-SUFFIX","igtv.com"],
    ["DOMAIN-SUFFIX","imstagram.com"],
    ["DOMAIN-SUFFIX","imtagram.com"],
    ["DOMAIN-SUFFIX","instaadder.com"],
    ["DOMAIN-SUFFIX","instachecker.com"],
    ["DOMAIN-SUFFIX","instafallow.com"],
    ["DOMAIN-SUFFIX","instafollower.com"],
    ["DOMAIN-SUFFIX","instagainer.com"],
    ["DOMAIN-SUFFIX","instagda.com"],
    ["DOMAIN-SUFFIX","instagify.com"],
    ["DOMAIN-SUFFIX","instagmania.com"],
    ["DOMAIN-SUFFIX","instagor.com"],
    ["DOMAIN-SUFFIX","instagram-brand.com"],
    ["DOMAIN-SUFFIX","instagram-engineering.com"],
    ["DOMAIN-SUFFIX","instagram-help.com"],
    ["DOMAIN-SUFFIX","instagram-press.com"],
    ["DOMAIN-SUFFIX","instagram-press.net"],
    ["DOMAIN-SUFFIX","instagram.com"],
    ["DOMAIN-SUFFIX","instagramci.com"],
    ["DOMAIN-SUFFIX","instagramcn.com"],
    ["DOMAIN-SUFFIX","instagramdi.com"],
    ["DOMAIN-SUFFIX","instagramhashtags.net"],
    ["DOMAIN-SUFFIX","instagramhilecim.com"],
    ["DOMAIN-SUFFIX","instagramhilesi.org"],
    ["DOMAIN-SUFFIX","instagramium.com"],
    ["DOMAIN-SUFFIX","instagramizlenme.com"],
    ["DOMAIN-SUFFIX","instagramkusu.com"],
    ["DOMAIN-SUFFIX","instagramlogin.com"],
    ["DOMAIN-SUFFIX","instagramm.com"],
    ["DOMAIN-SUFFIX","instagramn.com"],
    ["DOMAIN-SUFFIX","instagrampartners.com"],
    ["DOMAIN-SUFFIX","instagramphoto.com"],
    ["DOMAIN-SUFFIX","instagramq.com"],
    ["DOMAIN-SUFFIX","instagramsepeti.com"],
    ["DOMAIN-SUFFIX","instagramtakipcisatinal.net"],
    ["DOMAIN-SUFFIX","instagramtakiphilesi.com"],
    ["DOMAIN-SUFFIX","instagramtips.com"],
    ["DOMAIN-SUFFIX","instagramtr.com"],
    ["DOMAIN-SUFFIX","instagran.com"],
    ["DOMAIN-SUFFIX","instagranm.com"],
    ["DOMAIN-SUFFIX","instagrem.com"],
    ["DOMAIN-SUFFIX","instagrm.com"],
    ["DOMAIN-SUFFIX","instagtram.com"],
    ["DOMAIN-SUFFIX","instagy.com"],
    ["DOMAIN-SUFFIX","instamgram.com"],
    ["DOMAIN-SUFFIX","instangram.com"],
    ["DOMAIN-SUFFIX","instanttelegram.com"],
    ["DOMAIN-SUFFIX","instaplayer.net"],
    ["DOMAIN-SUFFIX","instastyle.tv"],
    ["DOMAIN-SUFFIX","instgram.com"],
    ["DOMAIN-SUFFIX","intagram.com"],
    ["DOMAIN-SUFFIX","intagrm.com"],
    ["DOMAIN-SUFFIX","internet.org"],
    ["DOMAIN-SUFFIX","intgram.com"],
    ["DOMAIN-SUFFIX","joinmaidez.com"],
    ["DOMAIN-SUFFIX","kingstagram.com"],
    ["DOMAIN-SUFFIX","klik.me"],
    ["DOMAIN-SUFFIX","lifeatspotify.com"],
    ["DOMAIN-SUFFIX","liverail.com"],
    ["DOMAIN-SUFFIX","liverail.tv"],
    ["DOMAIN-SUFFIX","lnstagram-help.com"],
    ["DOMAIN-SUFFIX","login-account.net"],
    ["DOMAIN-SUFFIX","lucasfilm.com"],
    ["DOMAIN-SUFFIX","m.me"],
    ["DOMAIN-SUFFIX","makeitopen.com"],
    ["DOMAIN-SUFFIX","markzuckerberg.com"],
    ["DOMAIN-SUFFIX","marvel.com"],
    ["DOMAIN-SUFFIX","marvel10thanniversary.com"],
    ["DOMAIN-SUFFIX","marveldimensionofheroes.com"],
    ["DOMAIN-SUFFIX","marvelparty.net"],
    ["DOMAIN-SUFFIX","marvelpinball.com"],
    ["DOMAIN-SUFFIX","marvelsdoubleagent.com"],
    ["DOMAIN-SUFFIX","marvelspotlightplays.com"],
    ["DOMAIN-SUFFIX","marvelsuperheroseptember.com"],
    ["DOMAIN-SUFFIX","marvelsuperwar.com"],
    ["DOMAIN-SUFFIX","mcrouter.net"],
    ["DOMAIN-SUFFIX","mcrouter.org"],
    ["DOMAIN-SUFFIX","messenger.com"],
    ["DOMAIN-SUFFIX","messengerdevelopers.com"],
    ["DOMAIN-SUFFIX","meta.com"],
    ["DOMAIN-SUFFIX","mickey.tv"],
    ["DOMAIN-SUFFIX","midentsolutions.com"],
    ["DOMAIN-SUFFIX","mobilefacebook.com"],
    ["DOMAIN-SUFFIX","moneywithfacebook.com"],
    ["DOMAIN-SUFFIX","moviesanywhere.com"],
    ["DOMAIN-SUFFIX","muscdn.com"],
    ["DOMAIN-SUFFIX","mushymush.tv"],
    ["DOMAIN-SUFFIX","musical.ly"],
    ["DOMAIN-SUFFIX","myfbfans.com"],
    ["DOMAIN-SUFFIX","myhulu.com"],
    ["DOMAIN-SUFFIX","natgeomaps.com"],
    ["DOMAIN-SUFFIX","nationalgeographic.com"],
    ["DOMAIN-SUFFIX","nationalgeographicpartners.com"],
    ["DOMAIN-SUFFIX","nbabot.net"],
    ["DOMAIN-SUFFIX","netflix.ca"],
    ["DOMAIN-SUFFIX","netflix.com"],
    ["DOMAIN-SUFFIX","netflix.net"],
    ["DOMAIN-SUFFIX","netflixdnstest0.com"],
    ["DOMAIN-SUFFIX","netflixdnstest1.com"],
    ["DOMAIN-SUFFIX","netflixdnstest10.com"],
    ["DOMAIN-SUFFIX","netflixdnstest2.com"],
    ["DOMAIN-SUFFIX","netflixdnstest3.com"],
    ["DOMAIN-SUFFIX","netflixdnstest4.com"],
    ["DOMAIN-SUFFIX","netflixdnstest5.com"],
    ["DOMAIN-SUFFIX","netflixdnstest6.com"],
    ["DOMAIN-SUFFIX","netflixdnstest7.com"],
    ["DOMAIN-SUFFIX","netflixdnstest8.com"],
    ["DOMAIN-SUFFIX","netflixdnstest9.com"],
    ["DOMAIN-SUFFIX","netflixinvestor.com"],
    ["DOMAIN-SUFFIX","netflixtechblog.com"],
    ["DOMAIN-SUFFIX","newsfeed.com"],
    ["DOMAIN-SUFFIX","nextstop.com"],
    ["DOMAIN-SUFFIX","nflxext.com"],
    ["DOMAIN-SUFFIX","nflximg.com"],
    ["DOMAIN-SUFFIX","nflximg.net"],
    ["DOMAIN-SUFFIX","nflxsearch.net"],
    ["DOMAIN-SUFFIX","nflxso.net"],
    ["DOMAIN-SUFFIX","nflxvideo.net"],
    ["DOMAIN-SUFFIX","ngeo.com"],
    ["DOMAIN-SUFFIX","nomadlandmovie.ch"],
    ["DOMAIN-SUFFIX","ocul.us"],
    ["DOMAIN-SUFFIX","oculus-china.com"],
    ["DOMAIN-SUFFIX","oculus.com"],
    ["DOMAIN-SUFFIX","oculus2014.com"],
    ["DOMAIN-SUFFIX","oculus3d.com"],
    ["DOMAIN-SUFFIX","oculusblog.com"],
    ["DOMAIN-SUFFIX","oculusbrand.com"],
    ["DOMAIN-SUFFIX","oculuscasino.net"],
    ["DOMAIN-SUFFIX","oculuscdn.com"],
    ["DOMAIN-SUFFIX","oculusconnect.com"],
    ["DOMAIN-SUFFIX","oculusdiving.com"],
    ["DOMAIN-SUFFIX","oculusforbusiness.com"],
    ["DOMAIN-SUFFIX","oculusrift.com"],
    ["DOMAIN-SUFFIX","oculusvr.com"],
    ["DOMAIN-SUFFIX","ogp.me"],
    ["DOMAIN-SUFFIX","oninstagram.com"],
    ["DOMAIN-SUFFIX","online-deals.net"],
    ["DOMAIN-SUFFIX","online-instagram.com"],
    ["DOMAIN-SUFFIX","onlineinstagram.com"],
    ["DOMAIN-SUFFIX","opencreate.org"],
    ["DOMAIN-SUFFIX","opengraphprotocol.com"],
    ["DOMAIN-SUFFIX","opengraphprotocol.org"],
    ["DOMAIN-SUFFIX","originalhulu.com"],
    ["DOMAIN-SUFFIX","parse.com"],
    ["DOMAIN-SUFFIX","payhulu.com"],
    ["DOMAIN-SUFFIX","periscope.tv"],
    ["DOMAIN-SUFFIX","pixar.com"],
    ["DOMAIN-SUFFIX","pixel.facebook.com"],
    ["DOMAIN-SUFFIX","playmation.com"],
    ["DOMAIN-SUFFIX","powersunitedvr.com"],
    ["DOMAIN-SUFFIX","pscdn.co"],
    ["DOMAIN-SUFFIX","pscp.tv"],
    ["DOMAIN-SUFFIX","pyrobot.org"],
    ["DOMAIN-SUFFIX","reachtheworldonfacebook.com"],
    ["DOMAIN-SUFFIX","react.com"],
    ["DOMAIN-SUFFIX","reactjs.com"],
    ["DOMAIN-SUFFIX","reactjs.org"],
    ["DOMAIN-SUFFIX","recoiljs.org"],
    ["DOMAIN-SUFFIX","redd.it"],
    ["DOMAIN-SUFFIX","reddit.app.link"],
    ["DOMAIN-SUFFIX","reddit.com"],
    ["DOMAIN-SUFFIX","reddit.map.fastly.net"],
    ["DOMAIN-SUFFIX","redditblog.com"],
    ["DOMAIN-SUFFIX","reddithelp.com"],
    ["DOMAIN-SUFFIX","redditinc.com"],
    ["DOMAIN-SUFFIX","redditmail.com"],
    ["DOMAIN-SUFFIX","redditmedia.com"],
    ["DOMAIN-SUFFIX","redditspace.com"],
    ["DOMAIN-SUFFIX","redditstatic.com"],
    ["DOMAIN-SUFFIX","redditstatus.com"],
    ["DOMAIN-SUFFIX","redkix.com"],
    ["DOMAIN-SUFFIX","registerhulu.com"],
    ["DOMAIN-SUFFIX","rocksdb.com"],
    ["DOMAIN-SUFFIX","rocksdb.net"],
    ["DOMAIN-SUFFIX","rocksdb.org"],
    ["DOMAIN-SUFFIX","scdn.co"],
    ["DOMAIN-SUFFIX","searchlightpictures.com"],
    ["DOMAIN-SUFFIX","shanghaidisneyresort.com"],
    ["DOMAIN-SUFFIX","shopdisney.com"],
    ["DOMAIN-SUFFIX","shopfacebook.com"],
    ["DOMAIN-SUFFIX","shops-disney.com"],
    ["DOMAIN-SUFFIX","sorcerersarena.com"],
    ["DOMAIN-SUFFIX","spaindisney.com"],
    ["DOMAIN-SUFFIX","sportsfacebook.com"],
    ["DOMAIN-SUFFIX","sportstream.com"],
    ["DOMAIN-SUFFIX","spoti.fi"],
    ["DOMAIN-SUFFIX","spotify-everywhere.com"],
    ["DOMAIN-SUFFIX","spotify.com"],
    ["DOMAIN-SUFFIX","spotify.design"],
    ["DOMAIN-SUFFIX","spotify.link"],
    ["DOMAIN-SUFFIX","spotifycdn.com"],
    ["DOMAIN-SUFFIX","spotifycdn.net"],
    ["DOMAIN-SUFFIX","spotifycharts.com"],
    ["DOMAIN-SUFFIX","spotifycodes.com"],
    ["DOMAIN-SUFFIX","spotifyforbrands.com"],
    ["DOMAIN-SUFFIX","spotifyforvendors.com"],
    ["DOMAIN-SUFFIX","spotifyjobs.com"],
    ["DOMAIN-SUFFIX","star-brasil.com"],
    ["DOMAIN-SUFFIX","star-latam.com"],
    ["DOMAIN-SUFFIX","starott.com"],
    ["DOMAIN-SUFFIX","starplus.com"],
    ["DOMAIN-SUFFIX","starwars.com"],
    ["DOMAIN-SUFFIX","starwarsgalacticstarcruiser.com"],
    ["DOMAIN-SUFFIX","starwarskids.com"],
    ["DOMAIN-SUFFIX","streamingdisney.net"],
    ["DOMAIN-SUFFIX","supportfacebook.com"],
    ["DOMAIN-SUFFIX","t.co"],
    ["DOMAIN-SUFFIX","tellapart.com"],
    ["DOMAIN-SUFFIX","terragraph.com"],
    ["DOMAIN-SUFFIX","tfbnw.net"],
    ["DOMAIN-SUFFIX","thefacebook.com"],
    ["DOMAIN-SUFFIX","thefacebook.net"],
    ["DOMAIN-SUFFIX","thefind.com"],
    ["DOMAIN-SUFFIX","thehulubraintrust.com"],
    ["DOMAIN-SUFFIX","theinstagramhack.com"],
    ["DOMAIN-SUFFIX","themarvelexperiencetour.com"],
    ["DOMAIN-SUFFIX","thestationbymaker.com"],
    ["DOMAIN-SUFFIX","thewaltdisneycompany.com"],
    ["DOMAIN-SUFFIX","thisispolaris.com"],
    ["DOMAIN-SUFFIX","threads.com"],
    ["DOMAIN-SUFFIX","threads.net"],
    ["DOMAIN-SUFFIX","tik-tokapi.com"],
    ["DOMAIN-SUFFIX","tiktok-minis.com"],
    ["DOMAIN-SUFFIX","tiktok-row.net"],
    ["DOMAIN-SUFFIX","tiktok.com"],
    ["DOMAIN-SUFFIX","tiktokcdn-eu.com"],
    ["DOMAIN-SUFFIX","tiktokcdn-us.com"],
    ["DOMAIN-SUFFIX","tiktokcdn-us.com.edgesuite.net"],
    ["DOMAIN-SUFFIX","tiktokcdn.com"],
    ["DOMAIN-SUFFIX","tiktokcdn.com.akamaized.net"],
    ["DOMAIN-SUFFIX","tiktokcdn.com.edgesuite.net"],
    ["DOMAIN-SUFFIX","tiktokd.net"],
    ["DOMAIN-SUFFIX","tiktokd.org"],
    ["DOMAIN-SUFFIX","tiktokeu-cdn.com"],
    ["DOMAIN-SUFFIX","tiktokglobalshopv.com"],
    ["DOMAIN-SUFFIX","tiktokminis.us"],
    ["DOMAIN-SUFFIX","tiktokrow-cdn.com"],
    ["DOMAIN-SUFFIX","tiktokv.com"],
    ["DOMAIN-SUFFIX","tiktokv.com.edgekey.net"],
    ["DOMAIN-SUFFIX","tiktokv.com.edgesuite.net"],
    ["DOMAIN-SUFFIX","tiktokv.eu"],
    ["DOMAIN-SUFFIX","tiktokv.us"],
    ["DOMAIN-SUFFIX","tiktokw.eu"],
    ["DOMAIN-SUFFIX","tiktokw.us"],
    ["DOMAIN-SUFFIX","tokyodisneyresort.jp"],
    ["DOMAIN-SUFFIX","toplayerserver.com"],
    ["DOMAIN-SUFFIX","tospotify.com"],
    ["DOMAIN-SUFFIX","ttcdn-us.com"],
    ["DOMAIN-SUFFIX","ttlivecdn.com"],
    ["DOMAIN-SUFFIX","ttoverseaus.net"],
    ["DOMAIN-SUFFIX","ttwstatic.com"],
    ["DOMAIN-SUFFIX","tweetdeck.com"],
    ["DOMAIN-SUFFIX","twimg.com"],
    ["DOMAIN-SUFFIX","twitpic.com"],
    ["DOMAIN-SUFFIX","twitter.biz"],
    ["DOMAIN-SUFFIX","twitter.com"],
    ["DOMAIN-SUFFIX","twitter.jp"],
    ["DOMAIN-SUFFIX","twitter.map.fastly.net"],
    ["DOMAIN-SUFFIX","twittercommunity.com"],
    ["DOMAIN-SUFFIX","twitterflightschool.com"],
    ["DOMAIN-SUFFIX","twitterinc.com"],
    ["DOMAIN-SUFFIX","twitteroauth.com"],
    ["DOMAIN-SUFFIX","twitterstat.us"],
    ["DOMAIN-SUFFIX","twtrdns.net"],
    ["DOMAIN-SUFFIX","twttr.com"],
    ["DOMAIN-SUFFIX","twttr.net"],
    ["DOMAIN-SUFFIX","twvid.com"],
    ["DOMAIN-SUFFIX","viewpointsfromfacebook.com"],
    ["DOMAIN-SUFFIX","vine.co"],
    ["DOMAIN-SUFFIX","wa.me"],
    ["DOMAIN-SUFFIX","waltdisneystudios.com"],
    ["DOMAIN-SUFFIX","watchdisneyfe.com"],
    ["DOMAIN-SUFFIX","watchespn.com"],
    ["DOMAIN-SUFFIX","web-instagram.net"],
    ["DOMAIN-SUFFIX","whatsapp-plus.info"],
    ["DOMAIN-SUFFIX","whatsapp-plus.me"],
    ["DOMAIN-SUFFIX","whatsapp-plus.net"],
    ["DOMAIN-SUFFIX","whatsapp.cc"],
    ["DOMAIN-SUFFIX","whatsapp.com"],
    ["DOMAIN-SUFFIX","whatsapp.info"],
    ["DOMAIN-SUFFIX","whatsapp.net"],
    ["DOMAIN-SUFFIX","whatsapp.org"],
    ["DOMAIN-SUFFIX","whatsapp.tv"],
    ["DOMAIN-SUFFIX","whatsappbrand.com"],
    ["DOMAIN-SUFFIX","whyfacebook.com"],
    ["DOMAIN-SUFFIX","wide-youtube.l.google.com"],
    ["DOMAIN-SUFFIX","withyoutube.com"],
    ["DOMAIN-SUFFIX","workplace.com"],
    ["DOMAIN-SUFFIX","workplaceusecases.com"],
    ["DOMAIN-SUFFIX","worldhack.com"],
    ["DOMAIN-SUFFIX","www-facebook.com"],
    ["DOMAIN-SUFFIX","wwwfacebok.com"],
    ["DOMAIN-SUFFIX","wwwfacebook.com"],
    ["DOMAIN-SUFFIX","wwwhuluplus.com"],
    ["DOMAIN-SUFFIX","wwwinstagram.com"],
    ["DOMAIN-SUFFIX","wwwmfacebook.com"],
    ["DOMAIN-SUFFIX","x.com"],
    ["DOMAIN-SUFFIX","yogalayout.com"],
    ["DOMAIN-SUFFIX","youtu.be"],
    ["DOMAIN-SUFFIX","youtube"],
    ["DOMAIN-SUFFIX","youtube-nocookie.com"],
    ["DOMAIN-SUFFIX","youtube-ui.l.google.com"],
    ["DOMAIN-SUFFIX","youtube.ae"],
    ["DOMAIN-SUFFIX","youtube.al"],
    ["DOMAIN-SUFFIX","youtube.am"],
    ["DOMAIN-SUFFIX","youtube.at"],
    ["DOMAIN-SUFFIX","youtube.az"],
    ["DOMAIN-SUFFIX","youtube.ba"],
    ["DOMAIN-SUFFIX","youtube.be"],
    ["DOMAIN-SUFFIX","youtube.bg"],
    ["DOMAIN-SUFFIX","youtube.bh"],
    ["DOMAIN-SUFFIX","youtube.bo"],
    ["DOMAIN-SUFFIX","youtube.by"],
    ["DOMAIN-SUFFIX","youtube.ca"],
    ["DOMAIN-SUFFIX","youtube.cat"],
    ["DOMAIN-SUFFIX","youtube.ch"],
    ["DOMAIN-SUFFIX","youtube.cl"],
    ["DOMAIN-SUFFIX","youtube.co"],
    ["DOMAIN-SUFFIX","youtube.co.ae"],
    ["DOMAIN-SUFFIX","youtube.co.at"],
    ["DOMAIN-SUFFIX","youtube.co.cr"],
    ["DOMAIN-SUFFIX","youtube.co.hu"],
    ["DOMAIN-SUFFIX","youtube.co.id"],
    ["DOMAIN-SUFFIX","youtube.co.il"],
    ["DOMAIN-SUFFIX","youtube.co.in"],
    ["DOMAIN-SUFFIX","youtube.co.jp"],
    ["DOMAIN-SUFFIX","youtube.co.ke"],
    ["DOMAIN-SUFFIX","youtube.co.kr"],
    ["DOMAIN-SUFFIX","youtube.co.ma"],
    ["DOMAIN-SUFFIX","youtube.co.nz"],
    ["DOMAIN-SUFFIX","youtube.co.th"],
    ["DOMAIN-SUFFIX","youtube.co.tz"],
    ["DOMAIN-SUFFIX","youtube.co.ug"],
    ["DOMAIN-SUFFIX","youtube.co.uk"],
    ["DOMAIN-SUFFIX","youtube.co.ve"],
    ["DOMAIN-SUFFIX","youtube.co.za"],
    ["DOMAIN-SUFFIX","youtube.co.zw"],
    ["DOMAIN-SUFFIX","youtube.com"],
    ["DOMAIN-SUFFIX","youtube.com.ar"],
    ["DOMAIN-SUFFIX","youtube.com.au"],
    ["DOMAIN-SUFFIX","youtube.com.az"],
    ["DOMAIN-SUFFIX","youtube.com.bd"],
    ["DOMAIN-SUFFIX","youtube.com.bh"],
    ["DOMAIN-SUFFIX","youtube.com.bo"],
    ["DOMAIN-SUFFIX","youtube.com.br"],
    ["DOMAIN-SUFFIX","youtube.com.by"],
    ["DOMAIN-SUFFIX","youtube.com.co"],
    ["DOMAIN-SUFFIX","youtube.com.do"],
    ["DOMAIN-SUFFIX","youtube.com.ec"],
    ["DOMAIN-SUFFIX","youtube.com.ee"],
    ["DOMAIN-SUFFIX","youtube.com.eg"],
    ["DOMAIN-SUFFIX","youtube.com.es"],
    ["DOMAIN-SUFFIX","youtube.com.gh"],
    ["DOMAIN-SUFFIX","youtube.com.gr"],
    ["DOMAIN-SUFFIX","youtube.com.gt"],
    ["DOMAIN-SUFFIX","youtube.com.hk"],
    ["DOMAIN-SUFFIX","youtube.com.hn"],
    ["DOMAIN-SUFFIX","youtube.com.hr"],
    ["DOMAIN-SUFFIX","youtube.com.jm"],
    ["DOMAIN-SUFFIX","youtube.com.jo"],
    ["DOMAIN-SUFFIX","youtube.com.kw"],
    ["DOMAIN-SUFFIX","youtube.com.lb"],
    ["DOMAIN-SUFFIX","youtube.com.lv"],
    ["DOMAIN-SUFFIX","youtube.com.ly"],
    ["DOMAIN-SUFFIX","youtube.com.mk"],
    ["DOMAIN-SUFFIX","youtube.com.mt"],
    ["DOMAIN-SUFFIX","youtube.com.mx"],
    ["DOMAIN-SUFFIX","youtube.com.my"],
    ["DOMAIN-SUFFIX","youtube.com.ng"],
    ["DOMAIN-SUFFIX","youtube.com.ni"],
    ["DOMAIN-SUFFIX","youtube.com.om"],
    ["DOMAIN-SUFFIX","youtube.com.pa"],
    ["DOMAIN-SUFFIX","youtube.com.pe"],
    ["DOMAIN-SUFFIX","youtube.com.ph"],
    ["DOMAIN-SUFFIX","youtube.com.pk"],
    ["DOMAIN-SUFFIX","youtube.com.pt"],
    ["DOMAIN-SUFFIX","youtube.com.py"],
    ["DOMAIN-SUFFIX","youtube.com.qa"],
    ["DOMAIN-SUFFIX","youtube.com.ro"],
    ["DOMAIN-SUFFIX","youtube.com.sa"],
    ["DOMAIN-SUFFIX","youtube.com.sg"],
    ["DOMAIN-SUFFIX","youtube.com.sv"],
    ["DOMAIN-SUFFIX","youtube.com.tn"],
    ["DOMAIN-SUFFIX","youtube.com.tr"],
    ["DOMAIN-SUFFIX","youtube.com.tw"],
    ["DOMAIN-SUFFIX","youtube.com.ua"],
    ["DOMAIN-SUFFIX","youtube.com.uy"],
    ["DOMAIN-SUFFIX","youtube.com.ve"],
    ["DOMAIN-SUFFIX","youtube.cr"],
    ["DOMAIN-SUFFIX","youtube.cz"],
    ["DOMAIN-SUFFIX","youtube.de"],
    ["DOMAIN-SUFFIX","youtube.dk"],
    ["DOMAIN-SUFFIX","youtube.ee"],
    ["DOMAIN-SUFFIX","youtube.es"],
    ["DOMAIN-SUFFIX","youtube.fi"],
    ["DOMAIN-SUFFIX","youtube.fr"],
    ["DOMAIN-SUFFIX","youtube.ge"],
    ["DOMAIN-SUFFIX","youtube.googleapis.com"],
    ["DOMAIN-SUFFIX","youtube.gr"],
    ["DOMAIN-SUFFIX","youtube.gt"],
    ["DOMAIN-SUFFIX","youtube.hk"],
    ["DOMAIN-SUFFIX","youtube.hr"],
    ["DOMAIN-SUFFIX","youtube.hu"],
    ["DOMAIN-SUFFIX","youtube.ie"],
    ["DOMAIN-SUFFIX","youtube.in"],
    ["DOMAIN-SUFFIX","youtube.iq"],
    ["DOMAIN-SUFFIX","youtube.is"],
    ["DOMAIN-SUFFIX","youtube.it"],
    ["DOMAIN-SUFFIX","youtube.jo"],
    ["DOMAIN-SUFFIX","youtube.jp"],
    ["DOMAIN-SUFFIX","youtube.kr"],
    ["DOMAIN-SUFFIX","youtube.kz"],
    ["DOMAIN-SUFFIX","youtube.la"],
    ["DOMAIN-SUFFIX","youtube.lk"],
    ["DOMAIN-SUFFIX","youtube.lt"],
    ["DOMAIN-SUFFIX","youtube.lu"],
    ["DOMAIN-SUFFIX","youtube.lv"],
    ["DOMAIN-SUFFIX","youtube.ly"],
    ["DOMAIN-SUFFIX","youtube.ma"],
    ["DOMAIN-SUFFIX","youtube.md"],
    ["DOMAIN-SUFFIX","youtube.me"],
    ["DOMAIN-SUFFIX","youtube.mk"],
    ["DOMAIN-SUFFIX","youtube.mn"],
    ["DOMAIN-SUFFIX","youtube.mx"],
    ["DOMAIN-SUFFIX","youtube.my"],
    ["DOMAIN-SUFFIX","youtube.ng"],
    ["DOMAIN-SUFFIX","youtube.ni"],
    ["DOMAIN-SUFFIX","youtube.nl"],
    ["DOMAIN-SUFFIX","youtube.no"],
    ["DOMAIN-SUFFIX","youtube.pa"],
    ["DOMAIN-SUFFIX","youtube.pe"],
    ["DOMAIN-SUFFIX","youtube.ph"],
    ["DOMAIN-SUFFIX","youtube.pk"],
    ["DOMAIN-SUFFIX","youtube.pl"],
    ["DOMAIN-SUFFIX","youtube.pr"],
    ["DOMAIN-SUFFIX","youtube.pt"],
    ["DOMAIN-SUFFIX","youtube.qa"],
    ["DOMAIN-SUFFIX","youtube.ro"],
    ["DOMAIN-SUFFIX","youtube.rs"],
    ["DOMAIN-SUFFIX","youtube.ru"],
    ["DOMAIN-SUFFIX","youtube.sa"],
    ["DOMAIN-SUFFIX","youtube.se"],
    ["DOMAIN-SUFFIX","youtube.sg"],
    ["DOMAIN-SUFFIX","youtube.si"],
    ["DOMAIN-SUFFIX","youtube.sk"],
    ["DOMAIN-SUFFIX","youtube.sn"],
    ["DOMAIN-SUFFIX","youtube.soy"],
    ["DOMAIN-SUFFIX","youtube.sv"],
    ["DOMAIN-SUFFIX","youtube.tn"],
    ["DOMAIN-SUFFIX","youtube.tv"],
    ["DOMAIN-SUFFIX","youtube.ua"],
    ["DOMAIN-SUFFIX","youtube.ug"],
    ["DOMAIN-SUFFIX","youtube.uy"],
    ["DOMAIN-SUFFIX","youtube.vn"],
    ["DOMAIN-SUFFIX","youtubeeducation.com"],
    ["DOMAIN-SUFFIX","youtubeembeddedplayer.googleapis.com"],
    ["DOMAIN-SUFFIX","youtubefanfest.com"],
    ["DOMAIN-SUFFIX","youtubegaming.com"],
    ["DOMAIN-SUFFIX","youtubego.co.id"],
    ["DOMAIN-SUFFIX","youtubego.co.in"],
    ["DOMAIN-SUFFIX","youtubego.com"],
    ["DOMAIN-SUFFIX","youtubego.com.br"],
    ["DOMAIN-SUFFIX","youtubego.id"],
    ["DOMAIN-SUFFIX","youtubego.in"],
    ["DOMAIN-SUFFIX","youtubei.googleapis.com"],
    ["DOMAIN-SUFFIX","youtubekids.com"],
    ["DOMAIN-SUFFIX","youtubemobilesupport.com"],
    ["DOMAIN-SUFFIX","yt.be"],
    ["DOMAIN-SUFFIX","ytimg.com"],
    ["DOMAIN-SUFFIX","zuckerberg.com"],
    ["DOMAIN-SUFFIX","zuckerberg.net"],
    ["DOMAIN","adeventtracker.spotify.com"],
    ["DOMAIN","adstudio-assets.scdn.co"],
    ["DOMAIN","aod-pod-uk-live.akamaized.net"],
    ["DOMAIN","as-dash-uk-live.akamaized.net"],
    ["DOMAIN","as-hls-uk-live.akamaized.net"],
    ["DOMAIN","audio-ak-spotify-com.akamaized.net"],
    ["DOMAIN","audio4-ak-spotify-com.akamaized.net"],
    ["DOMAIN","bloodhound.spotify.com"],
    ["DOMAIN","cdn-spotify-experiments.conductrics.com"],
    ["DOMAIN","developers.facebook.com"],
    ["DOMAIN","disney.my.sentry.io"],
    ["DOMAIN","disneyplus.com.ssl.sc.omtrdc.net"],
    ["DOMAIN","espn.api.edge.bamgrid.com"],
    ["DOMAIN","espn.hb.omtrdc.net"],
    ["DOMAIN","espndotcom.tt.omtrdc.net"],
    ["DOMAIN","fbcdn-a.akamaihd.net"],
    ["DOMAIN","heads-ak-spotify-com.akamaized.net"],
    ["DOMAIN","heads4-ak-spotify-com.akamaized.net"],
    ["DOMAIN","hulu.playback.edge.bamgrid.com"],
    ["DOMAIN","netflix.com.edgesuite.net"],
    ["DOMAIN","p16-tiktok-dm-sticker-sign-sg.ibyteimg.com"],
    ["DOMAIN","p16-tiktokcdn-com.akamaized.net"],
    ["DOMAIN","roovza-launches.appsflyersdk.com"],
    ["DOMAIN","roovza.inapps.appsflyersdk.com"],
    ["DOMAIN","roovza.launches.appsflyersdk.com"],
    ["DOMAIN","roovza.skadsdk.appsflyersdk.com"],
    ["DOMAIN","spotify.com.edgesuite.net"],
    ["DOMAIN","spotify.map.fastly.net"],
    ["DOMAIN","spotify.map.fastlylb.net"],
    ["DOMAIN","ve-dash-uk-live.akamaized.net"],
    ["DOMAIN","ve-uhd-push-uk-live.akamaized.net"],
    ["DOMAIN","vod-dash-uk-live.akamaized.net"],
    ["DOMAIN","vod-dash-ww-live.akamaized.net"],
    ["DOMAIN","vod-hls-uk-live.akamaized.net"],
    ["DOMAIN","vod-sub-uk-live.akamaized.net"],
    ["DOMAIN","vod-thumb-uk-live.akamaized.net"],
    ["DOMAIN","vod-thumb-ww-live.akamaized.net"],
    ["DOMAIN","vs-cmaf-push-uk-live.akamaized.net"],
    ["DOMAIN","vs-cmaf-pushb-ww-live.akamaized.net"],
    ["DOMAIN","vs-hls-push-uk-live.akamaized.net"],
    ["DOMAIN","vs-hls-pushb-uk-live.akamaized.net"],
    ["DOMAIN","yt3.googleusercontent.com"]
  ],
  "telegram": [
    ["DOMAIN-SUFFIX","airhorn.solutions"],
    ["DOMAIN-SUFFIX","airhornbot.com"],
    ["DOMAIN-SUFFIX","bigbeans.solutions"],
    ["DOMAIN-SUFFIX","cdn-telegram.org"],
    ["DOMAIN-SUFFIX","comments.app"],
    ["DOMAIN-SUFFIX","contest.com"],
    ["DOMAIN-SUFFIX","dis.gd"],
    ["DOMAIN-SUFFIX","discord-activities.com"],
    ["DOMAIN-SUFFIX","discord.co"],
    ["DOMAIN-SUFFIX","discord.com"],
    ["DOMAIN-SUFFIX","discord.design"],
    ["DOMAIN-SUFFIX","discord.dev"],
    ["DOMAIN-SUFFIX","discord.gg"],
    ["DOMAIN-SUFFIX","discord.gift"],
    ["DOMAIN-SUFFIX","discord.gifts"],
    ["DOMAIN-SUFFIX","discord.media"],
    ["DOMAIN-SUFFIX","discord.new"],
    ["DOMAIN-SUFFIX","discord.store"],
    ["DOMAIN-SUFFIX","discord.tools"],
    ["DOMAIN-SUFFIX","discordactivities.com"],
    ["DOMAIN-SUFFIX","discordapp.com"],
    ["DOMAIN-SUFFIX","discordapp.io"],
    ["DOMAIN-SUFFIX","discordapp.net"],
    ["DOMAIN-SUFFIX","discordcdn.com"],
    ["DOMAIN-SUFFIX","discordmerch.com"],
    ["DOMAIN-SUFFIX","discordpartygames.com"],
    ["DOMAIN-SUFFIX","discordsays.com"],
    ["DOMAIN-SUFFIX","discordstatus.com"],
    ["DOMAIN-SUFFIX","fragment.com"],
    ["DOMAIN-SUFFIX","graph.org"],
    ["DOMAIN-SUFFIX","quiz.directory"],
    ["DOMAIN-SUFFIX","t.me"],
    ["DOMAIN-SUFFIX","tdesktop.com"],
    ["DOMAIN-SUFFIX","telega.one"],
    ["DOMAIN-SUFFIX","telegra.ph"],
    ["DOMAIN-SUFFIX","telegram-cdn.org"],
    ["DOMAIN-SUFFIX","telegram.dog"],
    ["DOMAIN-SUFFIX","telegram.me"],
    ["DOMAIN-SUFFIX","telegram.org"],
    ["DOMAIN-SUFFIX","telegram.space"],
    ["DOMAIN-SUFFIX","telesco.pe"],
    ["DOMAIN-SUFFIX","tg.dev"],
    ["DOMAIN-SUFFIX","ton.org"],
    ["DOMAIN-SUFFIX","toncenter.com"],
    ["DOMAIN-SUFFIX","tx.me"],
    ["DOMAIN-SUFFIX","usercontent.dev"],
    ["DOMAIN-SUFFIX","watchanimeattheoffice.com"],
    ["DOMAIN","discord-attachments-uploads-prd.storage.googleapis.com"],
    ["DOMAIN","hammerandchisel.ssl.zendesk.com"]
  ],
  "github": [
    ["DOMAIN-SUFFIX","atom.io"],
    ["DOMAIN-SUFFIX","collector.github.com"],
    ["DOMAIN-SUFFIX","dependabot.com"],
    ["DOMAIN-SUFFIX","gh.io"],
    ["DOMAIN-SUFFIX","ghcr.io"],
    ["DOMAIN-SUFFIX","ghe.com"],
    ["DOMAIN-SUFFIX","git.io"],
    ["DOMAIN-SUFFIX","github.ai"],
    ["DOMAIN-SUFFIX","github.blog"],
    ["DOMAIN-SUFFIX","github.career"],
    ["DOMAIN-SUFFIX","github.com"],
    ["DOMAIN-SUFFIX","github.community"],
    ["DOMAIN-SUFFIX","github.dev"],
    ["DOMAIN-SUFFIX","github.io"],
    ["DOMAIN-SUFFIX","githubapp.com"],
    ["DOMAIN-SUFFIX","githubassets.com"],
    ["DOMAIN-SUFFIX","githubhackathon.com"],
    ["DOMAIN-SUFFIX","githubnext.com"],
    ["DOMAIN-SUFFIX","githubpreview.dev"],
    ["DOMAIN-SUFFIX","githubstatus.com"],
    ["DOMAIN-SUFFIX","githubsupport.com"],
    ["DOMAIN-SUFFIX","githubuniverse.com"],
    ["DOMAIN-SUFFIX","githubusercontent.com"],
    ["DOMAIN-SUFFIX","myoctocat.com"],
    ["DOMAIN-SUFFIX","npm.community"],
    ["DOMAIN-SUFFIX","npmjs.com"],
    ["DOMAIN-SUFFIX","npmjs.org"],
    ["DOMAIN-SUFFIX","octocaptcha.com"],
    ["DOMAIN-SUFFIX","opensource.guide"],
    ["DOMAIN-SUFFIX","repo.new"],
    ["DOMAIN-SUFFIX","thegithubshop.com"],
    ["DOMAIN","github-api.arkoselabs.com"],
    ["DOMAIN","github-cloud.s3.amazonaws.com"],
    ["DOMAIN","github-production-release-asset-2e65be.s3.amazonaws.com"],
    ["DOMAIN","github-production-repository-file-5c1aeb.s3.amazonaws.com"],
    ["DOMAIN","github-production-repository-image-32fea6.s3.amazonaws.com"],
    ["DOMAIN","github-production-upload-manifest-file-7fdce7.s3.amazonaws.com"],
    ["DOMAIN","github-production-user-asset-6210df.s3.amazonaws.com"],
    ["DOMAIN","productionresultssa0.blob.core.windows.net"],
    ["DOMAIN","productionresultssa1.blob.core.windows.net"],
    ["DOMAIN","productionresultssa10.blob.core.windows.net"],
    ["DOMAIN","productionresultssa11.blob.core.windows.net"],
    ["DOMAIN","productionresultssa12.blob.core.windows.net"],
    ["DOMAIN","productionresultssa13.blob.core.windows.net"],
    ["DOMAIN","productionresultssa14.blob.core.windows.net"],
    ["DOMAIN","productionresultssa15.blob.core.windows.net"],
    ["DOMAIN","productionresultssa16.blob.core.windows.net"],
    ["DOMAIN","productionresultssa17.blob.core.windows.net"],
    ["DOMAIN","productionresultssa18.blob.core.windows.net"],
    ["DOMAIN","productionresultssa19.blob.core.windows.net"],
    ["DOMAIN","productionresultssa2.blob.core.windows.net"],
    ["DOMAIN","productionresultssa3.blob.core.windows.net"],
    ["DOMAIN","productionresultssa4.blob.core.windows.net"],
    ["DOMAIN","productionresultssa5.blob.core.windows.net"],
    ["DOMAIN","productionresultssa6.blob.core.windows.net"],
    ["DOMAIN","productionresultssa7.blob.core.windows.net"],
    ["DOMAIN","productionresultssa8.blob.core.windows.net"],
    ["DOMAIN","productionresultssa9.blob.core.windows.net"]
  ]
};
// END GENERATED COMMUNITY RULES

// Local supplements and routing exceptions; community data is maintained separately.
var SOURCE_PATTERNS = {
  apple: {
    core: [
      "+.apple.com",
      "+.icloud.com",
      "+.icloud.com.cn"
    ],
    content: [
      "+.icloud-content.com",
      "+.mzstatic.com",
      "+.cdn-apple.com",
      "+.aaplimg.com"
    ],
    services: ["+.apple-cloudkit.com"]
  },
  nodeSelection: [
    "+.visualstudio.com",
    "+.marketplace.visualstudio.com",
    "+.gallery.vsassets.io",
    "+.gallerycdn.vsassets.io",
    "+.vscode.dev",
    "+.vscode-cdn.net",
    "+.vscode-unpkg.net",
    "+.vscode.download.prss.microsoft.com",
    "+.download.visualstudio.microsoft.com",
    "+.vscode-sync.trafficmanager.net",
    "+.vscode-sync-insiders.trafficmanager.net",
    "+.default.exp-tas.com",
    "+.vsmarketplacebadges.dev"
  ],
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
        "+.google.ca",
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
    ai: {
      anthropic: [
        "+.anthropic.com.cdn.cloudflare.net",
        "+.anthropic.auth0.com",
        "+.anthropic-com.ghost.io"
      ],
      openai: [
        "+.openaimerge.com"
      ],
      google_ai: [
        "+.assistant.google.com",
        "+.accounts.google.com",
        "+.accounts.google.ca",
        "+.ai.google",
        "+.antigravity-ide.com"
      ],
      kiro: [
        "+.prod.us-east-1.auth.desktop.kiro.dev",
        "+.management.us-east-1.kiro.dev",
        "+.q.us-east-1.amazonaws.com"
      ],
      perplexity: [
        "+.perplexitycdn.com"
      ],
      router_and_tools: [
        "+.mistral.com"
      ]
    },
    aiSharedInfrastructure: {
      support_and_analytics: [
        "+.intercom.io",
        "+.intercomcdn.com",
        "+.cdn.usefathom.com",
        "+.sentry.io",
        "+.datadoghq.com",
        "+.browser-intake-us5-datadoghq.com",
        "+.statsigapi.net",
        "+.statsig.com",
        "+.rum.browser-intake-datadoghq.com"
      ],
      auth_and_payments: [
        "+.ct.sendgrid.net",
        "+.workos.com",
        "+.workoscdn.com",
        "+.workos.imgix.net",
        "+.challenges.cloudflare.com",
        "+.js.stripe.com",
        "+.humb.apple.com"
      ]
    },
    media: {
      overrides: [
        "+.byteoversea.com"
      ],
      japan: [
        "+.sony.jp",
        "+.sony.co.jp",
        "+.nintendo.co.jp",
        "+.yahoo.co.jp",
        "+.yimg.jp",
        "+.line.me",
        "+.line-apps.com",
        "+.line-scdn.net",
        "+.line.naver.jp",
        "+.linecorp.com"
      ]
    },
    generalEgress: {
      infrastructure: [
        "+.cloudflare.com",
        "+.cloudflareinsights.com",
        "+.workers.dev"
      ],
      globalSites: [
        "+.oracle.com",
        "+.takealot.com",
        "+.pixpix.com",
        "+.naver.com",
        "+.noon.com",
        "+.wikipedia.org",
        "+.wikimedia.org",
        "+.wikimediafoundation.org",
        "+.yandex.com",
        "+.yandex.ru",
        "+.yastatic.net",
        "+.ya.ru"
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
    overrides: {
      domesticDns: [
        "+.rivotek.com",
        "+.larksuite.com",
        "+.larkoffice.com",
        "+.dashscope.aliyuncs.com",
        "+.feishu.net",
        "+.feishucdn.com",
        "+.dingtalkapps.com"
      ],
      overseasDns: [
        "+.typeless.com"
      ]
    }
  },
  policy: {
    dnsFallbackExtra: [
      "+.cdn.cloudflare.net",
      "ping0.cc",
      "ipinfo.io",
      "+.ip.net.coffee"
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
        "Cursor Helper (Renderer)",
        "Cursor Helper (GPU)",
        "Cursor Helper (Plugin)",
        "Cursor Helper (Alerts)",
        "Codex (Service)",
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
    aiCli: ["agy", "claude", "gemini", "codex", "claude.exe", "gemini.exe", "codex.exe"],
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
    { type: "IP-CIDR6", value: "fe80::/10",             target: BASE.ruleTargets.direct }
  ]
};

var SOURCE_ANTHROPIC_NETWORK_RULES = [
  { type: "IP-CIDR",  value: "160.79.104.0/21" },
  { type: "IP-CIDR6", value: "2607:6bc0::/32" }
];

var SOURCE_TAILSCALE_RULES = {
  destinationDirect: [
    { type: "IP-CIDR",  value: "100.64.0.0/10",       target: BASE.ruleTargets.direct },
    { type: "IP-CIDR",  value: "100.100.100.100/32",   target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48",  target: BASE.ruleTargets.direct }
  ],
  controlPlaneDomains: ["tailscale.com", "tailscale.io"],
  magicDnsDomains: ["ts.net"],
  processNames: [
    "tailscaled.exe",
    "tailscaled",
    "Tailscale",
    "IPNExtension",
    "io.tailscale.ipn.macsys.network-extension"
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

function communityDomainPatterns(target) {
  var patterns = [];
  var entries = COMMUNITY_RULES[target] || [];
  for (var i = 0; i < entries.length; i++) {
    patterns.push(entries[i][0] === "DOMAIN-SUFFIX" ? "+." + entries[i][1] : entries[i][1]);
  }
  return uniqueStrings(patterns);
}

function addCommunityRules(ruleLines, seenRuleIdentities, entries, target) {
  for (var i = 0; i < entries.length; i++) {
    addRuleIfNotExists(ruleLines, seenRuleIdentities, entries[i][0], entries[i][1], target);
  }
}

function buildCommunityAiRules(target) {
  var rules = [];
  if (target) addCommunityRules(rules, {}, COMMUNITY_RULES.ai, target);
  return rules;
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
  var directDomesticOverrides = uniqueStrings(SOURCE_PATTERNS.direct.overrides.domesticDns.slice());
  var directOverseasOverrides = uniqueStrings(SOURCE_PATTERNS.direct.overrides.overseasDns.slice());
  var directAll = mergeStringGroups([directDomesticOverrides, directOverseasOverrides]);
  var nodeSelectionDomains = mergeStringGroups([
    SOURCE_PATTERNS.nodeSelection,
    SOURCE_PATTERNS.microsoft.developer,
    SOURCE_PATTERNS.microsoft.search,
    // 保留通用 Google 精确规则，关闭 googleTrafficConsistency 时恢复原有节点选择行为。
    flattenGroupedPatterns(SOURCE_PATTERNS.chain.platform)
  ]);
  var microsoftDomains     = excludeStrings(flattenGroupedPatterns(SOURCE_PATTERNS.microsoft), nodeSelectionDomains);

  var aiPatterns       = flattenGroupedPatterns(SOURCE_PATTERNS.chain.ai);
  var aiSharedInfrastructure = flattenGroupedPatterns(SOURCE_PATTERNS.chain.aiSharedInfrastructure);
  var generalEgressDomains = excludeStrings(
    flattenGroupedPatterns(SOURCE_PATTERNS.chain.generalEgress),
    directAll
  );
  var validationExtra  = uniqueStrings(SOURCE_PATTERNS.policy.dnsFallbackExtra.slice());
  var strictAi         = excludeStrings(aiPatterns, directAll);
  var strictSupport    = [];
  var strictValidation = excludeStrings(validationExtra, directAll);
  var strictAll        = mergeStringGroups([strictAi, strictSupport, strictValidation]);

  var specs = [
    {
      name: "🌍 国际媒体",
      preference: "proxy",
      domains: excludeStrings(SOURCE_PATTERNS.chain.media.overrides, directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "📲 Telegram",
      preference: "proxy",
      domains: [],
      dnsPolicy: "overseas"
    },
    {
      name: "🐙 GitHub",
      preference: "proxy",
      domains: [],
      dnsPolicy: "overseas"
    },
    {
      name: "Ⓜ️ 微软服务",
      preference: "direct",
      domains: excludeStrings(microsoftDomains, directAll),
      dnsPolicy: "overseas"
    },
    {
      name: "🎮 游戏平台",
      preference: "proxy",
      domains: excludeStrings(flattenGroupedPatterns(SOURCE_PATTERNS.chain.gaming), directAll),
      dnsPolicy: "overseas"
    },
    {
      name: BASE.nodeNames.japanServices,
      preference: "proxy",
      preferredRegion: "JP",
      domains: excludeStrings(SOURCE_PATTERNS.chain.media.japan, directAll),
      dnsPolicy: "overseas",
      hidden: true
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
      fixedProxies: ["DIRECT"]
    }
  ];

  var snifferForce = mergeStringGroups([
    uniqueStrings(SOURCE_PATTERNS.policy.snifferForceBase.slice()),
    strictAll,
    communityDomainPatterns("ai")
  ]);
  var snifferSkip = uniqueStrings(
    SOURCE_PATTERNS.policy.snifferSkipBase.concat(directOverseasOverrides)
  );

  return {
    specs: specs,
    patterns: {
      strict: {
        ai: strictAi,
        sharedInfrastructure: aiSharedInfrastructure,
        support: strictSupport,
        validation: strictValidation,
        all: strictAll
      },
      direct: {
        overrides: {
          domesticDns: directDomesticOverrides,
          overseasDns: directOverseasOverrides
        },
        groups: [directDomesticOverrides, directOverseasOverrides]
      },
      nodeSelection: excludeStrings(nodeSelectionDomains, directAll),
      generalEgress: generalEgressDomains,
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
    { type: "DOMAIN-SUFFIX", value: "assistant.google.com" },
    { type: "DOMAIN-SUFFIX", value: "accounts.google.ca" },
    { type: "DOMAIN-SUFFIX", value: "cursor.sh" },
    { type: "DOMAIN-SUFFIX", value: "aistudio.google.com" },
    { type: "DOMAIN-SUFFIX", value: "perplexity.ai" },
    { type: "PROCESS-NAME",  value: "Claude" },
    { type: "PROCESS-NAME",  value: "Codex (Service)" }
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
  config.ipv6 = USER_OPTIONS.enableIPv6 === true;
  config.dns = buildDnsConfig();
  config.sniffer = buildSnifferConfig();
}

function ensureTunDnsHijack(config) {
  var hijacks;
  if (!config.tun) return;
  hijacks = Array.isArray(config.tun["dns-hijack"])
    ? config.tun["dns-hijack"]
    : [];
  config.tun["dns-hijack"] = uniqueStrings(hijacks.concat([
    "any:53",
    "tcp://any:53"
  ]));
}

function assignNameserverPolicyDomains(policy, domains, dohServers) {
  for (var i = 0; i < domains.length; i++) {
    policy[domains[i]] = dohServers;
  }
}

function routeDnsServers(dnsServers, proxyName) {
  var routedServers = [];
  for (var i = 0; i < dnsServers.length; i++) {
    routedServers.push(dnsServers[i] + "#" + proxyName);
  }
  return routedServers;
}

function getOverseasDnsTarget() {
  return USER_OPTIONS.overseasDnsTarget || BASE.nodeNames.aiAgent;
}

function getOverseasDnsServers() {
  return routeDnsServers(BASE.dns.overseas, getOverseasDnsTarget());
}

function getFallbackDnsServers() {
  return routeDnsServers(BASE.dns.fallback, getOverseasDnsTarget());
}

// 非 AI 的境外域名：cn 下与 AI 共用 overseasDnsTarget；overseas 下本机直连解析。
function getForeignDnsServers() {
  if (getLocationProfile().localDnsIsDomestic) return getOverseasDnsServers();
  return routeDnsServers(BASE.dns.overseas, BASE.ruleTargets.direct);
}

// 国内域名（geosite:cn 与国内直连例外）：cn 下直连国内 DoH；overseas 下经 🇨🇳 国内 组查询，拿到国内就近解析。
function getCnDnsServers() {
  if (!getLocationProfile().domesticDnsViaGroup) return BASE.dns.domestic;
  return routeDnsServers(BASE.dns.domestic, getDomesticTarget());
}

// 本机直连流量（direct-nameserver、dnsPolicy: "domestic" 的直连功能组）使用的本地 DNS。
function getLocalDnsServers() {
  // overseas 显式 #DIRECT：respect-rules 下 dns.google 会命中 GEOSITE,google → AI Agent。
  if (getLocationProfile().localDnsIsDomestic) return BASE.dns.domestic;
  return routeDnsServers(BASE.dns.overseas, BASE.ruleTargets.direct);
}

function buildNameserverPolicy() {
  var overseasDnsServers = getOverseasDnsServers();
  var foreignDnsServers = getForeignDnsServers();
  var cnDnsServers = getCnDnsServers();
  var localDnsServers = getLocalDnsServers();
  var policy = {
    "geosite:cn": cnDnsServers,
    "geosite:geolocation-!cn": foreignDnsServers,
    "geosite:gfw": foreignDnsServers,
    "geosite:openai": overseasDnsServers
  };
  var i;
  var spec;
  var dnsServers;
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.ai,              overseasDnsServers);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.support,         overseasDnsServers);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.strict.validation,      overseasDnsServers);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.generalEgress,           foreignDnsServers);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.direct.overrides.domesticDns, cnDnsServers);
  assignNameserverPolicyDomains(policy, DERIVED.patterns.direct.overrides.overseasDns, foreignDnsServers);
  if (isGoogleTrafficConsistencyEnabled()) {
    policy["geosite:google-deepmind"] = overseasDnsServers;
    policy["geosite:youtube"] = routeDnsServers(BASE.dns.overseas, "🌍 国际媒体");
    policy["geosite:google-play"] = routeDnsServers(BASE.dns.overseas, "🌍 国际媒体");
    policy["geosite:googlefcm"] = routeDnsServers(BASE.dns.overseas, "🌍 国际媒体");
    policy["geosite:google"] = overseasDnsServers;
  }
  for (i = 0; i < DERIVED.specs.length; i++) {
    spec = DERIVED.specs[i];
    if (!spec.domains || spec.domains.length === 0 || !spec.dnsPolicy) continue;
    dnsServers = spec.dnsPolicy === "overseas" ? foreignDnsServers : localDnsServers;
    assignNameserverPolicyDomains(policy, spec.domains, dnsServers);
  }
  var communityTargets = ["media", "telegram", "github", "ai"];
  for (i = 0; i < communityTargets.length; i++) {
    dnsServers = communityTargets[i] === "ai" ? overseasDnsServers : foreignDnsServers;
    assignNameserverPolicyDomains(policy, communityDomainPatterns(communityTargets[i]), dnsServers);
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
  var magicDnsDomains = [];
  for (var i = 0; i < SOURCE_TAILSCALE_RULES.magicDnsDomains.length; i++) {
    magicDnsDomains.push("+." + SOURCE_TAILSCALE_RULES.magicDnsDomains[i]);
  }
  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(DERIVED.patterns.apple)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains)
    .concat(magicDnsDomains);
}

function buildDnsFallbackFilterDomains() {
  var groups = [
    DERIVED.patterns.strict.all,
    DERIVED.patterns.generalEgress,
    DERIVED.patterns.direct.overrides.overseasDns,
    communityDomainPatterns("ai"),
    communityDomainPatterns("media"),
    communityDomainPatterns("telegram"),
    communityDomainPatterns("github")
  ];
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
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: buildDnsFallbackFilterDomains()
  };
}

function buildDnsBaseConfig() {
  var profile = getLocationProfile();
  var config;
  if (!profile.localDnsIsDomestic) {
    // 境外：本机直连 DNS 已经干净，不需要 CN GeoIP fallback。
    return {
      enable: true,
      listen: "0.0.0.0:1053",
      ipv6: USER_OPTIONS.enableIPv6 === true,
      "respect-rules": true,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.1/16",
      "default-nameserver": BASE.dns.overseasBootstrap.slice(),
      nameserver: getForeignDnsServers(),
      "proxy-server-nameserver": BASE.dns.overseas.slice(),
      "direct-nameserver": BASE.dns.overseas.slice(),
      "direct-nameserver-follow-policy": true
    };
  }
  config = {
    enable: true,
    listen: "0.0.0.0:1053",
    ipv6: USER_OPTIONS.enableIPv6 === true,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": BASE.dns.domesticBootstrap.slice(),
    nameserver: getOverseasDnsServers(),
    "proxy-server-nameserver": BASE.dns.domestic,
    "direct-nameserver": BASE.dns.domestic.slice(),
    "direct-nameserver-follow-policy": true,
    fallback: getFallbackDnsServers()
  };
  return config;
}

function buildDnsConfig() {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter();
  if (dnsConfig.fallback) dnsConfig["fallback-filter"] = buildDnsFallbackFilter();
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

function insertBeforeDirect(proxies, proxyName) {
  if (!proxies || proxies.indexOf(proxyName) >= 0) return;
  var directIdx = proxies.indexOf(BASE.ruleTargets.direct);
  if (directIdx >= 0) proxies.splice(directIdx, 0, proxyName);
  else proxies.push(proxyName);
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

function appendProxyNode(config, node) {
  if (findProxyByName(config.proxies, node.name)) {
    throw createUserError("代理节点与已有节点重名：" + node.name);
  }
  config.proxies.push(node);
  return node;
}

// 所有节点和组就绪后检查引用；同时覆盖组成员与 dialer-proxy 的混合链路。
function validateProxyGraph(config) {
  var entries = Object.create(null);
  var states = Object.create(null);
  var names = [];
  var stack = [];
  var builtins = { DIRECT: true, REJECT: true, "REJECT-DROP": true, PASS: true, COMPATIBLE: true };

  function isBuiltin(name) {
    return Object.prototype.hasOwnProperty.call(builtins, name);
  }

  function register(item, isGroup) {
    var name = item && item.name;
    if (typeof name !== "string" || !name.trim()) {
      throw createUserError("代理节点或策略组缺少有效名称");
    }
    if (entries[name] || isBuiltin(name)) {
      throw createUserError("节点或策略组重名：" + name);
    }
    entries[name] = { item: item, isGroup: isGroup, edges: [] };
    names.push(name);
  }

  function addReference(owner, target) {
    if (typeof target !== "string" || !target.trim()) {
      throw createUserError(owner + " 的代理引用必须为非空名称");
    }
    if (isBuiltin(target)) return;
    if (!entries[target]) {
      throw createUserError("代理引用不存在：" + owner + " -> " + target);
    }
    entries[owner].edges.push(target);
  }

  function visit(name) {
    if (states[name] === 2) return;
    if (states[name] === 1) {
      throw createUserError("代理循环引用：" + stack.slice(stack.indexOf(name)).concat([name]).join(" -> "));
    }
    states[name] = 1;
    stack.push(name);
    var edges = entries[name].edges;
    for (var i = 0; i < edges.length; i++) visit(edges[i]);
    stack.pop();
    states[name] = 2;
  }

  var i;
  var j;
  var entry;
  var members;
  var dialer;
  for (i = 0; i < config.proxies.length; i++) register(config.proxies[i], false);
  for (i = 0; i < config["proxy-groups"].length; i++) register(config["proxy-groups"][i], true);
  for (i = 0; i < names.length; i++) {
    entry = entries[names[i]];
    if (entry.isGroup) {
      members = typeof entry.item.proxies === "undefined" ? [] : entry.item.proxies;
      if (!Array.isArray(members)) throw createUserError(names[i] + " 的 proxies 必须为名称数组");
      for (j = 0; j < members.length; j++) addReference(names[i], members[j]);
    }
    dialer = entry.item["dialer-proxy"];
    if (dialer !== null && typeof dialer !== "undefined" && dialer !== "") {
      addReference(names[i], dialer);
    }
  }
  for (i = 0; i < names.length; i++) visit(names[i]);
}

function collectProxyNames(proxies) {
  var names = [];
  for (var i = 0; i < proxies.length; i++) {
    names.push(proxies[i].name);
  }
  return names;
}

function getAutoSelectExcludeKeywords() {
  var customKeywords = USER_OPTIONS.autoSelectExcludeKeywords || [];
  return uniqueStrings(AUTO_SELECT_INFO_NODE_KEYWORDS.concat(customKeywords));
}

function isAutoSelectInfoNodeName(proxyName) {
  var name = String(proxyName || "");
  var lowerName = name.toLowerCase();
  var keywords = getAutoSelectExcludeKeywords();
  var i;
  if (/https?:\/\//i.test(name)) return true;
  for (i = 0; i < keywords.length; i++) {
    if (lowerName.indexOf(String(keywords[i]).toLowerCase()) >= 0) return true;
  }
  return false;
}

function filterAutoSelectProxyNames(proxyNames) {
  var filtered = [];
  for (var i = 0; i < proxyNames.length; i++) {
    if (isAutoSelectInfoNodeName(proxyNames[i])) continue;
    filtered.push(proxyNames[i]);
  }
  return uniqueStrings(filtered);
}

function normalizeAutoSelectGroup(group) {
  if (group && group.proxies) {
    group.proxies = filterAutoSelectProxyNames(group.proxies);
  }
  if (group && (group.type === "url-test" || group.type === "smart")) {
    group.url = getProxyProbeUrl();
  }
  return group;
}

function isManagedProxyName(config, proxyName) {
  return (
    proxyName === BASE.nodeNames.home ||
    proxyName === BASE.nodeNames.homeChained ||
    proxyName === config._frontProxyName
  );
}

function collectRegionNodeNames(config, regionRegex) {
  var names = [];
  for (var i = 0; i < config.proxies.length; i++) {
    var proxy = config.proxies[i];
    if (regionRegex.test(proxy.name) && !isManagedProxyName(config, proxy.name)) {
      names.push(proxy.name);
    }
  }
  return names;
}

// 生成锚点组（节点选择）并按 BASE.regionOrder 顺序收集可用的地区节点。
// 节点选择的成员为 [自动选择, 地区组..., 自定义节点..., DIRECT]，选组而不是选裸节点。
// 地区组和 GLOBAL 由 appendTailGroups 插入底部。
function ensureAnchorGroups(config, options) {
  var opts = options || {};
  var enableAutoSelect = opts.enableAutoSelect !== false;
  var enableRegions = opts.enableRegions !== false;
  var allNodeNames = [];
  for (var i = 0; i < config.proxies.length; i++) {
    if (!isManagedProxyName(config, config.proxies[i].name)) {
      allNodeNames.push(config.proxies[i].name);
    }
  }

  // 收集地区组定义（暂不插入 proxy-groups）
  var regionGroups = [];
  var regionGroupNames = [];
  if (enableRegions) {
    for (var j = 0; j < BASE.regionOrder.length; j++) {
      var regionKey = BASE.regionOrder[j];
      var regionMeta = BASE.regions[regionKey];
      if (!regionMeta) continue;
      var regionNodes = collectRegionNodeNames(config, regionMeta.regex);
      if (regionNodes.length === 0) continue;
      var rgName = regionMeta.flag + "|" + regionMeta.label;
      regionGroups.push({
        name: rgName, type: "url-test", proxies: regionNodes,
        url: getProxyProbeUrl(), interval: 300, tolerance: 50
      });
      regionGroupNames.push(rgName);
    }
  }

  var nodeSelProxies = [];
  if (enableAutoSelect) {
    // 自动选择组已在 ensureAutoSelectGroup 中确保存在，直接查找名字
    var smartName = USER_OPTIONS.autoSelectGroupName + "(Smart Group)";
    var baseName  = USER_OPTIONS.autoSelectGroupName;
    var autoSelectName = hasProxyOrGroup(config, smartName) ? smartName : baseName;
    nodeSelProxies.push(autoSelectName);
  }

  // 节点选择 = [自动选择, 地区组..., 全部裸节点..., DIRECT]
  nodeSelProxies = nodeSelProxies.concat(regionGroupNames).concat(allNodeNames).concat(["DIRECT"]);
  upsertNamedItem(config["proxy-groups"], {
    name: "节点选择",
    type: "select",
    proxies: nodeSelProxies,
    url: getProxyProbeUrl()
  });

  return { allNodeNames: allNodeNames, regionGroups: regionGroups, regionGroupNames: regionGroupNames };
}

// 🌐 国外：境外流量策略组（原隐藏的“通用出海”）。cn 默认节点选择，overseas 默认 DIRECT。
function ensureOverseasPolicyGroup(config, regionGroupNames) {
  var head = getLocationProfile().inChina ? ["节点选择", "DIRECT"] : ["DIRECT", "节点选择"];
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.policyNames.overseas,
    type: "select",
    proxies: uniqueStrings(head.concat(regionGroupNames || [])),
    url: getProxyProbeUrl()
  });
  return BASE.policyNames.overseas;
}

// 🐟 兜底：最后一条 MATCH。候选为 🇨🇳 国内 / 🌐 国外（cn 默认国内，overseas 默认国外）；cn 另带 🔌 全协议回退。
function ensureFallbackPolicyGroup(config, fullProtocolTarget) {
  var proxies = getLocationProfile().inChina
    ? [BASE.policyNames.domestic, BASE.policyNames.overseas]
    : [BASE.policyNames.overseas, BASE.policyNames.domestic];
  if (fullProtocolTarget) proxies.push(fullProtocolTarget);
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.policyNames.fallback,
    type: "select",
    proxies: proxies,
    url: getProxyProbeUrl()
  });
  return BASE.policyNames.fallback;
}

function buildProxyNameLookup(proxies) {
  var lookup = {};
  for (var i = 0; i < proxies.length; i++) {
    if (proxies[i] && proxies[i].name) lookup[proxies[i].name] = proxies[i];
  }
  return lookup;
}

function buildProxyGroupNameLookup(proxyGroups) {
  var lookup = {};
  for (var i = 0; i < proxyGroups.length; i++) {
    if (proxyGroups[i] && proxyGroups[i].name) lookup[proxyGroups[i].name] = proxyGroups[i];
  }
  return lookup;
}

function isFullProtocolReference(name, proxyLookup, groupLookup, visitedProxyNames, visitedGroupNames) {
  if (name === "DIRECT") return true;
  if (proxyLookup[name]) {
    return isFullProtocolProxy(proxyLookup[name], proxyLookup, groupLookup, visitedProxyNames, visitedGroupNames);
  }
  if (groupLookup[name]) {
    return isFullProtocolProxyGroup(groupLookup[name], proxyLookup, groupLookup, visitedProxyNames, visitedGroupNames);
  }
  return false;
}

function isFullProtocolProxyGroup(group, proxyLookup, groupLookup, visitedProxyNames, visitedGroupNames) {
  var proxyNames;
  var visited;
  var isSupported = true;
  if (!group || group["disable-udp"] === true) return false;
  proxyNames = group.proxies || [];
  if (proxyNames.length === 0) return false;
  visited = visitedGroupNames || {};
  if (visited[group.name]) return false;
  visited[group.name] = true;
  for (var i = 0; i < proxyNames.length; i++) {
    if (!isFullProtocolReference(proxyNames[i], proxyLookup, groupLookup, visitedProxyNames, visited)) {
      isSupported = false;
      break;
    }
  }
  delete visited[group.name];
  return isSupported;
}

function isFullProtocolProxy(proxy, proxyLookup, groupLookup, visitedProxyNames, visitedGroupNames) {
  var dialerProxyName;
  var visited;
  var isSupported;
  if (!proxy || String(proxy.type || "").toLowerCase() === "http") return false;
  if (proxy.udp !== true) return false;

  dialerProxyName = proxy["dialer-proxy"];
  if (!dialerProxyName) return true;
  visited = visitedProxyNames || {};
  if (visited[proxy.name]) return false;
  visited[proxy.name] = true;
  isSupported = isFullProtocolReference(dialerProxyName, proxyLookup, groupLookup, visited, visitedGroupNames);
  delete visited[proxy.name];
  return isSupported;
}

function collectFullProtocolProxyNames(config, candidateNames) {
  var candidateLookup = buildStringLookup(candidateNames || []);
  var proxyLookup = buildProxyNameLookup(config.proxies);
  var groupLookup = buildProxyGroupNameLookup(config["proxy-groups"]);
  var names = [];
  for (var i = 0; i < config.proxies.length; i++) {
    var proxy = config.proxies[i];
    if (!candidateLookup[proxy.name] || !isFullProtocolProxy(proxy, proxyLookup, groupLookup)) continue;
    names.push(proxy.name);
  }
  return uniqueStrings(names);
}

function ensureFullProtocolFallbackGroup(config, candidateNames) {
  if (!isFullProtocolFallbackEnabled()) return null;
  var proxies = collectFullProtocolProxyNames(config, candidateNames);
  if (proxies.length === 0) return null;
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.nodeNames.fullProtocolFallback,
    type: "url-test",
    proxies: proxies,
    url: getProxyProbeUrl(),
    interval: 300,
    tolerance: 50,
    hidden: true
  });
  return BASE.nodeNames.fullProtocolFallback;
}

function getPreferredRegionGroupName(spec, regionGroupNames) {
  var regionMeta;
  var groupName;
  if (!spec.preferredRegion) return null;
  regionMeta = BASE.regions[spec.preferredRegion];
  if (!regionMeta) return null;
  groupName = regionMeta.flag + "|" + regionMeta.label;
  return (regionGroupNames || []).indexOf(groupName) >= 0 ? groupName : null;
}

// 按 DERIVED.specs 创建所有功能代理组。
// 地区 url-test 组和自定义出口节点均按 preference 插入到合适位置。
function buildFunctionalGroups(config, regionGroupNames) {
  var i;
  var spec;
  var proxies;
  var groupDef;
  var extra = regionGroupNames;
  var preferredRegionGroup;
  for (i = 0; i < DERIVED.specs.length; i++) {
    spec = DERIVED.specs[i];
    preferredRegionGroup = getPreferredRegionGroupName(spec, regionGroupNames);
    if (spec.fixedProxies) {
      proxies = spec.fixedProxies;
    } else if (spec.preference === "proxy") {
      proxies = [];
      // 境外本机已在海外：无指定地区的代理型组默认直连，节点选择保留为可选项。
      if (getLocationProfile().directFirstEgress && !spec.preferredRegion) proxies.push("DIRECT");
      if (preferredRegionGroup) proxies.push(preferredRegionGroup);
      proxies = proxies
        .concat(["节点选择"])
        .concat(extra)
        .concat(["DIRECT"]);
    } else {
      proxies = ["DIRECT", "节点选择"].concat(extra);
    }
    groupDef = {
      name: spec.name,
      type: "select",
      proxies: uniqueStrings(proxies),
      url: getGroupProbeUrl(spec)
    };
    if (spec.hidden === true) groupDef.hidden = true;
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
    normalizeAutoSelectGroup(config._savedAutoGroup);
    upsertNamedItem(config["proxy-groups"], config._savedAutoGroup);
    var savedName = config._savedAutoGroup.name;
    delete config._savedAutoGroup;
    return savedName;
  }

  // proxy-groups 中已存在
  var smartGroup = findProxyGroupByName(config["proxy-groups"], smartName);
  if (smartGroup) {
    normalizeAutoSelectGroup(smartGroup);
    return smartName;
  }
  var baseGroup = findProxyGroupByName(config["proxy-groups"], baseName);
  if (baseGroup) {
    normalizeAutoSelectGroup(baseGroup);
    return baseName;
  }

  // 都没有 → 自建 url-test
  var allNodeNames = [];
  for (var i = 0; i < config.proxies.length; i++) {
    if (!isManagedProxyName(config, config.proxies[i].name)) {
      allNodeNames.push(config.proxies[i].name);
    }
  }
  allNodeNames = filterAutoSelectProxyNames(allNodeNames);
  if (allNodeNames.length === 0) {
    throw createUserError("没有可用的订阅节点，无法创建自动选择组");
  }
  upsertNamedItem(config["proxy-groups"], {
    name: baseName, type: "url-test", proxies: allNodeNames,
    url: getProxyProbeUrl(), interval: 300, tolerance: 50
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

// 把家宽IP凭证转成 Clash 代理节点对象。
function buildHomeProxy(credentials, proxyName, relayGroupName) {
  var proxyType = credentials.type || "http";
  var node = {
    name: proxyName,
    type: proxyType,
    server: credentials.server,
    port: credentials.port,
    udp: resolveProxyUdp(credentials)
  };
  if (credentials.username) node.username = credentials.username;
  if (credentials.password) node.password = credentials.password;
  copyProtocolFields(credentials, node);
  if (relayGroupName) node["dialer-proxy"] = relayGroupName;
  return node;
}

// 家宽IP直连节点：先注入（本机可直连时它也是 🔗 前置 的候选）。
function injectHomeDirectProxy(config, credentials) {
  appendProxyNode(config, buildHomeProxy(credentials, BASE.nodeNames.home, null));
}

// 家宽IP链式节点：dialer-proxy 指向 🔗 前置（via 可覆盖）。返回 🏠 家宽IP 组成员顺序。
function injectHomeProxies(config, credentials, relayGroupName) {
  var chainProxies = [];
  var dialer = credentials.via || relayGroupName;
  if (dialer) {
    appendProxyNode(config, buildHomeProxy(credentials, BASE.nodeNames.homeChained, dialer));
    chainProxies.push(BASE.nodeNames.homeChained);
  }
  // cn 默认先选链式；境外直连家宽更稳，真直连排第一；本机直连不了家宽（端口被拦截）时也先选链式。
  if (getLocationProfile().homeChainFirst || !isDirectlyReachableSpec(credentials)) {
    chainProxies.push(BASE.nodeNames.home);
  } else {
    chainProxies.unshift(BASE.nodeNames.home);
  }
  return chainProxies;
}

// 读取并移除注入到 `config._frontProxy` 的前置代理配置（可选）。
// 存在时仅给订阅原始节点绑定 dialer-proxy，不影响自定义出口和家宽IP。
function takeFrontProxyCredentials(config) {
  if (!config._frontProxy) return null;
  var credentials = config._frontProxy;
  delete config._frontProxy;
  return credentials;
}

function buildFrontProxy(credentials) {
  if (!credentials.server || !credentials.port) {
    throw createUserError("前置代理配置不完整，请检查 server 和 port 字段");
  }
  var proxyType = credentials.type || "socks5";
  var node = {
    name: credentials.name || BASE.nodeNames.front,
    type: proxyType,
    server: credentials.server,
    port: credentials.port,
    udp: resolveProxyUdp(credentials)
  };
  if (credentials.username) node.username = credentials.username;
  if (credentials.password) node.password = credentials.password;
  copyProtocolFields(credentials, node);
  return node;
}

function injectFrontProxy(config, credentials, subscriptionNodeNames) {
  var frontNode = buildFrontProxy(credentials);
  if (subscriptionNodeNames.indexOf(frontNode.name) >= 0) {
    throw createUserError("前置代理名称与订阅节点重名，请修改 config._frontProxy.name");
  }
  appendProxyNode(config, frontNode);
  config._frontProxyName = frontNode.name;
  return frontNode.name;
}

function bindFrontProxyToSubscriptionNodes(config, frontProxyName, subscriptionNodeNames) {
  var subscriptionLookup = buildStringLookup(subscriptionNodeNames);
  for (var i = 0; i < config.proxies.length; i++) {
    var proxy = config.proxies[i];
    if (subscriptionLookup[proxy.name]) {
      proxy["dialer-proxy"] = frontProxyName;
    }
  }
}

// 返回家宽IP出口组的固定名称。
function ensureChainGroup() {
  return "🏠 家宽IP";
}

function ensureChainGroupWithProxies(config, chainProxies) {
  var chainGroupName = ensureChainGroup();
  upsertNamedItem(config["proxy-groups"], {
    name: chainGroupName, type: "select", proxies: chainProxies, url: getProxyProbeUrl()
  });
  return chainGroupName;
}

function buildAiAgentProxies(config, options) {
  var proxies = [];
  if (options.chainGroupName) proxies.push(options.chainGroupName);
  proxies.push("节点选择");
  proxies = proxies
    .concat(options.regionGroupNames || [])
    .concat(options.customProxyNames || []);
  if (options.includeRawNodes) {
    proxies = proxies.concat(options.allNodeNames || []);
  }
  proxies.push("DIRECT");
  return uniqueStrings(proxies);
}

function ensureAiAgentGroup(config, options) {
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.nodeNames.aiAgent,
    type: "select",
    proxies: buildAiAgentProxies(config, options),
    url: getProxyProbeUrl()
  });
  return BASE.nodeNames.aiAgent;
}

// ---- 🔗 前置 ----
// 节点只按“本机能不能直连”分两类：能直连的自动成为前置候选；需中转的（端口被本机出口拦截等）
// 自动 dialer-proxy 到 🔗 前置。不区分订阅节点、alivps、家宽IP、公司代理。
function getRelayOptions() {
  var r = USER_OPTIONS.relay || {};
  return {
    enable: r.enable !== false,
    excludePorts: r.excludePorts || [],
    excludeKeywords: r.excludeKeywords || [],
    prefer: r.prefer || []
  };
}

function isRelayExcludedPort(port) {
  var ports = getRelayOptions().excludePorts;
  for (var i = 0; i < ports.length; i++) {
    if (Number(ports[i]) === Number(port)) return true;
  }
  return false;
}

// 节点配置（自定义节点 / 家宽凭证）在本机是否可直连。
function isDirectlyReachableSpec(spec) {
  if (!spec) return false;
  if (spec.direct === false) return false;
  if (spec.direct === true) return true;
  return !isRelayExcludedPort(spec.port);
}

// 自定义节点 / 家宽节点应挂的前置：via 优先；需中转时用 🔗 前置；否则不挂。
function resolveNodeDialer(spec) {
  if (spec.via) return spec.via;
  if (getRelayOptions().enable && !isDirectlyReachableSpec(spec)) return BASE.nodeNames.relay;
  return null;
}

function isBuiltinInfoNodeName(proxyName) {
  var name = String(proxyName || "");
  var lowerName = name.toLowerCase();
  if (/https?:\/\//i.test(name)) return true;
  for (var i = 0; i < AUTO_SELECT_INFO_NODE_KEYWORDS.length; i++) {
    if (lowerName.indexOf(String(AUTO_SELECT_INFO_NODE_KEYWORDS[i]).toLowerCase()) >= 0) return true;
  }
  return false;
}

// 防循环：已挂 dialer-proxy 的节点、需中转的节点、家宽IP链式不能当前置。
function isRelayCandidateProxy(proxy, unreachableLookup) {
  if (!proxy || !proxy.name) return false;
  if (proxy["dialer-proxy"]) return false;
  if (proxy.name === BASE.nodeNames.homeChained) return false;
  if (unreachableLookup[proxy.name]) return false;
  if (isRelayExcludedPort(proxy.port)) return false;
  return !isBuiltinInfoNodeName(proxy.name);
}

// 生成可见的 🔗 前置（纯 select，固定选择，不自动跳变）：[DIRECT, prefer 命中的节点, 自定义节点, 其余订阅节点]。
// 默认 DIRECT（不走前置）；本机直连不了需中转节点时，在主机 selections 里固定一个可直连节点。
function ensureRelayGroups(config, subscriptionNodeNames, unreachableNames) {
  var opts = getRelayOptions();
  var unreachableLookup = buildStringLookup(unreachableNames || []);
  var subscriptionLookup = buildStringLookup(subscriptionNodeNames || []);
  var subscriptionCandidates = [];
  var otherCandidates = [];
  var preferred = [];
  var proxies;
  var i;
  var j;
  if (!opts.enable) return null;
  function excludedByKeyword(name) {
    var lowerName = String(name).toLowerCase();
    for (var k = 0; k < opts.excludeKeywords.length; k++) {
      if (lowerName.indexOf(String(opts.excludeKeywords[k]).toLowerCase()) >= 0) return true;
    }
    return false;
  }
  for (i = 0; i < config.proxies.length; i++) {
    var proxy = config.proxies[i];
    if (!isRelayCandidateProxy(proxy, unreachableLookup) || excludedByKeyword(proxy.name)) continue;
    if (subscriptionLookup[proxy.name]) subscriptionCandidates.push(proxy.name);
    else otherCandidates.push(proxy.name);
  }
  if (subscriptionCandidates.length + otherCandidates.length === 0) return null;
  for (i = 0; i < opts.prefer.length; i++) {
    var re = new RegExp(opts.prefer[i]);
    for (j = 0; j < subscriptionCandidates.length; j++) {
      if (re.test(subscriptionCandidates[j])) { preferred.push(subscriptionCandidates[j]); break; }
    }
  }
  proxies = uniqueStrings([BASE.ruleTargets.direct].concat(preferred).concat(otherCandidates).concat(subscriptionCandidates));
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.nodeNames.relay, type: "select", proxies: proxies, url: getProxyProbeUrl()
  });
  return BASE.nodeNames.relay;
}

// 解析本轮注入所需的关键目标。
function resolveRoutingTargets(config, relayGroupName) {
  return {
    relayGroupName: relayGroupName,
    chainGroupName: ensureChainGroup(),
    strictAiTarget: BASE.nodeNames.aiAgent
  };
}

// 读取并移除注入到 `config._customProxies` 的自定义出口配置（可选）。
function takeCustomProxies(config) {
  if (!config._customProxies) return null;
  var raw = config._customProxies;
  delete config._customProxies;
  return Array.isArray(raw) ? raw : [raw];
}

function partitionCustomProxies(proxyConfigs) {
  var ordinary = [];
  var dedicated = [];
  var configs = proxyConfigs || [];
  var seenNames = {};
  for (var i = 0; i < configs.length; i++) {
    var proxyConfig = configs[i];
    var scope = proxyConfig.scope || "ordinary";
    if (!proxyConfig.name) proxyConfig.name = "自定义出口" + (i + 1);
    if (seenNames[proxyConfig.name]) {
      throw createUserError("自定义出口名称重复：" + proxyConfig.name);
    }
    seenNames[proxyConfig.name] = true;
    if (scope === "dedicated") {
      dedicated.push(proxyConfig);
    } else if (scope === "ordinary") {
      ordinary.push(proxyConfig);
    } else {
      throw createUserError(
        "自定义出口 " + proxyConfig.name + " 的 scope 无效，仅支持 ordinary 或 dedicated"
      );
    }
  }
  return { ordinary: ordinary, dedicated: dedicated };
}

function validateDedicatedProxyNameAvailability(config, proxyConfigs, groupConfigs) {
  var pendingGroupNames = {};
  var groups = groupConfigs || [];
  for (var groupIndex = 0; groupIndex < groups.length; groupIndex++) {
    if (groups[groupIndex] && groups[groupIndex].name) {
      pendingGroupNames[groups[groupIndex].name] = true;
    }
  }
  for (var i = 0; i < proxyConfigs.length; i++) {
    var proxyName = proxyConfigs[i].name;
    if (findProxyByName(config.proxies, proxyName) ||
        findProxyGroupByName(config["proxy-groups"], proxyName) ||
        pendingGroupNames[proxyName]) {
      throw createUserError(
        "专用出口 " + proxyName + " 与已有节点或策略组重名，无法保证隔离"
      );
    }
  }
}

function validateDedicatedProxyReferences(proxyConfigs, groupConfigs) {
  var referencedNames = buildStringLookup(getDomesticExitNames());
  var groups = groupConfigs || [];
  var groupProxies;
  var i;
  var j;
  for (i = 0; i < groups.length; i++) {
    groupProxies = groups[i].proxies || [];
    for (j = 0; j < groupProxies.length; j++) {
      referencedNames[groupProxies[j]] = true;
    }
  }
  for (i = 0; i < proxyConfigs.length; i++) {
    if (!referencedNames[proxyConfigs[i].name]) {
      throw createUserError(
        "专用出口 " + proxyConfigs[i].name +
        " 未被 _customRuleGroups.proxies 引用（overseas 下也可由 USER_OPTIONS.domesticExit 引用）；dedicated 节点不能进入通用出口"
      );
    }
  }
}

function buildCustomProxyNode(proxyConfig, frontProxyName) {
  var proxyType = proxyConfig.type || "http";
  var node = {
    name: proxyConfig.name,
    type: proxyType,
    server: proxyConfig.server,
    port: proxyConfig.port,
    udp: resolveProxyUdp(proxyConfig)
  };
  if (proxyConfig.username) node.username = proxyConfig.username;
  if (proxyConfig.password) node.password = proxyConfig.password;
  if (proxyConfig.interfaceName || proxyConfig["interface-name"]) {
    node["interface-name"] = proxyConfig.interfaceName || proxyConfig["interface-name"];
  }
  if (proxyConfig.useFrontProxy) {
    if (!frontProxyName) {
      throw createUserError("自定义出口 " + proxyConfig.name + " 启用了 useFrontProxy，但未配置前置代理");
    }
    node["dialer-proxy"] = frontProxyName;
  } else if (resolveNodeDialer(proxyConfig)) {
    node["dialer-proxy"] = resolveNodeDialer(proxyConfig); // via 或需中转 → 🔗 前置
  }
  copyProtocolFields(proxyConfig, node);
  return node;
}

function injectCustomProxies(config, proxyConfigs, frontProxyName) {
  var names = [];
  for (var i = 0; i < proxyConfigs.length; i++) {
    var proxyConfig = proxyConfigs[i];
    if (!proxyConfig.server || !proxyConfig.port) {
      throw createUserError(
        "自定义出口配置不完整（第 " + (i + 1) + " 条），请检查 server 和 port 字段"
      );
    }
    appendProxyNode(config, buildCustomProxyNode(proxyConfig, frontProxyName));
    names.push(proxyConfig.name);
  }
  return names;
}

// 🇨🇳 国内：所有国内规则的策略组。候选 [回国出口..., DIRECT, 节点选择]；cn 主机 DIRECT 排第一。
// 引用存在性在所有组生成后校验。
function ensureDomesticGroup(config) {
  var names;
  var proxies = [];
  names = getDomesticExitNames();
  for (var i = 0; i < names.length; i++) {
    if (names[i] === BASE.policyNames.domestic) {
      throw createUserError("USER_OPTIONS.domesticExit 不能引用 " + BASE.policyNames.domestic + " 自身");
    }
    proxies.push(names[i]);
  }
  if (getLocationProfile().inChina || proxies.length === 0) proxies.unshift(BASE.ruleTargets.direct);
  else proxies.push(BASE.ruleTargets.direct);
  if (hasProxyOrGroup(config, "节点选择")) proxies.push("节点选择");
  upsertNamedItem(config["proxy-groups"], {
    name: BASE.policyNames.domestic,
    type: "select",
    proxies: uniqueStrings(proxies),
    url: getLocationProfile().domesticProbeUrl
  });
  return BASE.policyNames.domestic;
}

function takeCustomRuleGroups(config) {
  if (!config._customRuleGroups) return null;
  var raw = config._customRuleGroups;
  delete config._customRuleGroups;
  return Array.isArray(raw) ? raw : [raw];
}

function normalizeRuleType(type) {
  return String(type || "").toUpperCase();
}

function normalizeCustomRule(ruleConfig, target) {
  var parts;
  if (typeof ruleConfig === "string") {
    parts = ruleConfig.split(",");
    if (parts.length < 2) {
      throw createUserError("自定义规则格式不完整：" + ruleConfig);
    }
    return {
      type: normalizeRuleType(parts[0]),
      value: parts[1],
      target: target,
      option: parts.length > 2 ? parts.slice(2).join(",") : null
    };
  }
  if (!ruleConfig || !ruleConfig.type || !ruleConfig.value) {
    throw createUserError("自定义规则配置不完整，请检查 type 和 value 字段");
  }
  return {
    type: normalizeRuleType(ruleConfig.type),
    value: ruleConfig.value,
    target: target,
    option: ruleConfig.option || null
  };
}

function buildCustomRuleGroupRules(groupConfig) {
  var rules = [];
  var sourceRules = groupConfig.rules || [];
  for (var i = 0; i < sourceRules.length; i++) {
    rules.push(normalizeCustomRule(sourceRules[i], groupConfig.name));
  }
  return rules;
}

function injectCustomRuleGroups(config, groupConfigs, insertionIndex) {
  var rules = [];
  var seenRuleIdentities = {};
  for (var i = 0; i < groupConfigs.length; i++) {
    var groupConfig = groupConfigs[i];
    var proxies = [];
    if (!groupConfig.name) {
      throw createUserError("自定义规则组缺少 name 字段（第 " + (i + 1) + " 条）");
    }
    if (hasProxyOrGroup(config, groupConfig.name)) {
      throw createUserError("自定义规则组与已有节点或策略组重名：" + groupConfig.name);
    }
    if (groupConfig.proxy) {
      if (!groupConfig.proxy.name) groupConfig.proxy.name = groupConfig.name + "节点";
      if (!groupConfig.proxy.server || !groupConfig.proxy.port) {
        throw createUserError("自定义规则组 " + groupConfig.name + " 的 proxy 缺少 server 或 port");
      }
      if (groupConfig.proxy.name === groupConfig.name) {
        throw createUserError("自定义规则组与内嵌节点重名：" + groupConfig.name);
      }
      appendProxyNode(config, buildCustomProxyNode(groupConfig.proxy, null));
      proxies.push(groupConfig.proxy.name);
    }
    proxies = proxies.concat(groupConfig.proxies || []);
    if (proxies.length === 0) proxies.push(BASE.ruleTargets.direct);
    if (proxies.indexOf(BASE.ruleTargets.direct) < 0) proxies.push(BASE.ruleTargets.direct);
    var groupDefinition = {
      name: groupConfig.name,
      type: groupConfig.type || "select",
      proxies: uniqueStrings(proxies),
      url: getGroupProbeUrl(groupConfig)
    };
    var index = typeof insertionIndex === "number" ? insertionIndex + i : config["proxy-groups"].length;
    config["proxy-groups"].splice(index, 0, groupDefinition);
    addRawRulesIfNotExists(rules, seenRuleIdentities, buildCustomRuleGroupRules(groupConfig));
  }
  return rules;
}

// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

function getRuleIdentity(ruleLine) {
  var fields = splitTopLevelRuleFields(ruleLine);
  if (fields.length < 3) return null;
  return fields[0] + "," + fields[1];
}

function splitTopLevelRuleFields(ruleLine) {
  var fields = [];
  var depth = 0;
  var startIndex = 0;
  for (var i = 0; i < ruleLine.length; i++) {
    var character = ruleLine.charAt(i);
    if (character === "(") {
      depth++;
    } else if (character === ")" && depth > 0) {
      depth--;
    } else if (character === "," && depth === 0) {
      fields.push(ruleLine.substring(startIndex, i));
      startIndex = i + 1;
    }
  }
  fields.push(ruleLine.substring(startIndex));
  return fields;
}

function buildFunctionalRules() {
  var rules = [];
  var seen = {};
  addCommunityRules(rules, seen, COMMUNITY_RULES.media, "🌍 国际媒体");
  addCommunityRules(rules, seen, COMMUNITY_RULES.telegram, "📲 Telegram");
  addCommunityRules(rules, seen, COMMUNITY_RULES.github, "🐙 GitHub");
  for (var i = 0; i < DERIVED.specs.length; i++) {
    var spec = DERIVED.specs[i];
    if (spec.domains && spec.domains.length > 0) {
      addSuffixRulesIfNotExists(rules, seen, spec.domains, spec.name);
    }
  }
  return rules;
}

function addTransportAwareSuffixRulesIfNotExists(
  ruleLines,
  seenRuleIdentities,
  domains,
  tlsTarget,
  fallbackTarget
) {
  if (!fallbackTarget) {
    addSuffixRulesIfNotExists(ruleLines, seenRuleIdentities, domains, tlsTarget);
    return;
  }
  for (var i = 0; i < domains.length; i++) {
    var domain = toSuffix(domains[i]);
    var condition = "((NETWORK,tcp),(DST-PORT,443),(DOMAIN-SUFFIX," + domain + "))";
    var ruleIdentity = "AND," + condition;
    if (!seenRuleIdentities[ruleIdentity]) {
      seenRuleIdentities[ruleIdentity] = true;
      ruleLines.push(ruleIdentity + "," + tlsTarget);
    }
    addRuleIfNotExists(
      ruleLines,
      seenRuleIdentities,
      "DOMAIN-SUFFIX",
      domain,
      fallbackTarget
    );
  }
}

function buildGeneralEgressRules(fullProtocolTarget) {
  var rules = [];
  var seen = {};
  addTransportAwareSuffixRulesIfNotExists(
    rules,
    seen,
    DERIVED.patterns.generalEgress,
    BASE.policyNames.overseas,
    fullProtocolTarget
  );
  return rules;
}

function buildNodeSelectionRules(fullProtocolTarget) {
  var rules = [];
  var seen = {};
  addTransportAwareSuffixRulesIfNotExists(
    rules,
    seen,
    DERIVED.patterns.nodeSelection,
    "节点选择",
    fullProtocolTarget
  );
  return rules;
}

function buildNetworkProbeRules(strictAiTarget, frontProxyName) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  addRuleIfNotExists(ruleLines, seenRuleIdentities, "DOMAIN-SUFFIX", "ipapi.is", strictAiTarget);
  addRuleIfNotExists(
    ruleLines,
    seenRuleIdentities,
    "DOMAIN-SUFFIX",
    "ipwho.is",
    "节点选择"
  );
  addRuleIfNotExists(ruleLines, seenRuleIdentities, "DOMAIN-SUFFIX", "ip.sb", frontProxyName || BASE.ruleTargets.direct);
  return ruleLines;
}

function buildProxyServerDirectRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var proxyServerRules = DERIVED.networkRules.proxyServers || [];
  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, proxyServerRules);
  return ruleLines;
}

function buildTailscaleProcessRuleLines() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, buildTailscaleProcessRules());
  return ruleLines;
}

function buildYoutubeSharedPlatformRules() {
  var rules = [];
  var seen = {};
  // Shared Google API/asset hosts used by media must precede the Google catch-all.
  for (var i = 0; i < COMMUNITY_RULES.media.length; i++) {
    var entry = COMMUNITY_RULES.media[i];
    if (/(^|\.)(googleapis\.com|ggpht\.com|gstatic\.com)$/.test(entry[1])) {
      addRuleIfNotExists(rules, seen, entry[0], entry[1], "🌍 国际媒体");
    }
  }
  return rules;
}

function buildGooglePlayMtalkRules(fullProtocolTarget) {
  return [
    "AND,((NETWORK,tcp),(DST-PORT,5228),(DOMAIN-SUFFIX,mtalk.google.com))," +
      (fullProtocolTarget || "🌍 国际媒体")
  ];
}

function buildGoogleConsistencyRules(strictAiTarget, fullProtocolTarget) {
  if (!strictAiTarget || !isGoogleTrafficConsistencyEnabled()) return [];
  var fcmTarget = fullProtocolTarget || "🌍 国际媒体";
  var rules = [
    "DOMAIN-REGEX,^accounts\\.google\\..+$," + strictAiTarget,
    "DOMAIN,accounts.gstatic.com," + strictAiTarget,
    "DOMAIN,accounts.youtube.com," + strictAiTarget,
    "DOMAIN,oauthaccountmanager.googleapis.com," + strictAiTarget,
    "DOMAIN,www.googleapis.com," + strictAiTarget,
    "DOMAIN,ssl.gstatic.com," + strictAiTarget,
    "GEOSITE,google-deepmind," + strictAiTarget,
    "GEOSITE,youtube,🌍 国际媒体",
    "GEOSITE,google-play,🌍 国际媒体",
    "GEOSITE,googlefcm," + fcmTarget
  ];
  if (USER_OPTIONS.rejectAiQuic !== false) {
    rules.push("AND,((NETWORK,udp),(DST-PORT,443),(GEOSITE,google)),REJECT");
  }
  rules.push("GEOSITE,google," + strictAiTarget);
  return rules;
}

function buildGeminiChallengeRules(strictAiTarget) {
  if (!strictAiTarget) return [];
  return [
    "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN,www.google.com)),REJECT",
    "DOMAIN,www.google.com," + strictAiTarget
  ];
}

// strictAiTarget 为 null 时跳过 AI 进程和浏览器进程规则（纯分流模式）。
function buildManagedRules(strictAiTarget, frontProxyName, fullProtocolTarget) {
  var rules = [];
  rules = rules.concat(buildProxyServerDirectRules());
  // Tailscale 的 STUN 也会使用 UDP/3478，必须先于通用 WebRTC 防泄漏规则匹配。
  rules = rules.concat(buildTailscaleProcessRuleLines());
  rules = rules.concat(buildWebRtcUdpRejectRules());
  rules = rules.concat(buildGooglePlayMtalkRules(fullProtocolTarget));
  rules = rules.concat(buildGeminiChallengeRules(strictAiTarget));
  rules = rules.concat(buildAppStoreQuicRejectRules());
  if (strictAiTarget) {
    rules = rules.concat(buildYoutubeSharedPlatformRules());
    rules = rules.concat(buildAiQuicRejectRules());
    rules = rules.concat(buildCommunityAiRules(strictAiTarget));
    rules = rules.concat(buildGoogleConsistencyRules(strictAiTarget, fullProtocolTarget));
  }
  if (strictAiTarget) {
    rules = rules.concat(buildNetworkProbeRules(strictAiTarget, frontProxyName));
  }
  if (strictAiTarget) {
    rules = rules.concat(buildStrictChainRules(strictAiTarget));
    rules = rules.concat(buildBrowserChainRules(strictAiTarget));
  }
  return deduplicateManagedRules(rules
    .concat(buildNodeSelectionRules(fullProtocolTarget))
    .concat(buildGeneralEgressRules(fullProtocolTarget))
    .concat(buildFunctionalRules())
    .concat(buildDirectRules(fullProtocolTarget)));
}

function deduplicateManagedRules(ruleLines) {
  var seen = {};
  var rules = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var key = getRuleIdentity(ruleLines[i]) || ruleLines[i];
    if (seen[key]) continue;
    seen[key] = true;
    rules.push(ruleLines[i]);
  }
  return rules;
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

function injectManagedRules(config, strictAiTarget, frontProxyName, fullProtocolTarget) {
  var managedRules = buildManagedRules(strictAiTarget, frontProxyName, fullProtocolTarget);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);
  config.rules = filterConflictingRules(config.rules, managedRuleIdentities);
  prependRules(config.rules, managedRules);
}

function buildProtectedManagedRuleLines(strictAiTarget, fullProtocolTarget) {
  var rules = [];
  var tailscaleRuleLines = [];
  var seenTailscaleRuleIdentities = {};
  addRawRulesIfNotExists(
    tailscaleRuleLines,
    seenTailscaleRuleIdentities,
    buildTailscaleRules(false)
  );
  rules = rules
    .concat(buildProxyServerDirectRules())
    .concat(buildTailscaleProcessRuleLines())
    .concat(tailscaleRuleLines)
    .concat(buildGooglePlayMtalkRules(fullProtocolTarget))
    .concat(buildGeminiChallengeRules(strictAiTarget))
    .concat(buildAppStoreQuicRejectRules())
    .concat(buildGoogleConsistencyRules(strictAiTarget, fullProtocolTarget))
    .concat(buildWebRtcUdpRejectRules());
  if (strictAiTarget) {
    rules = rules
      .concat(buildAiQuicRejectRules())
      .concat(buildCommunityAiRules(strictAiTarget))
      .concat(buildStrictChainRules(strictAiTarget));
  }
  return rules;
}

function assertCustomRulesDoNotOverrideProtectedRules(ruleLines, protectedIdentities) {
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity && protectedIdentities[ruleIdentity]) {
      throw createUserError(
        "自定义规则与受保护的基础路由或安全规则冲突：" + ruleIdentity
      );
    }
  }
}

function injectCustomRuleGroupRules(config, ruleLines, strictAiTarget, fullProtocolTarget) {
  var ruleIdentities = buildRuleIdentityLookup(ruleLines);
  var protectedIdentities = buildRuleIdentityLookup(
    buildProtectedManagedRuleLines(strictAiTarget, fullProtocolTarget)
  );
  var protectedRules = [];
  var remainingRules = [];
  var ruleIdentity;
  assertCustomRulesDoNotOverrideProtectedRules(ruleLines, protectedIdentities);
  config.rules = filterConflictingRules(config.rules, ruleIdentities);
  for (var i = 0; i < config.rules.length; i++) {
    ruleIdentity = getRuleIdentity(config.rules[i]);
    if (ruleIdentity && protectedIdentities[ruleIdentity]) {
      protectedRules.push(config.rules[i]);
    } else {
      remainingRules.push(config.rules[i]);
    }
  }
  config.rules = protectedRules.concat(ruleLines).concat(remainingRules);
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

function buildQuicRejectRules(domainPatterns) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  for (var i = 0; i < domainPatterns.length; i++) {
    var condition = "((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX," +
      toSuffix(domainPatterns[i]) + "))";
    var ruleIdentity = "AND," + condition;
    if (seenRuleIdentities[ruleIdentity]) continue;
    seenRuleIdentities[ruleIdentity] = true;
    ruleLines.push(ruleIdentity + ",REJECT");
  }
  return ruleLines;
}

function buildAiQuicRejectRules() {
  if (USER_OPTIONS.rejectAiQuic === false) return [];
  var rules = buildQuicRejectRules(DERIVED.patterns.strict.all);
  for (var i = 0; i < COMMUNITY_RULES.ai.length; i++) {
    var entry = COMMUNITY_RULES.ai[i];
    rules.push("AND,((NETWORK,udp),(DST-PORT,443),(" + entry[0] + "," + entry[1] + ")),REJECT");
  }
  return deduplicateManagedRules(rules);
}

function buildAppStoreQuicRejectRules() {
  if (USER_OPTIONS.rejectAppStoreQuic === false) return [];
  return ["AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN,bag.itunes.apple.com)),REJECT"];
}

function buildWebRtcUdpRejectRules() {
  var ruleLines = [];
  var seenRuleIdentities = {};
  if (USER_OPTIONS.rejectWebRtcUdp === false) return ruleLines;
  for (var i = 0; i < BASE.webRtcStunPorts.length; i++) {
    var condition = "((NETWORK,udp),(DST-PORT," + BASE.webRtcStunPorts[i] + "))";
    var ruleIdentity = "AND," + condition;
    if (seenRuleIdentities[ruleIdentity]) continue;
    seenRuleIdentities[ruleIdentity] = true;
    ruleLines.push(ruleIdentity + ",REJECT");
  }
  return ruleLines;
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
  var anthropicNetworkRules = [];
  for (i = 0; i < SOURCE_ANTHROPIC_NETWORK_RULES.length; i++) {
    anthropicNetworkRules.push({
      type:   SOURCE_ANTHROPIC_NETWORK_RULES[i].type,
      value:  SOURCE_ANTHROPIC_NETWORK_RULES[i].value,
      target: strictAiTarget,
      option: "no-resolve"
    });
  }
  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, anthropicNetworkRules);
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

function parseIpv4Address(value) {
  if (typeof value !== "string") return null;
  var parts = value.split(".");
  var numbers = [];
  if (parts.length !== 4) return null;
  for (var i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    var part = parseInt(parts[i], 10);
    if (part < 0 || part > 255) return null;
    numbers.push(part);
  }
  return numbers;
}

function isPrivateOrTailnetIpv4(value) {
  var ip = parseIpv4Address(value);
  if (!ip) return false;
  if (ip[0] === 10) return true;
  if (ip[0] === 172 && ip[1] >= 16 && ip[1] <= 31) return true;
  if (ip[0] === 192 && ip[1] === 168) return true;
  if (ip[0] === 100 && ip[1] >= 64 && ip[1] <= 127) return true;
  return false;
}

function collectProxyServerRouteExcludeCidrs(proxyConfigs) {
  var cidrs = [];
  for (var i = 0; i < proxyConfigs.length; i++) {
    var proxyConfig = proxyConfigs[i];
    if (!proxyConfig || !isPrivateOrTailnetIpv4(proxyConfig.server)) continue;
    cidrs.push(proxyConfig.server + "/32");
  }
  return uniqueStrings(cidrs);
}

function isIpv4Literal(value) {
  return !!parseIpv4Address(value);
}

function normalizeProxyServerValue(value) {
  var server = String(value || "").trim();
  if (server.charAt(0) === "[" && server.charAt(server.length - 1) === "]") {
    server = server.substring(1, server.length - 1);
  }
  if (server.indexOf("+.") === 0) server = server.substring(2);
  if (server.indexOf("*.") === 0) server = server.substring(2);
  return server;
}

function getProxyServerResolvedIps(server) {
  var configured = USER_OPTIONS.proxyServerResolvedIps || {};
  var values = configured[server] || configured[String(server).toLowerCase()] || [];
  return Array.isArray(values) ? values : [values];
}

function addProxyServerDirectRule(rules, seen, server) {
  var type;
  var value;
  server = normalizeProxyServerValue(server);
  if (!server || server === "localhost" || server === "127.0.0.1" || server === "::1") return;
  if (isIpv4Literal(server)) {
    type = "IP-CIDR";
    value = server + "/32";
  } else if (server.indexOf(":") >= 0) {
    type = "IP-CIDR6";
    value = server + "/128";
  } else {
    type = "DOMAIN-SUFFIX";
    value = server;
  }
  if (seen[type + "," + value]) return;
  seen[type + "," + value] = true;
  rules.push({
    type: type,
    value: value,
    target: BASE.ruleTargets.direct,
    option: type.indexOf("IP-CIDR") === 0 ? "no-resolve" : null
  });
}

function collectProxyServerDirectRules(config) {
  var rules = [];
  var seen = {};
  var proxies = config.proxies || [];
  var server;
  var resolvedIps;
  for (var i = 0; i < proxies.length; i++) {
    server = normalizeProxyServerValue(proxies[i] && proxies[i].server);
    addProxyServerDirectRule(rules, seen, server);
    if (isIpv4Literal(server) || server.indexOf(":") >= 0) continue;
    resolvedIps = getProxyServerResolvedIps(server);
    for (var j = 0; j < resolvedIps.length; j++) {
      addProxyServerDirectRule(rules, seen, resolvedIps[j]);
    }
  }
  return rules;
}

function applyProxyServerDirectRules(config) {
  DERIVED.networkRules.proxyServers = USER_OPTIONS.directProxyServerRules
    ? collectProxyServerDirectRules(config)
    : [];
}

function applyTunRouteExcludes(config, customProxies, frontProxy, homeProxy) {
  var options = getTailscaleOptions();
  var candidates = [];
  var routeExcludes;
  var proxyConfigs = [];

  if (!options.enable) return;
  if (frontProxy) proxyConfigs.push(frontProxy);
  if (homeProxy) proxyConfigs.push(homeProxy);
  if (customProxies) proxyConfigs = proxyConfigs.concat(customProxies);
  if (config.proxies) proxyConfigs = proxyConfigs.concat(config.proxies);

  if (options.excludeProxyServerFromTun) {
    candidates = candidates.concat(collectProxyServerRouteExcludeCidrs(proxyConfigs));
  }
  candidates = candidates.concat(options.routeExcludeCidrs);
  candidates = uniqueStrings(candidates);
  if (candidates.length === 0) return;

  if (!config.tun) config.tun = {};
  routeExcludes = config.tun["route-exclude-address"] || [];
  config.tun["route-exclude-address"] = uniqueStrings(routeExcludes.concat(candidates));
}

function getTailscaleOptions() {
  var defaults = {
    enable: true,
    monitorGroups: true,
    hideMonitorGroups: true,
    subnetCidrs: [],
    excludeProxyServerFromTun: true,
    routeExcludeCidrs: [],
    controlPlaneTarget: BASE.ruleTargets.direct,
    processTarget: BASE.ruleTargets.direct,
    forceExitNodeTraffic: false,
    forceExitNodeTrafficTarget: "节点选择"
  };
  var provided = USER_OPTIONS.tailscale || {};
  return {
    enable: provided.enable !== false,
    monitorGroups: provided.monitorGroups !== false,
    hideMonitorGroups: provided.hideMonitorGroups !== false,
    subnetCidrs: Array.isArray(provided.subnetCidrs) ? provided.subnetCidrs : defaults.subnetCidrs,
    excludeProxyServerFromTun: provided.excludeProxyServerFromTun !== false,
    routeExcludeCidrs: Array.isArray(provided.routeExcludeCidrs) ? provided.routeExcludeCidrs : defaults.routeExcludeCidrs,
    controlPlaneTarget: provided.controlPlaneTarget || defaults.controlPlaneTarget,
    processTarget: provided.processTarget || defaults.processTarget,
    forceExitNodeTraffic: provided.forceExitNodeTraffic === true,
    forceExitNodeTrafficTarget: provided.forceExitNodeTrafficTarget || defaults.forceExitNodeTrafficTarget
  };
}

function getTailscaleRuleTargets(options) {
  if (!options.monitorGroups) {
    return {
      destinationTarget: BASE.ruleTargets.direct,
      controlPlaneTarget: options.controlPlaneTarget,
      processTarget: options.processTarget,
      exitNodeTarget: options.forceExitNodeTrafficTarget
    };
  }
  return {
    destinationTarget: BASE.nodeNames.tailnetDirect,
    controlPlaneTarget: BASE.nodeNames.tailscaleControl,
    processTarget: BASE.nodeNames.tailscaleProcess,
    exitNodeTarget: BASE.nodeNames.tailscaleExit
  };
}

function normalizeTailscaleMonitorTarget(target, groupName) {
  if (target === groupName) return BASE.ruleTargets.direct;
  return target || BASE.ruleTargets.direct;
}

function buildTailscaleMonitorGroup(name, proxies, options) {
  var group = {
    name: name,
    type: "select",
    proxies: proxies,
    url: getDefaultProbeUrl()
  };
  if (options.hideMonitorGroups) group.hidden = true;
  return group;
}

function ensureTailscaleMonitorGroups(config) {
  var options = getTailscaleOptions();
  if (!options.enable || !options.monitorGroups) return;
  upsertNamedItem(config["proxy-groups"], buildTailscaleMonitorGroup(
    BASE.nodeNames.tailnetDirect,
    [BASE.ruleTargets.direct],
    options
  ));
  upsertNamedItem(config["proxy-groups"], buildTailscaleMonitorGroup(
    BASE.nodeNames.tailscaleControl,
    [normalizeTailscaleMonitorTarget(options.controlPlaneTarget, BASE.nodeNames.tailscaleControl)],
    options
  ));
  upsertNamedItem(config["proxy-groups"], buildTailscaleMonitorGroup(
    BASE.nodeNames.tailscaleProcess,
    [normalizeTailscaleMonitorTarget(options.processTarget, BASE.nodeNames.tailscaleProcess)],
    options
  ));
  if (options.forceExitNodeTraffic) {
    upsertNamedItem(config["proxy-groups"], buildTailscaleMonitorGroup(
      BASE.nodeNames.tailscaleExit,
      [normalizeTailscaleMonitorTarget(options.forceExitNodeTrafficTarget, BASE.nodeNames.tailscaleExit)],
      options
    ));
  }
}

function buildTailscaleRules(includeProcessRules) {
  var options = getTailscaleOptions();
  var targets = getTailscaleRuleTargets(options);
  var rules = [];
  var i;
  if (!options.enable) return rules;

  for (i = 0; i < SOURCE_TAILSCALE_RULES.destinationDirect.length; i++) {
    rules.push({
      type: SOURCE_TAILSCALE_RULES.destinationDirect[i].type,
      value: SOURCE_TAILSCALE_RULES.destinationDirect[i].value,
      target: targets.destinationTarget,
      option: "no-resolve"
    });
  }
  for (i = 0; i < SOURCE_TAILSCALE_RULES.magicDnsDomains.length; i++) {
    rules.push({
      type: "DOMAIN-SUFFIX",
      value: SOURCE_TAILSCALE_RULES.magicDnsDomains[i],
      target: targets.destinationTarget
    });
  }
  for (i = 0; i < options.subnetCidrs.length; i++) {
    rules.push({
      type: options.subnetCidrs[i].indexOf(":") >= 0 ? "IP-CIDR6" : "IP-CIDR",
      value: options.subnetCidrs[i],
      target: targets.destinationTarget,
      option: "no-resolve"
    });
  }
  if (options.forceExitNodeTraffic) {
    rules.push({
      type: "SRC-IP-CIDR",
      value: "100.64.0.0/10",
      target: targets.exitNodeTarget,
      option: "no-resolve"
    });
  }
  for (i = 0; i < SOURCE_TAILSCALE_RULES.controlPlaneDomains.length; i++) {
    rules.push({
      type: "DOMAIN-SUFFIX",
      value: SOURCE_TAILSCALE_RULES.controlPlaneDomains[i],
      target: targets.controlPlaneTarget
    });
  }
  if (includeProcessRules !== false) {
    rules = rules.concat(buildTailscaleProcessRules());
  }
  return rules;
}

function buildTailscaleProcessRules() {
  var options = getTailscaleOptions();
  var targets = getTailscaleRuleTargets(options);
  var rules = [];
  if (!options.enable) return rules;
  for (var i = 0; i < SOURCE_TAILSCALE_RULES.processNames.length; i++) {
    rules.push({
      type: "PROCESS-NAME",
      value: SOURCE_TAILSCALE_RULES.processNames[i],
      target: targets.processTarget,
      option: "no-resolve"
    });
  }
  return rules;
}

function buildDirectRules(fullProtocolTarget) {
  var ruleLines = [];
  var seenRuleIdentities = {};
  var directNetworkRules = [];
  var directPatternGroups = DERIVED.patterns.direct.groups;
  var domesticTarget = getDomesticTarget();
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
  addRawRulesIfNotExists(ruleLines, seenRuleIdentities, buildTailscaleRules(false));
  // directPatternGroups = [国内 DNS 例外, 海外 DNS 例外]；国内例外跟随 domesticTarget。
  for (i = 0; i < directPatternGroups.length; i++) {
    addSuffixRulesIfNotExists(
      ruleLines,
      seenRuleIdentities,
      directPatternGroups[i],
      i === 0 ? domesticTarget : BASE.ruleTargets.direct
    );
  }

  // GeoSite/GeoIP：国内域名和 IP 一律进 🇨🇳 国内（cn 默认 DIRECT，overseas 默认回国出口）
  ruleLines.push("GEOSITE,cn," + domesticTarget);
  ruleLines.push("GEOIP,cn," + domesticTarget + ",no-resolve");

  // 未命中任何规则：🐟 兜底（候选 🇨🇳 国内 / 🌐 国外，默认值按 location）
  ruleLines.push("MATCH," + BASE.policyNames.fallback);
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

// 校验 location 相关的国内规则、🇨🇳 国内 组与最后的 🐟 兜底。
function validateLocationRouting(config) {
  var domesticTarget = getDomesticTarget();
  var group;
  if (config.rules.indexOf("GEOSITE,cn," + domesticTarget) < 0 ||
      config.rules.indexOf("GEOIP,cn," + domesticTarget + ",no-resolve") < 0) {
    throw createUserError("国内兜底规则未指向 " + domesticTarget + "，请检查 USER_OPTIONS.location");
  }
  group = findProxyGroupByName(config["proxy-groups"], domesticTarget);
  if (!group || group.type !== "select" ||
      (group.proxies || []).indexOf(BASE.ruleTargets.direct) < 0) {
    throw createUserError(domesticTarget + " 组内容异常，请检查 USER_OPTIONS.domesticExit");
  }
  if (config.rules[config.rules.length - 1] !== "MATCH," + BASE.policyNames.fallback) {
    throw createUserError("最后一条规则应为 MATCH," + BASE.policyNames.fallback);
  }
  for (var i = 0; i < group.proxies.length; i++) {
    if (group.proxies[i] !== BASE.ruleTargets.direct && !hasProxyOrGroup(config, group.proxies[i])) {
      throw createUserError("USER_OPTIONS.domesticExit 引用的节点或策略组不存在：" + group.proxies[i]);
    }
  }
}

// 校验家宽IP出口组、dialer-proxy 绑定、AI Agent 组、媒体组和关键规则目标。
function validateManagedRouting(config, routingTargets) {
  var i;
  var homeProxy;
  var homeChainedProxy;
  var chainGroup;
  var aiGroup;
  var mediaGroupName = "🌍 国际媒体";
  var strictValidationTargets  = buildStrictValidationTargets();
  var browserValidationTargets = buildBrowserValidationTargets();
  var mediaValidationTargets   = buildMediaValidationTargets();

  if (routingTargets.strictAiTarget !== BASE.nodeNames.aiAgent) {
    throw createUserError("域外 AI 与支撑平台未指向 AI Agent 组，请检查代理组注入逻辑");
  }
  if (routingTargets.relayGroupName && !hasProxyOrGroup(config, routingTargets.relayGroupName)) {
    throw createUserError(
      "前置组 \"" + routingTargets.relayGroupName + "\" 不存在，请检查代理组注入逻辑"
    );
  }

  homeProxy = findProxyByName(config.proxies, BASE.nodeNames.home);
  if (!homeProxy) {
    throw createUserError("家宽IP节点不存在，请检查 出口IP凭证.js 和节点注入逻辑");
  }
  if (homeProxy["dialer-proxy"]) {
    throw createUserError("家宽IP真直连节点不应绑定 dialer-proxy，请检查代理链路注入逻辑");
  }
  homeChainedProxy = findProxyByName(config.proxies, BASE.nodeNames.homeChained);
  if (routingTargets.homeDialer) {
    if (!homeChainedProxy ||
        homeChainedProxy["dialer-proxy"] !== routingTargets.homeDialer) {
      throw createUserError("家宽IP链式节点未正确绑定到前置，请检查代理链路注入逻辑");
    }
  }
  if (!routingTargets.homeDialer && homeChainedProxy) {
    throw createUserError("没有可用前置时不应创建家宽IP链式节点，请检查代理链路注入逻辑");
  }

  chainGroup = findProxyGroupByName(config["proxy-groups"], routingTargets.chainGroupName);
  if (!chainGroup || chainGroup.type !== "select" || !routingTargets.chainProxies ||
      !haveSameStrings(chainGroup.proxies || [], routingTargets.chainProxies)) {
    throw createUserError("家宽IP出口组内容异常，请检查代理组注入逻辑");
  }

  aiGroup = findProxyGroupByName(config["proxy-groups"], BASE.nodeNames.aiAgent);
  if (!aiGroup || aiGroup.type !== "select" ||
      (aiGroup.proxies || []).indexOf(routingTargets.chainGroupName) < 0) {
    throw createUserError("AI Agent 组内容异常，请检查代理组注入逻辑");
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
// _frontProxy、_homeProxy、_customProxies 和 _customRuleGroups 均为可选。
function main(config) {
  var frontProxy     = takeFrontProxyCredentials(config); // 可选：订阅节点前置代理
  var credentials    = takeHomeProxyCredentials(config); // 可选：取出家宽IP凭证
  var customProxies  = takeCustomProxies(config);        // 可选：取出自定义出口配置
  var customRuleGroups = takeCustomRuleGroups(config);   // 可选：取出自定义规则组配置
  var customProxySets = partitionCustomProxies(customProxies);
  var ordinaryCustomProxies = customProxySets.ordinary;
  var dedicatedCustomProxies = customProxySets.dedicated;
  var anchorResult;
  var regionGroupNames;
  var routingTargets;
  var hasHomeProxy = !!credentials;
  var frontProxyName = null;
  var subscriptionNodeNames = [];
  var hasSubscriptionNodes = false;
  var standaloneMode = false;
  getLocationName(); // 尽早校验 location 取值

  var customProxyNames = [];
  var customRuleGroupRules = [];
  var customGroupInsertionIndex;
  var fullProtocolTarget = null;

  ensureProxyContainers(config);
  validateDedicatedProxyReferences(dedicatedCustomProxies, customRuleGroups);
  subscriptionNodeNames = collectProxyNames(config.proxies);
  hasSubscriptionNodes = subscriptionNodeNames.length > 0;
  standaloneMode = !hasSubscriptionNodes;
  if (standaloneMode &&
      !hasHomeProxy &&
      (!customProxies || customProxies.length === 0) &&
      (!customRuleGroups || customRuleGroups.length === 0)) {
    throw createUserError("未检测到订阅节点，也未配置 _customProxies 或 _homeProxy。请导入订阅，或使用 出口IP凭证.js 添加公司节点/固定 IP。");
  }
  if (frontProxy) {
    frontProxyName = injectFrontProxy(config, frontProxy, subscriptionNodeNames);
    bindFrontProxyToSubscriptionNodes(config, frontProxyName, subscriptionNodeNames);
  }
  if (ordinaryCustomProxies.length > 0) {
    customProxyNames = injectCustomProxies(config, ordinaryCustomProxies, frontProxyName);
  }
  resetSubscriptionGroupsAndRules(config);

  // ① 自动选择组（最上面）：订阅有就用，没有就自建 url-test
  if (!standaloneMode) ensureAutoSelectGroup(config);

  // ② 节点选择（第二位）
  anchorResult = ensureAnchorGroups(config, {
    enableAutoSelect: !standaloneMode,
    enableRegions: !standaloneMode
  });
  regionGroupNames = anchorResult.regionGroupNames;
  ensureOverseasPolicyGroup(config, regionGroupNames);
  fullProtocolTarget = ensureFullProtocolFallbackGroup(
    config,
    subscriptionNodeNames.concat(customProxyNames)
  );

  // ③ GLOBAL（用户可见的第三个主入口）
  var nodeSelGroup = findProxyGroupByName(config["proxy-groups"], "节点选择");
  var globalProxies = ["节点选择"]
    .concat(nodeSelGroup ? nodeSelGroup.proxies.slice() : []);
  upsertNamedItem(config["proxy-groups"], {
    name: "GLOBAL",
    type: "select",
    proxies: globalProxies,
    url: getProxyProbeUrl()
  });
  var globalGroup = findProxyGroupByName(config["proxy-groups"], "GLOBAL");
  if (frontProxyName && globalGroup) {
    insertBeforeDirect(globalGroup.proxies, frontProxyName);
  }

  // ④ 功能组
  buildFunctionalGroups(config, regionGroupNames);
  ensureTailscaleMonitorGroups(config);
  if (dedicatedCustomProxies.length > 0) {
    validateDedicatedProxyNameAvailability(config, dedicatedCustomProxies, customRuleGroups);
    injectCustomProxies(config, dedicatedCustomProxies, frontProxyName);
  }
  customGroupInsertionIndex = config["proxy-groups"].length;
  ensureDomesticGroup(config);
  ensureFallbackPolicyGroup(config, fullProtocolTarget);

  // ⑤ 🔗 前置（本机可直连节点）+ 家宽出口（有凭证时）
  var chainGroupName = null;
  var unreachableNames = [];
  if (hasHomeProxy) {
    injectHomeDirectProxy(config, credentials);
    if (!isDirectlyReachableSpec(credentials)) unreachableNames.push(BASE.nodeNames.home);
  }
  // dedicated 节点只给引用它的规则组用，不当前置
  var relayGroupName = ensureRelayGroups(config, subscriptionNodeNames,
    unreachableNames.concat(collectProxyNames(dedicatedCustomProxies)));
  assertRelayReferencesResolved(config, relayGroupName);
  if (hasHomeProxy) {
    // 防循环：家宽IP链式不能拿家宽IP自己当前置；🔗 前置里只有家宽IP 时不生成链式节点。
    var homeRelay = relayHasCandidateOtherThan(config, relayGroupName, BASE.nodeNames.home) ? relayGroupName : null;
    routingTargets = resolveRoutingTargets(config, homeRelay);
    routingTargets.homeDialer = credentials.via || homeRelay;
    routingTargets.chainProxies = injectHomeProxies(config, credentials, homeRelay);
    chainGroupName = ensureChainGroupWithProxies(config, routingTargets.chainProxies);
    routingTargets.chainGroupName = chainGroupName;
    // 将 🏠 家宽IP 添加到节点选择和 GLOBAL 中（在 DIRECT 之前）
    var groups = [nodeSelGroup, globalGroup];
    for (var gi = 0; gi < groups.length; gi++) {
      if (!groups[gi]) continue;
      insertBeforeDirect(groups[gi].proxies, chainGroupName);
    }
  }

  // ⑥ AI Agent 策略组：有家宽时不展开订阅裸节点；无家宽时允许精确选择裸节点。
  var aiAgentTarget = ensureAiAgentGroup(config, {
    chainGroupName: chainGroupName,
    regionGroupNames: regionGroupNames,
    customProxyNames: customProxyNames,
    allNodeNames: anchorResult.allNodeNames,
    includeRawNodes: hasSubscriptionNodes && !hasHomeProxy
  });

  // ⑦ 地区 url-test 组（沉底）
  appendTailGroups(config, anchorResult.regionGroups);
  if (customRuleGroups) {
    customRuleGroupRules = injectCustomRuleGroups(config, customRuleGroups, customGroupInsertionIndex);
  }

  // ⑧ DNS / Sniffer / 规则注入
  applyDnsAndSniffer(config);
  applyTunRouteExcludes(config, customProxies, frontProxy, credentials);
  ensureTunDnsHijack(config);
  applyProxyServerDirectRules(config);
  if (hasHomeProxy) {
    injectManagedRules(config, aiAgentTarget, frontProxyName, fullProtocolTarget);
    if (customRuleGroupRules.length > 0) {
      injectCustomRuleGroupRules(config, customRuleGroupRules, aiAgentTarget, fullProtocolTarget);
    }
    validateManagedRouting(config, routingTargets);
  } else {
    // 无家宽凭证：AI 规则指向 AI Agent，用户可在组内选择支持 AI 的订阅节点。
    injectManagedRules(config, aiAgentTarget, frontProxyName, fullProtocolTarget);
    if (customRuleGroupRules.length > 0) {
      injectCustomRuleGroupRules(config, customRuleGroupRules, aiAgentTarget, fullProtocolTarget);
    }
  }

  orderProxyGroups(config);
  validateLocationRouting(config);
  validateProxyGraph(config);
  delete config._frontProxyName;
  return config;
}

function relayHasCandidateOtherThan(config, relayGroupName, name) {
  var group = relayGroupName ? findProxyGroupByName(config["proxy-groups"], relayGroupName) : null;
  if (!group) return false;
  for (var i = 0; i < group.proxies.length; i++) {
    if (group.proxies[i] !== name && group.proxies[i] !== BASE.ruleTargets.direct) return true;
  }
  return false;
}

// 需中转的节点引用了 🔗 前置，但本机没有任何可直连候选。
function assertRelayReferencesResolved(config, relayGroupName) {
  if (relayGroupName) return;
  for (var i = 0; i < config.proxies.length; i++) {
    if (config.proxies[i]["dialer-proxy"] === BASE.nodeNames.relay) {
      throw createUserError("节点 " + config.proxies[i].name + " 需要经 " + BASE.nodeNames.relay +
        " 中转，但本机没有可直连的前置候选（或 relay.enable=false）；可给它写 via 指定前置");
    }
  }
}

// 面板顺序：入口（自动选择/节点选择/GLOBAL）→ 策略组段（AI Agent、功能组、自定义规则组、国内/国外/兜底）
// → 隐藏组 → 节点组段（🏠 家宽IP、🔗 前置、🔌 全协议回退、地区组）。同段内保持原顺序。
function orderProxyGroups(config) {
  var groups = config["proxy-groups"];
  var autoNames = [USER_OPTIONS.autoSelectGroupName, USER_OPTIONS.autoSelectGroupName + "(Smart Group)"];
  var policyTail = [BASE.policyNames.domestic, BASE.policyNames.overseas, BASE.policyNames.fallback];
  var nodeGroups = [ensureChainGroup(), BASE.nodeNames.relay, BASE.nodeNames.fullProtocolFallback];
  function rank(g) {
    if (autoNames.indexOf(g.name) >= 0 || g.name === "节点选择" || g.name === "GLOBAL") return 0;
    if (g.name === BASE.nodeNames.aiAgent) return 1;
    if (policyTail.indexOf(g.name) >= 0) return 3 + policyTail.indexOf(g.name) / 10;
    if (nodeGroups.indexOf(g.name) >= 0) return 5 + nodeGroups.indexOf(g.name) / 10;
    if (/\|/.test(g.name) && g.type === "url-test") return 6;
    if (g.hidden === true) return 4;
    return 2;
  }
  var indexed = [];
  for (var i = 0; i < groups.length; i++) indexed.push({ g: groups[i], r: rank(groups[i]), i: i });
  indexed.sort(function (a, b) { return a.r - b.r || a.i - b.i; });
  config["proxy-groups"] = indexed.map(function (x) { return x.g; });
}
