/**
 * 完全覆写脚本行为与回归测试
 */
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const repoRoot   = path.resolve(__dirname, "..");
const scriptPath = path.join(repoRoot, "src", "完全覆写.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

const TEST_HOME_CREDENTIALS = {
  type: "http",
  server: "1.2.3.4",
  port: 1080
};

const EXPECTED = {
  aiGroupName:     "🤖 AI Agent",
  chainGroupName:  "🏠 家宽IP",
  homeNodeName:    "家宽IP",
  homeChainedNodeName: "家宽IP链式",
  relayGroupName:  "自动选择(Smart Group)",
  mediaGroupName:  "🌍 国际媒体",
  generalEgressGroupName: "🌐 国外",
  fullProtocolFallbackGroupName: "🔌 全协议回退",
  japanServicesGroupName: "🇯🇵 日本服务",
  microsoftGroupName: "Ⓜ️ 微软服务",
  tailscaleControlGroupName: "🧩 Tailscale 控制面",
  tailscaleProcessGroupName: "🧩 Tailscale 进程",
  tailnetDirectGroupName: "🧩 Tailnet 内部直连",
  tailscaleExitGroupName: "🧩 Tailscale Exit Node"
};

const EXPECTED_NETWORK_PROBES = [
  ["ipip.net", "direct"], ["ip.sb", "front"], ["ipwho.is", "node"],
  ["ipapi.is", "ai"], ["ip.net.coffee", "ai"], ["ping0.cc", "ai"], ["ipinfo.io", "ai"]
];

// ─── sandbox ────────────────────────────────────────────────────────────────

function loadSandbox() {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox);
  return sandbox;
}

function createBaseConfig() {
  return {
    proxies: [
      { name: "🇸🇬 SG Auto 01", type: "ss", udp: true },
      { name: "🇭🇰 HK Auto 01", type: "ss", udp: true },
      { name: "🇺🇸 US Auto 01", type: "ss", udp: true },
      { name: "🇯🇵 JP Auto 01", type: "ss", udp: true }
    ],
    "proxy-groups": [
      { name: "节点选择", type: "select", proxies: ["🇸🇬 SG Auto 01"] },
      {
        name: "自动选择(Smart Group)",
        type: "smart",
        proxies: ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01", "🇯🇵 JP Auto 01"]
      }
    ],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "MATCH,节点选择"
    ],
    _homeProxy: {
      type:   TEST_HOME_CREDENTIALS.type,
      server: TEST_HOME_CREDENTIALS.server,
      port:   TEST_HOME_CREDENTIALS.port
    }
  };
}

function runMain(configMutator, sandboxMutator) {
  const sandbox = loadSandbox();
  const config  = createBaseConfig();
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  if (typeof configMutator  === "function") configMutator(config);
  return { sandbox, output: sandbox.main(config) };
}

function runMainWithConfig(config, sandboxMutator) {
  const sandbox = loadSandbox();
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  return { sandbox, output: sandbox.main(config) };
}

function createEmptyConfig() {
  return {
    proxies: [],
    "proxy-groups": [],
    rules: ["MATCH,DIRECT"]
  };
}

// ─── assertion helpers ───────────────────────────────────────────────────────

function assertRuleExists(rules, ruleLine) {
  assert(rules.indexOf(ruleLine) >= 0, "Expected rule not found: " + ruleLine);
}

function tcp443DomainRule(domain, target) {
  return "AND,((NETWORK,tcp),(DST-PORT,443),(DOMAIN-SUFFIX," + domain + "))," + target;
}

function googlePlayMtalkRule(target) {
  return "AND,((NETWORK,tcp),(DST-PORT,5228),(DOMAIN-SUFFIX,mtalk.google.com))," +
    (target || EXPECTED.fullProtocolFallbackGroupName);
}

function geminiChallengeQuicRejectRule() {
  return "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN,www.google.com)),REJECT";
}

function googleGeositeQuicRejectRule() {
  return "AND,((NETWORK,udp),(DST-PORT,443),(GEOSITE,google)),REJECT";
}

function appStoreQuicRejectRule() {
  return "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN,bag.itunes.apple.com)),REJECT";
}

function assertTransportAwareDomainRules(rules, domain, tlsTarget) {
  const tlsRule = tcp443DomainRule(domain, tlsTarget);
  const fallbackRule = "DOMAIN-SUFFIX," + domain + "," + EXPECTED.fullProtocolFallbackGroupName;
  assertRuleExists(rules, tlsRule);
  assertRuleExists(rules, fallbackRule);
  assert(rules.indexOf(tlsRule) < rules.indexOf(fallbackRule),
    domain + " 的 TCP/443 规则应优先于全协议回退规则");
}

// 兜底统一为最后一条 MATCH,🐟 兜底；不再有按 TCP/443 拆分的通用兜底。
const FALLBACK_MATCH = "MATCH,🐟 兜底";
function assertTransportAwareFallbackRules(rules) {
  assert.strictEqual(rules[rules.length - 1], FALLBACK_MATCH, "最后一条规则应为 " + FALLBACK_MATCH);
  assertRulesMissing(rules, [
    "AND,((NETWORK,tcp),(DST-PORT,443))," + EXPECTED.generalEgressGroupName,
    "MATCH," + EXPECTED.fullProtocolFallbackGroupName
  ]);
}

function assertRulesMissing(rules, ruleLines) {
  for (const ruleLine of ruleLines) {
    assert(rules.indexOf(ruleLine) < 0, "Rule should NOT exist: " + ruleLine);
  }
}

function assertNoDuplicateRuleIdentities(rules) {
  const seen = {};
  for (const rule of rules) {
    const fields = splitTopLevelRuleFields(rule);
    if (fields.length < 3) continue;
    const identity = fields[0] + "," + fields[1];
    if (seen[identity]) throw new Error("Duplicate rule identity: " + identity);
    seen[identity] = true;
  }
}

function splitTopLevelRuleFields(rule) {
  const fields = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < rule.length; i++) {
    if (rule[i] === "(") depth++;
    else if (rule[i] === ")" && depth > 0) depth--;
    else if (rule[i] === "," && depth === 0) {
      fields.push(rule.slice(start, i));
      start = i + 1;
    }
  }
  fields.push(rule.slice(start));
  return fields;
}

function aiQuicRejectRule(domain) {
  return "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX," + domain + ")),REJECT";
}

function webRtcUdpRejectRule(port) {
  return "AND,((NETWORK,udp),(DST-PORT," + port + ")),REJECT";
}

function assertSingleProxy(group, proxyName, message) {
  assert(group, message + "：代理组不存在");
  assert.strictEqual(group.proxies.length, 1, message + "：应只有一个成员");
  assert.strictEqual(group.proxies[0], proxyName, message);
}

function assertHiddenGroup(group, message) {
  assert(group, message + "：代理组不存在");
  assert.strictEqual(group.hidden, true, message + "：应默认隐藏，避免在代理组列表展示");
}

// ─── tests ───────────────────────────────────────────────────────────────────

function testDefaultConfig() {
  const { sandbox, output } = runMain();

  // 凭证不输出到最终配置
  assert.strictEqual(output._homeProxy, undefined);

  // 家宽IP节点正确注入；真直连节点不挂 dialer-proxy
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert(homeNode, "家宽IP节点应存在");
  assert.strictEqual(homeNode.type,   TEST_HOME_CREDENTIALS.type);
  assert.strictEqual(homeNode.server, TEST_HOME_CREDENTIALS.server);
  assert.strictEqual(homeNode.port,   TEST_HOME_CREDENTIALS.port);
  assert.strictEqual(homeNode.udp, false, "HTTP 家宽节点不应声明 UDP 能力");
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "家宽IP节点应是真直连，不应挂 dialer-proxy");

  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert(homeChainedNode, "存在可用跳板时应额外创建家宽IP链式节点");
  assert.strictEqual(homeChainedNode["dialer-proxy"], "🔗 家宽跳板",
    "家宽IP链式节点的 dialer-proxy 应指向家宽跳板组");
  assert.strictEqual(homeChainedNode.udp, false, "HTTP 家宽链式节点不应声明 UDP 能力");

  // 家宽跳板组存在
  const relayGroup = output["proxy-groups"].find(function (g) { return g.name === "🔗 家宽跳板"; });
  assert(relayGroup, "家宽跳板组应存在");
  assert.strictEqual(relayGroup.type, "select");
  assert(relayGroup.proxies.indexOf(EXPECTED.relayGroupName) >= 0, "家宽跳板应包含自动选择组");

  // 🔗 前置：一级跳，默认 DIRECT；订阅节点都挂到它上面，家宽节点不挂
  const frontGroup = output["proxy-groups"].find(function (g) { return g.name === "🔗 前置"; });
  assert(frontGroup && frontGroup.type === "select", "🔗 前置 组应存在且为 select");
  assert.deepStrictEqual(Array.from(frontGroup.proxies),
    ["DIRECT", "⤴ 🇸🇬 SG Auto 01", "⤴ 🇭🇰 HK Auto 01", "⤴ 🇺🇸 US Auto 01", "⤴ 🇯🇵 JP Auto 01"],
    "🔗 前置 = DIRECT + 订阅节点的前置副本");
  output.proxies.filter(function (p) { return p.name.indexOf("⤴ ") === 0; }).forEach(function (copy) {
    assert.strictEqual(copy["dialer-proxy"], undefined, copy.name + " 副本不挂前置");
    output["proxy-groups"].forEach(function (g) {
      if (g.name !== "🔗 前置") assert(g.proxies.indexOf(copy.name) < 0, copy.name + " 不应出现在 " + g.name);
    });
  });
  ["🇸🇬 SG Auto 01", "🇺🇸 US Auto 01"].forEach(function (name) {
    const node = output.proxies.find(function (p) { return p.name === name; });
    assert.strictEqual(node["dialer-proxy"], "🔗 前置", name + " 应经 🔗 前置");
  });

  // 家宽IP节点不在节点选择中（在组生成之后注入）
  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup, "节点选择组应存在");
  assert(nodeSelGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "家宽IP不应在节点选择中");

  const generalEgressGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.generalEgressGroupName;
  });
  assert(generalEgressGroup, "🌐 国外 组应存在");
  assert.strictEqual(generalEgressGroup.proxies[0], "节点选择", "cn 下 🌐 国外 默认走节点选择");
  assert(generalEgressGroup.proxies.indexOf("DIRECT") >= 0, "🌐 国外 应保留 DIRECT 候选");
  assert.notStrictEqual(generalEgressGroup.hidden, true, "🌐 国外 是可见的策略组");
  const domesticPolicy = output["proxy-groups"].find(function (g) { return g.name === "🇨🇳 国内"; });
  assert(domesticPolicy && domesticPolicy.proxies[0] === "DIRECT", "cn 下 🇨🇳 国内 默认 DIRECT");
  const fallbackPolicy = output["proxy-groups"].find(function (g) { return g.name === "🐟 兜底"; });
  assert.deepStrictEqual(Array.from(fallbackPolicy.proxies).slice(0, 2), ["🇨🇳 国内", EXPECTED.generalEgressGroupName],
    "cn 下 🐟 兜底 默认国内");
  assert.strictEqual(output.rules[output.rules.length - 1], "MATCH,🐟 兜底", "最后一条规则应指向 🐟 兜底");

  const fullProtocolFallbackGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert(fullProtocolFallbackGroup, "存在全协议订阅节点时应创建全协议回退组");
  assert.strictEqual(fullProtocolFallbackGroup.type, "url-test");
  assertHiddenGroup(fullProtocolFallbackGroup, "全协议回退组");
  ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01", "🇯🇵 JP Auto 01"].forEach(function (name) {
    assert(fullProtocolFallbackGroup.proxies.indexOf(name) >= 0,
      "全协议回退组应包含订阅节点：" + name);
  });
  [EXPECTED.homeNodeName, EXPECTED.homeChainedNodeName].forEach(function (name) {
    assert(fullProtocolFallbackGroup.proxies.indexOf(name) < 0,
      "全协议回退组不应包含 HTTP 家宽节点：" + name);
  });

  // 家宽IP出口组存在且成员正确
  const chainGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.chainGroupName; });
  assert(chainGroup, "家宽IP出口组应存在");
  assert.strictEqual(chainGroup.type, "select");
  assert.strictEqual(chainGroup.proxies[0], EXPECTED.homeChainedNodeName, "有跳板时默认应优先使用链式家宽");
  assert.strictEqual(chainGroup.proxies[1], EXPECTED.homeNodeName, "家宽出口组应保留真直连备选");

  // AI Agent 组存在；有家宽IP时默认包含家宽IP，但不展开订阅裸节点
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup, "AI Agent 组应存在");
  assert.strictEqual(aiGroup.type, "select");
  assert.strictEqual(aiGroup.proxies[0], EXPECTED.chainGroupName, "有家宽IP时 AI Agent 应优先使用家宽IP");
  assert(aiGroup.proxies.indexOf("节点选择") >= 0, "AI Agent 应包含节点选择");
  assert(aiGroup.proxies.indexOf(EXPECTED.relayGroupName) < 0, "AI Agent 不应直接包含自动选择");
  assert(aiGroup.proxies.indexOf("🇭🇰|香港") >= 0, "AI Agent 应包含地区组");
  assert(aiGroup.proxies.indexOf("🇸🇬 SG Auto 01") < 0, "有家宽IP时 AI Agent 不应包含订阅裸节点");

  // 国际媒体组存在且为 select 类型，不含家宽IP节点
  const mediaGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.mediaGroupName; });
  assert(mediaGroup, "国际媒体组应存在");
  assert.strictEqual(mediaGroup.type, "select");
  assert.strictEqual(mediaGroup.proxies[0], "节点选择",
    "国际媒体默认应走节点选择");
  assert(mediaGroup.proxies.indexOf("节点选择") >= 0, "国际媒体应包含节点选择");
  assert(mediaGroup.proxies.indexOf(EXPECTED.generalEgressGroupName) < 0,
    "国际媒体不应暴露内部通用出海组");
  assert(mediaGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "媒体组不应含家宽IP节点");
  assert(mediaGroup.proxies.indexOf(EXPECTED.homeChainedNodeName) < 0, "媒体组不应含家宽IP链式节点");

  // 微软服务默认直连，但保留手动切换到节点选择/地区组的能力
  const microsoftGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.microsoftGroupName; });
  ["IP-CIDR,10.0.0.0/8", "IP-CIDR,192.168.0.0/16", "IP-CIDR6,fe80::/10"].forEach(function (r) {
    assertRuleExists(output.rules, r + ",🎯 直连,no-resolve");
  });
  [EXPECTED.microsoftGroupName, "🍎 Apple"].forEach(function (n) {
    const g = output["proxy-groups"].find(function (x) { return x.name === n; });
    assert.strictEqual(g.proxies[0], "DIRECT", n + " 默认 DIRECT");
    assert(g.proxies.indexOf("🇨🇳 国内") >= 0, n + " 候选应含 🇨🇳 国内");
  });
  assert(microsoftGroup, "微软服务组应存在");
  assert.strictEqual(microsoftGroup.type, "select");
  assert.strictEqual(microsoftGroup.proxies[0], "DIRECT", "微软服务默认应走直连");
  assert(microsoftGroup.proxies.indexOf("节点选择") >= 0, "微软服务应保留节点选择");

  assert(output["proxy-groups"].every(function (g) { return g.name !== "🧩 VS Code 插件"; }), "不应创建独立 VS Code 插件组");

  // 功能分组存在
  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  [
    EXPECTED.generalEgressGroupName,
    EXPECTED.japanServicesGroupName,
    "🐙 GitHub",
    "📲 Telegram",
    "🌍 国际媒体",
    "🎮 游戏平台",
    "🍎 Apple",
    "🎯 直连"
  ].forEach(function (name) {
    assert(groupNames.indexOf(name) >= 0, name + " 组应存在");
  });
  assert(groupNames.indexOf("🧰 开发服务") < 0, "不应创建独立开发服务组");
  const gamingGroup = output["proxy-groups"].find(function (g) { return g.name === "🎮 游戏平台"; });
  assert.strictEqual(gamingGroup.proxies[0], "节点选择",
    "国际游戏平台默认应走节点选择");
  const japanGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.japanServicesGroupName;
  });
  assert.strictEqual(japanGroup.proxies[0], "🇯🇵|日本",
    "存在日本地区节点时，日本服务应优先选择日本组");
  assertHiddenGroup(japanGroup, "日本服务应作为内部功能组隐藏");

  const globalGroup = output["proxy-groups"].find(function (g) { return g.name === "GLOBAL"; });
  assert(globalGroup, "GLOBAL 组应存在");
  assert(globalGroup.proxies.indexOf(EXPECTED.generalEgressGroupName) < 0,
    "GLOBAL 不应暴露内部通用出海组");

  // 关键 AI 规则统一指向 AI Agent 策略组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai,"   + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claudemcpcontent.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,anthropic.auth0.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,anthropic.com.cdn.cloudflare.net," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "IP-CIDR,160.79.104.0/21," + EXPECTED.aiGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR6,2607:6bc0::/32," + EXPECTED.aiGroupName + ",no-resolve");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,chatgpt.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,aistudio.google.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,gemini.gstatic.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,assistant.google.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,accounts.google.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,accounts.google.ca," + EXPECTED.aiGroupName);
  ["cursor.sh", "cursor.com", "cursorapi.com"].forEach(function (domain) {
    assertRuleExists(output.rules, "DOMAIN-SUFFIX," + domain + "," + EXPECTED.aiGroupName);
  });
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,antigravity.google," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,generativelanguage.googleapis.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,grokipedia.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,mistral.ai," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,oaistatsig.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,openaimerge.com," + EXPECTED.aiGroupName);
  const sharedAiInfrastructureDomains = [
    "intercom.io",
    "intercomcdn.com",
    "cdn.usefathom.com",
    "sentry.io",
    "datadoghq.com",
    "browser-intake-us5-datadoghq.com",
    "statsigapi.net",
    "statsig.com",
    "rum.browser-intake-datadoghq.com",
    "ct.sendgrid.net",
    "workos.com",
    "workoscdn.com",
    "workos.imgix.net",
    "challenges.cloudflare.com",
    "js.stripe.com",
    "humb.apple.com"
  ];
  sharedAiInfrastructureDomains.forEach(function (domain) {
    assert(sandbox.DERIVED.patterns.strict.sharedInfrastructure.indexOf("+." + domain) >= 0,
      "共享基础设施域名应保留在独立清单中：" + domain);
    assertRulesMissing(output.rules, [
      "DOMAIN-SUFFIX," + domain + "," + EXPECTED.aiGroupName,
      aiQuicRejectRule(domain)
    ]);
  });
  assertTransportAwareDomainRules(output.rules, "google.com", "节点选择");
  assertTransportAwareDomainRules(output.rules, "google.ca", "节点选择");
  assertTransportAwareDomainRules(output.rules, "googleapis.com", "节点选择");
  assertRuleExists(output.rules, "DOMAIN,cloudcode-pa.googleapis.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN,daily-cloudcode-pa.googleapis.com," + EXPECTED.aiGroupName);
  const googleDeepMindRule = "GEOSITE,google-deepmind," + EXPECTED.aiGroupName;
  const googleCatchAllRule = "GEOSITE,google," + EXPECTED.aiGroupName;
  const youtubeGeositeRule = "GEOSITE,youtube," + EXPECTED.mediaGroupName;
  const googlePlayGeositeRule = "GEOSITE,google-play," + EXPECTED.mediaGroupName;
  const googleFcmGeositeRule = "GEOSITE,googlefcm," + EXPECTED.fullProtocolFallbackGroupName;
  const googleAccountCountryRule = "DOMAIN-REGEX,^accounts\\.google\\..+$," + EXPECTED.aiGroupName;
  const youtubeAccountRule = "DOMAIN,accounts.youtube.com," + EXPECTED.aiGroupName;
  [
    googleDeepMindRule,
    googleCatchAllRule,
    youtubeGeositeRule,
    googlePlayGeositeRule,
    googleFcmGeositeRule,
    googleAccountCountryRule,
    youtubeAccountRule,
    "DOMAIN,accounts.gstatic.com," + EXPECTED.aiGroupName,
    "DOMAIN,oauthaccountmanager.googleapis.com," + EXPECTED.aiGroupName,
    "DOMAIN,www.googleapis.com," + EXPECTED.aiGroupName,
    "DOMAIN,ssl.gstatic.com," + EXPECTED.aiGroupName
  ].forEach(function (rule) {
    assertRuleExists(output.rules, rule);
  });
  assert(output.rules.indexOf(googleAccountCountryRule) < output.rules.indexOf(googleCatchAllRule),
    "Google 国家账号域名必须先于 Google 总集合进入 AI Agent");
  assert(output.rules.indexOf(youtubeAccountRule) < output.rules.indexOf(youtubeGeositeRule),
    "YouTube 登录域名必须先于 YouTube 内容流量进入 AI Agent");
  [googleDeepMindRule, youtubeGeositeRule, googlePlayGeositeRule, googleFcmGeositeRule].forEach(function (rule) {
    assert(output.rules.indexOf(rule) < output.rules.indexOf(googleCatchAllRule),
      rule + " 必须先于 Google 总集合");
  });
  assertRuleExists(output.rules, googleGeositeQuicRejectRule());
  assert(output.rules.indexOf(googleGeositeQuicRejectRule()) < output.rules.indexOf(googleCatchAllRule),
    "Google 账号与 AI 流量应先拒绝 QUIC，再通过统一 TCP 出口访问");
  assert(output.rules.indexOf(googleCatchAllRule) < output.rules.indexOf(
    tcp443DomainRule("google.com", "节点选择")
  ), "Google 总集合必须先于旧的通用 Google 规则");
  assertRuleExists(output.rules, "PROCESS-NAME,agy,"          + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude,"       + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,claude,"       + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,Codex (Service)," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,Cursor Helper (Plugin)," + EXPECTED.aiGroupName);
  assert(output.rules.indexOf("PROCESS-NAME,Codex (Service)," + EXPECTED.aiGroupName) <
      output.rules.indexOf(FALLBACK_MATCH),
    "Codex 桌面服务必须优先于兜底规则进入 AI Agent");
  assert(output.rules.indexOf("PROCESS-NAME,Cursor Helper (Plugin)," + EXPECTED.aiGroupName) <
      output.rules.indexOf(FALLBACK_MATCH),
    "Cursor 插件进程必须优先于兜底规则进入 AI Agent");

  // AI QUIC 先拒绝再回退 TCP，避免 HTTP 家宽出口不支持 UDP 时继续匹配到 DIRECT。
  ["openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.gstatic.com", "assistant.google.com", "accounts.google.com", "accounts.google.ca", "cursor.sh", "cursor.com", "cursorapi.com", "aistudio.google.com"].forEach(function (domain) {
    const rejectRule = aiQuicRejectRule(domain);
    const proxyRule = "DOMAIN-SUFFIX," + domain + "," + EXPECTED.aiGroupName;
    assertRuleExists(output.rules, rejectRule);
    assert(output.rules.indexOf(rejectRule) < output.rules.indexOf(proxyRule),
      domain + " 的 QUIC 拒绝规则应位于 AI 代理规则之前");
    assertRulesMissing(output.rules, [
      "DOMAIN-SUFFIX," + domain + "," + EXPECTED.fullProtocolFallbackGroupName
    ]);
  });
  assert(output.rules.indexOf("DOMAIN-SUFFIX,generativelanguage.googleapis.com," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,googleapis.com," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini API 精确规则必须先命中 AI Agent，不能落入 Google 全协议回退");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,assistant.google.com," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,google.com," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini 助手域名必须先命中 AI Agent，不能落入通用 Google 全协议回退");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,gemini.gstatic.com," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,gstatic.com," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini 静态资源域名必须先命中 AI Agent，不能落入通用 GStatic 规则");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,accounts.google.com," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,google.com," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini 登录域名必须先命中 AI Agent，不能落入通用 Google 规则");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,accounts.google.ca," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,google.ca," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini 加拿大登录域名必须先命中 AI Agent，不能落入通用 Google 规则");
  assertRuleExists(output.rules, geminiChallengeQuicRejectRule());
  assertRuleExists(output.rules, "DOMAIN,www.google.com," + EXPECTED.aiGroupName);
  assert(output.rules.indexOf(geminiChallengeQuicRejectRule()) < output.rules.indexOf(
    "DOMAIN,www.google.com," + EXPECTED.aiGroupName
  ), "Gemini 挑战域名的 QUIC 拒绝规则必须先于 AI Agent 路由");
  assert(output.rules.indexOf("DOMAIN,www.google.com," + EXPECTED.aiGroupName) <
      output.rules.indexOf("DOMAIN-SUFFIX,google.com," + EXPECTED.fullProtocolFallbackGroupName),
    "Gemini 挑战域名必须先命中 AI Agent，不能落入通用 Google 规则");
  sandbox.DERIVED.patterns.strict.all.forEach(function (pattern) {
    assertRuleExists(output.rules, aiQuicRejectRule(sandbox.toSuffix(pattern)));
  });

  // 网络信息检测源：AI / 普通代理 / 前置或直连，各司其职
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.net.coffee," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipip.net,DIRECT");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,🔗 前置");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,ip.sb,🔗 前置") < output.rules.indexOf("GEOSITE,cn,🇨🇳 国内"),
    "ip.sb 必须先于 GeoSite cn 命中 🔗 前置");

  // 媒体规则指向媒体组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,netflix.com," + EXPECTED.mediaGroupName);
  ["youtubei.googleapis.com", "youtube.googleapis.com", "ggpht.com"].forEach(function (domain) {
    var mediaRule = "DOMAIN-SUFFIX," + domain + "," + EXPECTED.mediaGroupName;
    assertRuleExists(output.rules, mediaRule);
    assert(output.rules.indexOf(mediaRule) < output.rules.indexOf(
      tcp443DomainRule("googleapis.com", "节点选择")
    ),
      domain + " 应优先于通用 Google 规则进入国际媒体");
  });
  assertRulesMissing(output.rules, [aiQuicRejectRule("googleapis.com")]);
  assertRuleExists(output.rules, googlePlayMtalkRule());
  assert(output.rules.indexOf(googlePlayMtalkRule()) < output.rules.indexOf(
    googleCatchAllRule
  ), "Google Play Services 的 5228 规则必须优先进入全协议出口");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,reddit.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tiktok.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,bbc.com," + EXPECTED.mediaGroupName);

  // Telegram / GitHub / Steam 各走专用组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,telegram.org,📲 Telegram");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,steampowered.com,🎮 游戏平台");
  assertRuleExists(output.rules, appStoreQuicRejectRule());
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,apple.com,🍎 Apple");
  assert(output.rules.indexOf(appStoreQuicRejectRule()) < output.rules.indexOf(
    "DOMAIN-SUFFIX,apple.com,🍎 Apple"
  ), "App Store QUIC 拒绝规则必须优先于 Apple 域名分流");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,icloud.com.cn,🍎 Apple");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,microsoft.com," + EXPECTED.microsoftGroupName);
  assertTransportAwareDomainRules(output.rules, "marketplace.visualstudio.com", "节点选择");
  assertTransportAwareDomainRules(output.rules, "gallery.vsassets.io", "节点选择");
  assertTransportAwareDomainRules(output.rules, "gallerycdn.vsassets.io", "节点选择");
  assertTransportAwareDomainRules(output.rules, "vscode-cdn.net", "节点选择");
  assertTransportAwareDomainRules(output.rules, "vscode-unpkg.net", "节点选择");
  assertTransportAwareDomainRules(output.rules, "npmjs.com", "节点选择");
  assertTransportAwareDomainRules(output.rules, "bing.com", "节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,line.me," + EXPECTED.japanServicesGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,yahoo.co.jp," + EXPECTED.japanServicesGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,sony.jp," + EXPECTED.japanServicesGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,nintendo.co.jp," + EXPECTED.japanServicesGroupName);

  const domesticDnsDirectOverrides = [
    "rivotek.com"
  ];
  // 已被 GEOSITE,cn 覆盖，不再写死：
  ["larksuite.com", "larkoffice.com", "dashscope.aliyuncs.com", "feishu.net", "feishucdn.com", "dingtalkapps.com"].forEach(function (domain) {
    assertRulesMissing(output.rules, ["DOMAIN-SUFFIX," + domain + ",🇨🇳 国内"]);
  });
  const overseasDnsDirectOverrides = ["typeless.com"];
  // 国内业务域名统一进 🇨🇳 国内（cn 默认 DIRECT）；海外 DNS 例外仍直接 DIRECT。
  domesticDnsDirectOverrides.forEach(function (domain) {
    assertRuleExists(output.rules, "DOMAIN-SUFFIX," + domain + ",🇨🇳 国内");
  });
  overseasDnsDirectOverrides.forEach(function (domain) {
    assertRuleExists(output.rules, "DOMAIN-SUFFIX," + domain + ",DIRECT");
  });
  domesticDnsDirectOverrides.forEach(function (domain) {
    assert.deepEqual(
      output.dns["nameserver-policy"]["+." + domain],
      output.dns["direct-nameserver"],
      domain + " 应使用国内 DNS 并保持直连"
    );
  });
  overseasDnsDirectOverrides.forEach(function (domain) {
    assert(output.dns["nameserver-policy"]["+." + domain].every(function (server) {
      return server.indexOf("#" + EXPECTED.aiGroupName) > 0;
    }), domain + " 应使用海外 DNS，但业务流量保持直连");
  });
  [
    "qq.com",
    "moonshot.cn",
    "aliyun.com",
    "aliyuncs.com",
    "feishu.cn",
    "wps.com",
    "kdocs.com",
    "alibabacloud.com"
  ].forEach(function (domain) {
    assertRulesMissing(output.rules, ["DOMAIN-SUFFIX," + domain + ",DIRECT"]);
  });
  assertRuleExists(output.rules, "GEOSITE,cn,🇨🇳 国内");
  assertRuleExists(output.rules, "GEOIP,cn,🇨🇳 国内");

  [
    "cloudflare.com",
    "workers.dev",
    "oracle.com",
    "takealot.com",
    "pixpix.com",
    "naver.com",
    "noon.com",
    "wikipedia.org",
    "yastatic.net"
  ].forEach(function (domain) {
    const tlsRule = tcp443DomainRule(domain, EXPECTED.generalEgressGroupName);
    assertTransportAwareDomainRules(output.rules, domain, EXPECTED.generalEgressGroupName);
    assert(output.rules.indexOf(tlsRule) < output.rules.indexOf("GEOSITE,cn,🇨🇳 国内"),
      domain + " 应在 GeoSite 国内直连规则之前固定进入通用出海");
  });

  // TCP/443 保留当前节点选择；HTTP、IMAP、UDP 等其余协议走全协议回退。
  assertTransportAwareFallbackRules(output.rules);

  // 海外解析器默认经 AI Agent，国内和代理节点解析仍使用国内 DNS，避免解析链路套娃。
  assert.strictEqual(output.dns["respect-rules"], true);
  assert(output.dns.nameserver.every(function (server) {
    return server.indexOf("#" + EXPECTED.aiGroupName) > 0;
  }), "默认 DNS 应固定经 AI Agent，避免未知海外域名使用国内递归 DNS");
  assert.deepEqual(output.dns["proxy-server-nameserver"], [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query"
  ]);
  assert.deepEqual(output.dns["direct-nameserver"], output.dns["proxy-server-nameserver"]);
  assert(output.dns.fallback.every(function (server) {
    return server.indexOf("#" + EXPECTED.aiGroupName) > 0;
  }), "海外 fallback DNS 应固定经 AI Agent");
  assert.deepEqual(
    output.dns["nameserver-policy"]["geosite:cn"],
    output.dns["direct-nameserver"]
  );
  assert(output.dns["nameserver-policy"]["geosite:geolocation-!cn"].every(function (server) {
    return server.indexOf("#" + EXPECTED.aiGroupName) > 0;
  }), "海外 nameserver-policy 应固定经 AI Agent");
  assert.deepEqual(
    output.dns["nameserver-policy"]["geosite:gfw"],
    output.dns["nameserver-policy"]["geosite:geolocation-!cn"]
  );
  ["geosite:google-deepmind", "geosite:google"].forEach(function (policyKey) {
    assert(output.dns["nameserver-policy"][policyKey].every(function (server) {
      return server.indexOf("#" + EXPECTED.aiGroupName) > 0;
    }), policyKey + " 的 DNS 应与 Google 账号出口一致");
  });
  ["geosite:youtube", "geosite:google-play", "geosite:googlefcm"].forEach(function (policyKey) {
    assert(output.dns["nameserver-policy"][policyKey].every(function (server) {
      return server.indexOf("#" + EXPECTED.mediaGroupName) > 0;
    }), policyKey + " 的 DNS 应跟随对应媒体出口");
  });
  assert.strictEqual(output.dns["fallback-filter"].geosite, undefined,
    "已迁移到 nameserver-policy 后不应继续使用即将废弃的 fallback-filter.geosite");
  assert.deepEqual(
    output.tun["dns-hijack"],
    ["any:53", "tcp://any:53"],
    "TUN 应同时劫持 UDP 与 TCP 的 53 端口 DNS 请求"
  );

  [3478, 5349, 19302].forEach(function (port) {
    assertRuleExists(output.rules, webRtcUdpRejectRule(port));
  });

  // Tailscale 自身和 Tailnet 地址进入隐藏监控组，组内默认直连，避免 Exit Node / DERP / WireGuard 套娃
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled.exe," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,IPNExtension," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,io.tailscale.ipn.macsys.network-extension," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.100.100.100/32," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR6,fd7a:115c:a1e0::/48," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ts.net," + EXPECTED.tailnetDirectGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.com," + EXPECTED.tailscaleControlGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.io," + EXPECTED.tailscaleControlGroupName);
  assert(output.dns["fake-ip-filter"].indexOf("+.ts.net") >= 0,
    "MagicDNS 域名必须排除 Fake-IP，交给系统 scoped resolver 解析");
  assert.strictEqual(output.dns["nameserver-policy"]["+.ts.net"], undefined,
    "Mihomo 不应将 MagicDNS 域名转发给任何上游 DNS");
  assert(output.dns["fallback-filter"].domain.indexOf("+.ts.net") < 0,
    "MagicDNS 域名不应进入海外 fallback DNS");

  const tailnetGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailnetDirectGroupName; });
  const tsControlGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleControlGroupName; });
  const tsProcessGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleProcessGroupName; });
  assertSingleProxy(tailnetGroup, "DIRECT", "Tailnet 内部地址默认仍直连");
  assertSingleProxy(tsControlGroup, "DIRECT", "Tailscale 控制面默认仍直连");
  assertSingleProxy(tsProcessGroup, "DIRECT", "Tailscale 进程默认仍直连");
  assertHiddenGroup(tailnetGroup, "Tailnet 内部直连监控组");
  assertHiddenGroup(tsControlGroup, "Tailscale 控制面监控组");
  assertHiddenGroup(tsProcessGroup, "Tailscale 进程监控组");

  // 无重复规则
  assertNoDuplicateRuleIdentities(output.rules);
}

function testIpv6IsDisabledByDefault() {
  [undefined, false, true].forEach(function (subscriptionIpv6) {
    const { output } = runMain(function (config) {
      config.ipv6 = subscriptionIpv6;
      config.dns = { ipv6: true };
    });
    assert.strictEqual(output.ipv6, false, "默认应关闭全局 IPv6，即使订阅原先开启");
    assert.strictEqual(output.dns.ipv6, false, "默认应同时关闭 DNS IPv6");
  });
}

function testIpv6CanBeEnabled() {
  const { output } = runMain(function (config) {
    config.ipv6 = false;
    config.dns = { ipv6: false };
  }, function (sandbox) {
    sandbox.USER_OPTIONS.enableIPv6 = true;
  });
  assert.strictEqual(output.ipv6, true, "用户开启 IPv6 后应覆盖订阅的关闭设置");
  assert.strictEqual(output.dns.ipv6, true, "用户开启 IPv6 后 DNS 应同步开启");
}

function testIpv6OptionAppliesWithoutSubscription() {
  [false, true].forEach(function (enableIPv6) {
    const config = createEmptyConfig();
    config._homeProxy = Object.assign({}, TEST_HOME_CREDENTIALS);
    config.ipv6 = !enableIPv6;
    const { output } = runMainWithConfig(config, function (sandbox) {
      sandbox.USER_OPTIONS.enableIPv6 = enableIPv6;
    });
    assert.strictEqual(output.ipv6, enableIPv6, "无订阅家宽模式应遵循 IPv6 开关");
    assert.strictEqual(output.dns.ipv6, enableIPv6, "无订阅模式的 DNS 应同步遵循 IPv6 开关");
  });
}

function testTunDnsHijackPreservesExistingEntries() {
  const { output } = runMain(function (config) {
    config.tun = {
      enable: true,
      "dns-hijack": ["udp://10.0.0.53:53"]
    };
  });

  assert.deepEqual(
    output.tun["dns-hijack"],
    ["udp://10.0.0.53:53", "any:53", "tcp://any:53"],
    "DNS 劫持补齐不应删除用户已有的 TUN 劫持项"
  );
}

function testNoCredentialPureOverwrite() {
  // 不配置 _homeProxy 时不抛错，纯分流模式
  const { output } = runMain(function (config) { delete config._homeProxy; });

  // 无家宽IP节点
  const homeNode = output.proxies.find(function (p) { return p.name === "家宽IP"; });
  assert(!homeNode, "纯分流模式不应注入家宽IP节点");

  // 无家宽出口组
  const chainGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.chainGroupName; });
  assert(!chainGroup, "纯分流模式不应创建家宽出口组");

  // 功能组仍正常存在
  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  [
    EXPECTED.generalEgressGroupName,
    EXPECTED.japanServicesGroupName,
    "🐙 GitHub",
    "📲 Telegram",
    "🌍 国际媒体",
    "🎮 游戏平台",
    "🍎 Apple",
    "🎯 直连"
  ].forEach(function (name) {
    assert(groupNames.indexOf(name) >= 0, name + " 组应存在");
  });

  // 无家宽时仍创建 AI Agent，并允许在组内精确选择订阅裸节点
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup, "无家宽时 AI Agent 组也应存在");
  assert.strictEqual(aiGroup.type, "select");
  assert(aiGroup.proxies.indexOf("节点选择") >= 0, "无家宽时 AI Agent 应包含节点选择");
  assert(aiGroup.proxies.indexOf(EXPECTED.relayGroupName) < 0, "无家宽时 AI Agent 不应直接包含自动选择");
  assert(aiGroup.proxies.indexOf("🇭🇰|香港") >= 0, "无家宽时 AI Agent 应包含地区组");
  assert(aiGroup.proxies.indexOf("🇸🇬 SG Auto 01") >= 0, "无家宽时 AI Agent 应包含订阅裸节点");
  assert(aiGroup.proxies.indexOf(EXPECTED.chainGroupName) < 0, "无家宽时 AI Agent 不应包含家宽IP");

  // 无家宽时 AI 进程规则也指向 AI Agent
  assertRuleExists(output.rules, "PROCESS-NAME,Claude," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.net.coffee," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipip.net,DIRECT");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,🔗 前置");
  assert(output.rules.indexOf("DOMAIN-SUFFIX,ip.sb,🔗 前置") < output.rules.indexOf("GEOSITE,cn,🇨🇳 国内"),
    "ip.sb 必须先于 GeoSite cn 命中 🔗 前置");

  // 域名规则正常
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com,🌍 国际媒体");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,microsoft.com," + EXPECTED.microsoftGroupName);
  assertTransportAwareFallbackRules(output.rules);

  const microsoftGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.microsoftGroupName; });
  assert(microsoftGroup, "微软服务组应存在");
  assert.strictEqual(microsoftGroup.proxies[0], "DIRECT", "微软服务默认应走直连");
}

function testAiQuicRejectCanBeDisabled() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.rejectAiQuic = false;
  });
  assert.deepStrictEqual(Array.from(output.rules.filter(function (rule) {
    return rule.indexOf("AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,") === 0;
  })), EXPECTED_NETWORK_PROBES.filter(([, role]) => role !== "direct").map(([domain]) => aiQuicRejectRule(domain)),
  "关闭 AI QUIC 保护后只保留独立的检测站保护");
  assertRulesMissing(output.rules, [googleGeositeQuicRejectRule()]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,openai.com," + EXPECTED.aiGroupName);
}

function testAppStoreQuicRejectCanBeDisabled() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.rejectAppStoreQuic = false;
  });
  assertRulesMissing(output.rules, [appStoreQuicRejectRule()]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,apple.com,🍎 Apple");
}

function testGoogleTrafficConsistencyCanBeDisabled() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.googleTrafficConsistency = false;
  });
  assertRulesMissing(output.rules, [
    "GEOSITE,google-deepmind," + EXPECTED.aiGroupName,
    "GEOSITE,youtube," + EXPECTED.mediaGroupName,
    "GEOSITE,google-play," + EXPECTED.mediaGroupName,
    "GEOSITE,googlefcm," + EXPECTED.fullProtocolFallbackGroupName,
    googleGeositeQuicRejectRule(),
    "GEOSITE,google," + EXPECTED.aiGroupName
  ]);
  assert.strictEqual(output.dns["nameserver-policy"]["geosite:google"], undefined,
    "关闭 Google 统一出口后不应注入 Google GEOSITE DNS 策略");
  assertTransportAwareDomainRules(output.rules, "google.com", "节点选择");
}

function testFullProtocolFallbackCanBeDisabled() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.fullProtocolFallback = false;
  });
  assert(!output["proxy-groups"].find(function (group) {
    return group.name === EXPECTED.fullProtocolFallbackGroupName;
  }), "关闭 fullProtocolFallback 后不应创建全协议回退组");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com,节点选择");
  assertRuleExists(output.rules, "GEOSITE,googlefcm," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, googlePlayMtalkRule(EXPECTED.mediaGroupName));
  assertRuleExists(output.rules, FALLBACK_MATCH);
  assertRulesMissing(output.rules, [
    tcp443DomainRule("google.com", "节点选择"),
    "MATCH," + EXPECTED.fullProtocolFallbackGroupName
  ]);
}

function testFullProtocolFallbackRequiresExplicitUdp() {
  const { output } = runMain(function (config) {
    delete config.proxies[1].udp;
    config.proxies[2].udp = false;
  }, function (sandbox) { sandbox.USER_OPTIONS.frontGroup = false; });
  const fallbackGroup = output["proxy-groups"].find(function (group) {
    return group.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert(fallbackGroup, "至少一个显式 UDP 节点时应创建全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇸🇬 SG Auto 01") >= 0,
    "明确 udp: true 的订阅节点应进入全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇯🇵 JP Auto 01") >= 0,
    "明确 udp: true 的订阅节点应进入全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇭🇰 HK Auto 01") < 0,
    "未声明 udp 的订阅节点不应被推断为全协议节点");
  assert(fallbackGroup.proxies.indexOf("🇺🇸 US Auto 01") < 0,
    "udp: false 的订阅节点不应进入全协议回退组");
}

function testHttpFrontProxyExcludesChainedSubscriptionFromFallback() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
    config._frontProxy = { name: "HTTP 前置代理", type: "http", server: "10.0.0.8", port: 8080 };
  });
  const frontNode = output.proxies.find(function (proxy) { return proxy.name === "HTTP 前置代理"; });
  const fallbackGroup = output["proxy-groups"].find(function (group) {
    return group.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert.strictEqual(frontNode.udp, false, "HTTP 前置代理不应声明 UDP 能力");
  assert.strictEqual(fallbackGroup, undefined,
    "所有订阅节点经 HTTP 前置代理时不应创建全协议回退组");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,gstatic.com,节点选择");
  assertRuleExists(output.rules, FALLBACK_MATCH);
}

function testFullProtocolFallbackChecksDialerProxyGroupsRecursively() {
  const config = createBaseConfig();
  config.proxies[0]["dialer-proxy"] = "自动选择(Smart Group)";
  config.proxies[1]["dialer-proxy"] = "HTTP 末跳";
  config.proxies[2]["dialer-proxy"] = "循环跳板 A";
  config.proxies.push(
    { name: "UDP 中继", type: "socks5", server: "10.0.0.11", port: 1080, udp: true, "dialer-proxy": "UDP 末跳" },
    { name: "UDP 末跳", type: "socks5", server: "10.0.0.12", port: 1080, udp: true },
    { name: "HTTP 末跳", type: "http", server: "10.0.0.13", port: 8080, udp: false },
    { name: "循环跳板 A", type: "socks5", server: "10.0.0.14", port: 1080, udp: true, "dialer-proxy": "循环跳板 B" },
    { name: "循环跳板 B", type: "socks5", server: "10.0.0.15", port: 1080, udp: true, "dialer-proxy": "循环跳板 A" }
  );
  config["proxy-groups"][1].proxies = ["UDP 中继"];
  const sandbox = loadSandbox();
  const fallbackNames = sandbox.collectFullProtocolProxyNames(config, config.proxies.map(function (proxy) {
    return proxy.name;
  }));
  assert(fallbackNames.indexOf("🇸🇬 SG Auto 01") >= 0,
    "经 UDP 策略组和 UDP 多跳链路的节点应进入全协议回退组");
  assert(fallbackNames.indexOf("🇭🇰 HK Auto 01") < 0,
    "经 HTTP 策略组的节点不应进入全协议回退组");
  assert(fallbackNames.indexOf("🇺🇸 US Auto 01") < 0,
    "循环 dialer-proxy 链路不应进入全协议回退组");
}

function testWebRtcUdpRejectCanBeDisabled() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.rejectWebRtcUdp = false;
  });
  [3478, 5349, 19302].forEach(function (port) {
    assertRulesMissing(output.rules, [webRtcUdpRejectRule(port)]);
  });
}

function testOverseasDnsTargetCanBeConfigured() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.overseasDnsTarget = "节点选择";
  });
  [output.dns.nameserver, output.dns.fallback, output.dns["nameserver-policy"]["geosite:geolocation-!cn"]].forEach(function (servers) {
    assert(servers.every(function (server) {
      return server.indexOf("#节点选择") > 0;
    }), "overseasDnsTarget 应控制海外 DNS 的连接出口");
  });
}

function testAuthCredentials() {
  const { output } = runMain(function (config) {
    config._homeProxy = { type: "socks5", server: "5.6.7.8", port: 1080, username: "alice", password: "s3cr3t" };
  });
  const homeNode = output.proxies.find(function (p) { return p.name === "家宽IP"; });
  assert.strictEqual(homeNode.type,     "socks5");
  assert.strictEqual(homeNode.username, "alice");
  assert.strictEqual(homeNode.password, "s3cr3t");
}

function testCustomProxiesAppearInGlobal() {
  // 自定义出口注入到 proxies 后，会通过"节点选择→自动选择→裸节点"间接可达
  // GLOBAL 现在成员是组级别的，与节点选择一致
  const { output } = runMain(function (config) {
    config._customProxies = [
      { name: "自定义出口A", type: "http", server: "10.0.0.1", port: 3128 }
    ];
  });
  // 自定义出口应存在于 proxies 中
  const customHttpNode = output.proxies.find(function (p) { return p.name === "自定义出口A"; });
  assert(customHttpNode, "自定义出口应在 proxies 中");
  assert.strictEqual(customHttpNode.udp, false, "HTTP 自定义出口不应声明 UDP 能力");
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup.proxies.indexOf("自定义出口A") >= 0, "AI Agent 应包含自定义出口");

  // 无名字时自动命名
  const { output: output2 } = runMain(function (config) {
    config._customProxies = [
      { type: "http", server: "10.0.0.1", port: 3128 },
      { type: "socks5", server: "10.0.0.2", port: 1080 }
    ];
  });
  const generatedHttpNode = output2.proxies.find(function (p) { return p.name === "自定义出口1"; });
  const generatedSocksNode = output2.proxies.find(function (p) { return p.name === "自定义出口2"; });
  assert(generatedHttpNode, "第1个应自动命名为 自定义出口1");
  assert(generatedSocksNode, "第2个应自动命名为 自定义出口2");
  assert.strictEqual(generatedHttpNode.udp, false, "自动命名的 HTTP 节点不应声明 UDP 能力");
  assert.strictEqual(generatedSocksNode.udp, false, "未声明 UDP 的 SOCKS5 节点不应被推断为支持 UDP");
}

function testNoCredentialAiAgentIncludesCustomAndRawNodes() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
    config._customProxies = [
      { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 }
    ];
  }, function (sandbox) {
    sandbox.USER_OPTIONS.front = { excludeKeywords: ["公司代理"] };
  });
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup, "无家宽时 AI Agent 组应存在");
  assert(aiGroup.proxies.indexOf("公司代理") >= 0, "无家宽时 AI Agent 应包含自定义出口");
  assert(aiGroup.proxies.indexOf("🇺🇸 US Auto 01") >= 0, "无家宽时 AI Agent 应包含订阅裸节点");

  const companyNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  assert.strictEqual(companyNode.udp, false, "公司 HTTP 代理不应声明 UDP 能力");
  const fallbackGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert(fallbackGroup, "订阅节点应形成全协议回退组");
  assert(fallbackGroup.proxies.indexOf("公司代理") < 0,
    "公司 HTTP 代理不应进入全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇺🇸 US Auto 01") >= 0,
    "支持完整隧道的订阅节点应进入全协议回退组");

  // 3080 实际故障样本：443 仍可走公司代理所在的节点选择，80/993 和 UDP 则进入全协议节点。
  assertTransportAwareDomainRules(output.rules, "gstatic.com", "节点选择");
  assertTransportAwareDomainRules(output.rules, "gmail.com", "节点选择");
  assertTransportAwareFallbackRules(output.rules);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,chatgpt.com," + EXPECTED.aiGroupName);
  assertRulesMissing(output.rules, [
    "DOMAIN-SUFFIX,chatgpt.com," + EXPECTED.fullProtocolFallbackGroupName
  ]);
}

function testDedicatedCustomProxyOnlyAppearsInExplicitRuleGroup() {
  const { output } = runMain(function (config) {
    config._customProxies = [
      {
        name: "公司代理",
        scope: "dedicated",
        type: "http",
        server: "192.168.88.10",
        port: 3456
      },
      {
        name: "普通备用出口",
        type: "socks5",
        server: "203.0.113.20",
        port: 1080
      }
    ];
    config._customRuleGroups = [
      {
        name: "公司内网",
        proxies: ["公司代理"],
        rules: [
          "DOMAIN-SUFFIX,gxatek.com",
          { type: "IP-CIDR", value: "10.0.0.0/8", option: "no-resolve" }
        ]
      }
    ];
  });

  assert(output.proxies.find(function (p) { return p.name === "公司代理"; }),
    "专用公司代理节点应被注入");
  assert(output.proxies.find(function (p) { return p.name === "普通备用出口"; }),
    "普通自定义出口应继续被注入");

  const companyGroup = output["proxy-groups"].find(function (g) { return g.name === "公司内网"; });
  assert(companyGroup, "公司内网规则组应存在");
  assert(companyGroup.proxies.indexOf("公司代理") >= 0, "公司内网规则组应引用专用节点");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,gxatek.com,公司内网");
  assertRuleExists(output.rules, "IP-CIDR,10.0.0.0/8,公司内网,no-resolve");
  assert(output.rules.indexOf("IP-CIDR,192.168.88.10/32,DIRECT,no-resolve") <
      output.rules.indexOf("IP-CIDR,10.0.0.0/8,公司内网,no-resolve"),
    "专用代理服务器直连规则必须优先于公司内网的宽网段规则");

  output["proxy-groups"].forEach(function (group) {
    if (group.name === "公司内网") return;
    assert(group.proxies.indexOf("公司代理") < 0,
      "专用公司代理不应进入通用组：" + group.name);
  });

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(nodeSelGroup.proxies.indexOf("普通备用出口") >= 0,
    "普通自定义出口应保持向后兼容，继续进入节点选择");
  assert(aiGroup.proxies.indexOf("普通备用出口") >= 0,
    "普通自定义出口应保持向后兼容，继续进入 AI Agent");
}

function testDedicatedBooleanPreservesScopeBehavior() {
  function render(fields) {
    const { output } = runMain(function (config) {
      config._customProxies = [Object.assign({
        name: "测试出口", type: "socks5", server: "203.0.113.25", port: 1080, udp: true
      }, fields)];
      config._customRuleGroups = [{
        name: "测试业务", proxies: ["测试出口"], rules: ["DOMAIN-SUFFIX,private.example"]
      }];
    });
    return JSON.parse(JSON.stringify(output));
  }

  const dedicatedOutput = render({ scope: "dedicated" });
  [{ dedicated: true }, { dedicated: true, scope: "dedicated" }].forEach(function (fields) {
    assert.deepStrictEqual(render(fields), dedicatedOutput, "布尔专用配置应与旧 scope 生成相同结果");
  });
  const ordinaryOutput = render({});
  [{ dedicated: false }, { scope: "ordinary" }, { dedicated: false, scope: "ordinary" }].forEach(function (fields) {
    assert.deepStrictEqual(render(fields), ordinaryOutput, "false 和旧 ordinary 应保持默认普通出口行为");
  });
  dedicatedOutput["proxy-groups"].forEach(function (group) {
    if (group.name !== "测试业务") assert(!group.proxies.includes("测试出口"), "专用节点不能进入 " + group.name);
  });
  assert(findGroup(ordinaryOutput, "节点选择").proxies.includes("测试出口"));
  [dedicatedOutput, ordinaryOutput].forEach(function (output) {
    assert(output.proxies.every(function (proxy) { return !("dedicated" in proxy) && !("scope" in proxy); }),
      "新旧管理字段不能进入最终节点或前置副本");
  });
}

function testDedicatedBooleanRejectsInvalidOrConflictingValues() {
  function render(fields) {
    return runMain(function (config) {
      config._customProxies = [Object.assign({
        name: "测试出口", type: "http", server: "203.0.113.25", port: 8080
      }, fields)];
    });
  }
  ["true", "false", 0, 1, null, {}, []].forEach(function (value) {
    assert.throws(function () { render({ dedicated: value }); }, /dedicated 必须为布尔值/);
  });
  [
    { dedicated: false, scope: "dedicated" },
    { dedicated: true, scope: "ordinary" }
  ].forEach(function (fields) {
    assert.throws(function () { render(fields); }, /dedicated 与 scope 配置冲突/);
  });
  assert.throws(function () { render({ dedicated: true, scope: "invalid" }); }, /scope 无效/);
  assert.throws(function () { render({ dedicated: true }); }, /未被 .*引用/,
    "布尔专用节点仍需明确用途，不能静默进入通用候选");
}

function testCustomRuleGroupsCannotOverrideProtectedRules() {
  const protectedCases = [
    {
      rule: "DOMAIN-SUFFIX,muse.ai",
      identity: "DOMAIN-SUFFIX,muse.ai"
    },
    {
      rule: "DOMAIN,ai.developer.meta.com",
      identity: "DOMAIN,ai.developer.meta.com"
    },
    {
      rule: "DOMAIN-SUFFIX,chatgpt.com",
      identity: "DOMAIN-SUFFIX,chatgpt.com"
    },
    {
      rule: { type: "PROCESS-NAME", value: "Codex (Service)" },
      identity: "PROCESS-NAME,Codex (Service)"
    },
    {
      rule: { type: "GEOSITE", value: "google" },
      identity: "GEOSITE,google"
    },
    {
      rule: { type: "IP-CIDR", value: "100.64.0.0/10", option: "no-resolve" },
      identity: "IP-CIDR,100.64.0.0/10"
    },
    {
      rule: { type: "AND", value: "((NETWORK,udp),(DST-PORT,3478))" },
      identity: "AND,((NETWORK,udp),(DST-PORT,3478))"
    },
    {
      rule: { type: "AND", value: "((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,ip.sb))" },
      identity: "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,ip.sb))"
    }
  ];

  EXPECTED_NETWORK_PROBES.forEach(([domain, role]) => {
    const identity = "DOMAIN-SUFFIX," + domain;
    protectedCases.push({ rule: identity, identity });
    if (role !== "direct") {
      const value = "((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX," + domain + "))";
      protectedCases.push({ rule: { type: "AND", value }, identity: "AND," + value });
    }
  });

  protectedCases.forEach(function (testCase) {
    assert.throws(function () {
      runMain(function (config) {
        config._customRuleGroups = [{
          name: "冲突业务组",
          rules: [testCase.rule]
        }];
      });
    }, function (error) {
      return error.message.indexOf("自定义规则与受保护") >= 0 &&
        error.message.indexOf(testCase.identity) >= 0;
    }, "自定义规则不得覆盖受保护规则：" + testCase.identity);
  });

  const { output } = runMain(function (config) {
    config._customRuleGroups = [{
      name: "普通共享服务",
      rules: ["DOMAIN-SUFFIX,sentry.io"]
    }];
  });
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,sentry.io,普通共享服务");
}

function testDedicatedCustomProxyMustBeReferenced() {
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [
        {
          name: "未使用公司代理",
          scope: "dedicated",
          type: "http",
          server: "192.168.88.10",
          port: 3456
        }
      ];
    });
  }, /未被 _customRuleGroups\.proxies.*allowAsFront.*引用/);
}

function testDedicatedCustomProxyRejectsNameCollisions() {
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [
        {
          name: "🇺🇸 US Auto 01",
          scope: "dedicated",
          type: "http",
          server: "192.168.88.10",
          port: 3456
        }
      ];
      config._customRuleGroups = [
        {
          name: "公司内网",
          proxies: ["🇺🇸 US Auto 01"],
          rules: ["DOMAIN-SUFFIX,example.corp"]
        }
      ];
    });
  }, /与已有节点或策略组重名/);

  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [
        {
          name: "公司内网",
          scope: "dedicated",
          type: "http",
          server: "192.168.88.10",
          port: 3456
        }
      ];
      config._customRuleGroups = [
        {
          name: "公司内网",
          proxies: ["公司内网"],
          rules: ["DOMAIN-SUFFIX,example.corp"]
        }
      ];
    });
  }, /与已有节点或策略组重名/);

  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [
        { name: "重复出口", type: "http", server: "10.0.0.1", port: 3128 },
        { name: "重复出口", type: "http", server: "10.0.0.2", port: 3128 }
      ];
    });
  }, /自定义出口名称重复/);
}

function testFrontProxyAppliesToSubscriptionAndOrdinaryNodes() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
    config._frontProxy = { name: "一级前置代理", type: "socks5", server: "10.0.0.8", port: 1080 };
    config._customProxies = [
      { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 }
    ];
  });

  const frontNode = output.proxies.find(function (p) { return p.name === "一级前置代理"; });
  assert.strictEqual(findGroup(output, "🔗 前置").proxies[0], "一级前置代理", "配置前置代理时 🔗 前置 默认选它");
  assert(frontNode, "前置代理节点应被注入");
  assert.strictEqual(frontNode.udp, false, "未声明 UDP 的 SOCKS5 前置代理不应被推断为支持 UDP");

  ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01"].forEach(function (name) {
    const node = output.proxies.find(function (p) { return p.name === name; });
    assert.strictEqual(node["dialer-proxy"], "🔗 前置", name + " 应先走 🔗 前置（默认选中前置代理节点）");
  });

  const customNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  assert.strictEqual(customNode["dialer-proxy"], "🔗 前置", "普通自定义出口默认跟随前置组");
  assert.strictEqual(customNode.udp, false, "HTTP 自定义出口不应声明 UDP 能力");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应作为最终出口出现在节点选择");

  const globalGroup = output["proxy-groups"].find(function (g) { return g.name === "GLOBAL"; });
  assert(globalGroup.proxies.indexOf("一级前置代理") >= 0, "前置代理应出现在 GLOBAL 中供全局模式选择");
  assert(globalGroup.proxies.indexOf("一级前置代理") < globalGroup.proxies.indexOf("DIRECT"),
    "前置代理应放在 GLOBAL 的 DIRECT 前面");

  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应作为最终出口出现在 AI Agent");

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.net.coffee," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipip.net,DIRECT");
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,ipip.net,一级前置代理"]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,🔗 前置");
}

function testFrontProxyDoesNotOverrideHomeProxyDialer() {
  const { output } = runMain(function (config) {
    config._frontProxy = { name: "一级前置代理", type: "socks5", server: "10.0.0.8", port: 1080 };
  });

  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "家宽IP真直连节点不应被前置代理覆盖");

  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert.strictEqual(homeChainedNode["dialer-proxy"], "🔗 家宽跳板", "家宽IP链式应继续走家宽跳板");

  const subNode = output.proxies.find(function (p) { return p.name === "🇺🇸 US Auto 01"; });
  assert.strictEqual(subNode["dialer-proxy"], "🔗 前置", "订阅节点应走 🔗 前置");
}

function testStandaloneCustomProxiesWithoutSubscription() {
  const config = createEmptyConfig();
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 },
    { name: "美国固定IP", type: "socks5", server: "20.0.0.1", port: 1080, udp: true }
  ];
  const { output } = runMainWithConfig(config);

  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  assert(groupNames.indexOf("自动选择") < 0, "无订阅模式不应自建自动选择组");
  assert(groupNames.indexOf("🇺🇸|美国") < 0, "无订阅模式不应生成地区组");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup, "无订阅模式应创建节点选择");
  assert(nodeSelGroup.proxies.indexOf("公司代理") >= 0, "节点选择应包含公司代理");
  assert(nodeSelGroup.proxies.indexOf("美国固定IP") >= 0, "节点选择应包含美国固定IP");
  assert(nodeSelGroup.proxies.indexOf("DIRECT") >= 0, "节点选择应包含 DIRECT");

  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup, "无订阅模式应创建 AI Agent");
  assert(aiGroup.proxies.indexOf("公司代理") >= 0, "AI Agent 应包含自定义节点");
  assert(aiGroup.proxies.indexOf("美国固定IP") >= 0, "AI Agent 应包含固定 IP 节点");
  assert(aiGroup.proxies.indexOf("自动选择") < 0, "AI Agent 不应包含自动选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.net.coffee," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertTransportAwareFallbackRules(output.rules);

  const companyNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  const fixedIpNode = output.proxies.find(function (p) { return p.name === "美国固定IP"; });
  assert.strictEqual(companyNode.udp, false, "HTTP 公司代理不应声明 UDP 能力");
  assert.strictEqual(fixedIpNode.udp, true, "明确 udp: true 的 SOCKS5 固定 IP 节点应保留 UDP 能力");
  const fallbackGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert(!fallbackGroup, "前置可切到 HTTP 时，SOCKS5 原节点不能保证整条链路支持 UDP");
  const udpOnly = createEmptyConfig();
  udpOnly._customProxies = [{ name: "UDP出口", type: "socks5", server: "203.0.113.2", port: 1080, udp: true }];
  const udpOutput = runMainWithConfig(udpOnly).output;
  assert.deepStrictEqual(Array.from(findGroup(udpOutput, EXPECTED.fullProtocolFallbackGroupName).proxies), ["UDP出口"],
    "全链路都支持 UDP 时仍应保留全协议回退，不放入前置副本");
}

function testCustomRuleGroupsRouteOnlyMatchedDomains() {
  const { output } = runMain(function (config) {
    config._customRuleGroups = [
      {
        name: "自定义业务",
        testUrl: "http://service.example.test/health",
        proxy: { name: "自定义业务节点", type: "socks5", server: "127.0.0.1", port: 10880 },
        rules: [
          "DOMAIN,service.example.test",
          { type: "DOMAIN-SUFFIX", value: "internal.example.test" },
          { type: "DOMAIN-SUFFIX", value: "github.com" }
        ]
      }
    ];
  });

  const customNode = output.proxies.find(function (p) { return p.name === "自定义业务节点"; });
  assert(customNode, "自定义规则组应能注入专用节点");
  assert.strictEqual(customNode.type, "socks5");
  assert.strictEqual(customNode.server, "127.0.0.1");
  assert.strictEqual(customNode.port, 10880);

  const customGroup = output["proxy-groups"].find(function (g) { return g.name === "自定义业务"; });
  assert(customGroup, "应创建自定义规则组");
  assert.strictEqual(customGroup.type, "select");
  assert.strictEqual(customGroup.url, "http://service.example.test/health",
    "自定义规则组应支持 testUrl 覆盖全局测速地址");
  assert(customGroup.proxies.indexOf("自定义业务节点") >= 0, "自定义规则组应包含专用节点");
  assert(customGroup.proxies.indexOf("DIRECT") >= 0, "自定义规则组应保留 DIRECT 兜底");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup.proxies.indexOf("自定义业务节点") < 0,
    "自定义规则组节点不应默认进入节点选择");
  assertRuleExists(output.rules, "DOMAIN,service.example.test,自定义业务");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,internal.example.test,自定义业务");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,自定义业务");
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,github.com,🐙 GitHub"]);
}

function testProbeUrlsAreSplitByGroupPurpose() {
  const { output } = runMain(function (config) {
    config._customRuleGroups = [
      {
        name: "本机直连业务",
        proxies: ["DIRECT"],
        rules: ["DOMAIN-SUFFIX,local.example.test"]
      }
    ];
  });

  const autoGroup = output["proxy-groups"].find(function (g) {
    return g.name === "自动选择" || g.name === "自动选择(Smart Group)";
  });
  const hkGroup = output["proxy-groups"].find(function (g) { return g.name === "🇭🇰|香港"; });
  const customGroup = output["proxy-groups"].find(function (g) { return g.name === "本机直连业务"; });
  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  const globalGroup = output["proxy-groups"].find(function (g) { return g.name === "GLOBAL"; });
  const chainGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.chainGroupName; });
  const githubGroup = output["proxy-groups"].find(function (g) { return g.name === "🐙 GitHub"; });
  const appleGroup = output["proxy-groups"].find(function (g) { return g.name === "🍎 Apple"; });
  const directGroup = output["proxy-groups"].find(function (g) { return g.name === "🎯 直连"; });
  const relayGroup = output["proxy-groups"].find(function (g) { return g.name === "🔗 家宽跳板"; });
  const tailnetGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailnetDirectGroupName; });

  assert.strictEqual(autoGroup.url, "https://www.gstatic.com/generate_204",
    "自动选择组应使用代理出海测速地址");
  assert.strictEqual(hkGroup.url, "https://www.gstatic.com/generate_204",
    "地区 url-test 组应使用代理出海测速地址");
  assert.strictEqual(nodeSelGroup.url, "https://www.gstatic.com/generate_204",
    "节点选择应使用代理出海测速地址");
  assert.strictEqual(aiGroup.url, "https://www.gstatic.com/generate_204",
    "AI Agent 应使用代理出海测速地址");
  assert.strictEqual(globalGroup.url, "https://www.gstatic.com/generate_204",
    "GLOBAL 应使用代理出海测速地址");
  assert.strictEqual(chainGroup.url, "https://www.gstatic.com/generate_204",
    "家宽 IP 组应使用代理出海测速地址");
  assert.strictEqual(githubGroup.url, "https://www.gstatic.com/generate_204",
    "代理优先功能组应使用代理出海测速地址");
  assert.strictEqual(relayGroup.url, "https://www.gstatic.com/generate_204",
    "家宽跳板应使用代理出海测速地址");
  assert.strictEqual(appleGroup.url, "http://connect.rom.miui.com/generate_204",
    "直连优先功能组应使用国内健康检查地址");
  assert.strictEqual(directGroup.url, "http://connect.rom.miui.com/generate_204",
    "直连组应使用国内健康检查地址");
  assert.strictEqual(tailnetGroup.url, "http://connect.rom.miui.com/generate_204",
    "Tailscale 监控组应使用国内健康检查地址");
  assert.strictEqual(customGroup.url, "http://connect.rom.miui.com/generate_204",
    "自定义规则组未设置 testUrl 时应继承直连/界面健康检查地址");
}

function testStandaloneCustomRuleGroupsWithoutSubscription() {
  const config = createEmptyConfig();
  config._customRuleGroups = [
    {
      name: "自定义业务",
      proxies: ["DIRECT"],
      rules: ["DOMAIN-SUFFIX,internal.example.test"]
    }
  ];
  const { output } = runMainWithConfig(config);

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup, "只有自定义规则组时仍应创建基础节点选择");
  assert(nodeSelGroup.proxies.indexOf("DIRECT") >= 0, "基础节点选择应保留 DIRECT");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,internal.example.test,自定义业务");
  assertRuleExists(output.rules, FALLBACK_MATCH);
}

function testStandaloneHomeOnlyWithoutSubscription() {
  const config = createEmptyConfig();
  config._homeProxy = { type: "http", server: "30.0.0.1", port: 3128 };
  const { output } = runMainWithConfig(config);

  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert(homeNode, "无订阅固定 IP 模式应注入家宽IP节点");
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "没有可用跳板时家宽IP不应绑定 dialer-proxy");

  const relayGroup = output["proxy-groups"].find(function (g) { return g.name === "🔗 家宽跳板"; });
  assert(!relayGroup, "没有订阅和自定义跳板时不应创建家宽跳板");

  const chainGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.chainGroupName; });
  assert(chainGroup, "无订阅固定 IP 模式应创建家宽IP组");
  assertSingleProxy(chainGroup, EXPECTED.homeNodeName, "没有跳板时家宽IP组只应包含真直连节点");

  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert(!homeChainedNode, "没有可用跳板时不应创建家宽IP链式节点");

  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert.strictEqual(aiGroup.proxies[0], EXPECTED.chainGroupName, "固定 IP 应优先出现在 AI Agent");
}

function testStandaloneCustomNodesFollowFrontGroup() {
  const config = createEmptyConfig();
  config._frontProxy = { name: "一级前置代理", type: "socks5", server: "10.0.0.8", port: 1080 };
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 },
    { name: "上游节点", type: "socks5", server: "10.0.0.10", port: 1080, useFrontProxy: true }
  ];
  const { output } = runMainWithConfig(config);

  const normalNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  const chainedNode = output.proxies.find(function (p) { return p.name === "上游节点"; });
  assert.strictEqual(normalNode["dialer-proxy"], "🔗 前置", "普通自定义节点默认跟随前置组，无需额外开关");
  assert.strictEqual(chainedNode["dialer-proxy"], "🔗 前置", "声明 useFrontProxy 的自定义节点应走 🔗 前置");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应进入节点选择");
}

function testTailnetCustomProxyServerBypassesTunRoute() {
  const config = createEmptyConfig();
  config._customProxies = [
    { name: "公司代理", type: "http", server: "192.168.88.10", port: 3456, interfaceName: "utun4" },
    { name: "公网代理", type: "http", server: "8.8.8.8", port: 8080 }
  ];
  const { output } = runMainWithConfig(config);
  const routeExcludes = output.tun && output.tun["route-exclude-address"];
  const companyNode = output.proxies.find(function (p) { return p.name === "公司代理"; });

  assert(routeExcludes, "Tailnet/private 自定义节点服务器应生成 tun.route-exclude-address");
  assert(routeExcludes.indexOf("192.168.88.10/32") >= 0,
    "作为自定义节点服务器的 Tailnet/private IP 应绕过 TUN，避免节点测速自拨被虚拟网卡截获");
  assert(routeExcludes.indexOf("8.8.8.8/32") < 0, "公网自定义节点服务器不应自动绕过 TUN");
  assert.strictEqual(companyNode["interface-name"], "utun4",
    "Tailnet 自定义节点应支持按节点绑定 Tailscale 出口接口");
}

function testProxyServerAddressesUseDirectRules() {
  const config = createBaseConfig();
  config.proxies = config.proxies.concat([
    { name: "上游IP节点", type: "http", server: "203.0.113.10", port: 443 },
    { name: "上游域名节点", type: "http", server: "edge.example.com", port: 443 }
  ]);
  const { output } = runMainWithConfig(config);

  assertRuleExists(output.rules, "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,edge.example.com,DIRECT");
  const infoConfig = createBaseConfig();
  infoConfig.proxies = infoConfig.proxies.concat([
    { name: "官网地址 - https://example.test", type: "ss", server: "www.baidu.com", port: 80, cipher: "aes-128-gcm", password: "x" },
    { name: "🇺🇸 Real", type: "ss", server: "entry.example.net", port: 8388, cipher: "aes-128-gcm", password: "x" },
    { name: "剩余流量：10GB", type: "ss", server: "entry.example.net", port: 8389, cipher: "aes-128-gcm", password: "x" }
  ]);
  const info = runMainWithConfig(infoConfig).output;
  assertRulesMissing(info.rules, ["DOMAIN-SUFFIX,www.baidu.com,DIRECT"]);
  assertRuleExists(info.rules, "DOMAIN-SUFFIX,entry.example.net,DIRECT");
  assert(output.rules.indexOf("IP-CIDR,203.0.113.10/32,DIRECT,no-resolve") <
      output.rules.indexOf(FALLBACK_MATCH),
    "代理服务器直连规则应在兜底规则之前");
}

function testHostnameProxyServerResolvedIpsUseDirectRules() {
  const config = createBaseConfig();
  config.proxies.push({ name: "上游域名节点", type: "http", server: "edge.example.com", port: 443 });
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.proxyServerResolvedIps = {
      "edge.example.com": ["203.0.113.11", "2001:db8::11"]
    };
  });

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,edge.example.com,DIRECT");
  assertRuleExists(output.rules, "IP-CIDR,203.0.113.11/32,DIRECT,no-resolve");
  assertRuleExists(output.rules, "IP-CIDR6,2001:db8::11/128,DIRECT,no-resolve");
}

function testTailscaleProcessRulesTakePriorityOverWebRtcReject() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  });
  assert(output.rules.indexOf("PROCESS-NAME,tailscaled,🧩 Tailscale 进程,no-resolve") <
      output.rules.indexOf(webRtcUdpRejectRule(3478)),
    "Tailscale 进程规则必须优先于通用 STUN UDP 拒绝规则");
}

function testTailnetDestinationRulesTakePriorityOverFullProtocolFallback() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.subnetCidrs = ["192.168.88.0/24", "fd00:abcd::/64"];
  });
  const fallbackIndex = output.rules.indexOf(FALLBACK_MATCH);
  [
    "IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48," + EXPECTED.tailnetDirectGroupName + ",no-resolve",
    "IP-CIDR,192.168.88.0/24," + EXPECTED.tailnetDirectGroupName + ",no-resolve",
    "IP-CIDR6,fd00:abcd::/64," + EXPECTED.tailnetDirectGroupName + ",no-resolve"
  ].forEach(function (rule) {
    assert(output.rules.indexOf(rule) >= 0 && output.rules.indexOf(rule) < fallbackIndex,
      "Tailnet 目的地址规则必须优先于全协议回退：" + rule);
  });
}

function testProxyServerDirectRulesCanBeDisabled() {
  const config = createBaseConfig();
  config.proxies = config.proxies.concat([
    { name: "上游IP节点", type: "http", server: "203.0.113.10", port: 443 }
  ]);
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.directProxyServerRules = false;
  });

  assertRulesMissing(output.rules, ["IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"]);
}

function testTailnetExistingProxyServerBypassesTunRoute() {
  const config = createEmptyConfig();
  config.proxies = [
    { name: "公司代理", type: "http", server: "192.168.88.10", port: 3456 },
    { name: "公网代理", type: "http", server: "8.8.8.8", port: 8080 }
  ];
  const { output } = runMainWithConfig(config);
  const routeExcludes = output.tun && output.tun["route-exclude-address"];

  assert(routeExcludes, "已有代理节点中的 Tailnet/private server 也应生成 tun.route-exclude-address");
  assert(routeExcludes.indexOf("192.168.88.10/32") >= 0,
    "最终配置内已有的 Tailnet/private 代理服务器应绕过 TUN");
  assert(routeExcludes.indexOf("8.8.8.8/32") < 0, "最终配置内已有的公网代理服务器不应自动绕过 TUN");
}

function testTunRouteExcludesAreMergedAndConfigurable() {
  const config = createEmptyConfig();
  config.tun = { enable: true, "route-exclude-address": ["192.168.88.10/32"] };
  config._frontProxy = { name: "一级前置代理", type: "http", server: "192.168.88.10", port: 3456 };
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.166.0.10", port: 8080 }
  ];
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.routeExcludeCidrs = ["10.168.100.0/24"];
  });
  const routeExcludes = output.tun["route-exclude-address"];

  assert.strictEqual(routeExcludes.filter(function (cidr) { return cidr === "192.168.88.10/32"; }).length, 1,
    "已有 TUN 排除项应保留且去重");
  assert(routeExcludes.indexOf("10.166.0.10/32") >= 0, "新增私网自定义节点服务器应追加到 TUN 排除");
  assert(routeExcludes.indexOf("10.168.100.0/24") >= 0, "用户手工配置的 routeExcludeCidrs 应追加到 TUN 排除");
}

function testTailscaleCgnatRangeBypassesTunByDefault() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  });
  const routeExcludes = output.tun && output.tun["route-exclude-address"];

  assert(routeExcludes, "默认配置应生成 tun.route-exclude-address");
  assert(routeExcludes.indexOf("100.64.0.0/10") >= 0,
    "默认应将整个 Tailscale CGNAT 网段排除出 Clash TUN，避免 Tailnet 地址被 utun1500 截获");
  assert(routeExcludes.indexOf("100.100.100.100/32") >= 0,
    "默认应将 Tailscale MagicDNS 地址排除出 Clash TUN，避免 dns-hijack 截获 scoped resolver 查询");
}

function testTailscaleRulesAreConfigurableAndExitNodeUsesNormalRules() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.controlPlaneTarget = "节点选择";
    sandbox.USER_OPTIONS.tailscale.processTarget = "节点选择";
  });

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.com," + EXPECTED.tailscaleControlGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.io," + EXPECTED.tailscaleControlGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,Tailscale," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assert(output.rules.indexOf("SRC-IP-CIDR,100.64.0.0/10,节点选择,no-resolve") < 0,
    "默认不应提前截获 Tailscale Exit Node 转发流量");

  const tsControlGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleControlGroupName; });
  const tsProcessGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleProcessGroupName; });
  assertSingleProxy(tsControlGroup, "节点选择", "控制面监控组应指向用户配置的目标");
  assertSingleProxy(tsProcessGroup, "节点选择", "进程监控组应指向用户配置的目标");
  assertHiddenGroup(tsControlGroup, "控制面监控组");
  assertHiddenGroup(tsProcessGroup, "进程监控组");
}

function testTailscaleExitNodeCanBeForced() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.forceExitNodeTraffic = true;
    sandbox.USER_OPTIONS.tailscale.forceExitNodeTrafficTarget = "节点选择";
  });

  const directIndex = output.rules.indexOf("IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  const forcedIndex = output.rules.indexOf("SRC-IP-CIDR,100.64.0.0/10," + EXPECTED.tailscaleExitGroupName + ",no-resolve");
  assert(directIndex >= 0, "Tailnet 目的地址直连规则应存在");
  assert(forcedIndex >= 0, "开启后应写入 Exit Node 转发强制出口规则");
  assert(directIndex < forcedIndex, "Tailnet 目的地址直连规则应早于 Exit Node 强制出口规则");

  const tsExitGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleExitGroupName; });
  assertSingleProxy(tsExitGroup, "节点选择", "Exit Node 强制出口监控组应指向用户配置目标");
  assertHiddenGroup(tsExitGroup, "Exit Node 强制出口监控组");
}

function testTailscaleMonitorGroupsCanBeDisabled() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.monitorGroups = false;
    sandbox.USER_OPTIONS.tailscale.controlPlaneTarget = "节点选择";
    sandbox.USER_OPTIONS.tailscale.processTarget = "节点选择";
  });

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.com,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.io,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ts.net,DIRECT");
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled,节点选择,no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve");
  assert(!output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleControlGroupName; }),
    "关闭 monitorGroups 后不应创建 Tailscale 控制面监控组");
}

function testTailscaleSubnetCidrsAreVisibleInTailnetGroup() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.subnetCidrs = ["192.168.88.0/24", "fd00:abcd::/64"];
  });

  assertRuleExists(output.rules, "IP-CIDR,192.168.88.0/24," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR6,fd00:abcd::/64," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
}

function testTailscaleMonitorGroupsCanBeShownForDebugging() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.hideMonitorGroups = false;
  });

  const tailnetGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailnetDirectGroupName; });
  const tsControlGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleControlGroupName; });
  const tsProcessGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.tailscaleProcessGroupName; });
  assert.strictEqual(tailnetGroup.hidden, undefined, "关闭隐藏开关后 Tailnet 监控组应可见");
  assert.strictEqual(tsControlGroup.hidden, undefined, "关闭隐藏开关后控制面监控组应可见");
  assert.strictEqual(tsProcessGroup.hidden, undefined, "关闭隐藏开关后进程监控组应可见");
}

function testStandaloneEmptyConfigFailsLoudly() {
  assert.throws(function () {
    runMainWithConfig(createEmptyConfig());
  }, /未检测到订阅节点/);
}

function testFallbackToUrlTestGroup() {
  // 没有 Smart Group，但有原始 url-test 组 → 应回退使用 url-test
  const { output } = runMain(function (config) {
    config["proxy-groups"] = config["proxy-groups"].map(function (g) {
      if (g.name === "自动选择(Smart Group)") {
        return { name: "自动选择", type: "url-test", proxies: g.proxies, url: "http://cp.cloudflare.com", interval: 300 };
      }
      return g;
    });
  });
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "回退时家宽IP真直连节点不应挂 dialer-proxy");
  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert.strictEqual(homeChainedNode["dialer-proxy"], "🔗 家宽跳板", "回退时家宽IP链式应指向家宽跳板组");
}

function testAutoCreateUrlTestGroup() {
  // Smart Group 和 url-test 都不存在 → 应自建 url-test
  const { output } = runMain(function (config) {
    config.proxies.push({ name: "剩余流量：48.35% 298.19GB", type: "ss" });
    config["proxy-groups"] = config["proxy-groups"].filter(function (g) {
      return g.name !== "自动选择(Smart Group)" && g.name !== "自动选择";
    });
  });
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "自建时家宽IP真直连节点不应挂 dialer-proxy");
  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert.strictEqual(homeChainedNode["dialer-proxy"], "🔗 家宽跳板", "自建时家宽IP链式应指向家宽跳板组");
  const autoGroup = output["proxy-groups"].find(function (g) { return g.name === "自动选择"; });
  assert(autoGroup, "自动选择组应被自动创建");
  assert.strictEqual(autoGroup.type, "url-test");
  assert.strictEqual(autoGroup.url, "https://www.gstatic.com/generate_204",
    "自动创建的测速组应使用代理出海测速地址");
  assert(autoGroup.proxies.length > 0, "自建组应包含订阅节点");
  assert(autoGroup.proxies.indexOf("剩余流量：48.35% 298.19GB") < 0,
    "自建自动选择组也应过滤订阅状态信息节点");
}

function testAutoSelectFiltersSubscriptionInfoNodes() {
  const infoNodeNames = [
    "官网地址 - https://hitun.io",
    "🌈 剩余流量：48.35% 298.19GB",
    "🌈 套餐时间：2026-07-19",
    "🌈 A应急续费使用 | 到期后可用5天"
  ];
  const { output } = runMain(function (config) {
    for (let i = 0; i < infoNodeNames.length; i++) {
      config.proxies.push({ name: infoNodeNames[i], type: "ss" });
    }
    const autoGroup = config["proxy-groups"].find(function (g) {
      return g.name === EXPECTED.relayGroupName;
    });
    autoGroup.proxies = autoGroup.proxies.concat(infoNodeNames);
    config.proxies.push({ name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 });
    autoGroup.proxies.push("公司代理");
  });

  const autoGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.relayGroupName;
  });
  const nodeSelGroup = output["proxy-groups"].find(function (g) {
    return g.name === "节点选择";
  });

  for (let i = 0; i < infoNodeNames.length; i++) {
    assert(output.proxies.find(function (p) { return p.name === infoNodeNames[i]; }),
      "信息节点仍应保留在订阅节点中: " + infoNodeNames[i]);
    assert(nodeSelGroup.proxies.indexOf(infoNodeNames[i]) >= 0,
      "信息节点仍应保留在节点选择中用于查看订阅状态: " + infoNodeNames[i]);
    assert(autoGroup.proxies.indexOf(infoNodeNames[i]) < 0,
      "信息节点不应进入自动选择测速组: " + infoNodeNames[i]);
  }
  assert(autoGroup.proxies.indexOf("🇸🇬 SG Auto 01") >= 0, "真实节点应保留在自动选择中");
  assert(nodeSelGroup.proxies.indexOf("公司代理") >= 0,
    "公司代理应保留在节点选择中供手动使用");
  assert(autoGroup.proxies.indexOf("公司代理") < 0,
    "公司代理不应进入自动选择测速组");
}

// ─── location profiles ──────────────────────────────────────────────────────

const DOMESTIC_GROUP = "🇨🇳 国内";
const DOMESTIC_EXIT  = { name: "阿里云回国", scope: "dedicated", type: "socks5", server: "198.51.100.20", port: 1080, udp: true };

function runOverseas(configMutator, optionMutator) {
  return runMain(function (config) {
    config._customProxies = [Object.assign({}, DOMESTIC_EXIT)];
    if (typeof configMutator === "function") configMutator(config);
  }, function (sandbox) {
    sandbox.USER_OPTIONS.location = "overseas";
    sandbox.USER_OPTIONS.domesticExit = [DOMESTIC_EXIT.name];
    if (typeof optionMutator === "function") optionMutator(sandbox);
  });
}

function findGroup(output, name) {
  return output["proxy-groups"].find(function (g) { return g.name === name; });
}

function testLocationDefaultsToCn() {
  const { sandbox, output } = runMain();
  assert.strictEqual(sandbox.USER_OPTIONS.location, "cn");
  assertRuleExists(output.rules, "GEOSITE,cn,🇨🇳 国内");
  assertRuleExists(output.rules, "GEOIP,cn,🇨🇳 国内");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,rivotek.com,🇨🇳 国内");
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,feishu.net,🇨🇳 国内"]);
  assert.deepStrictEqual(Array.from(findGroup(output, DOMESTIC_GROUP).proxies), ["DIRECT", "节点选择"], "cn 下 🇨🇳 国内 默认 DIRECT");
  assertRuleExists(output.rules, "GEOSITE,cn," + DOMESTIC_GROUP);
  assert.deepStrictEqual(Array.from(output.dns["default-nameserver"]), ["223.5.5.5", "119.29.29.29"]);
  assert.strictEqual(output.dns["fallback-filter"]["geoip-code"], "CN");
  assert.strictEqual(findGroup(output, "🎯 直连").url, "http://connect.rom.miui.com/generate_204");
  assert.deepStrictEqual(Array.from(findGroup(output, EXPECTED.chainGroupName).proxies),
    [EXPECTED.homeChainedNodeName, EXPECTED.homeNodeName], "cn 下家宽组默认先选链式");
  assertRuleExists(output.rules, FALLBACK_MATCH);
  assert.deepStrictEqual(Array.from(findGroup(output, "🐟 兜底").proxies),
    [DOMESTIC_GROUP, EXPECTED.generalEgressGroupName, EXPECTED.fullProtocolFallbackGroupName]);
}

function testCnIgnoresDomesticExit() {
  // cn 下 domesticExit 作为 🇨🇳 国内 的手动候选，默认仍 DIRECT。
  const { output } = runMain(function (config) {
    config._customProxies = [Object.assign({}, DOMESTIC_EXIT)];
  }, function (sandbox) {
    sandbox.USER_OPTIONS.domesticExit = [DOMESTIC_EXIT.name];
  });
  assert.deepStrictEqual(Array.from(findGroup(output, DOMESTIC_GROUP).proxies), ["DIRECT", DOMESTIC_EXIT.name, "节点选择"]);
}

function testOverseasRoutesDomesticTrafficToReturnGroup() {
  const { output } = runOverseas();
  const domesticGroup = findGroup(output, DOMESTIC_GROUP);
  assert(domesticGroup, "overseas 应创建回国组");
  assert.deepStrictEqual(Array.from(domesticGroup.proxies), [DOMESTIC_EXIT.name, "DIRECT", "节点选择"]);
  assert.strictEqual(domesticGroup.url, "http://connect.rom.miui.com/generate_204", "回国组应使用国内测速地址");
  assertRuleExists(output.rules, "GEOSITE,cn," + DOMESTIC_GROUP);
  assertRuleExists(output.rules, "GEOIP,cn," + DOMESTIC_GROUP);
  assertRulesMissing(output.rules, ["GEOSITE,cn,DIRECT", "GEOIP,cn,DIRECT,no-resolve"]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,rivotek.com," + DOMESTIC_GROUP);
  assertRulesMissing(output.rules, [
    "DOMAIN-SUFFIX,feishu.net," + DOMESTIC_GROUP,
    "DOMAIN-SUFFIX,dingtalkapps.com," + DOMESTIC_GROUP
  ]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,typeless.com,DIRECT");
  // 回国节点服务器本身必须直连，否则会自我代理。
  assertRuleExists(output.rules, "IP-CIDR,198.51.100.20/32,DIRECT,no-resolve");
  assert(output.rules.indexOf("IP-CIDR,198.51.100.20/32,DIRECT,no-resolve") <
    output.rules.indexOf("GEOIP,cn," + DOMESTIC_GROUP));
  // dedicated 回国节点不能进入通用出口。
  ["节点选择", "GLOBAL", EXPECTED.aiGroupName, "🔗 家宽跳板", EXPECTED.mediaGroupName].forEach(function (name) {
    const group = findGroup(output, name);
    if (!group) return;
    assert(group.proxies.indexOf(DOMESTIC_EXIT.name) < 0, name + " 不应包含回国节点");
  });
  // AI 与 Tailscale 边界不变。
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.com," + EXPECTED.tailscaleControlGroupName);
  assertNoDuplicateRuleIdentities(output.rules);
}

function testOverseasDefaultsPreferDirectEgress() {
  const { output } = runOverseas();
  assert.deepStrictEqual(Array.from(findGroup(output, EXPECTED.generalEgressGroupName).proxies).slice(0, 2), ["DIRECT", "节点选择"]);
  assert.deepStrictEqual(Array.from(findGroup(output, "🐟 兜底").proxies), [EXPECTED.generalEgressGroupName, DOMESTIC_GROUP]);
  assert.strictEqual(findGroup(output, EXPECTED.mediaGroupName).proxies[0], "DIRECT");
  assert.strictEqual(findGroup(output, "🐙 GitHub").proxies[0], "DIRECT");
  assert.notStrictEqual(findGroup(output, EXPECTED.japanServicesGroupName).proxies[0], "DIRECT",
    "指定地区的功能组仍应优先地区节点");
  assert.deepStrictEqual(Array.from(findGroup(output, EXPECTED.chainGroupName).proxies),
    [EXPECTED.homeNodeName, EXPECTED.homeChainedNodeName], "overseas 下家宽组默认先选真直连");
  assert(!findGroup(output, EXPECTED.fullProtocolFallbackGroupName), "overseas 默认关闭全协议回退");
  assertRuleExists(output.rules, FALLBACK_MATCH);
  assert.strictEqual(findGroup(output, "🎯 直连").url, "http://cp.cloudflare.com/generate_204");
}

function testOverseasDnsProfile() {
  const { output } = runOverseas();
  const dns = output.dns;
  const policy = dns["nameserver-policy"];
  assert.deepStrictEqual(Array.from(dns["default-nameserver"]), ["1.1.1.1", "8.8.8.8"]);
  assert(!dns.fallback && !dns["fallback-filter"], "overseas 不需要 CN GeoIP fallback");
  assert(dns.nameserver.every(function (s) { return /#DIRECT$/.test(s); }), "未知域名本机直连解析");
  assert(policy["geosite:cn"].every(function (s) { return s.indexOf("#" + DOMESTIC_GROUP) > 0; }), "国内域名经回国组解析");
  assert(policy["+.rivotek.com"].every(function (s) { return s.indexOf("#" + DOMESTIC_GROUP) > 0; }));
  assert(!policy["+.feishu.net"], "feishu.net 已由 geosite:cn 覆盖，不再单独写 DNS policy");
  assert(policy["+.apple.com"].every(function (s) { return /#DIRECT$/.test(s); }), "直连功能组用本地 DNS");
  assert(policy["geosite:openai"].every(function (s) { return s.indexOf("#" + EXPECTED.aiGroupName) > 0; }), "AI DNS 仍随 AI Agent");
  [].concat(dns["proxy-server-nameserver"], dns["direct-nameserver"]).forEach(function (s) {
    assert(s.indexOf("alidns") < 0 && s.indexOf("doh.pub") < 0, "overseas 直连 DNS 不应使用国内 DoH: " + s);
  });
}

function testOverseasWithoutDomesticExitFallsBackToDirect() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.location = "overseas";
  });
  assert.deepStrictEqual(Array.from(findGroup(output, DOMESTIC_GROUP).proxies), ["DIRECT", "节点选择"]);
  assertRuleExists(output.rules, "GEOSITE,cn," + DOMESTIC_GROUP);
}

function testOverseasStandaloneBoxProfile() {
  // 美国云主机：无订阅，只有家宽 IP + 阿里云回国。
  const config = createEmptyConfig();
  config._homeProxy = { type: "http", server: "203.0.113.10", port: 8080, username: "u", password: "p" };
  config._customProxies = [Object.assign({}, DOMESTIC_EXIT)];
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.location = "overseas";
    sandbox.USER_OPTIONS.domesticExit = [DOMESTIC_EXIT.name];
  });
  assert.deepStrictEqual(Array.from(findGroup(output, EXPECTED.chainGroupName).proxies), [EXPECTED.homeNodeName]);
  assert.strictEqual(findGroup(output, EXPECTED.aiGroupName).proxies[0], EXPECTED.chainGroupName);
  assert.strictEqual(findGroup(output, EXPECTED.generalEgressGroupName).proxies[0], "DIRECT");
  assertRuleExists(output.rules, "GEOSITE,cn," + DOMESTIC_GROUP);
  assert.strictEqual(output.rules[output.rules.length - 1], FALLBACK_MATCH);
}

function testOverseasExplicitOptionsWin() {
  const { output } = runOverseas(null, function (sandbox) {
    sandbox.USER_OPTIONS.urlTestProbeUrl = "http://probe.example.test/generate_204";
    sandbox.USER_OPTIONS.fullProtocolFallback = true;
  });
  assert.strictEqual(findGroup(output, "🎯 直连").url, "http://probe.example.test/generate_204");
  assert(findGroup(output, EXPECTED.fullProtocolFallbackGroupName), "显式开启时应保留全协议回退");
}

function testLocationValidation() {
  assert.throws(function () {
    runMain(null, function (sandbox) { sandbox.USER_OPTIONS.location = "mars"; });
  }, /location 无效/);
  assert.throws(function () {
    runMain(null, function (sandbox) {
      sandbox.USER_OPTIONS.location = "overseas";
      sandbox.USER_OPTIONS.domesticExit = ["不存在的回国节点"];
    });
  }, /domesticExit 引用的节点或策略组不存在/);
  assert.throws(function () {
    runOverseas(function (config) {
      config._customRuleGroups = [{ name: "抢回国规则", proxies: ["DIRECT"], rules: ["DOMAIN-SUFFIX,tailscale.com"] }];
    });
  }, /受保护的基础路由/, "location 不应放松受保护规则检查");
}

function testLocationRejectsInvalidValues() {
  ["constructor", "toString", "__proto__", "", null, false, 17, [], {}].forEach(function (location) {
    assert.throws(function () {
      runMain(null, function (sandbox) { sandbox.USER_OPTIONS.location = location; });
    }, /location 无效/, "仅允许明确的 cn 或 overseas");
  });
  const { output } = runMain(null, function (sandbox) { delete sandbox.USER_OPTIONS.location; });
  assertRuleExists(output.rules, "GEOSITE,cn,🇨🇳 国内");
}

function testDomesticExitNormalizesCandidates() {
  const { output } = runOverseas(null, function (sandbox) {
    sandbox.USER_OPTIONS.domesticExit = ["DIRECT", " " + DOMESTIC_EXIT.name + " ", "DIRECT", DOMESTIC_EXIT.name];
  });
  assert.deepStrictEqual(Array.from(findGroup(output, DOMESTIC_GROUP).proxies), [DOMESTIC_EXIT.name, "DIRECT", "节点选择"]);
  const { output: single } = runOverseas(null, function (sandbox) {
    sandbox.USER_OPTIONS.domesticExit = DOMESTIC_EXIT.name;
  });
  assert.deepStrictEqual(Array.from(findGroup(single, DOMESTIC_GROUP).proxies), [DOMESTIC_EXIT.name, "DIRECT", "节点选择"]);
}

function testDomesticExitRejectsInvalidValues() {
  [17, {}, false, [""], ["  "], [null], [17], [["节点选择"]]].forEach(function (domesticExit) {
    assert.throws(function () {
      runMain(null, function (sandbox) {
        sandbox.USER_OPTIONS.location = "overseas";
        sandbox.USER_OPTIONS.domesticExit = domesticExit;
      });
    }, /domesticExit/, "无效的候选应在生成前指出字段");
  });
}

function testDomesticExitAllowsForwardReferences() {
  const choices = ["🇭🇰|香港", EXPECTED.chainGroupName, EXPECTED.aiGroupName, "🔗 家宽跳板"];
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.location = "overseas";
    sandbox.USER_OPTIONS.domesticExit = choices;
  });
  assert.deepStrictEqual(Array.from(findGroup(output, DOMESTIC_GROUP).proxies), choices.concat("DIRECT", "节点选择"));
  const { output: custom } = runOverseas(function (config) {
    config._customRuleGroups = [{ name: "回国业务", proxies: [DOMESTIC_EXIT.name], rules: [] }];
  }, function (sandbox) { sandbox.USER_OPTIONS.domesticExit = ["回国业务"]; });
  assert.deepStrictEqual(Array.from(findGroup(custom, DOMESTIC_GROUP).proxies), ["回国业务", "DIRECT", "节点选择"]);
}

// 普通节点默认经前置组，候选只解除自动绑定，不改变显式 via。
function testFrontGroup() {
  const { output } = runMain(function (config) {
    config._customProxies = [
      { name: "公司", type: "http", server: "198.51.100.41", port: 3128 },
      { name: "经前置", type: "socks5", server: "198.51.100.42", port: 1080, useFrontProxy: true },
      { name: "指定", type: "http", server: "198.51.100.43", port: 8080, via: "公司" }
    ];
  });
  const byName = function (n) { return output.proxies.find(function (p) { return p.name === n; }); };
  const front = findGroup(output, "🔗 前置");
  assert.deepStrictEqual(Array.from(front.proxies).slice(0, 3), ["DIRECT", "⤴ 公司", "⤴ 经前置"],
    "候选只解除脚本自动添加的前置，不绕过显式 via");
  assert(front.proxies.indexOf("⤴ 指定") < 0, "显式 via 节点不能生成绕过上游的前置副本");
  assert(front.proxies.indexOf("⤴ 🇸🇬 SG Auto 01") >= 0);
  assert.strictEqual(byName("经前置")["dialer-proxy"], "🔗 前置");
  assert.strictEqual(byName("指定")["dialer-proxy"], "公司", "via 应覆盖默认前置");
  assert(!("via" in byName("指定")), "via 不应进入节点");
  assert.strictEqual(byName("公司")["dialer-proxy"], "🔗 前置", "普通自定义节点默认跟随前置组");
  assert.strictEqual(byName("⤴ 公司")["dialer-proxy"], undefined, "前置副本自身不挂前置（防循环）");
  assert.strictEqual(byName(EXPECTED.homeNodeName)["dialer-proxy"], undefined, "家宽IP 不挂前置");
  assert.strictEqual(byName(EXPECTED.homeChainedNodeName)["dialer-proxy"], "🔗 家宽跳板", "家宽链式仍走家宽跳板");
  assert(!findGroup(output, EXPECTED.fullProtocolFallbackGroupName),
    "可手动切换到 HTTP 前置的订阅节点不能保证完整链路的 UDP 能力");

  const { output: withFront } = runMain(function (config) {
    config._frontProxy = { name: "一级前置", type: "socks5", server: "198.51.100.50", port: 1080, udp: true };
  });
  assert.deepStrictEqual(Array.from(findGroup(withFront, "🔗 前置").proxies).slice(0, 2), ["一级前置", "DIRECT"],
    "配置 _frontProxy（旧 前置代理.js 开启）时它排第一");

  const { output: filtered } = runMain(function (config) {
    config.proxies[0].port = 443;
    config.proxies.push({ name: "🇺🇸 Game US | 遊戲專用", type: "ss", udp: true, port: 8388 });
  }, function (sandbox) {
    sandbox.USER_OPTIONS.front = { excludePorts: [80, 443], excludeKeywords: ["遊戲專用"], prefer: ["US Auto"] };
  });
  const fp = findGroup(filtered, "🔗 前置").proxies;
  assert.strictEqual(fp[1], "⤴ 🇺🇸 US Auto 01", "prefer 命中的副本排在 DIRECT 之后");
  assert(fp.indexOf("⤴ 🇸🇬 SG Auto 01") < 0, "excludePorts 的节点不生成副本");
  assert(fp.every(function (n) { return n.indexOf("遊戲專用") < 0; }), "excludeKeywords 生效");

  const { output: legacy } = runMain(function (config) {
    config._frontProxy = { name: "一级前置", type: "socks5", server: "198.51.100.50", port: 1080 };
  }, function (sandbox) { sandbox.USER_OPTIONS.frontGroup = false; });
  assert(!findGroup(legacy, "🔗 前置"), "frontGroup=false 不生成 🔗 前置");
  assert.strictEqual(legacy.proxies.find(function (p) { return p.name === "🇸🇬 SG Auto 01"; })["dialer-proxy"], "一级前置",
    "frontGroup=false 时沿用旧的单节点前置");
  assertRuleExists(legacy.rules, "DOMAIN-SUFFIX,ip.sb,一级前置");
  assertRuleExists(legacy.rules, "DOMAIN-SUFFIX,ipip.net,DIRECT");
  const { output: noFront } = runMain(null, function (sandbox) { sandbox.USER_OPTIONS.frontGroup = false; });
  assertRuleExists(noFront.rules, "DOMAIN-SUFFIX,ipip.net,DIRECT");
  assertRuleExists(noFront.rules, "DOMAIN-SUFFIX,ip.sb,DIRECT");
}

function testNetworkProbeRoutingAfterSwap() {
  const audit = require("../scripts/rule-routing-audit");
  for (const location of ["cn", "overseas"]) {
    for (const frontGroup of [true, false]) {
      for (const withFront of [true, false]) {
        const { output } = runMain(config => {
          delete config._homeProxy;
          if (withFront) config._frontProxy = { name: "检测前置", type: "socks5", server: "203.0.113.99", port: 1080 };
          config.rules.push("DOMAIN-SUFFIX,ip.sb,DIRECT", "DOMAIN-SUFFIX,ipip.net,节点选择");
        }, sandbox => {
          sandbox.USER_OPTIONS.location = location;
          sandbox.USER_OPTIONS.frontGroup = frontGroup;
          sandbox.USER_OPTIONS.enableChainRegionBrowserProcessProxy = true;
        });
        const frontTarget = frontGroup ? "🔗 前置" : withFront ? "检测前置" : "DIRECT";
        for (const [domain, suffix, target] of [
          ["ip.sb", "ip.sb", frontTarget], ["api.ip.sb", "ip.sb", frontTarget],
          ["ipv4.ip.sb", "ip.sb", frontTarget], ["stat.ip.sb", "ip.sb", frontTarget],
          ["ipip.net", "ipip.net", "DIRECT"], ["www.ipip.net", "ipip.net", "DIRECT"]
        ]) {
          const expectedRule = "DOMAIN-SUFFIX," + suffix + "," + target;
          for (const process of ["chrome.exe", "Clash Party.exe", "codex"]) {
            for (const port of [80, 443]) {
              assert.deepStrictEqual(audit.route(output.rules, { domain, process, port, network: "tcp" }),
                { rule: expectedRule, target }, "检测规则应优先于进程强制代理：" + domain);
            }
            const quicRule = "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,ip.sb)),REJECT";
            assert.deepStrictEqual(audit.route(output.rules, { domain, process, port: 443, network: "udp" }),
              suffix === "ip.sb" ? { rule: quicRule, target: "REJECT" } : { rule: expectedRule, target },
              "IP.SB 的 QUIC 必须拒绝以避免跳过无 UDP 前置，ipip.net 仍直连");
          }
          assert.strictEqual(output.rules.filter(r => r.startsWith("DOMAIN-SUFFIX," + suffix + ",")).length, 1,
            "不能残留交换前的重复检测规则");
        }
      }
    }
  }
}

function testIpSbQuicProtectionIsNarrowAndIndependent() {
  const audit = require("../scripts/rule-routing-audit");
  const guard = "AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,ip.sb)),REJECT";
  const { output } = runMain(config => {
    config._customRuleGroups = [{ name: "自定义测试业务", rules: ["DOMAIN-SUFFIX,example.corp"] }];
  }, sandbox => {
    sandbox.USER_OPTIONS.rejectAiQuic = false;
    sandbox.USER_OPTIONS.rejectAppStoreQuic = false;
  });
  assert.strictEqual(output.rules.filter(r => r === guard).length, 1);
  assert.strictEqual(audit.route(output.rules, { domain: "api.ip.sb", process: "Clash Party.exe", network: "udp", port: 443 }).rule, guard);
  ["example.com", "ip.sb.example.com", "notip.sb", "ipip.net", "api.ipip.net"].forEach(domain => {
    assert.strictEqual(audit.matches(guard, { domain, network: "udp", port: 443 }), false,
      "不能扩大到其他网站的 UDP：" + domain);
  });
  for (const network of ["tcp", "udp"]) {
    for (const port of [53, 80, 443, 8443]) {
      assert.strictEqual(audit.matches(guard, { domain: "api.ip.sb", network, port }), network === "udp" && port === 443);
    }
  }
}

function testNetworkProbeRegistryDrivesAllLayers() {
  const audit = require("../scripts/rule-routing-audit");
  for (const location of ["cn", "overseas"]) {
    for (const frontGroup of [true, false]) {
      for (const withFront of [true, false]) {
        const { output, sandbox } = runMain(config => {
          if (!withFront) delete config._homeProxy;
          if (withFront) config._frontProxy = { name: "检测前置", server: "203.0.113.99", port: 8080 };
          config._customRuleGroups = [{ name: "普通业务", rules: ["DOMAIN-SUFFIX,example.corp"] }];
        }, sandbox => {
          sandbox.USER_OPTIONS.location = location;
          sandbox.USER_OPTIONS.frontGroup = frontGroup;
          sandbox.USER_OPTIONS.enableChainRegionBrowserProcessProxy = true;
          sandbox.USER_OPTIONS.rejectAiQuic = false;
        });
        const targets = { direct: "DIRECT", front: frontGroup ? "🔗 前置" : withFront ? "检测前置" : "DIRECT",
          node: "节点选择", ai: EXPECTED.aiGroupName };
        assert.deepStrictEqual(JSON.parse(JSON.stringify(sandbox.NETWORK_PROBES.map(p => [p.domain, p.target]))),
          EXPECTED_NETWORK_PROBES, "检测站用途保持不变");
        const expectedBlock = EXPECTED_NETWORK_PROBES.filter(([, role]) => role !== "direct")
          .map(([domain]) => aiQuicRejectRule(domain))
          .concat(EXPECTED_NETWORK_PROBES.map(([domain, role]) => "DOMAIN-SUFFIX," + domain + "," + targets[role]));
        const blockStart = output.rules.indexOf(expectedBlock[0]);
        assert(blockStart >= 0);
        assert.deepStrictEqual(Array.from(output.rules.slice(blockStart, blockStart + expectedBlock.length)), expectedBlock,
          "检测规则应保持连续，且自定义业务不能把 AI 进程规则移到检测规则前面");
        for (const [suffix, role] of EXPECTED_NETWORK_PROBES) {
          const target = targets[role];
          const rule = "DOMAIN-SUFFIX," + suffix + "," + target;
          assert.strictEqual(output.rules.filter(r => r.startsWith("DOMAIN-SUFFIX," + suffix + ",")).length, 1);
          for (const domain of [suffix, "api." + suffix]) {
            for (const process of ["chrome.exe", "Clash Party.exe", "codex"]) {
              assert.deepStrictEqual(audit.route(output.rules, { domain, process, network: "tcp", port: 443 }), { rule, target });
              assert.deepStrictEqual(audit.route(output.rules, { domain, process, network: "udp", port: 443 }),
                role === "direct" ? { rule, target } : { rule: aiQuicRejectRule(suffix), target: "REJECT" });
            }
          }
          const servers = target === "DIRECT" && location === "cn" ? sandbox.BASE.dns.domestic : sandbox.BASE.dns.overseas;
          assert.deepStrictEqual(Array.from(output.dns["nameserver-policy"]["+." + suffix]),
            Array.from(sandbox.routeDnsServers(servers, target)), "检测 DNS 跟随观察链路：" + suffix);
          assert(output.sniffer["force-domain"].includes("+." + suffix));
          if (location === "cn") {
            assert.strictEqual(output.dns["fallback-filter"].domain.includes("+." + suffix), role !== "direct");
          }
        }
      }
    }
  }
  const { output } = runMain(null, sandbox => { sandbox.USER_OPTIONS.overseasDnsTarget = "节点选择"; });
  ["ipapi.is", "ip.net.coffee", "ping0.cc", "ipinfo.io"].forEach(domain => {
    assert(output.dns["nameserver-policy"]["+." + domain].every(server => server.endsWith("#节点选择")),
      "AI 检测尊重显式海外 DNS 出口设置");
  });
}

function testNetworkProbeRegistryCanBeMaintainedInOnePlace() {
  const { output } = runMain(null, sandbox => {
    sandbox.NETWORK_PROBES = sandbox.NETWORK_PROBES.filter(p => p.domain !== "ping0.cc");
    sandbox.NETWORK_PROBES.push({ domain: "probe.example", target: "node", purpose: "回归检测", rejectQuic: true });
    sandbox.NETWORK_PROBES.find(p => p.domain === "ipinfo.io").rejectQuic = false;
  });
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,probe.example,节点选择");
  assertRuleExists(output.rules, aiQuicRejectRule("probe.example"));
  assert(output.dns["nameserver-policy"]["+.probe.example"].every(server => server.endsWith("#节点选择")));
  assert(output.sniffer["force-domain"].includes("+.probe.example"));
  assert(output.dns["fallback-filter"].domain.includes("+.probe.example"));
  assert(!JSON.stringify(output).includes("ping0.cc"), "删除清单条目后不能残留旧 AI/DNS/嗅探规则");
  assertRulesMissing(output.rules, [aiQuicRejectRule("ipinfo.io")]);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipinfo.io," + EXPECTED.aiGroupName);
}

function testNetworkProbeRegistryRejectsInvalidEntries() {
  const valid = { domain: "probe.example", target: "node", purpose: "回归检测", rejectQuic: true };
  const invalid = [null, {}, { domain: "https://probe.example" }, { domain: "*.probe.example" },
    { domain: "Probe.example" }, { domain: "probe.example:443" }, { target: "unknown" },
    { purpose: " " }, { rejectQuic: "true" }];
  invalid.forEach(fields => {
    const entry = fields === null || Object.keys(fields).length === 0 ? fields : { ...valid, ...fields };
    assert.throws(() => runMain(null, sandbox => { sandbox.NETWORK_PROBES.push(entry); }), /NETWORK_PROBES/);
  });
  assert.throws(() => runMain(null, sandbox => { sandbox.NETWORK_PROBES = {}; }), /NETWORK_PROBES/);
  for (const domains of [["probe.example", "probe.example"], ["probe.example", "api.probe.example"],
    ["api.probe.example", "probe.example"]]) {
    assert.throws(() => runMain(null, sandbox => {
      sandbox.NETWORK_PROBES = domains.map(domain => ({ ...valid, domain }));
    }), /后缀重叠/);
  }
}

function testFrontCopiesPreserveExplicitDialersAndAvoidNameCollisions() {
  const { output } = runMain(function (config) {
    config.proxies[0]["dialer-proxy"] = "🇭🇰 HK Auto 01";
    config.proxies.push({ name: "⤴ 🇺🇸 US Auto 01", type: "ss", udp: true });
    config._customRuleGroups = [{ name: "⤴ 🇯🇵 JP Auto 01", proxies: ["DIRECT"], rules: [] }];
  });
  const front = findGroup(output, "🔗 前置");
  assert(front.proxies.indexOf("⤴ 🇸🇬 SG Auto 01") < 0, "订阅原有 dialer-proxy 不能被副本绕过");
  assert.strictEqual(output.proxies.find(function (p) { return p.name === "🇸🇬 SG Auto 01"; })["dialer-proxy"], "🇭🇰 HK Auto 01");
  ["⤴ 🇺🇸 US Auto 01 (2)", "⤴ 🇯🇵 JP Auto 01 (2)"].forEach(function (name) {
    const copy = output.proxies.find(function (p) { return p.name === name; });
    assert(copy && !copy["dialer-proxy"], "副本名称应避开已有节点和策略组：" + name);
    assert(front.proxies.indexOf(name) >= 0);
    assert(findGroup(output, "节点选择").proxies.indexOf(name) < 0);
  });
}

function testDomesticExitCanAlsoBeAnExplicitFrontCandidate() {
  ["cn", "overseas"].forEach(function (location) { [false, true].forEach(function (legacy) {
    const { output } = runMain(function (config) {
      config._customProxies = [{
        name: "共享国内节点", dedicated: true, allowAsFront: legacy ? true : undefined,
        type: "socks5", server: "203.0.113.88", port: 1080, udp: true
      }];
    }, function (sandbox) {
      sandbox.USER_OPTIONS.location = location;
      sandbox.USER_OPTIONS.domesticExit = ["共享国内节点"];
      if (!legacy) sandbox.USER_OPTIONS.front.include = [" 共享国内节点 ", "共享国内节点"];
    });
    const node = output.proxies.filter(function (proxy) { return proxy.name === "共享国内节点"; });
    assert.strictEqual(node.length, 1, "一个物理节点只生成一份凭证配置");
    assert.strictEqual(node[0]["dialer-proxy"], undefined, "共享前置节点必须自行直连拨号");
    assert(!Object.prototype.hasOwnProperty.call(node[0], "allowAsFront"), "角色字段不能进入内核节点配置");
    const domestic = findGroup(output, "🇨🇳 国内");
    const front = findGroup(output, "🔗 前置");
    assert.strictEqual(domestic.proxies[0], location === "cn" ? "DIRECT" : "共享国内节点");
    assert.strictEqual(front.proxies[0], "DIRECT", "允许当前置不等于默认启用它");
    assert.strictEqual(front.proxies.filter(function (name) { return name === "共享国内节点"; }).length, 1);
    ["节点选择", "GLOBAL", "自动选择(Smart Group)", "🤖 AI Agent", "🔗 家宽跳板", "🌍 国际媒体"].forEach(function (name) {
      const group = findGroup(output, name);
      assert(!group || group.proxies.indexOf("共享国内节点") < 0, "不能因当前置而混入 " + name);
    });
  }); });
}

function testOrdinaryFrontDefaultsAndLegacyOptOut() {
  const { output } = runMain(function (config) {
    config._customProxies = [
      { name: "自动前置", type: "socks5", server: "192.168.88.10", port: 1080, udp: true,
        username: "test-user", password: "test-password", interfaceName: "Tailscale", tls: true },
      { name: "旧直连", type: "http", server: "203.0.113.2", port: 8080, useFrontProxy: false },
      { name: "旧前置候选", type: "socks5", server: "203.0.113.3", port: 1080, allowAsFront: true },
      { name: "指定直连", type: "socks5", server: "203.0.113.4", port: 1080, via: "DIRECT" }
    ];
  });
  const proxy = name => output.proxies.find(p => p.name === name);
  assert.strictEqual(proxy("自动前置")["dialer-proxy"], "🔗 前置");
  const original = JSON.parse(JSON.stringify(proxy("自动前置")));
  original.name = "⤴ 自动前置";
  delete original["dialer-proxy"];
  assert.deepStrictEqual(JSON.parse(JSON.stringify(proxy(original.name))), original,
    "前置副本只解除自动绑定，保留认证、接口和协议字段");
  const front = findGroup(output, "🔗 前置");
  assert.strictEqual(front.proxies[0], "DIRECT");
  ["⤴ 自动前置", "旧直连", "旧前置候选", "指定直连"].forEach(name => assert(front.proxies.indexOf(name) >= 0));
  ["旧直连", "旧前置候选"].forEach(name => assert.strictEqual(proxy(name)["dialer-proxy"], undefined));
  assert.strictEqual(proxy("指定直连")["dialer-proxy"], "DIRECT");
  output["proxy-groups"].filter(g => g.name !== "🔗 前置").forEach(g => {
    assert((g.proxies || []).indexOf("⤴ 自动前置") < 0, "副本不能混入 " + g.name);
  });
  assert(output.tun["route-exclude-address"].indexOf("192.168.88.10/32") >= 0);
  assert(output.proxies.every(p => !("useFrontProxy" in p) && !("allowAsFront" in p)));

  [false, true].forEach(withLegacyFront => {
    const result = runMain(function (config) {
      if (withLegacyFront) config._frontProxy = { name: "旧一级", type: "socks5", server: "203.0.113.5", port: 1080 };
      config._customProxies = [{ name: "普通出口", server: "203.0.113.6", port: 8080 }];
    }, sandbox => { sandbox.USER_OPTIONS.frontGroup = false; }).output;
    assert.strictEqual(result.proxies.find(p => p.name === "普通出口")["dialer-proxy"], undefined,
      "禁用前置组时保留旧的普通节点直连行为");
  });
  assert.throws(() => runMain(config => {
    config._customProxies = [{ name: "错误开关", server: "203.0.113.6", port: 8080, useFrontProxy: "false" }];
  }), /useFrontProxy.*布尔/);
  const explicit = runMain(config => {
    config._customProxies = [{ name: "原生上游", server: "203.0.113.6", port: 8080, "dialer-proxy": "🇸🇬 SG Auto 01" }];
  }).output;
  assert.strictEqual(explicit.proxies.find(p => p.name === "原生上游")["dialer-proxy"], "🇸🇬 SG Auto 01");
  assert(!explicit.proxies.some(p => p.name === "⤴ 原生上游"), "原生显式上游也不能被解除");
  assert.throws(() => runMain(config => {
    config._customProxies = [{ name: "冲突上游", server: "203.0.113.6", port: 8080, via: "DIRECT", "dialer-proxy": "🇸🇬 SG Auto 01" }];
  }), /via 与 dialer-proxy 配置冲突/);
}

function testFrontIncludeValidatesCandidates() {
  const { output } = runMain(function (config) {
    config._customProxies = [{ name: "仅前置", dedicated: true, server: "203.0.113.8", port: 8080 }];
  }, function (sandbox) { sandbox.USER_OPTIONS.front.include = ["仅前置", "🇸🇬 SG Auto 01"]; });
  const front = findGroup(output, "🔗 前置");
  assert.strictEqual(front.proxies[0], "DIRECT");
  assert(front.proxies.indexOf("仅前置") >= 0);
  assert.strictEqual(front.proxies.filter(n => n === "⤴ 🇸🇬 SG Auto 01").length, 1);
  output["proxy-groups"].filter(g => g.name !== "🔗 前置").forEach(g => assert((g.proxies || []).indexOf("仅前置") < 0));
  ["wrong-type", null, [""], [" "], [1], ["不存在"], ["节点选择"], ["DIRECT"], ["家宽IP"]].forEach(include => {
    assert.throws(() => runMain(null, s => { s.USER_OPTIONS.front.include = include; }), /front.include/);
  });
  assert.throws(() => runMain(null, s => {
    s.USER_OPTIONS.frontGroup = false;
    s.USER_OPTIONS.front.include = ["🇸🇬 SG Auto 01"];
  }), /front.include.*frontGroup/);
  assert.throws(() => runMain(null, s => {
    s.USER_OPTIONS.front = { include: ["🇸🇬 SG Auto 01"], excludeKeywords: ["SG Auto"] };
  }), /front.include.*排除条件/);
  assert.throws(() => runMain(config => {
    config._customProxies = [{ name: "显式链路", server: "203.0.113.8", port: 8080, via: "🇸🇬 SG Auto 01" }];
  }, s => { s.USER_OPTIONS.front.include = ["显式链路"]; }), /front.include.*显式上游/);
  assert.throws(() => runMain(config => {
    config._customProxies = [{ name: "专用链路", dedicated: true, server: "203.0.113.8", port: 8080, useFrontProxy: true }];
  }, s => { s.USER_OPTIONS.front.include = ["专用链路"]; }), /front.include.*显式上游/);
  assert.throws(() => runMain(config => {
    config._customProxies = [{ name: "原生链路", dedicated: true, server: "203.0.113.8", port: 8080, "dialer-proxy": "🇸🇬 SG Auto 01" }];
  }, s => { s.USER_OPTIONS.front.include = ["原生链路"]; }), /front.include.*显式上游/);
}

function testCombinedCredentialSample() {
  const sample = fs.readFileSync(path.join(repoRoot, "src", "出口IP凭证_样本.js"), "utf8");
  const disabled = {};
  vm.runInNewContext(sample, disabled);
  assert.deepStrictEqual(disabled.main({}), {}, "不启用任何样本时不应注入节点");
  const existing = createBaseConfig();
  const original = JSON.stringify(existing);
  assert.strictEqual(disabled.main(existing), existing);
  assert.strictEqual(JSON.stringify(existing), original, "未启用样本不能覆盖已有配置");
  // Enable only commented code lines, leaving the Chinese instructions and auth hints as comments.
  const enabledCode = sample.replace("// testUrl:", "testUrl:").split(/\r?\n/).map(line => {
    const content = line.replace(/^  \/\/ /, "");
    return /^(config\._|[}\]];| {2,}[a-zA-Z{}\[\],"/])/.test(content) ? content : line;
  }).join("\n");
  const enabled = {};
  vm.runInNewContext(enabledCode, enabled);
  function configuredSample(withSubscription) {
    const config = enabled.main(withSubscription ? createBaseConfig() : createEmptyConfig());
    config._homeProxy.server = "203.0.113.10";
    config._customProxies.forEach((p, i) => { p.server = "203.0.113." + (20 + i); });
    const subnetProxy = config._customProxies.find(p => p.name === "Tailscale子网代理");
    subnetProxy.server = "192.168.88.10";
    subnetProxy.interfaceName = "Tailscale";
    return config;
  }
  for (const withSubscription of [true, false]) {
    for (const location of ["cn", "overseas"]) {
      for (const withLegacyFront of [true, false]) {
        const config = configuredSample(withSubscription);
        assert.strictEqual(config._customProxies.length, 3, "样本中的普通、国内和子网节点应共存而不是相互覆盖");
        assert.strictEqual(config._customRuleGroups.length, 2, "同一文件同时维护代理业务与直连业务");
        if (withLegacyFront) config._frontProxy = { name: "迁入的旧前置", server: "203.0.113.30", port: 1080 };
        const result = runMainWithConfig(config, sandbox => {
          sandbox.USER_OPTIONS.location = location;
          sandbox.USER_OPTIONS.domesticExit = ["阿里云回国"];
          sandbox.USER_OPTIONS.front.include = ["阿里云回国"];
        }).output;
        const front = findGroup(result, "🔗 前置");
        assert.strictEqual(front.proxies[0], withLegacyFront ? "迁入的旧前置" : "DIRECT");
        assert(front.proxies.includes("阿里云回国"));
        assert(front.proxies.includes("⤴ 普通备用出口"));
        assert(findGroup(result, "指定业务").proxies.includes("Tailscale子网代理"));
        assert.strictEqual(findGroup(result, "指定业务").url, "http://connect.rom.miui.com/generate_204");
        assert(findGroup(result, "节点选择").proxies.indexOf("Tailscale子网代理") < 0);
        assert(findGroup(result, "节点选择").proxies.indexOf("本机直连业务") < 0);
        const subnetProxy = result.proxies.find(p => p.name === "Tailscale子网代理");
        assert.strictEqual(subnetProxy["dialer-proxy"], "DIRECT", "子网代理不能跟随前置选择，须通过本机路由连接");
        assert.strictEqual(subnetProxy["interface-name"], "Tailscale");
        assert(result.tun["route-exclude-address"].includes("192.168.88.10/32"));
        assertRuleExists(result.rules, "IP-CIDR,192.168.88.10/32,DIRECT,no-resolve");
        assertRuleExists(result.rules, "DOMAIN,service.example.test,指定业务");
        assertRuleExists(result.rules, "DOMAIN-SUFFIX,internal.example.test,指定业务");
        assertRuleExists(result.rules, "IP-CIDR,198.51.100.0/24,指定业务,no-resolve");
        assertRuleExists(result.rules, "IP-CIDR,10.0.0.0/8,🎯 直连,no-resolve");
        assert(!result.rules.some(rule => /^IP-CIDR,/.test(rule) && rule.includes(",指定业务") &&
          !rule.startsWith("IP-CIDR,198.51.100.0/24,")), "不能把代理所在子网或全部私有网段送入业务代理");
        assertRuleExists(result.rules, "DOMAIN-SUFFIX,local.example.test,本机直连业务");
        assert.strictEqual(findGroup(result, "本机直连业务").proxies[0], "DIRECT");
      }
    }
  }
  const homeOnly = configuredSample(false);
  delete homeOnly._customProxies;
  delete homeOnly._customRuleGroups;
  assert(findGroup(runMainWithConfig(homeOnly).output, EXPECTED.chainGroupName));

  const ordinaryOnly = configuredSample(false);
  delete ordinaryOnly._homeProxy;
  delete ordinaryOnly._customRuleGroups;
  ordinaryOnly._customProxies = ordinaryOnly._customProxies.slice(0, 1);
  assert(findGroup(runMainWithConfig(ordinaryOnly).output, "节点选择").proxies.includes("普通备用出口"));

  const subnetOnly = configuredSample(false);
  delete subnetOnly._homeProxy;
  delete subnetOnly._customRuleGroups;
  subnetOnly._customProxies = subnetOnly._customProxies.filter(p => p.name === "Tailscale子网代理");
  subnetOnly._customProxies[0].dedicated = false;
  const subnetResult = runMainWithConfig(subnetOnly).output;
  assert(findGroup(subnetResult, "节点选择").proxies.includes("Tailscale子网代理"),
    "子网位置不决定用途，改为普通节点后可由通用组选择");
  assert(findGroup(subnetResult, "🔗 前置").proxies.includes("Tailscale子网代理"));
  assert(!subnetResult.proxies.some(p => p.name === "⤴ Tailscale子网代理"), "固定 DIRECT 的节点不需要前置副本");
  assert.strictEqual(subnetResult.proxies.find(p => p.name === "Tailscale子网代理")["dialer-proxy"], "DIRECT");

  const directRulesOnly = configuredSample(false);
  delete directRulesOnly._homeProxy;
  delete directRulesOnly._customProxies;
  directRulesOnly._customRuleGroups = directRulesOnly._customRuleGroups.slice(1);
  assertRuleExists(runMainWithConfig(directRulesOnly).output.rules,
    "DOMAIN-SUFFIX,local.example.test,本机直连业务");
}

function testExplicitFrontCandidatesRejectUnsafeConfiguration() {
  [{ allowAsFront: "true" }, { allowAsFront: true, useFrontProxy: true },
    { allowAsFront: true, via: "节点选择" }].forEach(function (fields) {
    assert.throws(function () {
      runMain(function (config) {
        config._customProxies = [Object.assign({
          name: "共享国内节点", scope: "dedicated", type: "http", server: "203.0.113.88", port: 8080
        }, fields)];
      }, function (sandbox) { sandbox.USER_OPTIONS.domesticExit = ["共享国内节点"]; });
    }, /allowAsFront/, "显式前置必须为布尔配置，且不能再次依赖前置或业务组");
  });
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [{ name: "共享国内节点", scope: "dedicated", allowAsFront: true,
        type: "http", server: "203.0.113.88", port: 8080 }];
    }, function (sandbox) { sandbox.USER_OPTIONS.frontGroup = false; });
  }, /allowAsFront/, "没有前置组时不能静默忽略前置角色");
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [{ name: "共享国内节点", scope: "dedicated", allowAsFront: true,
        type: "http", server: "203.0.113.88", port: 8080 }];
    }, function (sandbox) { sandbox.USER_OPTIONS.front = { excludePorts: [8080] }; });
  }, /allowAsFront.*front/, "显式引用与前置过滤冲突时应指出配置问题");

  const { output } = runMain(function (config) {
    config._customProxies = [{ name: "仅前置", scope: "dedicated", allowAsFront: true,
      type: "http", server: "203.0.113.89", port: 8080 }];
  });
  assert(findGroup(output, "🔗 前置").proxies.indexOf("仅前置") >= 0, "前置角色本身就是 dedicated 的显式引用");
  assert(findGroup(output, "🇨🇳 国内").proxies.indexOf("仅前置") < 0, "前置角色不自动授予国内业务出口角色");
}

function testProxyGraphRejectsCycles() {
  assert.throws(function () {
    runMain(function (config) {
      config._customRuleGroups = [{ name: "回国中转", proxies: [DOMESTIC_GROUP], rules: [] }];
    }, function (sandbox) {
      sandbox.USER_OPTIONS.location = "overseas";
      sandbox.USER_OPTIONS.domesticExit = ["回国中转"];
    });
  }, function (error) {
    const cycle = error.message.split("代理循环引用：")[1];
    if (!cycle) return false;
    const names = cycle.split(" -> ");
    return names.length === 3 && names[0] === names[2] &&
      names.indexOf(DOMESTIC_GROUP) >= 0 && names.indexOf("回国中转") >= 0;
  }, "错误应显示完整循环路径");
  assert.throws(function () {
    runMain(function (config) {
      config._customRuleGroups = [{ name: "自循环业务", proxies: ["自循环业务"], rules: [] }];
    });
  }, /循环引用.*自循环业务.*自循环业务/);
  assert.throws(function () {
    runMain(function (config) {
      config.proxies[0]["dialer-proxy"] = config.proxies[1].name;
      config.proxies[1]["dialer-proxy"] = config.proxies[0].name;
    });
  }, /循环引用.*SG Auto 01.*HK Auto 01.*SG Auto 01/);
  assert.throws(function () {
    runMain(function (config) { config.proxies[0]["dialer-proxy"] = EXPECTED.relayGroupName; });
  }, /循环引用.*SG Auto 01.*Smart Group.*SG Auto 01/, "必须覆盖节点与组混合循环");
}

function testProxyGraphRejectsMissingReferences() {
  assert.throws(function () {
    runMain(function (config) {
      config._customRuleGroups = [{ name: "缺失出口业务", proxies: ["不存在的节点"], rules: [] }];
    });
  }, /引用不存在.*缺失出口业务.*不存在的节点/);
  assert.throws(function () {
    runMain(function (config) { config.proxies[0]["dialer-proxy"] = "不存在的跳板"; });
  }, /引用不存在.*SG Auto 01.*不存在的跳板/);
  assert.throws(function () {
    runMain(function (config) { config["proxy-groups"][1].proxies = ["Ghost Proxy"]; });
  }, /引用不存在.*Smart Group.*Ghost Proxy/);
}

function testProxyNamesCannotBeOverwritten() {
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [{ name: config.proxies[0].name, server: "203.0.113.20", port: 8080 }];
    });
  }, /重名/, "普通自定义出口不能覆盖订阅节点");
  assert.throws(function () {
    runMain(function (config) {
      config._customRuleGroups = [{ name: "内嵌出口业务", proxy: {
        name: config.proxies[0].name, server: "203.0.113.20", port: 8080
      }, rules: [] }];
    });
  }, /重名/, "内嵌出口不能覆盖订阅节点");
  assert.throws(function () {
    runMain(function (config) {
      config.proxies.push({ name: EXPECTED.homeNodeName, type: "socks5" });
    });
  }, /重名/, "注入家宽节点不能覆盖同名订阅节点");
  assert.throws(function () {
    runMain(function (config) { config.proxies.push(Object.assign({}, config.proxies[0])); });
  }, /重名/, "原始订阅中的重名节点也应被拒绝");
}

function testProxyGroupNamesCannotBeOverwritten() {
  ["节点选择", EXPECTED.aiGroupName, "🇭🇰|香港", DOMESTIC_GROUP].forEach(function (name) {
    assert.throws(function () {
      runMain(function (config) {
        config._customRuleGroups = [{ name, proxies: ["DIRECT"], rules: [] }];
      }, function (sandbox) { sandbox.USER_OPTIONS.location = "overseas"; });
    }, /重名/, "自定义组不能覆盖受管组：" + name);
  });
  assert.throws(function () {
    runMain(function (config) {
      config._customRuleGroups = [{ name: "重复业务", rules: [] }, { name: "重复业务", rules: [] }];
    });
  }, /重名/);
  assert.throws(function () {
    runOverseas(function (config) {
      config._customProxies.push({ name: DOMESTIC_GROUP, type: "http", server: "203.0.113.20", port: 8080 });
    });
  }, /重名/, "节点与组使用同一个名字也应被拒绝");
}

function testProxyGraphAllowsSharedReferences() {
  const { output } = runMain(function (config) {
    config._customRuleGroups = [
      { name: "共享出口 A", proxies: ["共享出口 C"], rules: [] },
      { name: "共享出口 B", proxies: ["共享出口 C"], rules: [] },
      { name: "共享出口 C", proxies: ["DIRECT", "REJECT"], rules: [] }
    ];
  });
  assert.deepStrictEqual(Array.from(findGroup(output, "共享出口 A").proxies), ["共享出口 C", "DIRECT"]);
  assert.deepStrictEqual(Array.from(findGroup(output, "共享出口 B").proxies), ["共享出口 C", "DIRECT"]);
}

function testCommunityServiceBoundaries() {
  const audit = require("../scripts/rule-routing-audit");
  const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "rules", "community-sources.json"), "utf8"));
  [true, false].forEach(function (withHome) {
    const { output } = runMain(function (config) {
      if (!withHome) delete config._homeProxy;
    });
    audit.assertRoutingCases(output.rules, manifest.routingCases);
    assertNoDuplicateRuleIdentities(output.rules);
    ["ai.developer.meta.com", "muse.ai", "copilot.cloud.microsoft", "api.githubcopilot.com"].forEach(function (domain) {
      assert.strictEqual(audit.route(output.rules, { domain: domain, network: "tcp", port: 443 }).target, EXPECTED.aiGroupName);
      assert.strictEqual(audit.route(output.rules, { domain: domain, network: "udp", port: 3478 }).target, "REJECT",
        "社区 AI 路由不能跳过既有的 WebRTC STUN 防泄漏规则");
    });
    ["accounts.youtube.com", "accounts.google.com"].forEach(function (domain) {
      assert.strictEqual(audit.route(output.rules, { domain: domain, network: "tcp", port: 443 }).target, EXPECTED.aiGroupName);
    });
  });
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.googleTrafficConsistency = false;
  });
  audit.assertRoutingCases(output.rules, manifest.routingCases);
  audit.assertRoutingCases(runOverseas().output.rules, manifest.routingCases);
}

function testCommunityExactDomainsAndSharedServices() {
  const { output } = runMain();
  const audit = require("../scripts/rule-routing-audit");
  assertRuleExists(output.rules, "DOMAIN,ai.developer.meta.com," + EXPECTED.aiGroupName);
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,ai.developer.meta.com," + EXPECTED.aiGroupName]);
  assert.strictEqual(audit.route(output.rules, {
    domain: "unrelated.ai.developer.meta.com", network: "tcp", port: 443
  }).target, EXPECTED.mediaGroupName, "精确 API 规则不得扩展到未知子域名");
  assert(output.dns["nameserver-policy"]["ai.developer.meta.com"], "精确域名必须有对应 DNS 策略");
  assert.strictEqual(output.dns["nameserver-policy"]["+.ai.developer.meta.com"], undefined);
  assert(output.sniffer["force-domain"].indexOf("ai.developer.meta.com") >= 0);
  ["+.muse.ai", "+.metaaivm.com", "+.copilot.cloud.microsoft", "+.githubcopilot.com"].forEach(function (domain) {
    assert(output.dns["nameserver-policy"][domain].every(function (server) {
      return server.endsWith("#" + EXPECTED.aiGroupName);
    }), domain + " 的 DNS 必须与 AI 出口一致");
    assert(output.dns["fallback-filter"].domain.indexOf(domain) >= 0);
    assert(output.sniffer["force-domain"].indexOf(domain) >= 0);
  });
  ["sentry.io", "intercom.io", "stripe.com", "host.livekit.cloud", "turn.livekit.cloud", "browser-intake-datadoghq.com", "themeforest.net", "atmeta.com", "muse.com"].forEach(function (domain) {
    const result = audit.route(output.rules, { domain: domain, network: "tcp", port: 443 });
    assert(result.target !== EXPECTED.aiGroupName, "共享服务或未确认域名不应被整体送入 AI: " + domain);
  });
}

function testCommunityQuicOptionCoversNewDomains() {
  const audit = require("../scripts/rule-routing-audit");
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.rejectAiQuic = false;
  });
  ["muse.ai", "ai.developer.meta.com", "copilot.cloud.microsoft"].forEach(function (domain) {
    assert.strictEqual(audit.route(output.rules, { domain: domain, network: "udp", port: 443 }).target, EXPECTED.aiGroupName);
  });
}

function testOverseasPreservesIpv6AndCommunityDnsOptions() {
  const { output } = runOverseas();
  assert.strictEqual(output.ipv6, false, "境外模式默认也应关闭全局 IPv6");
  assert.strictEqual(output.dns.ipv6, false, "境外模式默认也应关闭 DNS IPv6");
  const policy = output.dns["nameserver-policy"];
  [
    ["+.muse.ai", EXPECTED.aiGroupName],
    ["ai.developer.meta.com", EXPECTED.aiGroupName],
    ["+.facebook.com", "DIRECT"],
    ["+.youtube.com", "DIRECT"],
    ["+.telegram.org", "DIRECT"],
    ["+.github.com", "DIRECT"]
  ].forEach(function (entry) {
    assert(policy[entry[0]] && policy[entry[0]].every(function (server) {
      return server.endsWith("#" + entry[1]);
    }), entry[0] + " 的社区 DNS 应遵循境外模式的服务分类");
  });
  const { output: enabled } = runOverseas(null, function (sandbox) {
    sandbox.USER_OPTIONS.enableIPv6 = true;
  });
  assert.strictEqual(enabled.ipv6, true, "境外模式允许显式开启全局 IPv6");
  assert.strictEqual(enabled.dns.ipv6, true, "境外模式允许显式开启 DNS IPv6");
}

// ─── run ─────────────────────────────────────────────────────────────────────

testDefaultConfig();
testIpv6IsDisabledByDefault();
testIpv6CanBeEnabled();
testIpv6OptionAppliesWithoutSubscription();
testTunDnsHijackPreservesExistingEntries();
testAiQuicRejectCanBeDisabled();
testAppStoreQuicRejectCanBeDisabled();
testGoogleTrafficConsistencyCanBeDisabled();
testFullProtocolFallbackCanBeDisabled();
testFullProtocolFallbackRequiresExplicitUdp();
testHttpFrontProxyExcludesChainedSubscriptionFromFallback();
testFullProtocolFallbackChecksDialerProxyGroupsRecursively();
testWebRtcUdpRejectCanBeDisabled();
testOverseasDnsTargetCanBeConfigured();
testNoCredentialPureOverwrite();
testFallbackToUrlTestGroup();
testAutoCreateUrlTestGroup();
testAutoSelectFiltersSubscriptionInfoNodes();
testAuthCredentials();
testCustomProxiesAppearInGlobal();
testNoCredentialAiAgentIncludesCustomAndRawNodes();
testDedicatedCustomProxyOnlyAppearsInExplicitRuleGroup();
testDedicatedBooleanPreservesScopeBehavior();
testDedicatedBooleanRejectsInvalidOrConflictingValues();
testCustomRuleGroupsCannotOverrideProtectedRules();
testDedicatedCustomProxyMustBeReferenced();
testDedicatedCustomProxyRejectsNameCollisions();
testFrontProxyAppliesToSubscriptionAndOrdinaryNodes();
testFrontProxyDoesNotOverrideHomeProxyDialer();
testStandaloneCustomProxiesWithoutSubscription();
testCustomRuleGroupsRouteOnlyMatchedDomains();
testProbeUrlsAreSplitByGroupPurpose();
testStandaloneCustomRuleGroupsWithoutSubscription();
testStandaloneHomeOnlyWithoutSubscription();
testStandaloneCustomNodesFollowFrontGroup();
testTailnetCustomProxyServerBypassesTunRoute();
testProxyServerAddressesUseDirectRules();
testHostnameProxyServerResolvedIpsUseDirectRules();
testProxyServerDirectRulesCanBeDisabled();
testTailnetExistingProxyServerBypassesTunRoute();
testTunRouteExcludesAreMergedAndConfigurable();
testTailscaleCgnatRangeBypassesTunByDefault();
testTailscaleProcessRulesTakePriorityOverWebRtcReject();
testTailnetDestinationRulesTakePriorityOverFullProtocolFallback();
testTailscaleRulesAreConfigurableAndExitNodeUsesNormalRules();
testTailscaleExitNodeCanBeForced();
testTailscaleMonitorGroupsCanBeDisabled();
testTailscaleSubnetCidrsAreVisibleInTailnetGroup();
testTailscaleMonitorGroupsCanBeShownForDebugging();
testStandaloneEmptyConfigFailsLoudly();
testLocationDefaultsToCn();
testCnIgnoresDomesticExit();
testOverseasRoutesDomesticTrafficToReturnGroup();
testOverseasDefaultsPreferDirectEgress();
testOverseasDnsProfile();
testOverseasWithoutDomesticExitFallsBackToDirect();
testOverseasStandaloneBoxProfile();
testOverseasExplicitOptionsWin();
testLocationValidation();
testLocationRejectsInvalidValues();
testDomesticExitNormalizesCandidates();
testDomesticExitRejectsInvalidValues();
testDomesticExitAllowsForwardReferences();
testProxyGraphRejectsCycles();
testProxyGraphRejectsMissingReferences();
testProxyNamesCannotBeOverwritten();
testProxyGroupNamesCannotBeOverwritten();
testProxyGraphAllowsSharedReferences();
testCommunityServiceBoundaries();
testCommunityExactDomainsAndSharedServices();
testCommunityQuicOptionCoversNewDomains();
testOverseasPreservesIpv6AndCommunityDnsOptions();
testFrontGroup();
testNetworkProbeRoutingAfterSwap();
testIpSbQuicProtectionIsNarrowAndIndependent();
testNetworkProbeRegistryDrivesAllLayers();
testNetworkProbeRegistryCanBeMaintainedInOnePlace();
testNetworkProbeRegistryRejectsInvalidEntries();
testFrontCopiesPreserveExplicitDialersAndAvoidNameCollisions();
testDomesticExitCanAlsoBeAnExplicitFrontCandidate();
testExplicitFrontCandidatesRejectUnsafeConfiguration();
testOrdinaryFrontDefaultsAndLegacyOptOut();
testFrontIncludeValidatesCandidates();
testCombinedCredentialSample();

console.log("validate-direct.js: all checks passed");
