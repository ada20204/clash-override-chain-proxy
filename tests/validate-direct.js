/**
 * 家宽IP-直连覆写脚本测试
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
  generalEgressGroupName: "🌐 通用出海",
  fullProtocolFallbackGroupName: "🔌 全协议回退",
  japanServicesGroupName: "🇯🇵 日本服务",
  microsoftGroupName: "Ⓜ️ 微软服务",
  tailscaleControlGroupName: "🧩 Tailscale 控制面",
  tailscaleProcessGroupName: "🧩 Tailscale 进程",
  tailnetDirectGroupName: "🧩 Tailnet 内部直连",
  tailscaleExitGroupName: "🧩 Tailscale Exit Node"
};

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

function assertTransportAwareFallbackRules(rules) {
  const tlsRule = "AND,((NETWORK,tcp),(DST-PORT,443))," + EXPECTED.generalEgressGroupName;
  const fallbackRule = "MATCH," + EXPECTED.fullProtocolFallbackGroupName;
  assertRuleExists(rules, tlsRule);
  assertRuleExists(rules, fallbackRule);
  assert(rules.indexOf(tlsRule) < rules.indexOf(fallbackRule),
    "TCP/443 兜底应优先于其余协议的全协议回退");
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

  // 家宽IP节点不在节点选择中（在组生成之后注入）
  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup, "节点选择组应存在");
  assert(nodeSelGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "家宽IP不应在节点选择中");

  const generalEgressGroup = output["proxy-groups"].find(function (g) {
    return g.name === EXPECTED.generalEgressGroupName;
  });
  assert(generalEgressGroup, "通用出海组应存在");
  assert.strictEqual(generalEgressGroup.proxies.length, 1,
    "通用出海不应保留额外出口选项");
  assert.strictEqual(generalEgressGroup.proxies[0], "节点选择",
    "通用出海只应复用人工选择结果");
  assert.strictEqual(generalEgressGroup.hidden, true, "通用出海应作为内部兜底组隐藏");

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
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,cloudcode-pa.googleapis.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,daily-cloudcode-pa.googleapis.com," + EXPECTED.aiGroupName);
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
      output.rules.indexOf("AND,((NETWORK,tcp),(DST-PORT,443))," + EXPECTED.generalEgressGroupName),
    "Codex 桌面服务必须优先于通用 TCP/443 回退规则进入 AI Agent");
  assert(output.rules.indexOf("PROCESS-NAME,Cursor Helper (Plugin)," + EXPECTED.aiGroupName) <
      output.rules.indexOf("AND,((NETWORK,tcp),(DST-PORT,443))," + EXPECTED.generalEgressGroupName),
    "Cursor 插件进程必须优先于通用 TCP/443 回退规则进入 AI Agent");

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
  const generatedAiQuicRules = output.rules.filter(function (rule) {
    return rule.indexOf("AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,") === 0;
  });
  assert.strictEqual(generatedAiQuicRules.length, sandbox.DERIVED.patterns.strict.all.length,
    "每个 AI Agent 域名都应自动生成一条 QUIC 拒绝规则");

  // 网络信息检测源：AI / 普通代理 / 前置或直连，各司其职
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.net.coffee," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,DIRECT");

  // 媒体规则指向媒体组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,netflix.com," + EXPECTED.mediaGroupName);
  ["youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com"].forEach(function (domain) {
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
    "rivotek.com",
    "larksuite.com",
    "larkoffice.com",
    "dashscope.aliyuncs.com",
    "feishu.net",
    "feishucdn.com",
    "dingtalkapps.com"
  ];
  const overseasDnsDirectOverrides = ["typeless.com"];
  domesticDnsDirectOverrides.concat(overseasDnsDirectOverrides).forEach(function (domain) {
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
  assertRuleExists(output.rules, "GEOSITE,cn,DIRECT");
  assertRuleExists(output.rules, "GEOIP,cn,DIRECT,no-resolve");

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
    assert(output.rules.indexOf(tlsRule) < output.rules.indexOf("GEOSITE,cn,DIRECT"),
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
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,DIRECT");

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
  assert.strictEqual(output.rules.filter(function (rule) {
    return rule.indexOf("AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN-SUFFIX,") === 0;
  }).length, 0, "关闭 rejectAiQuic 后不应生成 AI QUIC 拒绝规则");
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
  assertRuleExists(output.rules, "MATCH," + EXPECTED.generalEgressGroupName);
  assertRulesMissing(output.rules, [
    tcp443DomainRule("google.com", "节点选择"),
    "MATCH," + EXPECTED.fullProtocolFallbackGroupName
  ]);
}

function testFullProtocolFallbackRequiresExplicitUdp() {
  const { output } = runMain(function (config) {
    delete config.proxies[1].udp;
    config.proxies[2].udp = false;
  });
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
  assertRuleExists(output.rules, "MATCH," + EXPECTED.generalEgressGroupName);
}

function testFullProtocolFallbackChecksDialerProxyGroupsRecursively() {
  const { output } = runMain(function (config) {
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
  });
  const fallbackGroup = output["proxy-groups"].find(function (group) {
    return group.name === EXPECTED.fullProtocolFallbackGroupName;
  });
  assert(fallbackGroup.proxies.indexOf("🇸🇬 SG Auto 01") >= 0,
    "经 UDP 策略组和 UDP 多跳链路的节点应进入全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇭🇰 HK Auto 01") < 0,
    "经 HTTP 策略组的节点不应进入全协议回退组");
  assert(fallbackGroup.proxies.indexOf("🇺🇸 US Auto 01") < 0,
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
        server: "10.96.0.100",
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
  assert(output.rules.indexOf("IP-CIDR,10.96.0.100/32,DIRECT,no-resolve") <
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

function testCustomRuleGroupsCannotOverrideProtectedRules() {
  const protectedCases = [
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
    }
  ];

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
          server: "10.96.0.100",
          port: 3456
        }
      ];
    });
  }, /未被 _customRuleGroups\.proxies 引用/);
}

function testDedicatedCustomProxyRejectsNameCollisions() {
  assert.throws(function () {
    runMain(function (config) {
      config._customProxies = [
        {
          name: "🇺🇸 US Auto 01",
          scope: "dedicated",
          type: "http",
          server: "10.96.0.100",
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
          server: "10.96.0.100",
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

function testFrontProxyAppliesOnlyToSubscriptionNodes() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
    config._frontProxy = { name: "一级前置代理", type: "socks5", server: "10.0.0.8", port: 1080 };
    config._customProxies = [
      { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 }
    ];
  });

  const frontNode = output.proxies.find(function (p) { return p.name === "一级前置代理"; });
  assert(frontNode, "前置代理节点应被注入");
  assert.strictEqual(frontNode.udp, false, "未声明 UDP 的 SOCKS5 前置代理不应被推断为支持 UDP");

  ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01"].forEach(function (name) {
    const node = output.proxies.find(function (p) { return p.name === name; });
    assert.strictEqual(node["dialer-proxy"], "一级前置代理", name + " 应先走前置代理");
  });

  const customNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  assert.strictEqual(customNode["dialer-proxy"], undefined, "自定义出口不应被前置代理覆盖");
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
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,一级前置代理");
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
  assert.strictEqual(subNode["dialer-proxy"], "一级前置代理", "订阅节点应走前置代理");
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
  assert(fallbackGroup, "SOCKS5 自定义节点应形成全协议回退组");
  assert.deepEqual(fallbackGroup.proxies, ["美国固定IP"],
    "全协议回退组应排除 HTTP 公司代理，只保留 SOCKS5 节点");
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
  assertRuleExists(output.rules, "MATCH," + EXPECTED.generalEgressGroupName);
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

function testStandaloneFrontProxyOnlyAppliesWhenRequested() {
  const config = createEmptyConfig();
  config._frontProxy = { name: "一级前置代理", type: "socks5", server: "10.0.0.8", port: 1080 };
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.0.0.9", port: 8080 },
    { name: "上游节点", type: "socks5", server: "10.0.0.10", port: 1080, useFrontProxy: true }
  ];
  const { output } = runMainWithConfig(config);

  const normalNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  const chainedNode = output.proxies.find(function (p) { return p.name === "上游节点"; });
  assert.strictEqual(normalNode["dialer-proxy"], undefined, "未声明 useFrontProxy 的自定义节点不应走前置代理");
  assert.strictEqual(chainedNode["dialer-proxy"], "一级前置代理", "声明 useFrontProxy 的自定义节点应走前置代理");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应进入节点选择");
}

function testTailnetCustomProxyServerBypassesTunRoute() {
  const config = createEmptyConfig();
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.96.0.100", port: 3456, interfaceName: "utun4" },
    { name: "公网代理", type: "http", server: "8.8.8.8", port: 8080 }
  ];
  const { output } = runMainWithConfig(config);
  const routeExcludes = output.tun && output.tun["route-exclude-address"];
  const companyNode = output.proxies.find(function (p) { return p.name === "公司代理"; });

  assert(routeExcludes, "Tailnet/private 自定义节点服务器应生成 tun.route-exclude-address");
  assert(routeExcludes.indexOf("10.96.0.100/32") >= 0,
    "作为自定义节点服务器的 Tailnet/private IP 应绕过 TUN，避免节点测速自拨被虚拟网卡截获");
  assert(routeExcludes.indexOf("8.8.8.8/32") < 0, "公网自定义节点服务器不应自动绕过 TUN");
  assert.strictEqual(companyNode["interface-name"], "utun4",
    "Tailnet 自定义节点应支持按节点绑定 Tailscale 出口接口");
}

function testProxyServerAddressesUseDirectRules() {
  const config = createBaseConfig();
  config.proxies = config.proxies.concat([
    { name: "订阅IP节点", type: "http", server: "203.0.113.10", port: 443 },
    { name: "订阅域名节点", type: "http", server: "edge.example.com", port: 443 }
  ]);
  const { output } = runMainWithConfig(config);

  assertRuleExists(output.rules, "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,edge.example.com,DIRECT");
  assert(output.rules.indexOf("IP-CIDR,203.0.113.10/32,DIRECT,no-resolve") <
      output.rules.indexOf("MATCH," + EXPECTED.fullProtocolFallbackGroupName),
    "代理服务器直连规则应在兜底规则之前");
}

function testHostnameProxyServerResolvedIpsUseDirectRules() {
  const config = createBaseConfig();
  config.proxies.push({ name: "订阅域名节点", type: "http", server: "edge.example.com", port: 443 });
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
  const fallbackIndex = output.rules.indexOf("MATCH," + EXPECTED.fullProtocolFallbackGroupName);
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
    { name: "订阅IP节点", type: "http", server: "203.0.113.10", port: 443 }
  ]);
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.directProxyServerRules = false;
  });

  assertRulesMissing(output.rules, ["IP-CIDR,203.0.113.10/32,DIRECT,no-resolve"]);
}

function testTailnetExistingProxyServerBypassesTunRoute() {
  const config = createEmptyConfig();
  config.proxies = [
    { name: "公司代理", type: "http", server: "10.96.0.100", port: 3456 },
    { name: "公网代理", type: "http", server: "8.8.8.8", port: 8080 }
  ];
  const { output } = runMainWithConfig(config);
  const routeExcludes = output.tun && output.tun["route-exclude-address"];

  assert(routeExcludes, "已有代理节点中的 Tailnet/private server 也应生成 tun.route-exclude-address");
  assert(routeExcludes.indexOf("10.96.0.100/32") >= 0,
    "最终配置内已有的 Tailnet/private 代理服务器应绕过 TUN");
  assert(routeExcludes.indexOf("8.8.8.8/32") < 0, "最终配置内已有的公网代理服务器不应自动绕过 TUN");
}

function testTunRouteExcludesAreMergedAndConfigurable() {
  const config = createEmptyConfig();
  config.tun = { enable: true, "route-exclude-address": ["10.96.0.100/32"] };
  config._frontProxy = { name: "一级前置代理", type: "http", server: "10.96.0.100", port: 3456 };
  config._customProxies = [
    { name: "公司代理", type: "http", server: "10.166.0.10", port: 8080 }
  ];
  const { output } = runMainWithConfig(config, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.routeExcludeCidrs = ["10.168.100.0/24"];
  });
  const routeExcludes = output.tun["route-exclude-address"];

  assert.strictEqual(routeExcludes.filter(function (cidr) { return cidr === "10.96.0.100/32"; }).length, 1,
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

// ─── run ─────────────────────────────────────────────────────────────────────

testDefaultConfig();
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
testCustomRuleGroupsCannotOverrideProtectedRules();
testDedicatedCustomProxyMustBeReferenced();
testDedicatedCustomProxyRejectsNameCollisions();
testFrontProxyAppliesOnlyToSubscriptionNodes();
testFrontProxyDoesNotOverrideHomeProxyDialer();
testStandaloneCustomProxiesWithoutSubscription();
testCustomRuleGroupsRouteOnlyMatchedDomains();
testProbeUrlsAreSplitByGroupPurpose();
testStandaloneCustomRuleGroupsWithoutSubscription();
testStandaloneHomeOnlyWithoutSubscription();
testStandaloneFrontProxyOnlyAppliesWhenRequested();
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

console.log("validate-direct.js: all checks passed");
