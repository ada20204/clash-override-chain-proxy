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
      { name: "🇸🇬 SG Auto 01", type: "ss" },
      { name: "🇭🇰 HK Auto 01", type: "ss" },
      { name: "🇺🇸 US Auto 01", type: "ss" }
    ],
    "proxy-groups": [
      { name: "节点选择", type: "select", proxies: ["🇸🇬 SG Auto 01"] },
      { name: "自动选择(Smart Group)", type: "smart", proxies: ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01"] }
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

function assertRulesMissing(rules, ruleLines) {
  for (const ruleLine of ruleLines) {
    assert(rules.indexOf(ruleLine) < 0, "Rule should NOT exist: " + ruleLine);
  }
}

function assertNoDuplicateRuleIdentities(rules) {
  const seen = {};
  for (const rule of rules) {
    const firstComma  = rule.indexOf(",");
    const secondComma = rule.indexOf(",", firstComma + 1);
    if (firstComma < 0 || secondComma < 0) continue;
    const identity = rule.substring(0, secondComma);
    if (seen[identity]) throw new Error("Duplicate rule identity: " + identity);
    seen[identity] = true;
  }
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
  const { output } = runMain();

  // 凭证不输出到最终配置
  assert.strictEqual(output._homeProxy, undefined);

  // 家宽IP节点正确注入；真直连节点不挂 dialer-proxy
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert(homeNode, "家宽IP节点应存在");
  assert.strictEqual(homeNode.type,   TEST_HOME_CREDENTIALS.type);
  assert.strictEqual(homeNode.server, TEST_HOME_CREDENTIALS.server);
  assert.strictEqual(homeNode.port,   TEST_HOME_CREDENTIALS.port);
  assert.strictEqual(homeNode["dialer-proxy"], undefined, "家宽IP节点应是真直连，不应挂 dialer-proxy");

  const homeChainedNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeChainedNodeName; });
  assert(homeChainedNode, "存在可用跳板时应额外创建家宽IP链式节点");
  assert.strictEqual(homeChainedNode["dialer-proxy"], "🔗 家宽跳板",
    "家宽IP链式节点的 dialer-proxy 应指向家宽跳板组");

  // 家宽跳板组存在
  const relayGroup = output["proxy-groups"].find(function (g) { return g.name === "🔗 家宽跳板"; });
  assert(relayGroup, "家宽跳板组应存在");
  assert.strictEqual(relayGroup.type, "select");
  assert(relayGroup.proxies.indexOf(EXPECTED.relayGroupName) >= 0, "家宽跳板应包含自动选择组");

  // 家宽IP节点不在节点选择中（在组生成之后注入）
  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup, "节点选择组应存在");
  assert(nodeSelGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "家宽IP不应在节点选择中");

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
  assert(mediaGroup.proxies.indexOf("节点选择") >= 0, "国际媒体应包含节点选择");
  assert(mediaGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "媒体组不应含家宽IP节点");
  assert(mediaGroup.proxies.indexOf(EXPECTED.homeChainedNodeName) < 0, "媒体组不应含家宽IP链式节点");

  // 微软服务默认直连，但保留手动切换到节点选择/地区组的能力
  const microsoftGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.microsoftGroupName; });
  assert(microsoftGroup, "微软服务组应存在");
  assert.strictEqual(microsoftGroup.type, "select");
  assert.strictEqual(microsoftGroup.proxies[0], "DIRECT", "微软服务默认应走直连");
  assert(microsoftGroup.proxies.indexOf("节点选择") >= 0, "微软服务应保留节点选择");

  // 功能分组存在
  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  ["🐙 GitHub", "📲 Telegram", "🌍 国际媒体", "🎮 游戏平台", "🍎 Apple", "🎯 直连"].forEach(function (name) {
    assert(groupNames.indexOf(name) >= 0, name + " 组应存在");
  });

  // 关键 AI 规则统一指向 AI Agent 策略组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai,"   + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,chatgpt.com," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com,"  + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude,"       + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,claude,"       + EXPECTED.aiGroupName);

  // 网络信息检测源：AI / 普通代理 / 前置或直连，各司其职
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,DIRECT");

  // 媒体规则指向媒体组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,netflix.com," + EXPECTED.mediaGroupName);

  // Telegram / GitHub / Steam 各走专用组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,telegram.org,📲 Telegram");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,steampowered.com,🎮 游戏平台");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,apple.com,🍎 Apple");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,icloud.com.cn,🍎 Apple");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,microsoft.com," + EXPECTED.microsoftGroupName);

  // 兜底 MATCH
  assertRuleExists(output.rules, "MATCH,节点选择");

  // Tailscale 自身和 Tailnet 地址进入可见监控组，组内默认直连，避免 Exit Node / DERP / WireGuard 套娃
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,tailscaled.exe," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,IPNExtension," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "PROCESS-NAME,io.tailscale.ipn.macsys.network-extension," + EXPECTED.tailscaleProcessGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.64.0.0/10," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR,100.100.100.100/32," + EXPECTED.tailnetDirectGroupName + ",no-resolve");
  assertRuleExists(output.rules, "IP-CIDR6,fd7a:115c:a1e0::/48," + EXPECTED.tailnetDirectGroupName + ",no-resolve");

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
  ["🐙 GitHub", "📲 Telegram", "🌍 国际媒体", "🎮 游戏平台", "🍎 Apple", "🎯 直连"].forEach(function (name) {
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
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ip.sb,DIRECT");

  // 域名规则正常
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com,🌍 国际媒体");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,microsoft.com," + EXPECTED.microsoftGroupName);
  assertRuleExists(output.rules, "MATCH,节点选择");

  const microsoftGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.microsoftGroupName; });
  assert(microsoftGroup, "微软服务组应存在");
  assert.strictEqual(microsoftGroup.proxies[0], "DIRECT", "微软服务默认应走直连");
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
  assert(output.proxies.find(function (p) { return p.name === "自定义出口A"; }), "自定义出口应在 proxies 中");
  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup.proxies.indexOf("自定义出口A") >= 0, "AI Agent 应包含自定义出口");

  // 无名字时自动命名
  const { output: output2 } = runMain(function (config) {
    config._customProxies = [
      { type: "http", server: "10.0.0.1", port: 3128 },
      { type: "socks5", server: "10.0.0.2", port: 1080 }
    ];
  });
  assert(output2.proxies.find(function (p) { return p.name === "自定义出口1"; }), "第1个应自动命名为 自定义出口1");
  assert(output2.proxies.find(function (p) { return p.name === "自定义出口2"; }), "第2个应自动命名为 自定义出口2");
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

  ["🇸🇬 SG Auto 01", "🇭🇰 HK Auto 01", "🇺🇸 US Auto 01"].forEach(function (name) {
    const node = output.proxies.find(function (p) { return p.name === name; });
    assert.strictEqual(node["dialer-proxy"], "一级前置代理", name + " 应先走前置代理");
  });

  const customNode = output.proxies.find(function (p) { return p.name === "公司代理"; });
  assert.strictEqual(customNode["dialer-proxy"], undefined, "自定义出口不应被前置代理覆盖");

  const nodeSelGroup = output["proxy-groups"].find(function (g) { return g.name === "节点选择"; });
  assert(nodeSelGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应作为最终出口出现在节点选择");

  const globalGroup = output["proxy-groups"].find(function (g) { return g.name === "GLOBAL"; });
  assert(globalGroup.proxies.indexOf("一级前置代理") >= 0, "前置代理应出现在 GLOBAL 中供全局模式选择");
  assert(globalGroup.proxies.indexOf("一级前置代理") < globalGroup.proxies.indexOf("DIRECT"),
    "前置代理应放在 GLOBAL 的 DIRECT 前面");

  const aiGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.aiGroupName; });
  assert(aiGroup.proxies.indexOf("一级前置代理") < 0, "前置代理不应作为最终出口出现在 AI Agent");

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
    { name: "美国固定IP", type: "socks5", server: "20.0.0.1", port: 1080 }
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
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipapi.is," + EXPECTED.aiGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,ipwho.is,节点选择");
  assertRuleExists(output.rules, "MATCH,节点选择");
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

function testTailscaleRulesAreConfigurableAndExitNodeUsesNormalRules() {
  const { output } = runMain(function (config) {
    delete config._homeProxy;
  }, function (sandbox) {
    sandbox.USER_OPTIONS.tailscale.controlPlaneTarget = "节点选择";
    sandbox.USER_OPTIONS.tailscale.processTarget = "节点选择";
  });

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,tailscale.com," + EXPECTED.tailscaleControlGroupName);
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
    "自动创建的测速组应使用 HTTPS 探测，避免 HTTP 代理节点被 HTTP delay 误判");
  assert(autoGroup.proxies.length > 0, "自建组应包含订阅节点");
}

// ─── run ─────────────────────────────────────────────────────────────────────

testDefaultConfig();
testNoCredentialPureOverwrite();
testFallbackToUrlTestGroup();
testAutoCreateUrlTestGroup();
testAuthCredentials();
testCustomProxiesAppearInGlobal();
testNoCredentialAiAgentIncludesCustomAndRawNodes();
testFrontProxyAppliesOnlyToSubscriptionNodes();
testFrontProxyDoesNotOverrideHomeProxyDialer();
testStandaloneCustomProxiesWithoutSubscription();
testStandaloneHomeOnlyWithoutSubscription();
testStandaloneFrontProxyOnlyAppliesWhenRequested();
testTailnetCustomProxyServerBypassesTunRoute();
testTailnetExistingProxyServerBypassesTunRoute();
testTunRouteExcludesAreMergedAndConfigurable();
testTailscaleRulesAreConfigurableAndExitNodeUsesNormalRules();
testTailscaleExitNodeCanBeForced();
testTailscaleMonitorGroupsCanBeDisabled();
testTailscaleSubnetCidrsAreVisibleInTailnetGroup();
testTailscaleMonitorGroupsCanBeShownForDebugging();
testStandaloneEmptyConfigFailsLoudly();

console.log("validate-direct.js: all checks passed");
