const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const scriptPath = path.join(__dirname, "..", "src", "家宽IP-链式代理.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

const TEST_MIYA_CREDENTIALS = {
  username: "user",
  password: "pass",
  relay: { server: "1.2.3.4", port: 8000 },
  transit: { server: "transit.example.com", port: 8001 }
};

// ---------------------------------------------------------------------------
// Sandbox + config fixtures
// ---------------------------------------------------------------------------

function loadSandbox() {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox, { filename: scriptPath });
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
      { name: "节点选择", type: "select", proxies: ["🇸🇬 SG Auto 01"] }
    ],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "DOMAIN-SUFFIX,tailscale.com,REJECT",
      "MATCH,节点选择"
    ],
    _miya: JSON.parse(JSON.stringify(TEST_MIYA_CREDENTIALS))
  };
}

function runMain(configMutator, sandboxMutator) {
  const sandbox = loadSandbox();
  const config = createBaseConfig();
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  if (typeof configMutator === "function") configMutator(config);
  return { sandbox, output: sandbox.main(config) };
}

// ---------------------------------------------------------------------------
// Derive canonical group names / process lists from sandbox metadata
// ---------------------------------------------------------------------------

function regionGroupName(sandbox, regionKey, suffix) {
  const meta = sandbox.BASE.regions[regionKey];
  return meta.flag + "|" + meta.label + suffix;
}

function expectedGroupNames(sandbox) {
  const suffix = sandbox.BASE.groupNameSuffixes;
  const opt = sandbox.USER_OPTIONS;
  return {
    relay: regionGroupName(sandbox, opt.chainRegion, suffix.relay),
    chain: regionGroupName(sandbox, opt.chainRegion, suffix.chain),
    media: regionGroupName(sandbox, opt.mediaRegion, suffix.media)
  };
}

function derivedBrowserProcessNames(sandbox) {
  return sandbox.DERIVED.processNames.general.browser.slice();
}

function derivedAiCliProcessNames(sandbox) {
  return sandbox.DERIVED.processNames.strict.optionalAiCli.slice();
}

// ---------------------------------------------------------------------------
// Rule and proxy helpers
// ---------------------------------------------------------------------------

function ruleIdentity(ruleLine) {
  const firstComma = ruleLine.indexOf(",");
  const secondComma = ruleLine.indexOf(",", firstComma + 1);
  return ruleLine.slice(0, secondComma);
}

function assertNoDuplicateRuleIdentities(ruleLines) {
  const seen = new Set();
  for (const line of ruleLines) {
    const id = ruleIdentity(line);
    assert(!seen.has(id), "Duplicate managed rule identity: " + id);
    seen.add(id);
  }
}

function assertRulesExist(ruleLines, expected) {
  for (const line of expected) {
    assert(ruleLines.includes(line), "Expected rule not found: " + line);
  }
}

function assertRulesMissing(ruleLines, unexpected) {
  for (const line of unexpected) {
    assert(!ruleLines.includes(line), "Unexpected rule found: " + line);
  }
}

function assertProcessRules(output, enabled, processNames, target) {
  const lines = processNames.map((p) => "PROCESS-NAME," + p + "," + target);
  if (enabled) assertRulesExist(output.rules, lines);
  else assertRulesMissing(output.rules, lines);
}

function findGroup(output, name) {
  return output["proxy-groups"].find((g) => g.name === name);
}

function findProxy(output, name) {
  return output.proxies.find((p) => p.name === name);
}

function assertNameserverPolicyValues(output, domains, expected) {
  for (const domain of domains) {
    assert.deepEqual(output.dns["nameserver-policy"][domain], expected);
  }
}

function assertIncludes(values, expected, label) {
  for (const v of expected) {
    assert(values.includes(v), label + " missing: " + v);
  }
}

function assertExcludes(values, excluded, label) {
  for (const v of excluded) {
    assert(!values.includes(v), label + " unexpectedly contains: " + v);
  }
}

function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((v) => set.has(v));
}

// ---------------------------------------------------------------------------
// Structural assertions (derived from sandbox metadata)
// ---------------------------------------------------------------------------

function assertManagedProxyTopology(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  const nodeNames = sandbox.BASE.nodeNames;

  const relayProxy = findProxy(output, nodeNames.relay);
  const transitProxy = findProxy(output, nodeNames.transit);

  assert(relayProxy, "relay proxy missing");
  assert.strictEqual(relayProxy.type, "http");
  assert.strictEqual(relayProxy.server, TEST_MIYA_CREDENTIALS.relay.server);
  assert.strictEqual(relayProxy.port, TEST_MIYA_CREDENTIALS.relay.port);
  assert.strictEqual(relayProxy["dialer-proxy"], names.relay);

  assert(transitProxy, "transit proxy missing");
  assert.strictEqual(transitProxy.type, "http");
  assert.strictEqual(transitProxy.server, TEST_MIYA_CREDENTIALS.transit.server);
  assert.strictEqual(transitProxy["dialer-proxy"], undefined);

  const relayGroup = findGroup(output, names.relay);
  assert(relayGroup, "relay group missing");
  assert.strictEqual(relayGroup.type, "url-test");
  assert.deepEqual(relayGroup.proxies, ["🇸🇬 SG Auto 01"]);

  const chainGroup = findGroup(output, names.chain);
  assert(chainGroup, "chain group missing");
  assert.strictEqual(chainGroup.type, "select");
  assert(sameSet(chainGroup.proxies, [nodeNames.transit, nodeNames.relay]),
    "chain group members mismatch");

  const mediaGroup = findGroup(output, names.media);
  assert(mediaGroup, "media group missing");
  assert.strictEqual(mediaGroup.type, "url-test");
  assert.deepEqual(mediaGroup.proxies, ["🇺🇸 US Auto 01"]);

  const nodeSelection = findGroup(output, sandbox.BASE.groupNames.nodeSelection);
  assert(nodeSelection, "node selection group missing");
  assert.deepEqual(
    nodeSelection.proxies,
    ["🇸🇬 SG Auto 01", names.relay, names.media]
  );
}

// EXPECTED_ROUTES sample → rule lines
function sampleRuleLines(sample, target) {
  const lines = [];
  for (const d of sample.domains || []) lines.push("DOMAIN-SUFFIX," + d + "," + target);
  for (const p of sample.processNames || []) lines.push("PROCESS-NAME," + p + "," + target);
  for (const p of sample.cliNames || []) lines.push("PROCESS-NAME," + p + "," + target);
  return lines;
}

function assertCoreStrictRouting(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  assertRulesExist(output.rules, sampleRuleLines(sandbox.EXPECTED_ROUTES.toChain, names.chain));
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,claude.ai,DIRECT"]);
}

function assertMediaRouting(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  assertRulesExist(output.rules, sampleRuleLines(sandbox.EXPECTED_ROUTES.toMedia, names.media));
  assertRulesMissing(output.rules, sampleRuleLines(sandbox.EXPECTED_ROUTES.toMedia, names.chain));
}

function assertBrowserRouting(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, true, derivedBrowserProcessNames(sandbox), names.chain);
  // 受管浏览器不应被误路由到媒体目标
  assertProcessRules(output, false, derivedBrowserProcessNames(sandbox), names.media);
  // 未列入源的浏览器不应出现
  assertProcessRules(output, false, ["Arc", "Microsoft Edge"], names.chain);
}

function assertDomesticDirectCoverage(output, sandbox) {
  const officeDomains = ["+.docs.qq.com", "+.dingtalk.com", "+.feishu.cn", "+.wps.cn"];
  assertRulesExist(output.rules, officeDomains.map((d) =>
    "DOMAIN-SUFFIX," + d.replace("+.", "") + ",DIRECT"
  ));
  // 办公软件走域名规则，不应出现进程直连
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,DingTalk,DIRECT",
    "PROCESS-NAME,Feishu,DIRECT"
  ]);
  assertNameserverPolicyValues(output, officeDomains, sandbox.BASE.dns.domestic);
}

function assertOverseasAppDirectCoverage(output, sandbox) {
  const overseasAppDomains = ["+.tailscale.com", "+.tailscale.io", "+.ts.net"];
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,tailscale.com,DIRECT",
    "DOMAIN-SUFFIX,tailscale.io,DIRECT",
    "DOMAIN-SUFFIX,ts.net,DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve"
  ]);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,Tailscale,DIRECT",
    "PROCESS-NAME,tailscale,DIRECT"
  ]);
  assertNameserverPolicyValues(output, overseasAppDomains, sandbox.BASE.dns.overseas);
  assertIncludes(output.dns["fallback-filter"].domain, overseasAppDomains, "fallback-filter.domain");
  assertIncludes(output.sniffer["skip-domain"], overseasAppDomains, "sniffer.skip-domain");
  assertExcludes(output.dns["fake-ip-filter"], ["+.tailscale.com"], "fake-ip-filter");
}

function assertDnsAndSniffer(output, sandbox) {
  assertNameserverPolicyValues(
    output,
    ["+.sora.com", "+.notebooklm.google", "+.m365.cloud.microsoft"],
    sandbox.BASE.dns.overseas
  );
  assertIncludes(output.dns["fake-ip-filter"], ["+.xboxlive.com", "stun.*.*"], "fake-ip-filter");
  assertIncludes(output.dns["fallback-filter"].domain, ["+.sora.com", "+.youtube.com"], "fallback-filter.domain");
  assertIncludes(output.sniffer["force-domain"], ["+.claude.ai", "+.google.com"], "sniffer.force-domain");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function testDefaultConfig() {
  const { sandbox, output } = runMain();
  assert.strictEqual(sandbox.USER_OPTIONS.routeBrowserToChain, true);
  assert.strictEqual(sandbox.USER_OPTIONS.routeAiCliToChain, true);
  assert.strictEqual(output._miya, undefined);
  assertManagedProxyTopology(output, sandbox);
  assertCoreStrictRouting(output, sandbox);
  assertMediaRouting(output, sandbox);
  assertBrowserRouting(output, sandbox);
  assertDomesticDirectCoverage(output, sandbox);
  assertOverseasAppDirectCoverage(output, sandbox);
  assertDnsAndSniffer(output, sandbox);
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 250));
}

function testDisableBrowserProcessProxy() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, false, derivedBrowserProcessNames(sandbox), names.chain);
}

function testAiCliProcessProxyDefaultsOn() {
  const { sandbox, output } = runMain();
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, true, derivedAiCliProcessNames(sandbox), names.chain);
  assertProcessRules(output, false, ["opencode"], names.chain);
}

function testDisableAiCliProcessProxy() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeAiCliToChain = false;
  });
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, false, derivedAiCliProcessNames(sandbox), names.chain);
}

function testOnlyAiAndBrowserProcessesAreManaged() {
  const { sandbox, output } = runMain();
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, false, ["Google Drive", "Visual Studio Code"], names.chain);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,Tailscale,DIRECT"
  ]);
}

function testMissingRegionFails() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.chainRegion = "JP";
  assert.throws(() => sandbox.main(createBaseConfig()), /未找到可用的 JP 节点/);
}

function testMissingMediaRegionFails() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.mediaRegion = "JP";
  assert.throws(() => sandbox.main(createBaseConfig()), /未找到可用的 JP 媒体节点/);
}

function testMissingStrictTargetFails() {
  const sandbox = loadSandbox();
  const original = sandbox.resolveRoutingTargets;
  sandbox.resolveRoutingTargets = (config, chainRegion, mediaRegion) => {
    const rt = original(config, chainRegion, mediaRegion);
    rt.strictAiTarget = "错误目标";
    return rt;
  };
  assert.throws(() => sandbox.main(createBaseConfig()),
    /域外 AI 与支撑平台未直接指向当前 chainRegion 出口/);
}

function testExistingManagedObjectsAreReconciled() {
  const { sandbox, output } = runMain((config) => {
    const base = loadSandbox().BASE;
    const nodeNames = base.nodeNames;
    const suffix = base.groupNameSuffixes;
    const flag = base.regions.SG.flag + "|" + base.regions.SG.label;
    const mediaFlag = base.regions.US.flag + "|" + base.regions.US.label;

    config.proxies.push({
      name: nodeNames.relay, type: "http", server: "bad", port: 1,
      username: "bad", password: "bad", udp: false, "dialer-proxy": "错误目标"
    });
    config.proxies.push({
      name: nodeNames.transit, type: "http", server: "bad", port: 2,
      username: "bad", password: "bad", udp: false, "dialer-proxy": "错误目标"
    });
    config["proxy-groups"].push({ name: flag + suffix.relay, type: "select", proxies: [flag + suffix.chain] });
    config["proxy-groups"].push({ name: flag + suffix.chain, type: "select", proxies: ["DIRECT"] });
    config["proxy-groups"].push({ name: mediaFlag + suffix.media, type: "select", proxies: ["DIRECT"] });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testChainGroupIsNotReusedAsRelayTarget() {
  const { sandbox, output } = runMain((config) => {
    const base = loadSandbox().BASE;
    const chainName = base.regions.SG.flag + "|" + base.regions.SG.label + base.groupNameSuffixes.chain;
    config["proxy-groups"].push({
      name: chainName, type: "select",
      proxies: [base.nodeNames.transit, base.nodeNames.relay]
    });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testBadExternalRegionGroupIsNotReused() {
  const { sandbox, output } = runMain((config) => {
    config["proxy-groups"].push({
      name: "🇸🇬 错误地区组", type: "select", proxies: ["DIRECT"]
    });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testNodeSelectionKeepsOnlyCurrentRelayGroup() {
  const { sandbox, output } = runMain((config) => {
    const base = loadSandbox().BASE;
    const staleRelay = base.regions.HK.flag + "|" + base.regions.HK.label + base.groupNameSuffixes.relay;
    const staleMedia = base.regions.SG.flag + "|" + base.regions.SG.label + base.groupNameSuffixes.media;
    config["proxy-groups"][0].proxies = ["🇸🇬 SG Auto 01", staleRelay, staleMedia];
  });
  assertManagedProxyTopology(output, sandbox);
}

function testRepeatedRunDoesNotCreateSelfReference() {
  const first = runMain();
  const rerunInput = JSON.parse(JSON.stringify(first.output));
  rerunInput._miya = JSON.parse(JSON.stringify(TEST_MIYA_CREDENTIALS));
  const sandbox = loadSandbox();
  const second = sandbox.main(rerunInput);
  const names = expectedGroupNames(sandbox);

  assertManagedProxyTopology(second, sandbox);
  for (const name of [names.chain, names.relay, names.media]) {
    const count = second["proxy-groups"].filter((g) => g.name === name).length;
    assert.strictEqual(count, 1, "duplicate group after rerun: " + name);
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const tests = [
  testDefaultConfig,
  testDisableBrowserProcessProxy,
  testAiCliProcessProxyDefaultsOn,
  testDisableAiCliProcessProxy,
  testOnlyAiAndBrowserProcessesAreManaged,
  testMissingRegionFails,
  testMissingMediaRegionFails,
  testMissingStrictTargetFails,
  testExistingManagedObjectsAreReconciled,
  testChainGroupIsNotReusedAsRelayTarget,
  testBadExternalRegionGroupIsNotReused,
  testNodeSelectionKeepsOnlyCurrentRelayGroup,
  testRepeatedRunDoesNotCreateSelfReference
];

for (const test of tests) {
  test();
}

console.log("validate.js: " + tests.length + " checks passed");
