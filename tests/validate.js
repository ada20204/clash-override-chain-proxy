const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(repoRoot, "src", "家宽IP-链式代理.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

const CHAIN_GROUP_NAME = "🇸🇬|新加坡-链式代理-家宽IP出口";
const RELAY_GROUP_NAME = "🇸🇬|新加坡线路-链式代理-跳板";
const LEGACY_GROUP_NAME = "AI 严格链式代理";

const DEFAULT_DIRECT_RULE_PREFIX = [
  "PROCESS-NAME,Tailscale,DIRECT",
  "PROCESS-NAME,tailscale,DIRECT",
  "PROCESS-NAME,tailscaled,DIRECT",
  "PROCESS-NAME,IPNExtension,DIRECT",
  "PROCESS-NAME,io.tailscale.ipn.macos.network-extension,DIRECT",
  "PROCESS-NAME,io.tailscale.ipn.macsys.network-extension,DIRECT",
  "PROCESS-NAME,WeChat,DIRECT",
  "PROCESS-NAME,QQ,DIRECT",
  "PROCESS-NAME,WeCom,DIRECT",
  "PROCESS-NAME,TencentMeeting,DIRECT",
  "PROCESS-NAME,DingTalk,DIRECT",
  "PROCESS-NAME,AliyunDrive,DIRECT",
  "PROCESS-NAME,Quark,DIRECT",
  "PROCESS-NAME,Feishu,DIRECT",
  "PROCESS-NAME,Lark,DIRECT",
  "PROCESS-NAME,WPS Office,DIRECT",
  "PROCESS-NAME,WPS,DIRECT",
  "PROCESS-NAME,WPS Office Helper,DIRECT",
  "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
  "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve",
];

const DOMESTIC_OFFICE_DOMAINS = [
  "+.docs.qq.com",
  "+.dingtalk.com",
  "+.feishu.cn",
  "+.wps.cn",
];

const DOMESTIC_OFFICE_DIRECT_RULES = [
  "DOMAIN-SUFFIX,docs.qq.com,DIRECT",
  "DOMAIN-SUFFIX,dingtalk.com,DIRECT",
  "DOMAIN-SUFFIX,feishu.cn,DIRECT",
  "DOMAIN-SUFFIX,wps.cn,DIRECT",
];

const DOMESTIC_OFFICE_DIRECT_PROCESSES = [
  "PROCESS-NAME,WeChat,DIRECT",
  "PROCESS-NAME,DingTalk,DIRECT",
  "PROCESS-NAME,Feishu,DIRECT",
  "PROCESS-NAME,WPS Office,DIRECT",
];

function loadSandbox() {
  const sandbox = {
    console,
    Object,
    Array,
    String,
    Error,
  };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox, { filename: scriptPath });
  return sandbox;
}

function createBaseConfig() {
  return {
    proxies: [
      { name: "🇸🇬 SG Auto 01", type: "ss" },
      { name: "🇭🇰 HK Auto 01", type: "ss" },
      { name: "手动节点A", type: "ss" },
    ],
    "proxy-groups": [{ name: "节点选择", type: "select", proxies: ["🇸🇬 SG Auto 01"] }],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "DOMAIN-SUFFIX,tailscale.com,REJECT",
      "MATCH,节点选择",
    ],
    _miya: {
      username: "user",
      password: "pass",
      relay: { server: "1.2.3.4", port: 8000 },
      transit: { server: "transit.example.com", port: 8001 },
    },
  };
}

function runMain(configMutator, sandboxMutator) {
  const sandbox = loadSandbox();
  const config = createBaseConfig();

  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  if (typeof configMutator === "function") configMutator(config);

  return {
    sandbox,
    output: sandbox.main(config),
  };
}

function extractRuleIdentity(ruleLine) {
  const firstCommaIndex = ruleLine.indexOf(",");
  const secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  return ruleLine.slice(0, secondCommaIndex);
}

function assertNoDuplicateRuleIdentities(ruleLines) {
  const seen = new Set();
  for (const ruleLine of ruleLines) {
    const identity = extractRuleIdentity(ruleLine);
    if (seen.has(identity)) {
      throw new Error("Duplicate managed rule identity found: " + identity);
    }
    seen.add(identity);
  }
}

function assertRuleExists(ruleLines, ruleLine) {
  assert(ruleLines.includes(ruleLine), "Expected rule not found: " + ruleLine);
}

function assertRuleMissing(ruleLines, ruleLine) {
  assert(!ruleLines.includes(ruleLine), "Unexpected rule found: " + ruleLine);
}

function assertRulePrefix(actualRules, expectedPrefix) {
  const actualPrefix = Array.prototype.slice.call(actualRules, 0, expectedPrefix.length);
  assert.strictEqual(JSON.stringify(actualPrefix), JSON.stringify(expectedPrefix));
}

function assertRulesExist(ruleLines, expectedRules) {
  for (const ruleLine of expectedRules) {
    assertRuleExists(ruleLines, ruleLine);
  }
}

function assertProcessRules(output, enabled, processNames, target) {
  for (const processName of processNames) {
    const ruleLine = "PROCESS-NAME," + processName + "," + target;
    if (enabled) assertRuleExists(output.rules, ruleLine);
    else assertRuleMissing(output.rules, ruleLine);
  }
}

function findGroup(output, groupName) {
  return output["proxy-groups"].find((group) => group.name === groupName);
}

function assertNameserverPolicyValue(output, domain, expectedValue) {
  assert.deepStrictEqual(output.dns["nameserver-policy"][domain], expectedValue);
}

function assertDomesticOfficeDirectCoverage(output, sandbox) {
  assertRulesExist(output.rules, DOMESTIC_OFFICE_DIRECT_RULES);
  assertRulesExist(output.rules, DOMESTIC_OFFICE_DIRECT_PROCESSES);

  for (const domain of DOMESTIC_OFFICE_DOMAINS) {
    assertNameserverPolicyValue(output, domain, sandbox.DOH_DOMESTIC);
  }
}

function assertCoreStrictRouting(output) {
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,claude," + CHAIN_GROUP_NAME);
  assertRuleMissing(output.rules, "PROCESS-NAME,Arc," + CHAIN_GROUP_NAME);
  assertRuleMissing(output.rules, "DOMAIN-SUFFIX,claude.ai,DIRECT");
}

function assertDnsAndSniffer(output, sandbox) {
  assertNameserverPolicyValue(output, "+.tailscale.com", sandbox.DOH_OVERSEAS);
  assertNameserverPolicyValue(output, "+.tailscale.io", sandbox.DOH_OVERSEAS);
  assertNameserverPolicyValue(output, "+.ts.net", sandbox.DOH_OVERSEAS);
  assertNameserverPolicyValue(output, "+.sora.com", sandbox.DOH_OVERSEAS);
  assertNameserverPolicyValue(output, "+.notebooklm.google", sandbox.DOH_OVERSEAS);
  assertNameserverPolicyValue(output, "+.m365.cloud.microsoft", sandbox.DOH_OVERSEAS);
  assert(output.dns["fake-ip-filter"].includes("+.xboxlive.com"));
  assert(output.dns["fake-ip-filter"].includes("stun.*.*"));
  assert(output.dns["fallback-filter"].domain.includes("+.sora.com"));
  assert(output.dns["fallback-filter"].domain.includes("+.youtube.com"));
  assert(output.sniffer["force-domain"].includes("+.claude.ai"));
  assert(output.sniffer["force-domain"].includes("+.google.com"));
  assert(output.sniffer["skip-domain"].includes("+.tailscale.com"));
  assert(output.sniffer["skip-domain"].includes("+.tailscale.io"));
  assert(output.sniffer["skip-domain"].includes("+.ts.net"));
}

function testDefaultConfig() {
  const { sandbox, output } = runMain(function (config) {
    config["proxy-groups"].push({
      name: LEGACY_GROUP_NAME,
      type: "select",
      proxies: ["错误旧组"],
    });
  });

  assert.strictEqual(sandbox.USER_OPTIONS.enableBrowserProcessProxy, false);
  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(
    output.proxies.find((proxy) => proxy.name === "自选节点 + 家宽IP")["dialer-proxy"],
    RELAY_GROUP_NAME,
  );

  assert(findGroup(output, CHAIN_GROUP_NAME), "Expected chain group to exist");
  assert(!findGroup(output, LEGACY_GROUP_NAME), "Legacy proxy group should be removed");

  assertCoreStrictRouting(output);
  assertDomesticOfficeDirectCoverage(output, sandbox);
  assertDnsAndSniffer(output, sandbox);
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 250));
  assertRulePrefix(output.rules, DEFAULT_DIRECT_RULE_PREFIX);
}

function testEnableBrowserProcessProxy() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.enableBrowserProcessProxy = true;
  });

  assertProcessRules(output, true, ["Arc", "Google Chrome", "Claude"], CHAIN_GROUP_NAME);
}

function testAiCliProcessProxyDefaultsOn() {
  const { output } = runMain();
  assertProcessRules(output, true, ["claude", "opencode", "gemini", "codex"], CHAIN_GROUP_NAME);
}

function testDisableAiCliProcessProxy() {
  const { output } = runMain(null, function (sandbox) {
    sandbox.USER_OPTIONS.enableAiCliProcessProxy = false;
  });

  assertProcessRules(output, false, ["claude", "opencode", "gemini", "codex"], CHAIN_GROUP_NAME);
}

function testMissingRegionFails() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.chainRegion = "US";
  const config = createBaseConfig();
  config.proxies = config.proxies.filter((proxy) => proxy.name.indexOf("🇸🇬") < 0);
  config["proxy-groups"] = [{ name: "节点选择", type: "select", proxies: ["🇭🇰 HK Auto 01"] }];

  assert.throws(
    () => sandbox.main(config),
    /未找到可用的 US 跳板节点或代理组/,
  );
}

function testInvalidManualNodeFails() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.manualNode = "不存在的节点";

  assert.throws(
    () => sandbox.main(createBaseConfig()),
    /manualNode 未命中现有节点或代理组/,
  );
}

function testMissingStrictTargetFails() {
  const sandbox = loadSandbox();
  const originalResolveRoutingTargets = sandbox.resolveRoutingTargets;
  sandbox.resolveRoutingTargets = function (config, region, manualNode) {
    const routingTargets = originalResolveRoutingTargets(config, region, manualNode);
    routingTargets.strictAiTarget = "错误目标";
    return routingTargets;
  };

  assert.throws(
    () => sandbox.main(createBaseConfig()),
    /域外 AI 与支撑平台未直接指向当前 chainRegion 出口/,
  );
}

testDefaultConfig();
testEnableBrowserProcessProxy();
testAiCliProcessProxyDefaultsOn();
testDisableAiCliProcessProxy();
testMissingRegionFails();
testInvalidManualNodeFails();
testMissingStrictTargetFails();

console.log("validate.js: all checks passed");
