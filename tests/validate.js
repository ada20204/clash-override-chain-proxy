const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(repoRoot, "src", "家宽IP-链式代理.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

const CHAIN_GROUP_NAME = "🇸🇬|新加坡-链式代理-家宽IP出口";
const RELAY_GROUP_NAME = "🇸🇬|新加坡线路-链式代理-跳板";
const LEGACY_STRICT_AI_GROUP_NAME = "AI 严格链式代理";

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

function assertRulePrefix(actualRules, expectedPrefix) {
  const actualPrefix = Array.prototype.slice.call(actualRules, 0, expectedPrefix.length);
  assert.strictEqual(JSON.stringify(actualPrefix), JSON.stringify(expectedPrefix));
}

function assertRuleExists(ruleLines, ruleLine) {
  assert(ruleLines.includes(ruleLine), "Expected rule not found: " + ruleLine);
}

function assertRuleMissing(ruleLines, ruleLine) {
  assert(!ruleLines.includes(ruleLine), "Unexpected rule found: " + ruleLine);
}

function findGroup(output, groupName) {
  return output["proxy-groups"].find((group) => group.name === groupName);
}

function assertNameserverPolicyOverseas(output, sandbox, domain) {
  assert.deepStrictEqual(output.dns["nameserver-policy"][domain], sandbox.DOH_OVERSEAS);
}

function assertProcessRuleToggle(output, enabled, processName, target) {
  const ruleLine = "PROCESS-NAME," + processName + "," + target;
  if (enabled) assertRuleExists(output.rules, ruleLine);
  else assertRuleMissing(output.rules, ruleLine);
}

function assertProcessRules(output, enabled, processNames, target) {
  for (const processName of processNames) {
    assertProcessRuleToggle(output, enabled, processName, target);
  }
}

function testDefaultStrictConfig() {
  const sandbox = loadSandbox();
  const config = createBaseConfig();
  config["proxy-groups"].push({
    name: LEGACY_STRICT_AI_GROUP_NAME,
    type: "select",
    proxies: ["错误旧组"],
  });
  const output = sandbox.main(config);

  assert.strictEqual(sandbox.USER_OPTIONS.strictAiRouting, true);
  assert.strictEqual(sandbox.USER_OPTIONS.enableBrowserProcessProxy, false);
  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(
    output.proxies.find((proxy) => proxy.name === "自选节点 + 家宽IP")["dialer-proxy"],
    RELAY_GROUP_NAME,
  );

  const chainGroup = findGroup(output, CHAIN_GROUP_NAME);
  assert(chainGroup, "Expected chain group to exist");
  assert(!findGroup(output, LEGACY_STRICT_AI_GROUP_NAME), "Legacy strict AI group should be removed");

  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,claude," + CHAIN_GROUP_NAME);
  assertRuleMissing(output.rules, "PROCESS-NAME,Arc," + CHAIN_GROUP_NAME);
  assertRuleMissing(output.rules, "DOMAIN-SUFFIX,claude.ai,DIRECT");
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 250));

  assertRulePrefix(output.rules, [
    "PROCESS-NAME,Tailscale,DIRECT",
    "PROCESS-NAME,tailscale,DIRECT",
    "PROCESS-NAME,tailscaled,DIRECT",
    "PROCESS-NAME,IPNExtension,DIRECT",
    "PROCESS-NAME,io.tailscale.ipn.macos.network-extension,DIRECT",
    "PROCESS-NAME,io.tailscale.ipn.macsys.network-extension,DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
    "DOMAIN-SUFFIX,tongyi.aliyun.com,DIRECT",
    "DOMAIN-SUFFIX,qianwen.aliyun.com,DIRECT",
    "DOMAIN-SUFFIX,dashscope.aliyuncs.com,DIRECT",
    "DOMAIN-SUFFIX,moonshot.cn,DIRECT",
    "DOMAIN-SUFFIX,chatglm.cn,DIRECT",
    "DOMAIN-SUFFIX,zhipuai.cn,DIRECT",
    "DOMAIN-SUFFIX,bigmodel.cn,DIRECT",
    "DOMAIN-SUFFIX,siliconflow.cn,DIRECT",
    "DOMAIN-SUFFIX,tailscale.com,DIRECT",
    "DOMAIN-SUFFIX,tailscale.io,DIRECT",
    "DOMAIN-SUFFIX,ts.net,DIRECT",
  ]);

  assertNameserverPolicyOverseas(output, sandbox, "+.tailscale.com");
  assertNameserverPolicyOverseas(output, sandbox, "+.tailscale.io");
  assertNameserverPolicyOverseas(output, sandbox, "+.ts.net");
  assertNameserverPolicyOverseas(output, sandbox, "+.sora.com");
  assertNameserverPolicyOverseas(output, sandbox, "+.notebooklm.google");
  assertNameserverPolicyOverseas(output, sandbox, "+.m365.cloud.microsoft");
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

function testCompatibilityMode() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.strictAiRouting = false;
  const config = createBaseConfig();
  config["proxy-groups"].push({
    name: LEGACY_STRICT_AI_GROUP_NAME,
    type: "select",
    proxies: ["错误旧组"],
  });
  const output = sandbox.main(config);

  assert(!findGroup(output, LEGACY_STRICT_AI_GROUP_NAME), "Compatibility mode should remove legacy strict AI group");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude," + CHAIN_GROUP_NAME);
  assertRuleExists(output.rules, "PROCESS-NAME,claude," + CHAIN_GROUP_NAME);
  assertNameserverPolicyOverseas(output, sandbox, "+.sora.com");
  assert(output.dns["fallback-filter"].domain.includes("+.sora.com"));
  assert(output.sniffer["force-domain"].includes("+.claude.ai"));
}

function testEnableBrowserProcessProxy() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.enableBrowserProcessProxy = true;
  const output = sandbox.main(createBaseConfig());

  assertProcessRuleToggle(output, true, "Arc", CHAIN_GROUP_NAME);
  assertProcessRuleToggle(output, true, "Google Chrome", CHAIN_GROUP_NAME);
  assertProcessRuleToggle(output, true, "Claude", CHAIN_GROUP_NAME);
}

function testAiCliProcessProxyDefaultsOn() {
  const sandbox = loadSandbox();
  const output = sandbox.main(createBaseConfig());

  assertProcessRules(
    output,
    true,
    ["claude", "opencode", "gemini", "codex"],
    CHAIN_GROUP_NAME,
  );
}

function testDisableAiCliProcessProxy() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.enableAiCliProcessProxy = false;
  const output = sandbox.main(createBaseConfig());

  assertProcessRules(
    output,
    false,
    ["claude", "opencode", "gemini", "codex"],
    CHAIN_GROUP_NAME,
  );
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

function testMissingStrictAiTargetFails() {
  const sandbox = loadSandbox();
  sandbox.resolveStrictAiTarget = function () {
    return "错误目标";
  };

  assert.throws(
    () => sandbox.main(createBaseConfig()),
    /严格 AI 路由未直接指向当前 chainRegion 出口/,
  );
}

testDefaultStrictConfig();
testCompatibilityMode();
testEnableBrowserProcessProxy();
testAiCliProcessProxyDefaultsOn();
testDisableAiCliProcessProxy();
testMissingRegionFails();
testInvalidManualNodeFails();
testMissingStrictAiTargetFails();

console.log("validate.js: all checks passed");
