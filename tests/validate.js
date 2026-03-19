const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(repoRoot, "src", "家宽IP-链式代理.js");
const scriptCode = fs.readFileSync(scriptPath, "utf8");

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

function testDefaultConfig() {
  const sandbox = loadSandbox();
  const config = createBaseConfig();
  const output = sandbox.main(config);
  const chainGroupName = "🇸🇬|新加坡-链式代理-家宽IP出口";

  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(
    output.proxies.find((proxy) => proxy.name === "自选节点 + 家宽IP")["dialer-proxy"],
    "🇸🇬|新加坡线路-链式代理-跳板",
  );
  assert(output["proxy-groups"].some((group) => group.name === chainGroupName));
  assert(output.rules[0].startsWith("PROCESS-NAME,Tailscale,DIRECT"));
  assert(output.rules.includes("DOMAIN-SUFFIX,claude.ai," + chainGroupName));
  assert(!output.rules.includes("DOMAIN-SUFFIX,claude.ai,DIRECT"));
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 200));

  assert.deepStrictEqual(
    output.dns["nameserver-policy"]["+.tailscale.com"],
    sandbox.DOH_OVERSEAS,
  );
  assert.deepStrictEqual(
    output.dns["nameserver-policy"]["+.sora.com"],
    sandbox.DOH_OVERSEAS,
  );
  assert.deepStrictEqual(
    output.dns["nameserver-policy"]["+.notebooklm.google"],
    sandbox.DOH_OVERSEAS,
  );
  assert.deepStrictEqual(
    output.dns["nameserver-policy"]["+.m365.cloud.microsoft"],
    sandbox.DOH_OVERSEAS,
  );
  assert(output.dns["fake-ip-filter"].includes("+.xboxlive.com"));
  assert(output.dns["fake-ip-filter"].includes("stun.*.*"));
  assert(output.dns["fallback-filter"].domain.includes("+.sora.com"));
  assert(output.sniffer["skip-domain"].includes("+.tailscale.com"));
}

function testDisableBrowserProcessProxy() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.enableBrowserProcessProxy = false;
  const output = sandbox.main(createBaseConfig());

  assert(!output.rules.includes("PROCESS-NAME,Arc,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(!output.rules.includes("PROCESS-NAME,Google Chrome,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(output.rules.includes("PROCESS-NAME,Claude,🇸🇬|新加坡-链式代理-家宽IP出口"));
}

function testAiCliProcessProxyDefaultsOn() {
  const sandbox = loadSandbox();
  const output = sandbox.main(createBaseConfig());

  assert(output.rules.includes("PROCESS-NAME,claude,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(output.rules.includes("PROCESS-NAME,opencode,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(output.rules.includes("PROCESS-NAME,gemini,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(output.rules.includes("PROCESS-NAME,codex,🇸🇬|新加坡-链式代理-家宽IP出口"));
}

function testDisableAiCliProcessProxy() {
  const sandbox = loadSandbox();
  sandbox.USER_OPTIONS.enableAiCliProcessProxy = false;
  const output = sandbox.main(createBaseConfig());

  assert(!output.rules.includes("PROCESS-NAME,claude,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(!output.rules.includes("PROCESS-NAME,opencode,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(!output.rules.includes("PROCESS-NAME,gemini,🇸🇬|新加坡-链式代理-家宽IP出口"));
  assert(!output.rules.includes("PROCESS-NAME,codex,🇸🇬|新加坡-链式代理-家宽IP出口"));
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

testDefaultConfig();
testDisableBrowserProcessProxy();
testAiCliProcessProxyDefaultsOn();
testDisableAiCliProcessProxy();
testMissingRegionFails();
testInvalidManualNodeFails();

console.log("validate.js: all checks passed");
