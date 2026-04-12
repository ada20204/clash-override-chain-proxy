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
  chainGroupName:  "🏠家宽IP",
  homeNodeName:    "家宽IP",
  relayGroupName:  "自动选择(Smart Group)",
  mediaGroupName:  "🌍 国际媒体"
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

// ─── tests ───────────────────────────────────────────────────────────────────

function testDefaultConfig() {
  const { output } = runMain();

  // 凭证不输出到最终配置
  assert.strictEqual(output._homeProxy, undefined);

  // 家宽IP节点正确注入
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert(homeNode, "家宽IP节点应存在");
  assert.strictEqual(homeNode.type,   TEST_HOME_CREDENTIALS.type);
  assert.strictEqual(homeNode.server, TEST_HOME_CREDENTIALS.server);
  assert.strictEqual(homeNode.port,   TEST_HOME_CREDENTIALS.port);
  assert.strictEqual(homeNode["dialer-proxy"], "🔗 家宽跳板",
    "家宽IP节点的 dialer-proxy 应指向家宽跳板组");

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
  assert.strictEqual(chainGroup.proxies.length, 1);
  assert.strictEqual(chainGroup.proxies[0], EXPECTED.homeNodeName);

  // 国际媒体组存在且为 select 类型，不含家宽IP节点
  const mediaGroup = output["proxy-groups"].find(function (g) { return g.name === EXPECTED.mediaGroupName; });
  assert(mediaGroup, "国际媒体组应存在");
  assert.strictEqual(mediaGroup.type, "select");
  assert(mediaGroup.proxies.indexOf("节点选择") >= 0, "国际媒体应包含节点选择");
  assert(mediaGroup.proxies.indexOf(EXPECTED.homeNodeName) < 0, "媒体组不应含家宽IP节点");

  // 功能分组存在
  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  ["🐙 GitHub", "📲 Telegram", "🌍 国际媒体", "🎮 游戏平台", "🍎 Apple", "🎯 直连"].forEach(function (name) {
    assert(groupNames.indexOf(name) >= 0, name + " 组应存在");
  });

  // 关键 AI 规则指向家宽IP出口
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,claude.ai,"   + EXPECTED.chainGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,chatgpt.com," + EXPECTED.chainGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,google.com,"  + EXPECTED.chainGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,Claude,"       + EXPECTED.chainGroupName);
  assertRuleExists(output.rules, "PROCESS-NAME,claude,"       + EXPECTED.chainGroupName);

  // 媒体规则指向媒体组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com," + EXPECTED.mediaGroupName);
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,netflix.com," + EXPECTED.mediaGroupName);

  // Telegram / GitHub / Steam 各走专用组
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,telegram.org,📲 Telegram");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,steampowered.com,🎮 游戏平台");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,apple.com,🍎 Apple");

  // 兜底 MATCH
  assertRuleExists(output.rules, "MATCH,节点选择");

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
  const chainGroup = output["proxy-groups"].find(function (g) { return g.name === "家宽IP出口"; });
  assert(!chainGroup, "纯分流模式不应创建家宽出口组");

  // 功能组仍正常存在
  const groupNames = output["proxy-groups"].map(function (g) { return g.name; });
  ["🐙 GitHub", "📲 Telegram", "🌍 国际媒体", "🎮 游戏平台", "🍎 Apple", "🎯 直连"].forEach(function (name) {
    assert(groupNames.indexOf(name) >= 0, name + " 组应存在");
  });

  // 无 AI 进程规则（无家宽出口目标）
  var hasProcessRule = output.rules.some(function (r) { return r.indexOf("PROCESS-NAME,Claude,") >= 0; });
  assert(!hasProcessRule, "纯分流模式不应有 AI 进程规则");

  // 域名规则正常
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,youtube.com,🌍 国际媒体");
  assertRuleExists(output.rules, "DOMAIN-SUFFIX,github.com,🐙 GitHub");
  assertRuleExists(output.rules, "MATCH,节点选择");
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
  assert.strictEqual(homeNode["dialer-proxy"], "🔗 家宽跳板", "回退时 dialer-proxy 应指向家宽跳板组");
}

function testAutoCreateUrlTestGroup() {
  // Smart Group 和 url-test 都不存在 → 应自建 url-test
  const { output } = runMain(function (config) {
    config["proxy-groups"] = config["proxy-groups"].filter(function (g) {
      return g.name !== "自动选择(Smart Group)" && g.name !== "自动选择";
    });
  });
  const homeNode = output.proxies.find(function (p) { return p.name === EXPECTED.homeNodeName; });
  assert.strictEqual(homeNode["dialer-proxy"], "🔗 家宽跳板", "自建时 dialer-proxy 应指向家宽跳板组");
  const autoGroup = output["proxy-groups"].find(function (g) { return g.name === "自动选择"; });
  assert(autoGroup, "自动选择组应被自动创建");
  assert.strictEqual(autoGroup.type, "url-test");
  assert(autoGroup.proxies.length > 0, "自建组应包含订阅节点");
}

// ─── run ─────────────────────────────────────────────────────────────────────

testDefaultConfig();
testNoCredentialPureOverwrite();
testFallbackToUrlTestGroup();
testAutoCreateUrlTestGroup();
testAuthCredentials();
testCustomProxiesAppearInGlobal();

console.log("validate-direct.js: all checks passed");
