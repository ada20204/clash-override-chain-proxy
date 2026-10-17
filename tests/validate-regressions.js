"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const acorn = require("acorn");
const { route } = require("../scripts/rule-routing-audit");
const source = fs.readFileSync(path.join(__dirname, "../src/完全覆写.js"), "utf8");
acorn.parse(source, { ecmaVersion: 5 });

function generate(mutate = () => {}, options = () => {}) {
  const sandbox = { console };
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox);
  options(sandbox.USER_OPTIONS);
  const config = {
    proxies: ["US A", "JP B"].map((name, index) => ({
      name, type: "ss", server: "192.0.2." + (index + 1), port: 8388,
      cipher: "aes-128-gcm", password: "fixture", udp: true
    })),
    "proxy-groups": [{ name: "自动选择", type: "url-test", proxies: ["US A", "JP B"],
      url: "https://www.gstatic.com/generate_204", interval: 300 }],
    rules: [],
    _homeProxy: { server: "203.0.113.5", port: 8080 }
  };
  mutate(config);
  return JSON.parse(JSON.stringify(sandbox.main(config)));
}

function testInterfaceBindingAcrossRoles() {
  for (const field of ["interfaceName", "interface-name"]) {
    for (const location of ["cn", "overseas"]) {
      const config = generate(input => {
        const credentials = { server: "203.0.113.5", port: 8443, type: "http",
          username: "user", password: "fixture", tls: true, [field]: "Tailscale" };
        input._homeProxy = { ...credentials };
        input._frontProxy = { ...credentials, name: "legacy-front" };
        input._customProxies = [{ ...credentials, name: "custom", via: "DIRECT" }];
      }, options => { options.location = location; });
      for (const name of ["家宽IP", "家宽IP链式", "legacy-front", "custom"]) {
        const node = config.proxies.find(p => p.name === name);
        assert.strictEqual(node["interface-name"], "Tailscale", name + " must retain interface binding");
        assert.strictEqual(node.interfaceName, undefined);
        assert.strictEqual(node.tls, true);
        assert.strictEqual(node.username, "user");
        assert.strictEqual(node.password, "fixture");
        assert.strictEqual(node["dialer-proxy"], name === "家宽IP链式" ? "🔗 家宽跳板" : name === "custom" ? "DIRECT" : undefined);
      }
    }
  }
}

testInterfaceBindingAcrossRoles();

function testSharedCdnIsNotAnAiService() {
  for (const location of ["cn", "overseas"]) {
    const config = generate(() => {}, options => { options.location = location; });
    for (const network of ["tcp", "udp"]) {
      const shared = route(config.rules, { domain: "shop.example.com.cdn.cloudflare.net", port: 443, network });
      assert.strictEqual(shared.target, "🐟 兜底", "shared CDN must not inherit AI routing or QUIC rejection");
      for (const domain of ["anthropic.com.cdn.cloudflare.net", "openai.com.cdn.cloudflare.net"]) {
        assert.strictEqual(route(config.rules, { domain, port: 443, network }).target, network === "udp" ? "REJECT" : "🤖 AI Agent");
      }
    }
    assert.strictEqual(config.dns["nameserver-policy"]["+.cdn.cloudflare.net"], undefined);
    assert(!config.sniffer["force-domain"].includes("+.cdn.cloudflare.net"));
    assert(!((config.dns["fallback-filter"] || {}).domain || []).includes("+.cdn.cloudflare.net"));
    assert(config.sniffer["force-domain"].includes("+.anthropic.com.cdn.cloudflare.net"));
  }
}

testSharedCdnIsNotAnAiService();

function testLocalDestinationsBeforeApplicationRules() {
  for (const location of ["cn", "overseas"]) for (const home of [true, false]) {
    for (const custom of [true, false]) for (const monitor of [true, false]) {
      const config = generate(input => {
        if (!home) delete input._homeProxy;
        if (custom) input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"],
          rules: ["DOMAIN-SUFFIX,business.example", "IP-CIDR,10.20.0.0/16,no-resolve"] }];
      }, options => {
        options.location = location;
        options.enableChainRegionBrowserProcessProxy = true;
        options.tailscale.monitorGroups = monitor;
        options.tailscale.subnetCidrs = ["192.168.88.0/24", "fd00:abcd::/64"];
      });
      for (const process of ["chrome.exe", "claude", "Antigravity.exe"]) {
        for (const [domain, target] of [["login.tailscale.com", monitor ? "🧩 Tailscale 控制面" : "DIRECT"],
          ["host.example.ts.net", monitor ? "🧩 Tailnet 内部直连" : "DIRECT"]]) {
          assert.strictEqual(route(config.rules, { domain, network: "tcp", port: 443, process }).target, target);
        }
        const processIndex = config.rules.indexOf("PROCESS-NAME," + process + ",🤖 AI Agent");
        assert(processIndex >= 0);
        for (const prefix of ["IP-CIDR,192.168.0.0/16,", "IP-CIDR,10.0.0.0/8,", "IP-CIDR6,fc00::/7,",
          "IP-CIDR,100.64.0.0/10,", "IP-CIDR6,fd7a:115c:a1e0::/48,", "IP-CIDR,192.168.88.0/24,"]) {
          const index = config.rules.findIndex(rule => rule.startsWith(prefix));
          assert(index >= 0 && index < processIndex, prefix + " must precede application rules");
        }
      }
      assert(config.rules.findIndex(r => r.startsWith("IP-CIDR,192.168.88.0/24,")) <
        config.rules.findIndex(r => r.startsWith("IP-CIDR,192.168.0.0/16,")), "Tailnet subnet monitoring must not be shadowed by generic private ranges");
      if (custom) assert(config.rules.indexOf("IP-CIDR,10.20.0.0/16,business,no-resolve") <
        config.rules.indexOf("IP-CIDR,10.0.0.0/8,🎯 直连,no-resolve"), "explicit business subnet must remain effective");
      const youtube = config.rules.indexOf("DOMAIN-SUFFIX,youtubei.googleapis.com,🌍 国际媒体");
      assert(youtube >= 0 && youtube < config.rules.indexOf("GEOSITE,google,🤖 AI Agent"), "custom groups must not reorder YouTube behind Google");
    }
  }
}

testLocalDestinationsBeforeApplicationRules();

function testSubscriptionDependencyClosure() {
  for (const type of ["url-test", "smart"]) {
    const config = generate(input => {
      const auto = input["proxy-groups"][0];
      auto.type = type;
      if (type === "smart") auto.name += "(Smart Group)";
      auto.proxies = ["nested"];
      input["proxy-groups"].push(
        { name: "nested", type: "select", proxies: ["US A"] },
        { name: "upstream", type: "select", proxies: ["JP B"] },
        { name: "unused", type: "select", proxies: ["JP B"] }
      );
      input.proxies[0]["dialer-proxy"] = "upstream";
    });
    assert.deepStrictEqual(config["proxy-groups"].find(g => g.name === "nested").proxies, ["US A"]);
    assert.deepStrictEqual(config["proxy-groups"].find(g => g.name === "upstream").proxies, ["JP B"]);
    assert(!config["proxy-groups"].some(g => g.name === "unused"));
    assert.strictEqual(config.proxies.find(p => p.name === "US A")["dialer-proxy"], "upstream");
    assert(!config.proxies.some(p => p.name === "⤴ US A"), "explicit upstream must not be stripped");
    assert(config.proxies.some(p => p.name === "⤴ JP B" && !p["dialer-proxy"]));
  }
}

testSubscriptionDependencyClosure();

function testDependencyFailuresAreStillRejected() {
  assert.throws(() => generate(input => { input.proxies[0]["dialer-proxy"] = "missing"; }), /代理引用不存在/);
  assert.throws(() => generate(input => {
    input.proxies[0]["dialer-proxy"] = "loop";
    input["proxy-groups"].push({ name: "loop", type: "select", proxies: ["US A"] });
  }), /循环引用/);
  assert.throws(() => generate(input => {
    input.proxies[0]["dialer-proxy"] = "节点选择";
    input["proxy-groups"].push({ name: "节点选择", type: "select", proxies: ["JP B"] });
  }), /订阅依赖组与覆写名称冲突/);
}

function testCustomRulesPreserveManagedOrderAndOptionalSwitches() {
  for (const location of ["cn", "overseas"]) for (const home of [true, false]) {
    for (const enabled of [true, false]) {
      const mutate = input => { if (!home) delete input._homeProxy; };
      const options = opts => {
        opts.location = location;
        opts.tailscale.enable = enabled;
        opts.enableChainRegionBrowserProcessProxy = enabled;
        opts.enableChainRegionAiCliProcessProxy = enabled;
        opts.rejectAiQuic = enabled;
      };
      const original = generate(mutate, options);
      const withCustom = generate(input => {
        mutate(input);
        input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"], rules: ["DOMAIN,business.example"] }];
      }, options);
      assert.deepStrictEqual(withCustom.rules.filter(rule => rule !== "DOMAIN,business.example,business"), original.rules,
        "an unrelated business group must not change managed rule order");
      assert.strictEqual(original.rules.includes("PROCESS-NAME,chrome.exe,🤖 AI Agent"), enabled);
      assert.strictEqual(original.rules.includes("PROCESS-NAME,claude,🤖 AI Agent"), enabled);
      assert.strictEqual(original.rules.some(r => r.startsWith("DOMAIN-SUFFIX,ts.net,")), enabled);
      assert.strictEqual(route(original.rules, { domain: "claude.ai", port: 443, network: "udp" }).target,
        enabled ? "REJECT" : "🤖 AI Agent");
    }
  }
}

testDependencyFailuresAreStillRejected();
testCustomRulesPreserveManagedOrderAndOptionalSwitches();

function testOnlyPrivateCustomNetworksArePromoted() {
  const publicRules = ["IP-CIDR,160.79.104.0/24,no-resolve", "IP-CIDR,0.0.0.0/0,no-resolve",
    "IP-CIDR6,2607:6bc0::/48,no-resolve", "IP-CIDR6,fc00::/6,no-resolve"];
  const privateRules = ["IP-CIDR,172.16.4.0/24,no-resolve", "IP-CIDR,192.168.4.0/24,no-resolve",
    "IP-CIDR6,fd12:3456::/48,no-resolve", "IP-CIDR6,fe80::1234/128,no-resolve"];
  const config = generate(input => {
    input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"], rules: publicRules.concat(privateRules) }];
  });
  const aiIndex = config.rules.indexOf("PROCESS-NAME,claude,🤖 AI Agent");
  for (const rule of publicRules) {
    assert(config.rules.indexOf(rule.replace(",no-resolve", ",business,no-resolve")) > aiIndex,
      "public or overbroad custom ranges must not bypass AI priority: " + rule);
  }
  for (const rule of privateRules) {
    assert(config.rules.indexOf(rule.replace(",no-resolve", ",business,no-resolve")) <
      config.rules.indexOf("IP-CIDR,10.0.0.0/8,🎯 直连,no-resolve"), "private exceptions must precede generic private rules");
  }
}

testOnlyPrivateCustomNetworksArePromoted();

function testForcedExitAndTailnetBoundaries() {
  for (const custom of [true, false]) {
    const config = generate(input => {
      if (custom) input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"], rules: ["DOMAIN,business.example"] }];
    }, options => { options.tailscale.forceExitNodeTraffic = true; });
    const forced = config.rules.indexOf("SRC-IP-CIDR,100.64.0.0/10,🧩 Tailscale Exit Node,no-resolve");
    assert(forced > config.rules.indexOf("IP-CIDR,192.168.0.0/16,🎯 直连,no-resolve"));
    assert(forced < config.rules.indexOf("PROCESS-NAME,claude,🤖 AI Agent"));
  }
  assert.throws(() => generate(input => {
    input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"], rules: ["IP-CIDR,10.0.0.0/8,no-resolve"] }];
  }, options => { options.tailscale.subnetCidrs = ["10.0.0.0/8"]; }), /受保护/,
  "Tailnet protection must survive overlap with a generic private range");
}

testForcedExitAndTailnetBoundaries();

function testReplacingAllPrivateDefaultsKeepsExceptionsBeforeProcesses() {
  const config = generate(input => {
    input._customRuleGroups = [{ name: "business", proxies: ["DIRECT"], rules: [
      "IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,172.16.0.0/12,no-resolve",
      "IP-CIDR,192.168.0.0/16,no-resolve", "IP-CIDR,169.254.0.0/16,no-resolve",
      "IP-CIDR,127.0.0.0/8,no-resolve", "IP-CIDR6,::1/128,no-resolve",
      "IP-CIDR6,fc00::/7,no-resolve", "IP-CIDR6,fe80::/10,no-resolve"
    ] }];
  });
  assert(config.rules.indexOf("IP-CIDR,10.0.0.0/8,business,no-resolve") <
    config.rules.indexOf("PROCESS-NAME,claude,🤖 AI Agent"), "removing every default must not remove the network priority boundary");
}

testReplacingAllPrivateDefaultsKeepsExceptionsBeforeProcesses();
console.log("validate-regressions: ok");
