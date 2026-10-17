"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const sync = require("../scripts/sync-community-rules");
const audit = require("../scripts/rule-routing-audit");

const root = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "rules", "community-sources.json"), "utf8"));
const snapshot = JSON.parse(fs.readFileSync(path.join(root, "rules", "community.snapshot.json"), "utf8"));
const script = fs.readFileSync(path.join(root, "src", "完全覆写.js"), "utf8");
const clone = value => JSON.parse(JSON.stringify(value));

function generatedConfig(bundles) {
  const sandbox = { console };
  vm.createContext(sandbox);
  vm.runInContext(sync.replaceGeneratedBlock(script, sync.renderBlock(bundles)), sandbox);
  return sandbox.main({ proxies: [{ name: "US test", type: "ss", server: "203.0.113.1", port: 443, udp: true }], "proxy-groups": [], rules: [] });
}

function testParsersPreserveScopeAndRejectUnsupportedData() {
  assert.deepStrictEqual(sync.parseRules("# example\napi.example.com\n+.example.com\n+.youtube\napi.example.com\n", "domain-list"), [
    { type: "DOMAIN-SUFFIX", value: "example.com" },
    { type: "DOMAIN-SUFFIX", value: "youtube" },
    { type: "DOMAIN", value: "api.example.com" }
  ]);
  assert.deepStrictEqual(sync.parseRules("payload:\n  - DOMAIN,API.EXAMPLE.COM\n  - 'DOMAIN-SUFFIX,example.com'\n", "classical-yaml"), [
    { type: "DOMAIN-SUFFIX", value: "example.com" },
    { type: "DOMAIN", value: "api.example.com" }
  ]);
  for (const input of ["<html>error</html>", "regexp:.*example", "*.example.com", "api.example.com/path", "203.0.113.1", "example.com,REJECT", ""]) {
    assert.throws(() => sync.parseRules(input, "domain-list"));
  }
  for (const input of ["payload:\n- PROCESS-NAME,Agent", "payload:\n- IP-CIDR,203.0.113.0/24", "payload:\n- DOMAIN,example.com,REJECT", "rules:\n- DOMAIN,example.com"]) {
    assert.throws(() => sync.parseRules(input, "classical-yaml"));
  }
}

function testPolicyDoesNotDependOnSourceOrder() {
  const reordered = clone(manifest);
  reordered.sources.reverse();
  assert.deepStrictEqual(sync.compileRules(reordered, snapshot).bundles, sync.compileRules(manifest, snapshot).bundles);
}

function testInvalidUpdatesAreRejected() {
  const missing = clone(snapshot);
  missing.sources.find(s => s.id === "meta-ai").rules = missing.sources.find(s => s.id === "meta-ai").rules.filter(r => r.value !== "muse.ai");
  assert.throws(() => sync.validateSnapshot(manifest, missing), /missing required rule/);
  const broad = clone(snapshot);
  broad.sources.find(s => s.id === "ai-core").rules.push({ type: "DOMAIN-SUFFIX", value: "facebook.com" });
  assert.throws(() => sync.validateSnapshot(manifest, broad), /shared vendor\/service/);
  const conflicting = clone(snapshot);
  conflicting.sources.find(s => s.id === "github").rules.push({ type: "DOMAIN-SUFFIX", value: "youtube.com" });
  assert.throws(() => sync.validateSnapshot(manifest, conflicting), /Conflicting service targets/);
  const brokenScope = clone(snapshot);
  brokenScope.sources.find(s => s.id === "meta-ai").rules.push({ type: "DOMAIN-SUFFIX", value: "meta.com" });
  assert.throws(() => sync.validateSnapshot(manifest, brokenScope), /shared vendor\/service/);
  const renamedSource = clone(manifest);
  renamedSource.sources[0].path = "changed.list";
  assert.throws(() => sync.validateSnapshot(renamedSource, snapshot), /Source definition changed/);
}

function testIncrementalAdditionsAndRemovalsPropagate() {
  const next = clone(snapshot);
  next.sources.find(s => s.id === "meta-ai").rules.push({ type: "DOMAIN-SUFFIX", value: "incremental-agent.example" });
  const delta = sync.diffSnapshots(snapshot, next);
  assert.deepStrictEqual(delta, [{ source: "meta-ai", added: ["DOMAIN-SUFFIX,incremental-agent.example"], removed: [] }]);
  assert.deepStrictEqual(sync.diffBundles(sync.validateSnapshot(manifest, snapshot).bundles, sync.validateSnapshot(manifest, next).bundles),
    [{ source: "ai", added: ["DOMAIN-SUFFIX,incremental-agent.example"], removed: [] }]);
  const output = generatedConfig(sync.validateSnapshot(manifest, next).bundles);
  assert.strictEqual(audit.route(output.rules, { domain: "api.incremental-agent.example", network: "tcp", port: 443 }).target, "🤖 AI Agent");
  assert.strictEqual(audit.route(output.rules, { domain: "api.incremental-agent.example", network: "udp", port: 443 }).target, "REJECT");
  assert(output.dns["nameserver-policy"]["+.incremental-agent.example"]);
  assert(output.dns["fallback-filter"].domain.includes("+.incremental-agent.example"));
  assert(output.sniffer["force-domain"].includes("+.incremental-agent.example"));
  assert.deepStrictEqual(sync.diffSnapshots(next, snapshot), [{ source: "meta-ai", added: [], removed: ["DOMAIN-SUFFIX,incremental-agent.example"] }]);
  const reverted = generatedConfig(sync.validateSnapshot(manifest, snapshot).bundles);
  assert.notStrictEqual(audit.route(reverted.rules, { domain: "api.incremental-agent.example", network: "tcp", port: 443 }).target, "🤖 AI Agent");
  assert.strictEqual(reverted.dns["nameserver-policy"]["+.incremental-agent.example"], undefined);
  assert(!reverted.sniffer["force-domain"].includes("+.incremental-agent.example"));
  const removed = clone(snapshot);
  const aiSource = removed.sources.find(s => s.id === "ai-core");
  aiSource.rules = aiSource.rules.filter(rule => rule.value !== "perplexity.com");
  const removedOutput = generatedConfig(sync.validateSnapshot(manifest, removed).bundles);
  assert.notStrictEqual(audit.route(removedOutput.rules, { domain: "perplexity.com", network: "tcp", port: 443 }).target, "🤖 AI Agent",
    "上游删除的域名不得通过旧的手工清单重新出现");
}

function testExactUpdatesDoNotExpandToSubdomains() {
  const next = clone(snapshot);
  next.sources.find(s => s.id === "meta-ai").rules.push({ type: "DOMAIN", value: "api.specific-agent.example" });
  const output = generatedConfig(sync.validateSnapshot(manifest, next).bundles);
  assert.strictEqual(audit.route(output.rules, { domain: "api.specific-agent.example", network: "tcp", port: 443 }).target, "🤖 AI Agent");
  assert.notStrictEqual(audit.route(output.rules, { domain: "child.api.specific-agent.example", network: "tcp", port: 443 }).target, "🤖 AI Agent");
  assert.strictEqual(audit.route(output.rules, { domain: "api.specific-agent.example", network: "udp", port: 443 }).target, "REJECT");
  assert.notStrictEqual(audit.route(output.rules, { domain: "child.api.specific-agent.example", network: "udp", port: 443 }).target, "REJECT");
  assert(output.dns["nameserver-policy"]["api.specific-agent.example"]);
  assert.strictEqual(output.dns["nameserver-policy"]["+.api.specific-agent.example"], undefined);
}

function testSnapshotsAreReproducible() {
  const result = sync.validateSnapshot(manifest, snapshot);
  assert.strictEqual(sync.replaceGeneratedBlock(script, sync.renderBlock(result.bundles)), script);
  assert.deepStrictEqual(sync.diffSnapshots(snapshot, clone(snapshot)), []);
  audit.assertRoutingCases(generatedConfig(result.bundles).rules, manifest.routingCases);
  const checker = require("../scripts/check-claude-rules");
  const configured = checker.extractConfiguredRules(script);
  assert(checker.domainCovered("claude.ai", configured.domainRules), "Claude 检查工具必须读取社区快照，而不只看本地补充");
  assert(checker.domainCovered("ai.developer.meta.com", configured.domainRules));
  assert(!checker.domainCovered("child.ai.developer.meta.com", configured.domainRules), "检查工具也必须保留精确域名的范围");
}

testParsersPreserveScopeAndRejectUnsupportedData();
testPolicyDoesNotDependOnSourceOrder();
testInvalidUpdatesAreRejected();
testIncrementalAdditionsAndRemovalsPropagate();
testExactUpdatesDoNotExpandToSubdomains();
testSnapshotsAreReproducible();
console.log("validate-community.js: 6 checks passed");
