#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const net = require("net");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "rules", "community-sources.json");
const SNAPSHOT_PATH = path.join(ROOT, "rules", "community.snapshot.json");
const SCRIPT_PATH = path.join(ROOT, "src", "完全覆写.js");
const HISTORY_PATH = path.join(ROOT, "rules", "community-update-history.json");
const BEGIN = "// BEGIN GENERATED COMMUNITY RULES";
const END = "// END GENERATED COMMUNITY RULES";
const TARGETS = ["ai", "media", "telegram", "github"];

function identity(rule) { return rule.type + "," + rule.value; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function encodePath(value) { return value.split("/").map(encodeURIComponent).join("/"); }

function validateDomain(value, allowTld) {
  if (typeof value !== "string" || net.isIP(value) || value.length > 253 || (!allowTld && !value.includes("."))) {
    throw new Error("Invalid domain: " + value);
  }
  if (!value.split(".").every(part => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(part))) {
    throw new Error("Unsupported domain pattern: " + value);
  }
  return value.toLowerCase();
}

function parseRules(text, format) {
  const rules = [];
  const seen = new Set();
  let payload = false;
  for (let line of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;
    let type;
    let value;
    if (format === "domain-list") {
      type = line.startsWith("+.") ? "DOMAIN-SUFFIX" : "DOMAIN";
      value = type === "DOMAIN-SUFFIX" ? line.slice(2) : line;
    } else if (format === "classical-yaml") {
      if (line === "payload:") { payload = true; continue; }
      if (!payload || !line.startsWith("- ")) throw new Error("Unexpected YAML entry: " + line);
      line = line.slice(2).trim();
      if ((line.startsWith("'") && line.endsWith("'")) || (line.startsWith('"') && line.endsWith('"'))) {
        line = line.slice(1, -1);
      }
      const parts = line.split(",");
      if (parts.length !== 2 || !["DOMAIN", "DOMAIN-SUFFIX"].includes(parts[0])) {
        throw new Error("Unsupported classical rule; review before importing: " + line);
      }
      [type, value] = parts;
    } else {
      throw new Error("Unsupported source format: " + format);
    }
    const rule = { type, value: validateDomain(value, type === "DOMAIN-SUFFIX") };
    const key = identity(rule);
    if (!seen.has(key)) { seen.add(key); rules.push(rule); }
  }
  if (!rules.length) throw new Error("Empty rule source");
  return rules.sort((a, b) => identity(a).localeCompare(identity(b), "en"));
}

function assertRequired(source, rules) {
  const keys = new Set(rules.map(identity));
  for (const required of source.required || []) {
    if (!keys.has(required)) throw new Error(source.id + " is missing required rule " + required);
  }
}

function domainMatches(rule, domain) {
  return rule.value === domain || (rule.type === "DOMAIN-SUFFIX" && domain.endsWith("." + rule.value));
}

function compileRules(manifest, snapshot) {
  const bundles = Object.fromEntries(TARGETS.map(target => [target, []]));
  const skipped = [];
  const seen = new Map();
  const expectedIds = manifest.sources.map(source => source.id);
  if (snapshot.sources.length !== expectedIds.length || snapshot.sources.some(s => !expectedIds.includes(s.id))) {
    throw new Error("Source manifest changed; refresh the snapshot before rendering");
  }
  // AI rules take precedence over broad vendor sets, regardless of manifest order.
  const ordered = manifest.sources.filter(s => s.target === "ai").concat(manifest.sources.filter(s => s.target !== "ai"));
  for (const source of ordered) {
    if (!TARGETS.includes(source.target)) throw new Error("Unsupported target: " + source.target);
    const stored = snapshot.sources.find(s => s.id === source.id);
    if (!stored || stored.repository !== source.repository || stored.path !== source.path || stored.format !== source.format) {
      throw new Error("Source definition changed: " + source.id + "; run --refresh");
    }
    assertRequired(source, stored.rules);
    for (const input of stored.rules) {
      if (!["DOMAIN", "DOMAIN-SUFFIX"].includes(input.type)) throw new Error("Unsupported rule type: " + input.type);
      const rule = { type: input.type, value: validateDomain(input.value, input.type === "DOMAIN-SUFFIX") };
      const key = identity(rule);
      if (source.target === "ai" && Object.hasOwn(manifest.excludedAiDomains, rule.value)) {
        skipped.push({ source: source.id, rule: key, reason: manifest.excludedAiDomains[rule.value] });
        continue;
      }
      if (source.target === "ai" && manifest.forbiddenAiSuffixes.includes(rule.value)) {
        throw new Error("AI source contains a shared vendor/service suffix: " + key);
      }
      if ((manifest.aiOverrides[source.target] || []).includes(rule.value)) {
        if (!seen.has(key) || seen.get(key) !== "ai") throw new Error("Missing AI override for " + key);
        skipped.push({ source: source.id, rule: key, reason: "Dedicated AI service has priority over the ordinary service set." });
        continue;
      }
      if (seen.has(key)) {
        if (seen.get(key) !== source.target) throw new Error("Conflicting service targets for " + key);
        continue;
      }
      seen.set(key, source.target);
      bundles[source.target].push(rule);
    }
  }
  for (const rules of Object.values(bundles)) rules.sort((a, b) => identity(a).localeCompare(identity(b), "en"));
  for (const example of manifest.routingCases) {
    const matched = TARGETS.find(target => bundles[target].some(rule => domainMatches(rule, example.domain)));
    if (matched !== example.target) throw new Error("Routing boundary failed: " + example.domain + " -> " + matched + ", expected " + example.target);
  }
  return { bundles, skipped };
}

function renderBlock(bundles) {
  const lines = [BEGIN, "// Generated by scripts/sync-community-rules.js; edit sources/policy, not this block.", "var COMMUNITY_RULES = {"];
  TARGETS.forEach((target, index) => {
    lines.push('  "' + target + '": [');
    bundles[target].forEach((rule, ruleIndex) => {
      lines.push("    " + JSON.stringify([rule.type, rule.value]) + (ruleIndex + 1 < bundles[target].length ? "," : ""));
    });
    lines.push("  ]" + (index + 1 < TARGETS.length ? "," : ""));
  });
  lines.push("};", END);
  return lines.join("\n");
}

function replaceGeneratedBlock(script, block) {
  const start = script.indexOf(BEGIN);
  const end = script.indexOf(END);
  if (start < 0 || end < start || script.indexOf(BEGIN, start + BEGIN.length) >= 0 || script.indexOf(END, end + END.length) >= 0) {
    throw new Error("Expected exactly one generated block in the override script");
  }
  const newline = script.includes("\r\n") ? "\r\n" : "\n";
  return script.slice(0, start) + block.replace(/\n/g, newline) + script.slice(end + END.length);
}

function diffSnapshots(previous, next) {
  const changes = [];
  const ids = new Set([...(previous ? previous.sources.map(s => s.id) : []), ...next.sources.map(s => s.id)]);
  for (const id of ids) {
    const before = new Set((previous && previous.sources.find(s => s.id === id) || { rules: [] }).rules.map(identity));
    const after = new Set((next.sources.find(s => s.id === id) || { rules: [] }).rules.map(identity));
    const added = [...after].filter(key => !before.has(key));
    const removed = [...before].filter(key => !after.has(key));
    if (added.length || removed.length) changes.push({ source: id, added, removed });
  }
  return changes;
}

function diffBundles(previous, next) {
  function asSnapshot(bundles) {
    return { sources: TARGETS.map(target => ({ id: target, rules: (bundles[target] || []).map(rule => Array.isArray(rule) ? { type: rule[0], value: rule[1] } : rule) })) };
  }
  return diffSnapshots(asSnapshot(previous), asSnapshot(next));
}

function requestText(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { "User-Agent": "clash-community-rule-sync/1.0", Accept: "application/vnd.github+json" } }, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        response.resume();
        if (!response.headers.location || redirects >= 3) return reject(new Error("Too many redirects: " + url));
        resolve(requestText(new URL(response.headers.location, url).href, redirects + 1));
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error("HTTP " + response.statusCode + ": " + url));
        return;
      }
      let text = "";
      let bytes = 0;
      response.setEncoding("utf8");
      response.on("data", chunk => {
        bytes += Buffer.byteLength(chunk);
        if (bytes > 4 * 1024 * 1024) response.destroy(new Error("Rule source exceeds 4 MB"));
        else text += chunk;
      });
      response.on("end", () => resolve(text));
      response.on("error", reject);
      response.on("aborted", () => reject(new Error("Aborted response: " + url)));
    });
    request.setTimeout(15000, () => request.destroy(new Error("Download timeout: " + url)));
    request.on("error", reject);
  });
}

async function download(url) {
  let error;
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await requestText(url); } catch (failure) { error = failure; }
  }
  throw error;
}

async function refreshSnapshot(manifest) {
  const revisions = {};
  for (const [key, repository] of Object.entries(manifest.repositories)) {
    const commit = JSON.parse(await download("https://api.github.com/repos/" + repository.repo + "/commits/" + repository.branch));
    if (!/^[a-f0-9]{40}$/.test(commit.sha)) throw new Error("Invalid upstream commit for " + key);
    revisions[key] = { repo: repository.repo, branch: repository.branch, commit: commit.sha, committedAt: commit.commit.committer.date };
  }
  const sources = [];
  // Keep downloads bounded and pin every file to a single repository revision.
  for (let offset = 0; offset < manifest.sources.length; offset += 3) {
    const batch = await Promise.all(manifest.sources.slice(offset, offset + 3).map(async source => {
      const repository = revisions[source.repository];
      const url = "https://raw.githubusercontent.com/" + repository.repo + "/" + repository.commit + "/" + encodePath(source.path);
      const raw = await download(url);
      const rules = parseRules(raw, source.format);
      assertRequired(source, rules);
      console.log(source.id + ": " + rules.length + " rules");
      return { id: source.id, repository: source.repository, path: source.path, format: source.format, url, sha256: sha256(raw), rules };
    }));
    sources.push(...batch);
  }
  return { schemaVersion: 1, repositories: revisions, sources };
}

function validateSnapshot(manifest, snapshot) {
  if (snapshot.schemaVersion !== 1) throw new Error("Unsupported snapshot schema");
  for (const [key, repository] of Object.entries(manifest.repositories)) {
    const stored = snapshot.repositories[key];
    if (!stored || stored.repo !== repository.repo || stored.branch !== repository.branch || !/^[a-f0-9]{40}$/.test(stored.commit)) {
      throw new Error("Snapshot repository does not match manifest: " + key);
    }
  }
  return compileRules(manifest, snapshot);
}

async function main(args) {
  const mode = args[0];
  if (args.length !== 1 || !["--refresh", "--dry-run", "--render", "--check"].includes(mode)) {
    throw new Error("Usage: node scripts/sync-community-rules.js --refresh|--dry-run|--render|--check");
  }
  const manifest = readJson(MANIFEST_PATH);
  const previous = fs.existsSync(SNAPSHOT_PATH) ? readJson(SNAPSHOT_PATH) : null;
  const snapshot = mode === "--refresh" || mode === "--dry-run" ? await refreshSnapshot(manifest) : previous;
  if (!snapshot) throw new Error("No snapshot; run --refresh first");
  const { bundles, skipped } = validateSnapshot(manifest, snapshot);
  const originalScript = fs.readFileSync(SCRIPT_PATH, "utf8");
  const generatedScript = replaceGeneratedBlock(originalScript, renderBlock(bundles));
  // Recheck boundaries in the actual generated configuration before replacing any files.
  const vm = require("vm");
  const sandbox = { console };
  vm.createContext(sandbox);
  vm.runInContext(originalScript, sandbox);
  const previousBundles = JSON.parse(JSON.stringify(sandbox.COMMUNITY_RULES));
  vm.runInContext(generatedScript, sandbox);
  const output = sandbox.main({ proxies: [{ name: "US validation", type: "ss", server: "203.0.113.1", port: 443, udp: true }], "proxy-groups": [], rules: [] });
  const audit = require("./rule-routing-audit");
  audit.assertRoutingCases(output.rules, manifest.routingCases);
  if (mode === "--check") {
    if (generatedScript !== originalScript) throw new Error("Generated rules differ from snapshot/policy; run --render");
    console.log("Community snapshot, generated block and routing boundaries: OK");
    return;
  }
  const changes = diffSnapshots(previous, snapshot);
  const effectiveChanges = diffBundles(previousBundles, bundles);
  for (const change of changes) console.log(change.source + ": +" + change.added.length + " -" + change.removed.length);
  console.log("Effective rules: " + TARGETS.map(target => target + "=" + bundles[target].length).join(", ") + "; excluded=" + skipped.length);
  if (mode === "--dry-run") {
    console.log(JSON.stringify({ repositories: snapshot.repositories, changes, effectiveChanges, skipped }, null, 2));
    return;
  }
  if (mode === "--refresh") {
    const serialized = JSON.stringify(snapshot, null, 2) + "\n";
    if (!previous || JSON.stringify(previous) !== JSON.stringify(snapshot)) fs.writeFileSync(SNAPSHOT_PATH, serialized);
  }
  if (generatedScript !== originalScript) fs.writeFileSync(SCRIPT_PATH, generatedScript);
  const history = fs.existsSync(HISTORY_PATH) ? readJson(HISTORY_PATH) : [];
  const policySha256 = sha256(fs.readFileSync(MANIFEST_PATH));
  if (changes.length || generatedScript !== originalScript || !history.length || history[history.length - 1].policySha256 !== policySha256) {
    history.push({ updatedAt: new Date().toISOString(), mode, repositories: snapshot.repositories, policySha256, changes, effectiveChanges,
      effectiveCounts: Object.fromEntries(TARGETS.map(target => [target, bundles[target].length])), skipped });
    fs.writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2) + "\n");
  }
}

module.exports = { parseRules, compileRules, renderBlock, replaceGeneratedBlock, diffSnapshots, diffBundles, validateSnapshot, domainMatches };
if (require.main === module) main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
