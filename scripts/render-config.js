#!/usr/bin/env node
"use strict";
/*
 * Headless 渲染器：不依赖 Clash Party，按 Clash Party 的顺序跑覆写链，为每台主机生成一份通用 mihomo 配置。
 *
 *   订阅（拉取 + 本地缓存） → 凭证步骤（主机文件 + secrets → _homeProxy / _customProxies / _customRuleGroups）
 *   → src/完全覆写.js main(config)（USER_OPTIONS 由主机文件覆盖，不改共享脚本）
 *   → 主机偏好（家宽跳板排序）→ runtime（端口、监听、控制器、TUN）→ out/<host>.yaml（600）→ mihomo -t
 *
 * 用法：
 *   node scripts/render-config.js --host grok-bot            # 渲染 hosts/grok-bot.js
 *   node scripts/render-config.js --all                      # 渲染 hosts/ 下所有主机（跳过 *.example.js）
 *   选项：--hosts-dir DIR  --out DIR  --secrets FILE  --offline（只用订阅缓存）
 *         --mihomo BIN（默认 $MIHOMO_BIN 或 PATH 中的 mihomo）  --mihomo-dir DIR（mihomo -t 的工作目录，放 geo 数据）
 *         --no-test（跳过 mihomo -t）
 *
 * 秘密值：主机文件里写 "secret:KEY"，渲染时从环境变量 KEY 或 secrets 文件（KEY=VALUE）读取。日志只打印 KEY，不打印值。
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { fileURLToPath } = require("url");
const { parseProxyUri } = require("./lib/proxy-uri");

let YAML;
try { YAML = require("yaml"); } catch (e) {
  console.error("缺少依赖 yaml：在仓库根目录执行 npm install"); process.exit(2);
}

const ROOT = path.resolve(__dirname, "..");
const OVERRIDE = path.join(ROOT, "src", "完全覆写.js");
const HOME_GROUP = "🏠 家宽IP", RELAY_GROUP = "🔗 家宽跳板";

function parseArgs(argv) {
  const a = { hosts: [], hostsDir: path.join(ROOT, "hosts"), out: path.join(ROOT, "out"),
              secrets: process.env.COCP_SECRETS || path.join(ROOT, "secrets.env"),
              mihomo: process.env.MIHOMO_BIN || "mihomo", mihomoDir: null, offline: false, test: true, all: false };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i], v = () => argv[++i];
    if (k === "--host") a.hosts.push(v());
    else if (k === "--all") a.all = true;
    else if (k === "--hosts-dir") a.hostsDir = path.resolve(v());
    else if (k === "--out") a.out = path.resolve(v());
    else if (k === "--secrets") a.secrets = path.resolve(v());
    else if (k === "--mihomo") a.mihomo = v();
    else if (k === "--mihomo-dir") a.mihomoDir = path.resolve(v());
    else if (k === "--offline") a.offline = true;
    else if (k === "--no-test") a.test = false;
    else if (k === "-h" || k === "--help") { console.log(fs.readFileSync(__filename, "utf8").split("*/")[0]); process.exit(0); }
    else throw new Error("未知参数：" + k);
  }
  if (a.all) {
    a.hosts = fs.readdirSync(a.hostsDir).filter(f => f.endsWith(".js") && !f.endsWith(".example.js")).map(f => f.slice(0, -3));
  }
  if (!a.hosts.length) throw new Error("需要 --host NAME 或 --all");
  a.mihomoDir = a.mihomoDir || path.join(a.out, ".mihomo-test");
  return a;
}

function loadSecrets(file) {
  const s = {};
  if (file && fs.existsSync(file)) {
    const mode = fs.statSync(file).mode & 0o077;
    if (mode && process.platform !== "win32") console.warn("警告：secrets 文件权限过宽，建议 chmod 600");
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      if (/^\s*#/.test(line)) continue;
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (m) s[m[1]] = m[2].replace(/^(['"])(.*)\1$/, "$2");
    }
  }
  return new Proxy(s, { get: (t, k) => (typeof k === "string" && process.env[k]) || t[k] || undefined });
}

// 把对象里所有 "secret:KEY" 字符串替换成真实值；缺失时记录 KEY
function resolveSecrets(value, secrets, missing) {
  if (typeof value === "string") {
    const m = /^secret:([A-Za-z_][A-Za-z0-9_]*)$/.exec(value);
    if (!m) return value;
    const v = secrets[m[1]];
    if (!v) { missing.push(m[1]); return undefined; }
    return v;
  }
  if (Array.isArray(value)) return value.map(x => resolveSecrets(x, secrets, missing));
  if (value && typeof value === "object") {
    const o = {};
    for (const k of Object.keys(value)) o[k] = resolveSecrets(value[k], secrets, missing);
    return o;
  }
  return value;
}

// 出口：{ name, uri } | { name, secret: "KEY" } | 完整 mihomo 节点；optional: true 时缺 secret 跳过
function resolveExit(spec, secrets, label) {
  if (!spec) return null;
  if (typeof spec === "string") spec = { secret: spec.replace(/^secret:/, "") };
  const { optional, secret, uri, ...rest } = spec;
  let raw = uri;
  if (secret) {
    raw = secrets[secret];
    if (!raw) {
      if (optional) { console.log(`  ${label}: secret ${secret} 未设置，跳过（optional）`); return null; }
      throw new Error(`${label}: 缺少 secret ${secret}`);
    }
  }
  const missing = [];
  const node = raw ? Object.assign(parseProxyUri(raw, rest.name), rest) : resolveSecrets(rest, secrets, missing);
  if (missing.length) {
    if (optional) { console.log(`  ${label}: 缺少 secret ${missing.join(",")}，跳过（optional）`); return null; }
    throw new Error(`${label}: 缺少 secret ${missing.join(",")}`);
  }
  return node;
}

async function loadSubscription(sub, idx, secrets, args) {
  const name = sub.name || "sub" + idx;
  const cacheDir = path.join(args.out, ".cache");
  fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const cache = path.join(cacheDir, "sub-" + crypto.createHash("sha1").update(name).digest("hex").slice(0, 12) + ".yaml");
  const url = sub.secret ? secrets[sub.secret] : resolveSecrets(sub.url, secrets, []);
  const parse = text => {
    const doc = YAML.parse(text);
    if (!doc || !Array.isArray(doc.proxies) || !doc.proxies.length) throw new Error("订阅 " + name + " 无节点");
    return doc;
  };
  if (url && (/^(file:|\/|\.)/.test(url) || path.isAbsolute(url))) {
    const file = url.startsWith("file:") ? fileURLToPath(url) : url;
    return parse(fs.readFileSync(file, "utf8"));
  }
  if (url && !args.offline) {
    try {
      const res = await fetch(url, { headers: { "User-Agent": sub.ua || "clash-verge/v1.7.7" }, signal: AbortSignal.timeout(30000) });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const text = await res.text();
      const doc = parse(text);
      fs.writeFileSync(cache + ".tmp", text, { mode: 0o600 }); fs.renameSync(cache + ".tmp", cache);
      console.log(`  订阅 ${name}: 拉取成功 ${doc.proxies.length} 个节点`);
      return doc;
    } catch (e) {
      console.log(`  订阅 ${name}: 拉取失败（${e.message}），改用缓存`);
    }
  } else if (!url && !fs.existsSync(cache)) {
    throw new Error(`订阅 ${name}: 缺少 URL（secret ${sub.secret || "?"}）且无缓存`);
  }
  if (!fs.existsSync(cache)) throw new Error(`订阅 ${name}: 无缓存可用`);
  const doc = parse(fs.readFileSync(cache, "utf8"));
  console.log(`  订阅 ${name}: 使用缓存 ${doc.proxies.length} 个节点`);
  return doc;
}

function runOverride(config, options) {
  const ctx = { console: { log() {}, info() {}, warn: console.warn, error: console.error } };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(OVERRIDE, "utf8"), ctx, { filename: "完全覆写.js", timeout: 30000 });
  if (!ctx.USER_OPTIONS || typeof ctx.main !== "function") throw new Error("完全覆写.js 缺少 USER_OPTIONS 或 main");
  for (const k of Object.keys(options)) {
    const v = options[k];
    ctx.USER_OPTIONS[k] = v && typeof v === "object" && !Array.isArray(v) && ctx.USER_OPTIONS[k] && typeof ctx.USER_OPTIONS[k] === "object"
      ? Object.assign({}, ctx.USER_OPTIONS[k], v) : v;
  }
  // 跨 vm 边界的对象转成普通 JSON，避免原型差异
  return JSON.parse(JSON.stringify(ctx.main(JSON.parse(JSON.stringify(config)))));
}

function applyRelayPrefs(config, relay) {
  if (!relay) return;
  const g = (config["proxy-groups"] || []).find(x => x.name === RELAY_GROUP);
  if (!g) return;
  const ex = new Set(relay.excludePorts || []);
  const ok = n => { const p = config.proxies.find(x => x.name === n); return !p || !ex.has(p.port); };
  const prefs = (relay.prefer || []).map(re => new RegExp(re))
    .map(re => config.proxies.find(p => re.test(p.name) && !ex.has(p.port))).filter(Boolean).map(p => p.name);
  let rest = g.proxies.filter(n => !prefs.includes(n));
  if (relay.dropExcluded) rest = rest.filter(ok);
  g.proxies = prefs.concat(rest);
}

function applyRuntime(config, rt, secrets) {
  rt = rt || {};
  for (const k of ["port", "socks-port", "redir-port", "tproxy-port", "external-ui", "external-ui-url", "external-ui-name",
                   "external-controller-tls", "external-controller-unix", "external-controller-pipe", "listeners", "clash-for-android"]) delete config[k];
  const missing = [];
  const secret = resolveSecrets(rt.secret, secrets, missing);
  if (missing.length) throw new Error("runtime.secret 缺少 secret " + missing.join(","));
  Object.assign(config, {
    "mixed-port": rt.mixedPort || 7890,
    "allow-lan": !!rt.allowLan,
    "bind-address": rt.bindAddress || "127.0.0.1",
    "external-controller": rt.controller || "127.0.0.1:9090",
    mode: "rule",
    "log-level": rt.logLevel || "info",
    profile: Object.assign({}, config.profile || {}, { "store-selected": true, "store-fake-ip": false }),
  });
  if (secret) config.secret = secret; else delete config.secret;
  if (rt.socksPort) config["socks-port"] = rt.socksPort;
  if (rt.externalUi) config["external-ui"] = rt.externalUi;
  config.tun = Object.assign({}, config.tun || {}, { enable: rt.tun === true });
  if (rt.tun !== true && config.dns) delete config.dns.listen;
  if (rt.dnsListen) config.dns = Object.assign({}, config.dns || {}, { listen: rt.dnsListen });
  if (rt.extra) Object.assign(config, rt.extra);
}

function hostKey(name) { return name.toUpperCase().replace(/[^A-Z0-9]/g, "_"); }

async function renderHost(name, args, secrets) {
  const file = path.join(args.hostsDir, name + ".js");
  if (!fs.existsSync(file)) throw new Error("主机文件不存在：" + file);
  delete require.cache[require.resolve(file)];
  const host = require(file);
  console.log(`[${name}] location=${host.location || "cn"}`);

  // 1) 订阅：第一个作为基础配置，其余只合并节点
  const subs = host.subscriptions || [];
  let config = { proxies: [], "proxy-groups": [], rules: [] };
  for (let i = 0; i < subs.length; i++) {
    const doc = await loadSubscription(subs[i], i, secrets, args);
    if (i === 0) config = doc;
    else {
      const seen = new Set(config.proxies.map(p => p.name));
      for (const p of doc.proxies) if (!seen.has(p.name)) { config.proxies.push(p); seen.add(p.name); }
    }
  }

  // 2) 凭证步骤（相当于 Clash Party 里排在前面的 出口IP凭证.js）
  const roles = host.roles || {};
  const options = Object.assign({}, host.options || {});
  if (host.location) options.location = host.location;
  const home = resolveExit(roles.home, secrets, "roles.home");
  if (home) { delete home.name; delete home.tls; config._homeProxy = home; }
  const front = resolveExit(roles.front, secrets, "roles.front");
  if (front) config._frontProxy = front;
  const custom = [];
  const cnNames = [];
  for (const [i, spec] of (roles.cnReturn || []).entries()) {
    if (typeof spec === "string" && !spec.startsWith("secret:")) { cnNames.push(spec); continue; } // 订阅节点或组名
    const n = resolveExit(spec, secrets, `roles.cnReturn[${i}]`);
    if (!n) continue;
    n.name = n.name || "回国出口" + (i + 1);
    n.scope = n.scope || "dedicated";
    custom.push(n); cnNames.push(n.name);
  }
  for (const [i, spec] of (host.customProxies || []).entries()) {
    const n = resolveExit(spec, secrets, `customProxies[${i}]`);
    if (n) custom.push(n);
  }
  if (custom.length) config._customProxies = custom;
  if (host.customRuleGroups) config._customRuleGroups = resolveSecrets(host.customRuleGroups, secrets, []);
  if (cnNames.length) options.domesticExit = cnNames;

  // 3) 主覆写
  config = runOverride(config, options);

  // 4) 主机偏好 + runtime
  applyRelayPrefs(config, roles.relay);
  applyRuntime(config, host.runtime, secrets);

  // 5) 输出（内容确定：同样输入 → 同样字节 → 同样 ETag）
  let rev = "";
  try { rev = execFileSync("git", ["-C", ROOT, "rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim(); } catch (e) {}
  const body = YAML.stringify(config, { lineWidth: 0, aliasDuplicateObjects: false });
  const header = [
    `# generated by clash-override-chain-proxy scripts/render-config.js — host=${name} rev=${rev || "unknown"}`,
    "# 不要手改：在渲染主机上改 hosts/" + name + ".js 后重新渲染",
    host.selections ? "# cocp-selections: " + JSON.stringify(host.selections) : null,
    host.note ? "# note: " + String(host.note).replace(/\n/g, " ") : null,
  ].filter(Boolean).join("\n") + "\n";
  const text = header + body;
  fs.mkdirSync(args.out, { recursive: true, mode: 0o700 });
  const out = path.join(args.out, name + ".yaml");
  const tmp = out + ".tmp";
  fs.writeFileSync(tmp, text, { mode: 0o600 });

  if (args.test) {
    fs.mkdirSync(args.mihomoDir, { recursive: true, mode: 0o700 });
    try {
      execFileSync(args.mihomo, ["-t", "-d", args.mihomoDir, "-f", tmp], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120000 });
    } catch (e) {
      const msg = String((e.stdout || "") + (e.stderr || "")).split("\n").filter(l => /error|fatal|failed/i.test(l)).slice(-3).join(" | ");
      fs.unlinkSync(tmp);
      throw new Error("mihomo -t 校验失败：" + (msg || e.message).replace(/:\/\/[^\s"']+/g, "://***"));
    }
  }
  const changed = !fs.existsSync(out) || fs.readFileSync(out, "utf8") !== text;
  fs.renameSync(tmp, out);
  fs.chmodSync(out, 0o600);
  const g = n => (config["proxy-groups"] || []).find(x => x.name === n);
  const summary = {
    host: name, out, changed, etag: crypto.createHash("sha256").update(text).digest("hex").slice(0, 16),
    proxies: config.proxies.length, groups: (config["proxy-groups"] || []).length, rules: (config.rules || []).length,
    home: !!home, domestic: g("🇨🇳 国内") ? g("🇨🇳 国内").proxies : null,
    front: g("🔗 前置") ? g("🔗 前置").proxies : null, match: (config.rules || []).slice(-1)[0],
    relayFirst: g(RELAY_GROUP) ? g(RELAY_GROUP).proxies.slice(0, 2) : null,
    tun: config.tun.enable, mixed: `${config["bind-address"]}:${config["mixed-port"]}`, controller: config["external-controller"],
    publishToken: !!secrets["PUBLISH_TOKEN_" + hostKey(name)], tested: args.test,
  };
  console.log(JSON.stringify(summary));
  return summary;
}

(async () => {
  const args = parseArgs(process.argv);
  const secrets = loadSecrets(args.secrets);
  let failed = 0;
  for (const h of args.hosts) {
    try { await renderHost(h, args, secrets); }
    catch (e) { failed++; console.error(`[${h}] 渲染失败：${e.message}`); }
  }
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error("render 失败：" + e.message); process.exit(1); });
