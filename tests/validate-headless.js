// headless 渲染器回归：订阅（本地文件）+ secrets（环境变量）→ out/<host>.yaml；不需要网络和 mihomo。
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { pathToFileURL } = require("url");
const YAML = require("yaml");
const { parseProxyUri } = require("../scripts/lib/proxy-uri");

const ROOT = path.join(__dirname, "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cocp-headless-"));
const hostsDir = path.join(tmp, "hosts"), out = path.join(tmp, "out");
fs.mkdirSync(hostsDir);

// URI 解析
const ss = parseProxyUri("ss://" + Buffer.from("2022-blake3-aes-128-gcm:pw").toString("base64") + "@198.51.100.7:8388#x", "SS");
assert.deepStrictEqual([ss.type, ss.cipher, ss.password, ss.port, ss.udp], ["ss", "2022-blake3-aes-128-gcm", "pw", 8388, true]);
const vl = parseProxyUri("vless://11111111-2222-3333-4444-555555555555@198.51.100.8:443?security=reality&sni=a.example&pbk=PK&sid=ab&flow=xtls-rprx-vision&fp=chrome", "VL");
assert.strictEqual(vl.uuid, "11111111-2222-3333-4444-555555555555");
assert.deepStrictEqual(vl["reality-opts"], { "public-key": "PK", "short-id": "ab" });
const so = parseProxyUri("socks5://u:p%40ss@198.51.100.9:1080");
assert.deepStrictEqual([so.type, so.username, so.password, so.udp], ["socks5", "u", "p@ss", undefined]);
assert.throws(() => parseProxyUri("nope"), e => !/nope/.test(e.message));

// 渲染
const sub = path.join(tmp, "sub.yaml");
fs.writeFileSync(sub, YAML.stringify({
  proxies: [
    { name: "🇺🇸 US A", type: "ss", server: "192.0.2.1", port: 443, cipher: "aes-128-gcm", password: "x", udp: true },
    { name: "🇺🇸 US B", type: "ss", server: "192.0.2.2", port: 42337, cipher: "aes-128-gcm", password: "x", udp: true },
    { name: "🇭🇰 HK A", type: "ss", server: "192.0.2.3", port: 8388, cipher: "aes-128-gcm", password: "x", udp: true }
  ],
  "proxy-groups": [{ name: "节点选择", type: "select", proxies: ["🇺🇸 US A", "🇺🇸 US B", "🇭🇰 HK A"] }],
  rules: ["MATCH,节点选择"]
}));
fs.writeFileSync(path.join(hostsDir, "t1.js"), `module.exports = {
  location: "overseas",
  subscriptions: [{ name: "t", url: "secret:T_SUB" }],
  roles: {
    home: { secret: "T_HOME" },
    cnReturn: [{ name: "回国SS", secret: "T_CN" }, { name: "可选出口", secret: "T_MISSING", optional: true }],
    relay: { prefer: ["^🇺🇸 US"], excludePorts: [443] }
  },
  options: { front: { excludePorts: [443], prefer: ["^🇺🇸 US B"] } },
  runtime: { mixedPort: 17890, controller: "127.0.0.1:19090", secret: "secret:T_CTRL", tun: false },
  selections: { "🤖 AI Agent": "🏠 家宽IP" }
};\n`);
const env = Object.assign({}, process.env, {
  T_SUB: sub, T_HOME: "http://hu:hp@203.0.113.5:443",
  T_CN: "ss://" + Buffer.from("aes-256-gcm:cnpw").toString("base64") + "@198.51.100.20:8443", T_CTRL: "ctrl-secret"
});
const log = execFileSync("node", [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"], { env, encoding: "utf8" });
assert(!/hp@|cnpw|ctrl-secret/.test(log), "日志不能包含秘密");
const file = path.join(out, "t1.yaml");
if (process.platform !== "win32") assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
assert(fs.statSync(file).size > 0, "输出文件应可读取且非空");
const text = fs.readFileSync(file, "utf8");
assert(/^# cocp-selections: \{"🤖 AI Agent":"🏠 家宽IP"\}$/m.test(text));
const cfg = YAML.parse(text);
const cn = cfg.proxies.find(p => p.name === "回国SS");
assert.deepStrictEqual([cn.type, cn.cipher, cn.password, cn.port], ["ss", "aes-256-gcm", "cnpw", 8443], "ss 字段应完整透传");
assert(!("scope" in cn), "管理字段不应进入节点");
assert(!cfg.proxies.some(p => p.name === "可选出口"), "optional 缺失时跳过");
const G = n => cfg["proxy-groups"].find(g => g.name === n);
assert.deepStrictEqual(G("🇨🇳 国内").proxies, ["回国SS", "DIRECT", "节点选择"], "overseas 下 🇨🇳 国内 默认回国出口");
assert.deepStrictEqual(G("🌐 国外").proxies.slice(0, 2), ["DIRECT", "节点选择"]);
assert.deepStrictEqual(G("🐟 兜底").proxies, ["🌐 国外", "🇨🇳 国内"]);
assert.strictEqual(cfg.rules[cfg.rules.length - 1], "MATCH,🐟 兜底");
assert.strictEqual(G("🔗 家宽跳板").proxies[0], "🇺🇸 US B", "家宽跳板应优先非 443 美国节点");
assert(cfg.proxies.some(p => p.name === "家宽IP链式" && p["dialer-proxy"] === "🔗 家宽跳板"));
assert.deepStrictEqual(G("🔗 前置").proxies, ["DIRECT", "⤴ 🇺🇸 US B", "⤴ 🇭🇰 HK A"], "🔗 前置：DIRECT + 可直连副本；443 与 dedicated 节点不进");
assert(cfg.proxies.filter(p => /^🇺🇸|^🇭🇰/.test(p.name)).every(p => p["dialer-proxy"] === "🔗 前置"), "订阅节点经 🔗 前置");
const names = cfg["proxy-groups"].map(g => g.name);
assert(names.indexOf("🐟 兜底") < names.indexOf("🏠 家宽IP") && names.indexOf("🏠 家宽IP") < names.indexOf("🔗 前置"), "策略组段在节点组段之前");
assert.deepStrictEqual([cfg["mixed-port"], cfg["bind-address"], cfg["allow-lan"], cfg["external-controller"], cfg.secret, cfg.tun.enable],
  [17890, "127.0.0.1", false, "127.0.0.1:19090", "ctrl-secret", false]);

// 同样输入 → 同样字节（ETag 稳定）
execFileSync("node", [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"], { env });
assert.strictEqual(fs.readFileSync(file, "utf8"), text, "重复渲染应字节一致");

const spacedSub = path.join(tmp, "sub fixture.yaml");
fs.copyFileSync(sub, spacedSub);
execFileSync(process.execPath, [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"],
  { env: Object.assign({}, env, { T_SUB: pathToFileURL(spacedSub).href }), stdio: "pipe" });
assert.strictEqual(fs.readFileSync(file, "utf8"), text, "file URL 应正确处理转义的空格和本地盘符");

// 缺少必需 secret 时失败且不打印值
let failed = false;
try { execFileSync("node", [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"], { env: Object.assign({}, env, { T_CN: "" }), stdio: "pipe" }); }
catch (e) { failed = true; assert(/T_CN/.test(String(e.stderr))); }
assert(failed);

function renderFixture(name, spec, variables) {
  fs.writeFileSync(path.join(hostsDir, name + ".js"), "module.exports = " + JSON.stringify(spec) + ";\n");
  const log = execFileSync(process.execPath, [path.join(ROOT, "scripts/render-config.js"), "--host", name, "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"],
    { env: Object.assign({}, env, variables), stdio: "pipe", encoding: "utf8" });
  return { config: YAML.parse(fs.readFileSync(path.join(out, name + ".yaml"), "utf8")), log };
}

const tlsSpec = {
  subscriptions: [{ url: sub }],
  roles: { home: { uri: "https://hu:hp@203.0.113.5:443" } }
};
const tlsResult = renderFixture("tls", tlsSpec);
const tlsNodes = tlsResult.config.proxies.filter(p => p.name === "家宽IP" || p.name === "家宽IP链式");
assert.strictEqual(tlsNodes.length, 2);
assert(tlsNodes.every(p => p.tls === true),
  "家宽直连和链式节点必须保留 HTTPS 的 TLS 字段");

const fields = renderFixture("fields", {
  roles: { home: { uri: "secret:T_HOME", password: "secret:T_PASSWORD" } }
}, { T_PASSWORD: "resolved-field-password" });
assert.strictEqual(fields.config.proxies.find(p => p.name === "家宽IP").password, "resolved-field-password");
assert(!fields.log.includes("resolved-field-password"), "字段凭证不应进入日志");

const optional = renderFixture("optional-fields", {
  roles: { home: { uri: "http://203.0.113.5:8080", password: "secret:T_PASSWORD", optional: true } },
  customProxies: [{ name: "available", type: "http", server: "203.0.113.6", port: 8080 }]
}, { T_PASSWORD: "" });
assert(!optional.config.proxies.some(p => p.name === "家宽IP"), "optional 出口缺少附加字段凭证时应跳过");

const requiredGroup = {
  customRuleGroups: [{ name: "required-group", proxy: {
    type: "http", server: "203.0.113.7", port: 8080, username: "user", password: "secret:T_PASSWORD"
  }, rules: [] }]
};
renderFixture("required-group", requiredGroup, { T_PASSWORD: "group-password" });
const groupFile = path.join(out, "required-group.yaml");
const groupBefore = fs.readFileSync(groupFile, "utf8");
assert.throws(() => renderFixture("required-group", requiredGroup, { T_PASSWORD: "" }), error => /T_PASSWORD/.test(String(error.stderr)));
assert.strictEqual(fs.readFileSync(groupFile, "utf8"), groupBefore, "凭证缺失不能覆盖已生成的有效配置");

fs.rmSync(tmp, { recursive: true, force: true });
console.log("validate-headless: ok");
