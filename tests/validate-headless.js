// headless 渲染器回归：订阅（本地文件）+ secrets（环境变量）→ out/<host>.yaml；不需要网络和 mihomo。
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
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
assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
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
const relay = G("🔗 前置").proxies;
assert.deepStrictEqual(relay.slice(0, 2), ["⚡ 前置自动", "🇺🇸 US B"], "前置默认自动，prefer 命中的节点排在手动候选前面");
assert(!relay.includes("🇺🇸 US A") && !G("⚡ 前置自动").proxies.includes("🇺🇸 US A"), "excludePorts(443) 的节点不能当前置");
assert(!relay.includes("回国SS"), "dedicated 节点不当前置");
assert(!relay.includes("家宽IP") && !relay.includes("家宽IP链式"), "需中转的家宽IP / 链式节点不能当前置");
assert(cfg.proxies.some(p => p.name === "家宽IP链式" && p["dialer-proxy"] === "🔗 前置"));
assert.deepStrictEqual(G("🏠 家宽IP").proxies, ["家宽IP链式", "家宽IP"], "家宽端口被拦截时默认链式");
const names = cfg["proxy-groups"].map(g => g.name);
assert(names.indexOf("🐟 兜底") < names.indexOf("🏠 家宽IP") && names.indexOf("🏠 家宽IP") < names.indexOf("🔗 前置"), "策略组段在节点组段之前");
assert.deepStrictEqual([cfg["mixed-port"], cfg["bind-address"], cfg["allow-lan"], cfg["external-controller"], cfg.secret, cfg.tun.enable],
  [17890, "127.0.0.1", false, "127.0.0.1:19090", "ctrl-secret", false]);

// 同样输入 → 同样字节（ETag 稳定）
execFileSync("node", [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"], { env });
assert.strictEqual(fs.readFileSync(file, "utf8"), text, "重复渲染应字节一致");

// 缺少必需 secret 时失败且不打印值
let failed = false;
try { execFileSync("node", [path.join(ROOT, "scripts/render-config.js"), "--host", "t1", "--hosts-dir", hostsDir, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test"], { env: Object.assign({}, env, { T_CN: "" }), stdio: "pipe" }); }
catch (e) { failed = true; assert(/T_CN/.test(String(e.stderr))); }
assert(failed);

fs.rmSync(tmp, { recursive: true, force: true });
console.log("validate-headless: ok");
