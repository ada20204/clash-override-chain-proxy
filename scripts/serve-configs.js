#!/usr/bin/env node
"use strict";
/*
 * 极简配置发布器：只在 tailnet（或回环）地址上提供 out/<host>.yaml。
 *   GET /<host>.yaml   Authorization: Bearer <PUBLISH_TOKEN_<HOST>>   支持 If-None-Match → 304
 *   GET /healthz       无需鉴权，只返回 ok
 * 每台主机一个 token（secrets 文件或环境变量 PUBLISH_TOKEN_<HOST>，HOST 为主机名大写、非字母数字换成 _）。
 * 主机 A 的 token 拿不到主机 B 的配置。没有 token 的主机一律 404。
 *
 * 用法：node scripts/serve-configs.js --listen 100.x.y.z:7898 [--out DIR] [--secrets FILE] [--allow-any-address]
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");

const ROOT = path.resolve(__dirname, "..");
const a = { listen: null, out: path.join(ROOT, "out"), secrets: process.env.COCP_SECRETS || path.join(ROOT, "secrets.env"), any: false };
for (let i = 2; i < process.argv.length; i++) {
  const k = process.argv[i];
  if (k === "--listen") a.listen = process.argv[++i];
  else if (k === "--out") a.out = path.resolve(process.argv[++i]);
  else if (k === "--secrets") a.secrets = path.resolve(process.argv[++i]);
  else if (k === "--allow-any-address") a.any = true;
  else { console.error("未知参数：" + k); process.exit(2); }
}
const m = /^\[?([^\]]+)\]?:(\d+)$/.exec(a.listen || "");
if (!m) { console.error("需要 --listen ADDR:PORT（tailnet IP）"); process.exit(2); }
const [addr, port] = [m[1], Number(m[2])];

function isTailnetOrLoopback(ip) {
  if (ip === "127.0.0.1" || ip === "::1") return true;
  if (net.isIPv4(ip)) { const [x, y] = ip.split(".").map(Number); return x === 100 && y >= 64 && y <= 127; } // 100.64.0.0/10
  return /^fd7a:115c:a1e0:/i.test(ip);
}
if (!a.any && !isTailnetOrLoopback(addr)) { console.error("拒绝监听非 tailnet 地址：" + addr + "（确需可加 --allow-any-address）"); process.exit(2); }

function loadTokens() {
  const t = {};
  const add = (k, v) => { const mm = /^PUBLISH_TOKEN_([A-Z0-9_]+)$/.exec(k); if (mm && v) t[mm[1]] = v; };
  if (fs.existsSync(a.secrets)) {
    for (const line of fs.readFileSync(a.secrets, "utf8").split(/\r?\n/)) {
      const kv = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (kv && !/^\s*#/.test(line)) add(kv[1], kv[2].replace(/^(['"])(.*)\1$/, "$2"));
    }
  }
  for (const k of Object.keys(process.env)) add(k, process.env[k]);
  return t;
}
const hostKey = n => n.toUpperCase().replace(/[^A-Z0-9]/g, "_");
const eq = (x, y) => { const bx = Buffer.from(String(x)), by = Buffer.from(String(y)); return bx.length === by.length && crypto.timingSafeEqual(bx, by); };
const cache = new Map(); // file → { mtimeMs, size, etag, body }

function load(file) {
  const st = fs.statSync(file);
  const c = cache.get(file);
  if (c && c.mtimeMs === st.mtimeMs && c.size === st.size) return c;
  const body = fs.readFileSync(file);
  const v = { mtimeMs: st.mtimeMs, size: st.size, body, etag: '"' + crypto.createHash("sha256").update(body).digest("hex").slice(0, 32) + '"' };
  cache.set(file, v);
  return v;
}

const server = http.createServer((req, res) => {
  const log = (code, host) => console.log(`${new Date().toISOString()} ${req.socket.remoteAddress} ${req.method} ${req.url.split("?")[0]} ${code}${host ? " host=" + host : ""}`);
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return log(405); }
  if (req.url === "/healthz") { res.writeHead(200, { "Content-Type": "text/plain" }).end("ok\n"); return; }
  const mm = /^\/([A-Za-z0-9][A-Za-z0-9._-]*)\.yaml(?:\?.*)?$/.exec(req.url);
  if (!mm) { res.writeHead(404).end(); return log(404); }
  const host = mm[1];
  const token = loadTokens()[hostKey(host)];
  const auth = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || "");
  if (!token || !auth || !eq(auth[1].trim(), token)) { res.writeHead(token ? 401 : 404).end(); return log(token ? 401 : 404, host); }
  const file = path.join(a.out, host + ".yaml");
  let f;
  try { f = load(file); } catch (e) { res.writeHead(404).end(); return log(404, host); }
  const headers = { ETag: f.etag, "Cache-Control": "no-cache", "Content-Type": "text/yaml; charset=utf-8" };
  const inm = req.headers["if-none-match"];
  if (inm && inm.split(",").map(s => s.trim()).includes(f.etag)) { res.writeHead(304, headers).end(); return log(304, host); }
  res.writeHead(200, Object.assign(headers, { "Content-Length": f.body.length }));
  res.end(req.method === "HEAD" ? undefined : f.body);
  log(200, host);
});
server.listen(port, addr, () => console.log(`serve-configs 监听 http://${addr.includes(":") ? "[" + addr + "]" : addr}:${port}/<host>.yaml  目录 ${a.out}`));
