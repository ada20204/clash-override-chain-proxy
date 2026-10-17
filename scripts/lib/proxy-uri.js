"use strict";
// 代理 URI → mihomo 节点对象（headless 渲染器使用；错误信息不包含 URI 内容）
// 支持：http(s)、socks5(h)、ss（SIP002 与旧式 base64）、vless、trojan、hysteria2/hy2

function dec(s) { try { return decodeURIComponent(s || ""); } catch (e) { return s || ""; } }
function b64(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
}
function query(q) {
  const o = {};
  for (const kv of (q || "").split("&")) {
    if (!kv) continue;
    const i = kv.indexOf("=");
    o[dec(i < 0 ? kv : kv.slice(0, i))] = dec(i < 0 ? "" : kv.slice(i + 1));
  }
  return o;
}
function hostPort(s) {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(s);
  return m ? { host: m[1], port: Number(m[2]) } : { host: null, port: null };
}
function split(url) {
  const m = /^([a-z0-9+]+):\/\/(.*)$/i.exec(String(url).trim());
  if (!m) throw new Error("代理 URI 格式无效（内容未打印）");
  let scheme = m[1].toLowerCase(), rest = m[2], frag = "", q = "";
  const h = rest.indexOf("#"); if (h >= 0) { frag = dec(rest.slice(h + 1)); rest = rest.slice(0, h); }
  const qi = rest.indexOf("?"); if (qi >= 0) { q = rest.slice(qi + 1); rest = rest.slice(0, qi); }
  rest = rest.replace(/\/+$/, "");
  const at = rest.lastIndexOf("@");
  const userinfo = at >= 0 ? rest.slice(0, at) : null;
  const hp = at >= 0 ? rest.slice(at + 1) : rest;
  return Object.assign({ scheme, userinfo, hostport: hp, q: query(q), frag }, hostPort(hp));
}
function userPass(userinfo, o) {
  if (!userinfo) return o;
  const c = userinfo.indexOf(":");
  o.username = dec(c < 0 ? userinfo : userinfo.slice(0, c));
  if (c >= 0) o.password = dec(userinfo.slice(c + 1));
  return o;
}
function tlsCommon(p, q) {
  if (q.sni || q.peer) p[p.type === "vless" ? "servername" : "sni"] = q.sni || q.peer;
  if (q.fp) p["client-fingerprint"] = q.fp;
  if (q.alpn) p.alpn = q.alpn.split(",");
  if (q.allowInsecure === "1" || q.insecure === "1") p["skip-cert-verify"] = true;
}
function transport(p, q) {
  if (p.network === "ws") p["ws-opts"] = Object.assign({ path: q.path || "/" }, q.host ? { headers: { Host: q.host } } : {});
  if (p.network === "grpc") p["grpc-opts"] = { "grpc-service-name": q.serviceName || "" };
}

function parseProxyUri(url, name) {
  const u = split(url);
  let p;
  switch (u.scheme) {
    case "http": case "https": case "socks": case "socks5": case "socks5h": {
      if (!u.host || !u.port) throw new Error("代理 URI 缺少 host:port");
      p = { type: u.scheme.startsWith("socks") ? "socks5" : "http", server: u.host, port: u.port };
      if (u.scheme === "https") p.tls = true;
      userPass(u.userinfo, p);
      if (u.q.udp === "1") p.udp = true;
      break;
    }
    case "ss": {
      let method, pass, host = u.host, port = u.port;
      if (u.userinfo != null) {
        let ui = dec(u.userinfo);
        if (ui.indexOf(":") < 0) ui = b64(ui);
        const c = ui.indexOf(":"); method = ui.slice(0, c); pass = ui.slice(c + 1);
      } else {
        const all = b64(u.hostport), a = all.lastIndexOf("@"), c = all.indexOf(":");
        method = all.slice(0, c); pass = all.slice(c + 1, a);
        const hp = hostPort(all.slice(a + 1)); host = hp.host; port = hp.port;
      }
      p = { type: "ss", server: host, port, cipher: method, password: pass, udp: true };
      if (u.q.plugin) {
        const parts = u.q.plugin.split(";");
        p.plugin = parts[0] === "obfs-local" ? "obfs" : parts[0];
        p["plugin-opts"] = {};
        for (const kv of parts.slice(1)) {
          const i = kv.indexOf("="), k = i < 0 ? kv : kv.slice(0, i);
          p["plugin-opts"][k === "obfs" ? "mode" : k === "obfs-host" ? "host" : k] = i < 0 ? true : kv.slice(i + 1);
        }
      }
      break;
    }
    case "vless": {
      const q = u.q;
      p = { type: "vless", server: u.host, port: u.port, uuid: dec(u.userinfo), udp: true,
            network: q.type || "tcp", tls: q.security === "tls" || q.security === "reality" };
      if (q.flow) p.flow = q.flow;
      tlsCommon(p, q);
      if (q.security === "reality") p["reality-opts"] = { "public-key": q.pbk, "short-id": q.sid || "" };
      transport(p, q);
      break;
    }
    case "trojan": {
      const q = u.q;
      p = { type: "trojan", server: u.host, port: u.port, password: dec(u.userinfo), udp: true };
      if (q.type && q.type !== "tcp") p.network = q.type;
      tlsCommon(p, q);
      transport(p, q);
      break;
    }
    case "hysteria2": case "hy2": {
      const q = u.q;
      p = { type: "hysteria2", server: u.host, port: u.port, password: dec(u.userinfo), udp: true };
      tlsCommon(p, q);
      if (q.obfs) { p.obfs = q.obfs; if (q["obfs-password"]) p["obfs-password"] = q["obfs-password"]; }
      break;
    }
    default:
      throw new Error("不支持的代理 URI 协议：" + u.scheme);
  }
  if (!p.server || !p.port) throw new Error("代理 URI 缺少 host:port");
  p.name = name || u.frag || p.type + "-" + p.server;
  return p;
}

module.exports = { parseProxyUri };
