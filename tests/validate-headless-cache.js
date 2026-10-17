"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { execFile } = require("child_process");
const YAML = require("yaml");

const ROOT = path.resolve(__dirname, "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cocp-cache-"));
const hosts = path.join(tmp, "hosts");
const out = path.join(tmp, "out");
fs.mkdirSync(hosts);
let unavailable = false;
let requests = 0;
const server = http.createServer((req, res) => {
  requests++;
  if (unavailable || !req.url.startsWith("/a?")) { res.writeHead(503).end(); return; }
  res.end(YAML.stringify({ proxies: [{
    name: "US node-a", type: "ss", server: "203.0.113.9", port: 8388,
    cipher: "aes-128-gcm", password: "fixture-only", udp: true,
  }], "proxy-groups": [], rules: [] }));
});

function render(name, url, offline = false, ua = "review-agent") {
  fs.writeFileSync(path.join(hosts, name + ".js"), "module.exports = " + JSON.stringify({
    subscriptions: [{ name: "shared-name", secret: "REVIEW_SUB_URL", ua }],
  }) + ";\n");
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [path.join(ROOT, "scripts/render-config.js"), "--host", name,
      "--hosts-dir", hosts, "--out", out, "--secrets", path.join(tmp, "none.env"), "--no-test",
      ...(offline ? ["--offline"] : []),
    ], { cwd: ROOT, env: { ...process.env, REVIEW_SUB_URL: url || "" }, windowsHide: true },
    (error, stdout, stderr) => {
      if (error && typeof error.code !== "number") { reject(error); return; }
      if ((stdout + stderr).includes("review-subscription-secret")) {
        reject(new Error("subscription URL must not enter logs")); return;
      }
      resolve({ status: error ? error.code : 0, stdout, stderr });
    });
  });
}

(async () => {
  try {
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const url = "http://127.0.0.1:" + server.address().port;
    const a = url + "/a?token=review-subscription-secret";
    const b = url + "/b?token=review-subscription-secret";
    assert.strictEqual((await render("alpha", a)).status, 0);
    const alphaFile = path.join(out, "alpha.yaml");
    const original = fs.readFileSync(alphaFile, "utf8");
    assert.strictEqual((await render("gamma", a, true)).status, 1, "even an identical URL must not share another host's cache");
    assert.strictEqual((await render("beta", b)).status, 1, "another host must not use alpha's same-name cache");
    assert(!fs.existsSync(path.join(out, "beta.yaml")));
    assert.strictEqual((await render("alpha", b)).status, 1, "a changed URL must not use the previous account's cache");
    assert.strictEqual(fs.readFileSync(alphaFile, "utf8"), original);
    assert.strictEqual((await render("alpha", undefined, true)).status, 1, "missing credentials must not select an ambiguous cache");
    assert.strictEqual((await render("alpha", a, true, "different-agent")).status, 1, "cache identity must include the subscription user agent");

    unavailable = true;
    assert.strictEqual((await render("alpha", a)).status, 0, "a failed request can use this exact subscription's cache");
    const before = requests;
    assert.strictEqual((await render("alpha", a, true)).status, 0);
    assert.strictEqual(requests, before, "offline mode must not contact the server");
    assert.strictEqual(fs.readFileSync(alphaFile, "utf8"), original);
    console.log("validate-headless-cache: ok");
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
