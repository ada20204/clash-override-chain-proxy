"use strict";
// Opt-in offline core validation. Never use the active client's config or working directory.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const YAML = require("yaml");
const { execFileSync } = require("child_process");
const { parseProxyUri } = require("../scripts/lib/proxy-uri");
const args = process.argv.slice(2);
const get = flag => args[args.indexOf(flag) + 1];
assert(args.includes("--mihomo") && args.includes("--geodata-dir"),
  "Usage: node tests/validate-kernel.js --mihomo <binary> --geodata-dir <offline geodata directory>");
const core = get("--mihomo"), data = get("--geodata-dir");
const source = fs.readFileSync(path.join(__dirname, "../src/完全覆写.js"), "utf8");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cocp-kernel-"));
let count = 0;
try {
  for (const name of ["geosite.dat", "geoip.dat", "country.mmdb", "ASN.mmdb"]) {
    fs.copyFileSync(path.join(data, name), path.join(temp, name));
  }
  console.log(execFileSync(core, ["-v"], { encoding: "utf8", timeout: 10000 }).trim());
  for (const location of ["cn", "overseas"]) for (const home of [true, false]) {
    const sandbox = {};
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);
    sandbox.USER_OPTIONS.location = location;
    sandbox.USER_OPTIONS.enableChainRegionBrowserProcessProxy = true;
    const input = {
      mode: "rule", "geodata-mode": true, "geo-auto-update": false, tun: { enable: false },
      proxies: [parseProxyUri("trojan://fixture@203.0.113.7:443?sni=tls.example.test", "US A"),
        parseProxyUri("hy2://fixture@203.0.113.8:443?sni=tls.example.test", "JP B")],
      "proxy-groups": [
        { name: "自动选择", type: "url-test", proxies: ["nested"], url: "https://www.gstatic.com/generate_204", interval: 300 },
        { name: "nested", type: "select", proxies: ["US A", "JP B"] }
      ],
      rules: [],
      _customProxies: [{ name: "custom", type: "http", server: "192.168.88.10", port: 3128, via: "DIRECT", dedicated: true }],
      _customRuleGroups: [{ name: "business", proxies: ["custom"], rules: ["IP-CIDR,10.20.0.0/16,no-resolve"] }]
    };
    if (home) input._homeProxy = { type: "http", server: "203.0.113.9", port: 8080 };
    const config = sandbox.main(input);
    const file = path.join(temp, "fixture.yaml");
    fs.writeFileSync(file, YAML.stringify(JSON.parse(JSON.stringify(config))), { mode: 0o600 });
    try {
      execFileSync(core, ["-t", "-d", temp, "-f", file], { encoding: "utf8", timeout: 30000 });
    } catch (error) {
      throw new Error(location + "/home=" + home + ": " + error.stdout + error.stderr);
    }
    count++;
  }
  console.log("validate-kernel: " + count + " generated configs accepted (isolated -t, no client reload)");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
