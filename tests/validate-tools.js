"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { spawnSync, execFile } = require("child_process");
const http = require("http");
const root = path.resolve(__dirname, "..");

function testInterfaceUpdater() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cocp-interface-"));
  const file = path.join(tmp, "credentials.js");
  const command = [path.join(root, "scripts/update-interface-name.js"), "--file", file,
    "--server", "192.168.88.10", "--interface", "Tailscale"];
  const evaluate = text => {
    const context = vm.createContext({});
    new vm.Script(text).runInContext(context);
    return JSON.parse(JSON.stringify(context.main({})));
  };
  try {
    for (const body of [
      'port: 3128,\n  server: "192.168.88.10"',
      '"server": "192.168.88.10", port: 3128',
      'server: "192.168.88.10", port: 3128, // keep comment\n',
      'server: "192.168.88.10", port: 3128, interfaceName: "old"',
      'server: "192.168.88.10", port: 3128, "interface-name": "old",',
      'server: "192.168.88.10", port: 3128, note: "{ server: ignored }"'
    ]) {
      const before = '// server: "192.168.88.10"\nfunction main(config) {\nconfig._customProxies = [{\n' +
        'name: "fixture", password: "do-not-print-me", ' + body + '\n}]; return config; }\n';
      fs.writeFileSync(file, before);
      const preview = spawnSync(process.execPath, command, { encoding: "utf8" });
      assert.strictEqual(preview.status, 0, preview.stderr);
      assert.strictEqual(fs.readFileSync(file, "utf8"), before, "dry-run must not write");
      assert(!preview.stdout.includes("do-not-print-me"), "preview must not disclose credentials");
      const result = spawnSync(process.execPath, command.concat("--write"), { encoding: "utf8" });
      assert.strictEqual(result.status, 0, result.stderr);
      const after = fs.readFileSync(file, "utf8");
      const expected = evaluate(before);
      const node = expected._customProxies[0];
      node[Object.hasOwn(node, "interface-name") ? "interface-name" : "interfaceName"] = "Tailscale";
      assert.deepStrictEqual(evaluate(after), expected, "only the interface should change");
      assert(after.startsWith('// server: "192.168.88.10"'), "comments must not be edited");
      assert.strictEqual(spawnSync(process.execPath, command.concat("--write")).status, 0);
      assert.strictEqual(fs.readFileSync(file, "utf8"), after, "repeated update must be byte-stable");
    }
    for (const before of [
      'function main(c) { c.x = [{server:"192.168.88.10"}, {server:"192.168.88.10"}]; return c; }',
      'function main(c) { c.x = {server:"192.168.88.10", interfaceName:"a", "interface-name":"b"}; return c; }',
      'function main(c) { c.x = {server:"192.168.88.10", server:"192.168.88.11"}; return c; }',
      'function main(c) { c.x = {server:"192.168.88.11"}; return c; }',
      'function main(c) { c.x = {server:"192.168.88.10"; return c; }'
    ]) {
      fs.writeFileSync(file, before);
      const result = spawnSync(process.execPath, command.concat("--write"), { encoding: "utf8" });
      assert.notStrictEqual(result.status, 0, "ambiguous or invalid input must be refused");
      assert.strictEqual(fs.readFileSync(file, "utf8"), before, "failed validation must preserve original file");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function testProxyReliability() {
  const python = [process.env.PYTHON, "python3", "python"].filter(Boolean).find(command => {
    const result = spawnSync(command, ["--version"], { encoding: "utf8", timeout: 5000 });
    return result.status === 0 && /Python 3\./.test(result.stdout);
  });
  assert(python, "Python 3 is required for reliability CLI tests (or set PYTHON)");
  let status = 407;
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests++;
    assert.strictEqual(request.url, "http://fixture.invalid/check");
    response.writeHead(status);
    response.end("fixture");
  });
  server.on("connect", (request, socket) => {
    requests++;
    socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    for (const [code, scheme, expected] of [[407, "http", false], [200, "http", true],
      [404, "http", true], [503, "http", false], [407, "https", false]]) {
      status = code;
      const before = requests;
      const result = await new Promise(resolve => {
        execFile(python, ["-B", path.join(root, "scripts/proxy-reliability-test.py"), "--proxy",
          "http://fixture-user:fixture-password@127.0.0.1:" + server.address().port,
          "--url", scheme + "://fixture.invalid/check", "--count", "2", "--concurrency", "2", "--timeout", "2", "--json"],
        { env: { ...process.env, no_proxy: "", NO_PROXY: "" }, timeout: 15000 },
        (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }));
      });
      assert.strictEqual(requests - before, 2, "every request must reach the loopback proxy");
      assert.strictEqual(result.code, expected ? 0 : 1, code + " must be classified correctly: " + result.stdout + result.stderr);
      const summary = JSON.parse(result.stdout.slice(result.stdout.lastIndexOf("\n{") + 1));
      assert.strictEqual(summary.success, expected ? 2 : 0);
      assert.strictEqual(summary.success_rate, expected ? 100 : 0);
      assert(!result.stdout.includes("fixture-password"));
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function main() {
  testInterfaceUpdater();
  await testProxyReliability();
  console.log("validate-tools: ok");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
