// Offline checks for repository documentation; external URLs are not fetched.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const docs = fs.readdirSync(path.join(root, "docs"))
  .filter(name => name.endsWith(".md")).map(name => "docs/" + name);
const files = ["README.md", "AGENTS.md", ...docs];

function withoutFences(text) {
  return text.replace(/^```[^\n]*\n[\s\S]*?^```[^\n]*$/gm, "");
}

function headingAnchors(text) {
  const counts = new Map();
  return new Set([...withoutFences(text).matchAll(/^#{1,6}\s+(.+)$/gm)].map(match => {
    const base = match[1].trim().toLowerCase().replace(/<[^>]*>/g, "")
      .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, "").replace(/ /g, "-");
    const count = counts.get(base) || 0;
    counts.set(base, count + 1);
    return base + (count ? "-" + count : "");
  }));
}

function localReferences(text) {
  const prose = withoutFences(text);
  const refs = [...prose.matchAll(/\[[^\]\r\n]*\]\(([^)\r\n]+)\)/g)].map(match => match[1]);
  refs.push(...[...prose.matchAll(/<img[^>]*\bsrc="([^"]+)"/g)].map(match => match[1]));
  return refs.filter(ref => !/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(ref));
}

assert.deepEqual([...headingAnchors("## 示例（location）\n## 示例（location）\n````\n## hidden\n````\n")],
  ["示例location", "示例location-1"]);
assert.deepEqual(localReferences("[local](./readme.md#intro) [web](https://example.com)\n```text\n[x](missing.md)\n```"),
  ["./readme.md#intro"]);

let linkCount = 0;
const errors = [];
for (const file of files) {
  for (const ref of localReferences(fs.readFileSync(path.join(root, file), "utf8"))) {
    linkCount++;
    const [name, fragment] = decodeURIComponent(ref).split("#");
    const target = name ? path.resolve(root, path.dirname(file), name) : path.resolve(root, file);
    if (!fs.existsSync(target)) {
      errors.push(file + " -> missing file: " + ref);
    } else if (fragment && target.endsWith(".md") &&
               !headingAnchors(fs.readFileSync(target, "utf8")).has(fragment)) {
      errors.push(file + " -> missing heading: " + ref);
    }
  }
}

const indexRefs = localReferences(fs.readFileSync(path.join(root, "docs/README.md"), "utf8"))
  .map(ref => path.resolve(root, "docs", ref.split("#")[0]));
for (const file of docs.filter(file => file !== "docs/README.md")) {
  assert(indexRefs.includes(path.resolve(root, file)), "Document missing from index: " + file);
}
assert.deepEqual(errors, [], errors.join("\n"));

// The executable tutorial excerpt must track actual defaults; design drafts are excluded.
const tutorial = fs.readFileSync(path.join(root, "docs/配置教程.md"), "utf8");
const excerpt = tutorial.match(/```javascript\s*\n(var USER_OPTIONS = \{[\s\S]*?\n\};)\s*\n```/);
assert(excerpt, "Tutorial USER_OPTIONS excerpt is missing");
const actual = {}, documented = {};
vm.runInNewContext(fs.readFileSync(path.join(root, "src/完全覆写.js"), "utf8"), actual);
vm.runInNewContext(excerpt[1], documented);
for (const [key, value] of Object.entries(documented.USER_OPTIONS)) {
  assert.equal(JSON.stringify(value), JSON.stringify(actual.USER_OPTIONS[key]), "Outdated documented default: " + key);
}
console.log(`validate-docs: ${files.length} documents, ${linkCount} local links/anchors and tutorial defaults checked`);
