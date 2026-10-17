"use strict";

const assert = require("assert");
const TARGET_NAMES = { ai: "🤖 AI Agent", media: "🌍 国际媒体", telegram: "📲 Telegram", github: "🐙 GitHub" };

function splitFields(rule) {
  const fields = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < rule.length; i++) {
    if (rule[i] === "(") depth++;
    else if (rule[i] === ")") depth--;
    else if (rule[i] === "," && depth === 0) { fields.push(rule.slice(start, i)); start = i + 1; }
  }
  fields.push(rule.slice(start));
  return fields;
}

function matches(rule, request) {
  const fields = splitFields(rule);
  const value = fields[1];
  switch (fields[0]) {
    case "DOMAIN": return request.domain === value;
    case "DOMAIN-SUFFIX": return request.domain === value || request.domain.endsWith("." + value);
    case "DOMAIN-KEYWORD": return request.domain.includes(value);
    case "DOMAIN-REGEX": return new RegExp(value).test(request.domain);
    case "NETWORK": return request.network === value;
    case "DST-PORT": return String(request.port) === value;
    case "PROCESS-NAME": return request.process === value;
    case "AND": return splitFields(value.slice(1, -1)).every(part => matches(part.slice(1, -1), request));
    case "OR": return splitFields(value.slice(1, -1)).some(part => matches(part.slice(1, -1), request));
    case "NOT": return !matches(value.slice(1, -1), request);
    case "MATCH": return true;
    // Geodata is intentionally absent: this checks explicit routing, not a running core.
    default: return false;
  }
}

function route(rules, request) {
  const rule = rules.find(line => matches(line, request));
  if (!rule) return null;
  const fields = splitFields(rule);
  return { rule, target: fields[0] === "MATCH" ? fields[1] : fields[2] };
}

function assertRoutingCases(rules, cases) {
  for (const example of cases) {
    const result = route(rules, { domain: example.domain, network: "tcp", port: 443 });
    assert(result && result.target === TARGET_NAMES[example.target],
      example.domain + " should route to " + TARGET_NAMES[example.target] + "; got " + (result && result.rule));
    if (example.target === "ai") {
      const quic = route(rules, { domain: example.domain, network: "udp", port: 443 });
      assert(quic && quic.target === "REJECT", example.domain + " is missing AI QUIC protection");
    }
  }
}

module.exports = { route, matches, assertRoutingCases };
