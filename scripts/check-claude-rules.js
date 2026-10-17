#!/usr/bin/env node
"use strict";

var fs = require("fs");
var path = require("path");
var https = require("https");
var vm = require("vm");

var DEFAULT_REFERENCE_URL = "https://ip.net.coffee/claude/site.html";
var DEFAULT_SCRIPT_PATH = path.join(__dirname, "..", "src", "完全覆写.js");

var RELEVANT_DOMAIN_HINTS = [
  "anthropic",
  "claude",
  "clau.de",
  "intercom",
  "usefathom",
  "sentry",
  "statsig",
  "datadog",
  "datadoghq",
  "ghost.io",
  "auth0.com",
  "cloudflare.net",
  "b-cdn.net"
];

function usage() {
  console.log([
    "Usage:",
    "  node scripts/check-claude-rules.js [--url <reference-url>] [--script <完全覆写.js>]",
    "  node scripts/check-claude-rules.js --source <downloaded-html> [--script <完全覆写.js>]",
    "",
    "Options:",
    "  --url     Reference page URL. Defaults to " + DEFAULT_REFERENCE_URL,
    "  --source  Use a local HTML/text snapshot instead of downloading",
    "  --script  Override script path. Defaults to src/完全覆写.js",
    "  --json    Print machine-readable JSON",
    "  --help    Show this help"
  ].join("\n"));
}

function parseArgs(argv) {
  var args = {
    url: DEFAULT_REFERENCE_URL,
    script: DEFAULT_SCRIPT_PATH,
    json: false
  };

  for (var i = 2; i < argv.length; i++) {
    var item = argv[i];
    if (item === "--help" || item === "-h") {
      args.help = true;
    } else if (item === "--json") {
      args.json = true;
    } else if (item === "--url" || item === "--source" || item === "--script") {
      if (i + 1 >= argv.length) throw new Error(item + " requires a value");
      args[item.slice(2)] = argv[++i];
    } else {
      throw new Error("Unknown argument: " + item);
    }
  }
  return args;
}

function fetchText(url) {
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { "User-Agent": "clash-override-chain-proxy-rule-check/1.0" } }, function (res) {
      var chunks = [];
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error("HTTP " + res.statusCode + " while fetching " + url));
        return;
      }
      res.setEncoding("utf8");
      res.on("data", function (chunk) { chunks.push(chunk); });
      res.on("end", function () { resolve(chunks.join("")); });
    }).on("error", reject);
  });
}

function stripHtml(text) {
  return String(text)
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&#x2F;/g, "/")
    .replace(/\s+/g, " ");
}

function uniqueSorted(values) {
  var seen = {};
  var result = [];
  for (var i = 0; i < values.length; i++) {
    var value = values[i];
    if (!value || seen[value]) continue;
    seen[value] = true;
    result.push(value);
  }
  return result.sort();
}

function isRelevantDomain(domain) {
  var lower = domain.toLowerCase();
  for (var i = 0; i < RELEVANT_DOMAIN_HINTS.length; i++) {
    if (lower.indexOf(RELEVANT_DOMAIN_HINTS[i]) >= 0) return true;
  }
  return false;
}

function extractReferenceRules(text) {
  var plainText = stripHtml(text).toLowerCase();
  var domainMatches = plainText.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/g) || [];
  var ipv4Matches = plainText.match(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/g) || [];
  var ipv6Matches = plainText.match(/\b[0-9a-f:]+::\/\d{1,3}\b/g) || [];
  var asnMatches = plainText.match(/\bas\d+\b/g) || [];
  var keywordMatches = plainText.match(/关键词[:：]\s*[a-z0-9-]+/g) || [];
  var geositeMatches = plainText.match(/\bgeosite:[a-z0-9_-]+\b/g) || [];

  return {
    domains: uniqueSorted(domainMatches.filter(isRelevantDomain)),
    ipv4Cidrs: uniqueSorted(ipv4Matches),
    ipv6Cidrs: uniqueSorted(ipv6Matches),
    asns: uniqueSorted(asnMatches.map(function (asn) { return asn.toUpperCase(); })),
    keywords: uniqueSorted(keywordMatches.map(function (item) {
      return item.replace(/关键词[:：]\s*/i, "").trim();
    })),
    geosite: uniqueSorted(geositeMatches)
  };
}

function extractArrayBody(scriptText, marker) {
  var markerIndex = scriptText.indexOf(marker);
  var start;
  var depth = 0;
  var quote = null;
  var escaped = false;

  if (markerIndex < 0) return "";
  start = scriptText.indexOf("[", markerIndex);
  if (start < 0) return "";

  for (var i = start; i < scriptText.length; i++) {
    var ch = scriptText[i];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "\"" || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "[") depth++;
    if (ch === "]") {
      depth--;
      if (depth === 0) return scriptText.slice(start, i + 1);
    }
  }
  return "";
}

function stripDomainPrefix(value) {
  return value.replace(/^\+\./, "").toLowerCase();
}

function extractQuotedStrings(text) {
  var values = [];
  var re = /["']([^"']+)["']/g;
  var match;
  while ((match = re.exec(text))) values.push(match[1]);
  return values;
}

function extractConfiguredRules(scriptText) {
  var anthropicBody = extractArrayBody(scriptText, "anthropic:");
  var networkBody = extractArrayBody(scriptText, "SOURCE_ANTHROPIC_NETWORK_RULES");
  var domains = extractQuotedStrings(anthropicBody).map(stripDomainPrefix).filter(function (value) {
    return value.indexOf(".") >= 0;
  });
  var domainRules = domains.map(function (value) { return { type: "DOMAIN-SUFFIX", value: value }; });
  var sandbox = { console: console };
  vm.runInNewContext(scriptText, sandbox);
  if (sandbox.COMMUNITY_RULES && sandbox.COMMUNITY_RULES.ai) {
    sandbox.COMMUNITY_RULES.ai.forEach(function (entry) {
      domainRules.push({ type: entry[0], value: entry[1] });
      domains.push(entry[1]);
    });
  }
  var ipv4Cidrs = [];
  var ipv6Cidrs = [];
  var cidrRe = /value:\s*["']([^"']+\/\d{1,3})["']/g;
  var match;
  while ((match = cidrRe.exec(networkBody))) {
    if (match[1].indexOf(":") >= 0) ipv6Cidrs.push(match[1].toLowerCase());
    else ipv4Cidrs.push(match[1]);
  }
  return {
    domains: uniqueSorted(domains),
    domainRules: domainRules,
    ipv4Cidrs: uniqueSorted(ipv4Cidrs),
    ipv6Cidrs: uniqueSorted(ipv6Cidrs)
  };
}

function domainCovered(domain, configuredDomains) {
  for (var i = 0; i < configuredDomains.length; i++) {
    var rule = configuredDomains[i];
    var suffix = typeof rule === "string" ? rule : rule.value;
    if (domain === suffix || ((typeof rule === "string" || rule.type === "DOMAIN-SUFFIX") &&
        domain.slice(-(suffix.length + 1)) === "." + suffix)) return true;
  }
  return false;
}

function compareRules(reference, configured) {
  var missingDomains = reference.domains.filter(function (domain) {
    return !domainCovered(domain, configured.domainRules || configured.domains);
  });
  var missingIpv4Cidrs = reference.ipv4Cidrs.filter(function (cidr) {
    return configured.ipv4Cidrs.indexOf(cidr) < 0;
  });
  var missingIpv6Cidrs = reference.ipv6Cidrs.filter(function (cidr) {
    return configured.ipv6Cidrs.indexOf(cidr.toLowerCase()) < 0;
  });

  return {
    ok: missingDomains.length === 0 && missingIpv4Cidrs.length === 0 && missingIpv6Cidrs.length === 0,
    missing: {
      domains: missingDomains,
      ipv4Cidrs: missingIpv4Cidrs,
      ipv6Cidrs: missingIpv6Cidrs
    },
    advisory: {
      keywords: reference.keywords,
      asns: reference.asns,
      geosite: reference.geosite
    },
    reference: reference,
    configured: configured
  };
}

function printList(title, values) {
  if (!values || values.length === 0) return;
  console.log(title);
  for (var i = 0; i < values.length; i++) console.log("  - " + values[i]);
}

function printResult(result, sourceLabel) {
  console.log("Claude reference: " + sourceLabel);
  console.log("Configured domains: " + result.configured.domains.length);
  console.log("Reference domains: " + result.reference.domains.length);
  console.log("");

  if (result.ok) {
    console.log("OK: no missing concrete Claude domains or Anthropic CIDRs.");
  } else {
    console.log("Missing concrete rules:");
    printList("Domains", result.missing.domains);
    printList("IPv4 CIDRs", result.missing.ipv4Cidrs);
    printList("IPv6 CIDRs", result.missing.ipv6Cidrs);
  }

  if (result.advisory.keywords.length || result.advisory.asns.length || result.advisory.geosite.length) {
    console.log("");
    console.log("Advisory only, not enforced by default:");
    printList("Keywords", result.advisory.keywords);
    printList("ASN", result.advisory.asns);
    printList("GeoSite", result.advisory.geosite);
  }
}

async function main() {
  var args = parseArgs(process.argv);
  var referenceText;
  var scriptText;
  var result;
  var sourceLabel;

  if (args.help) {
    usage();
    return;
  }

  if (args.source) {
    referenceText = fs.readFileSync(args.source, "utf8");
    sourceLabel = args.source;
  } else {
    referenceText = await fetchText(args.url);
    sourceLabel = args.url;
  }

  scriptText = fs.readFileSync(args.script, "utf8");
  result = compareRules(extractReferenceRules(referenceText), extractConfiguredRules(scriptText));

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResult(result, sourceLabel);
  }

  if (!result.ok) process.exit(1);
}

module.exports = { extractConfiguredRules: extractConfiguredRules, domainCovered: domainCovered };
if (require.main === module) main().catch(function (error) {
  console.error("error: " + error.message);
  process.exit(1);
});
