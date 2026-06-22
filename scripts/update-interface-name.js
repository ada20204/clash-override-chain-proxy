#!/usr/bin/env node
"use strict";

var fs = require("fs");
var os = require("os");
var childProcess = require("child_process");

function usage() {
  console.log([
    "Usage:",
    "  node scripts/update-interface-name.js --file <出口IP凭证.js> --server <IP> [--write]",
    "  node scripts/update-interface-name.js --file <出口IP凭证.js> --server <IP> --interface <ifname> [--write]",
    "",
    "Options:",
    "  --file       JS credential override file to update",
    "  --server     Proxy server IP to match, for example 10.96.0.100",
    "  --interface  Interface name to write; auto-detected when omitted",
    "  --write      Modify the file. Without this flag, only prints a dry-run preview",
    "  --help       Show this help"
  ].join("\n"));
}

function parseArgs(argv) {
  var args = { write: false };
  for (var i = 2; i < argv.length; i++) {
    var item = argv[i];
    if (item === "--help" || item === "-h") {
      args.help = true;
    } else if (item === "--write") {
      args.write = true;
    } else if (item === "--file" || item === "--server" || item === "--interface") {
      if (i + 1 >= argv.length) throw new Error(item + " requires a value");
      args[item.slice(2)] = argv[++i];
    } else {
      throw new Error("Unknown argument: " + item);
    }
  }
  return args;
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

function detectInterface(server) {
  var platform = os.platform();
  var output;
  var match;

  if (platform === "darwin") {
    output = childProcess.execFileSync("route", ["-n", "get", server], { encoding: "utf8" });
    match = output.match(/^\s*interface:\s*(\S+)/m);
    if (match) return match[1];
    throw new Error("Unable to parse interface from route output:\n" + output);
  }

  if (platform === "linux") {
    output = childProcess.execFileSync("ip", ["route", "get", server], { encoding: "utf8" });
    match = output.match(/\bdev\s+(\S+)/);
    if (match) return match[1];
    throw new Error("Unable to parse interface from ip route output:\n" + output);
  }

  throw new Error("Auto-detect is not supported on " + platform + ". Use --interface <name>.");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function findMatchingBrace(text, startIndex) {
  var depth = 0;
  var quote = null;
  var escaped = false;
  var lineComment = false;
  var blockComment = false;

  for (var i = startIndex; i < text.length; i++) {
    var ch = text[i];
    var next = text[i + 1];

    if (lineComment) {
      if (ch === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (ch === "*" && next === "/") {
        blockComment = false;
        i++;
      }
      continue;
    }
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

    if (ch === "/" && next === "/") {
      lineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      blockComment = true;
      i++;
      continue;
    }
    if (ch === "\"" || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "{") depth++;
    if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function findProxyObject(text, server) {
  var serverPattern = new RegExp("server\\s*:\\s*['\\\"]" + escapeRegExp(server) + "['\\\"]");
  var match = serverPattern.exec(text);
  var start;
  var end;

  if (!match) throw new Error("Cannot find custom proxy with server: " + server);
  start = text.lastIndexOf("{", match.index);
  if (start < 0) throw new Error("Cannot find object start for server: " + server);
  end = findMatchingBrace(text, start);
  if (end < 0) throw new Error("Cannot find object end for server: " + server);
  return { start: start, end: end + 1, body: text.slice(start, end + 1) };
}

function updateObjectInterfaceName(objectBody, interfaceName) {
  var quotedInterface = JSON.stringify(interfaceName);
  var interfacePattern = /(^[ \t]*)(?:(?:interfaceName)|(?:"interface-name")|(?:'interface-name'))\s*:\s*(['"])(?:\\.|(?!\2).)*\2\s*,?/m;
  var match = interfacePattern.exec(objectBody);
  var lineMatch;
  var insertIndex;
  var indent;

  if (match) {
    return objectBody.replace(interfacePattern, match[1] + "interfaceName: " + quotedInterface + ",");
  }

  lineMatch = /(^[ \t]*server\s*:\s*['"][^'"]+['"]\s*,?.*$)/m.exec(objectBody);
  if (!lineMatch) lineMatch = /(^[ \t]*port\s*:\s*[^,\n]+,?.*$)/m.exec(objectBody);
  if (!lineMatch) throw new Error("Cannot find insertion point inside proxy object");

  insertIndex = lineMatch.index + lineMatch[0].length;
  indent = (/^[ \t]*/.exec(lineMatch[0]) || [""])[0];
  return objectBody.slice(0, insertIndex) +
    "\n" + indent + "interfaceName: " + quotedInterface + "," +
    objectBody.slice(insertIndex);
}

function updateFileContent(text, server, interfaceName) {
  var objectInfo = findProxyObject(text, server);
  var updatedBody = updateObjectInterfaceName(objectInfo.body, interfaceName);
  return {
    changed: updatedBody !== objectInfo.body,
    content: text.slice(0, objectInfo.start) + updatedBody + text.slice(objectInfo.end),
    objectBefore: objectInfo.body,
    objectAfter: updatedBody
  };
}

function main() {
  var args = parseArgs(process.argv);
  var interfaceName;
  var text;
  var result;

  if (args.help) {
    usage();
    return;
  }
  if (!args.file || !args.server) {
    usage();
    throw new Error("--file and --server are required");
  }

  interfaceName = args.interface || detectInterface(args.server);
  text = fs.readFileSync(args.file, "utf8");
  result = updateFileContent(text, args.server, interfaceName);

  console.log("server: " + args.server);
  console.log("interfaceName: " + interfaceName);
  console.log("file: " + args.file);
  console.log("mode: " + (args.write ? "write" : "dry-run"));

  if (args.write) {
    fs.writeFileSync(args.file, result.content);
    console.log(result.changed ? "updated: yes" : "updated: no-change");
  } else {
    console.log("");
    console.log("Preview:");
    console.log(result.objectAfter);
    console.log("");
    console.log("Run with --write to modify the file:");
    console.log("node scripts/update-interface-name.js --file " + shellQuote(args.file) +
      " --server " + shellQuote(args.server) + " --write");
  }
}

try {
  main();
} catch (error) {
  console.error("error: " + error.message);
  process.exit(1);
}
