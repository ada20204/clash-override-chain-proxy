#!/usr/bin/env node
"use strict";

var fs = require("fs");
var os = require("os");
var childProcess = require("child_process");
var acorn = require("acorn");

function usage() {
  console.log([
    "Usage:",
    "  node scripts/update-interface-name.js --file <出口IP凭证.js> --server <IP> [--write]",
    "  node scripts/update-interface-name.js --file <出口IP凭证.js> --server <IP> --interface <ifname> [--write]",
    "",
    "Options:",
    "  --file       JS credential override file to update",
    "  --server     Proxy server IP to match, for example 192.168.88.10",
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

function updateFileContent(text, server, interfaceName) {
  var objects = [];
  function key(property) {
    if (property.type !== "Property" || property.computed) return null;
    return property.key.name || property.key.value;
  }
  function visit(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "ObjectExpression" && node.properties.some(function (p) {
      return key(p) === "server" && p.value.type === "Literal" && p.value.value === server;
    })) objects.push(node);
    Object.keys(node).forEach(function (field) {
      if (Array.isArray(node[field])) node[field].forEach(visit);
      else if (node[field] && typeof node[field].type === "string") visit(node[field]);
    });
  }
  visit(acorn.parse(text, { ecmaVersion: "latest" }));
  if (objects.length !== 1) throw new Error("Expected exactly one proxy object matching --server; found " + objects.length);
  var object = objects[0];
  if (object.properties.filter(function (p) { return key(p) === "server"; }).length !== 1) {
    throw new Error("Ambiguous server fields in proxy object");
  }
  if (object.properties.some(function (p) { return p.type !== "Property" || p.computed || p.kind !== "init" || p.method || p.shorthand; })) {
    throw new Error("Proxy must use static properties, without spread, computed keys or accessors");
  }
  var interfaces = object.properties.filter(function (p) { return key(p) === "interfaceName" || key(p) === "interface-name"; });
  if (interfaces.length > 1) throw new Error("Ambiguous interface fields in proxy object");
  var content;
  if (interfaces.length) {
    var value = interfaces[0].value;
    content = text.slice(0, value.start) + JSON.stringify(interfaceName) + text.slice(value.end);
  } else {
    // Insert before the first property, so existing trailing commas and comments stay intact.
    var first = object.properties[0];
    var indent = /^[ \t]*/.exec(text.slice(text.lastIndexOf("\n", first.start - 1) + 1, first.start))[0];
    var separator = text.slice(object.start, object.end).indexOf("\n") >= 0
      ? (text.indexOf("\r\n") >= 0 ? "\r\n" : "\n") + indent : " ";
    content = text.slice(0, first.start) + "interfaceName: " + JSON.stringify(interfaceName) + "," + separator + text.slice(first.start);
  }
  acorn.parse(content, { ecmaVersion: "latest" });
  return { changed: content !== text, content: content };
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
    console.log(result.changed ? "Preview: matching proxy interface will be updated (credentials hidden)." : "Preview: no change.");
    console.log("Repeat the same command, keeping --interface if supplied, and add --write to modify the file.");
  }
}

try {
  main();
} catch (error) {
  console.error("error: " + error.message);
  process.exit(1);
}
