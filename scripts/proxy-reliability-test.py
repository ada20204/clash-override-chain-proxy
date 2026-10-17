#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def build_proxy_url(args):
    if args.proxy:
        return args.proxy
    if not args.host or not args.port:
        raise SystemExit("Either --proxy or both --host and --port are required.")
    auth = ""
    if args.username:
        auth = urllib.parse.quote(args.username, safe="")
        if args.password:
            auth += ":" + urllib.parse.quote(args.password, safe="")
        auth += "@"
    return "%s://%s%s:%s" % (args.scheme, auth, args.host, args.port)


def redact_proxy(proxy_url):
    parsed = urllib.parse.urlsplit(proxy_url)
    host = parsed.hostname or ""
    port = (":" + str(parsed.port)) if parsed.port else ""
    if parsed.username:
        netloc = "***:***@" + host + port
    else:
        netloc = host + port
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def tcp_probe(host, port, timeout):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {
                "ok": True,
                "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                "error": ""
            }
    except Exception as exc:
        return {
            "ok": False,
            "latency_ms": round((time.perf_counter() - start) * 1000, 1),
            "error": exc.__class__.__name__ + ": " + str(exc)
        }


def proxy_request(index, proxy_url, target_url, timeout, insecure):
    start = time.perf_counter()
    proxies = {"http": proxy_url, "https": proxy_url}
    context = ssl._create_unverified_context() if insecure else None
    handlers = [urllib.request.ProxyHandler(proxies)]
    if context:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "proxy-reliability-test/1.0",
            "Accept": "application/json,text/plain,*/*"
        }
    )
    try:
        resp = opener.open(req, timeout=timeout)
        with resp:
            body = resp.read(512)
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            return {
                "index": index,
                "ok": reachable_status(resp.status),
                "status": resp.status,
                "latency_ms": latency_ms,
                "error_type": "",
                "error": "",
                "sample": body.decode("utf-8", "replace").replace("\n", " ")[:160]
            }
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {
            "index": index,
            "ok": reachable_status(exc.code),
            "status": exc.code,
            "latency_ms": latency_ms,
            "error_type": "HTTPError",
            "error": str(exc),
            "sample": ""
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {
            "index": index,
            "ok": False,
            "status": "",
            "latency_ms": latency_ms,
            "error_type": exc.__class__.__name__,
            "error": str(exc),
            "sample": ""
        }


def reachable_status(status):
    # Target 4xx can demonstrate reachability; 407 means proxy authentication failed.
    return 200 <= status < 500 and status != 407


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct / 100.0
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    weight = pos - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 1)


def summarize(results):
    ok = [r for r in results if r["ok"]]
    fail = [r for r in results if not r["ok"]]
    latencies = [r["latency_ms"] for r in ok]
    errors = {}
    for r in fail:
        key = r["error_type"] or ("HTTP " + str(r["status"]))
        errors[key] = errors.get(key, 0) + 1
    return {
        "total": len(results),
        "success": len(ok),
        "failed": len(fail),
        "success_rate": round(len(ok) * 100.0 / len(results), 2) if results else 0,
        "latency_ms": {
            "min": min(latencies) if latencies else None,
            "avg": round(sum(latencies) / len(latencies), 1) if latencies else None,
            "p50": percentile(latencies, 50),
            "p90": percentile(latencies, 90),
            "max": max(latencies) if latencies else None
        },
        "errors": errors
    }


def write_csv(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["index", "ok", "status", "latency_ms", "error_type", "error", "sample"]
        )
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(
        description="Batch test HTTP proxy reliability through a target URL."
    )
    parser.add_argument("--proxy", help="Full proxy URL, e.g. http://user:pass@1.2.3.4:8080")
    parser.add_argument("--scheme", default="http", choices=["http", "https"], help="Proxy scheme when using --host.")
    parser.add_argument("--host", help="Proxy host/IP.")
    parser.add_argument("--port", type=int, help="Proxy port.")
    parser.add_argument("--username", help="Proxy username.")
    parser.add_argument("--password", help="Proxy password.")
    parser.add_argument("--url", default="https://ipapi.is/", help="Target URL used through the proxy.")
    parser.add_argument("--count", type=int, default=30, help="Total request attempts.")
    parser.add_argument("--concurrency", type=int, default=1, help="Concurrent requests.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-attempt timeout seconds.")
    parser.add_argument("--interval", type=float, default=0.0, help="Delay between scheduling attempts.")
    parser.add_argument("--csv", help="Optional CSV output path.")
    parser.add_argument("--json", action="store_true", help="Print final summary as JSON.")
    parser.add_argument("--tcp-check", action="store_true", help="Check TCP port before HTTP proxy requests.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification for target URL.")
    args = parser.parse_args()

    proxy_url = build_proxy_url(args)
    if args.count < 1:
        raise SystemExit("--count must be >= 1.")
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be >= 1.")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be > 0.")
    if args.interval < 0:
        raise SystemExit("--interval must be >= 0.")

    parsed_proxy = urllib.parse.urlsplit(proxy_url)
    if not parsed_proxy.scheme or not parsed_proxy.hostname or not parsed_proxy.port:
        raise SystemExit("Proxy URL must include scheme, host and port, e.g. http://user:pass@1.2.3.4:8080")

    print("Proxy:  %s" % redact_proxy(proxy_url))
    print("Target: %s" % args.url)
    print("Count:  %s, concurrency: %s, timeout: %ss" % (args.count, args.concurrency, args.timeout))

    if args.tcp_check:
        tcp = tcp_probe(parsed_proxy.hostname, parsed_proxy.port, args.timeout)
        print("TCP:    %s latency=%sms %s" % ("OK" if tcp["ok"] else "FAIL", tcp["latency_ms"], tcp["error"]))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = []
        for i in range(1, args.count + 1):
            futures.append(pool.submit(proxy_request, i, proxy_url, args.url, args.timeout, args.insecure))
            if args.interval > 0:
                time.sleep(args.interval)
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            status = result["status"] if result["status"] != "" else "-"
            state = "OK" if result["ok"] else "FAIL"
            print(
                "#%03d %-4s status=%s latency=%sms %s" %
                (result["index"], state, status, result["latency_ms"], result["error_type"] or "")
            )

    results.sort(key=lambda r: r["index"])
    summary = summarize(results)
    if args.csv:
        write_csv(args.csv, results)
        print("CSV:    %s" % args.csv)

    print("\nSummary")
    print("  success: %s/%s (%s%%)" % (summary["success"], summary["total"], summary["success_rate"]))
    print("  latency: min={min} avg={avg} p50={p50} p90={p90} max={max} ms".format(**summary["latency_ms"]))
    if summary["errors"]:
        print("  errors:")
        for key in sorted(summary["errors"]):
            print("    %s: %s" % (key, summary["errors"][key]))
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    if summary["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
