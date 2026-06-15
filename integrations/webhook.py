#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST promptmirror JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True,
                    help="HTTPS/HTTP destination URL")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra header in 'Key: Value' form (repeatable)")
    ap.add_argument("--timeout", type=int, default=15,
                    help="Request timeout in seconds (default: 15)")
    args = ap.parse_args()

    # Validate URL scheme — only http/https accepted.
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print(
            f"error: --url must be an http or https URL, got {args.url!r}",
            file=sys.stderr,
        )
        return 2
    if not parsed.netloc:
        print(f"error: --url has no host: {args.url!r}", file=sys.stderr)
        return 2

    # Validate timeout range.
    if args.timeout <= 0:
        print("error: --timeout must be a positive integer", file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("error: empty payload on stdin — nothing to send", file=sys.stderr)
        return 2
    payload = raw.encode("utf-8")

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, sep, v = h.partition(":")
        if not sep:
            print(
                f"error: header {h!r} must be in 'Key: Value' form",
                file=sys.stderr,
            )
            return 2
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"webhook error: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook error: {e.reason}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
