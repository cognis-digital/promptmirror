"""Command-line interface for PROMPTMIRROR.

Usage:
    promptmirror scan FILE [FILE ...] [--format table|json] [--fail-on low|medium|high]
    echo "..." | promptmirror scan -        # read from stdin
    promptmirror --version

Exit codes:
    0  no findings at/above the --fail-on threshold
    1  findings at/above the threshold (e.g. for CI gating)
    2  usage / IO error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ScanReport,
    Severity,
    findings_to_dict,
    scan_text,
)


def _read_source(path: str) -> tuple:
    """Return (label, text) for a path, supporting '-' as stdin."""
    if path == "-":
        return "<stdin>", sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return path, fh.read()


def _build_report(paths: List[str]) -> ScanReport:
    report = ScanReport()
    for p in paths:
        label, text = _read_source(p)
        report.scanned_sources.append(label)
        report.findings.extend(scan_text(text, source=label))
    report.findings.sort(
        key=lambda f: (-f.severity.rank, f.source, f.line, f.column, f.rule_id)
    )
    return report


def _render_table(report: ScanReport) -> str:
    lines: List[str] = []
    lines.append("PROMPTMIRROR scan")
    lines.append("  sources : " + (", ".join(report.scanned_sources) or "(none)"))
    counts = report.counts_by_severity()
    lines.append(
        "  summary : %d finding(s)  [high=%d medium=%d low=%d]"
        % (
            len(report.findings),
            counts["high"],
            counts["medium"],
            counts["low"],
        )
    )
    lines.append("")
    if not report.findings:
        lines.append("  No prompt-injection indicators detected.")
        return "\n".join(lines)

    header = "  %-8s %-5s %-22s %-7s  %s" % (
        "SEVERITY",
        "RULE",
        "CATEGORY",
        "LOC",
        "SNIPPET",
    )
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for f in report.findings:
        loc = "%d:%d" % (f.line, f.column)
        snippet = f.snippet if len(f.snippet) <= 60 else f.snippet[:57] + "…"
        lines.append(
            "  %-8s %-5s %-22s %-7s  %s"
            % (f.severity.value.upper(), f.rule_id, f.category, loc, snippet)
        )
    return "\n".join(lines)


def _render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Prompt-injection & indirect-injection scanner for LLM context inputs.",
        epilog="Example: promptmirror scan retrieved_doc.txt --format json --fail-on high",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + TOOL_VERSION,
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan one or more files (use '-' for stdin) for injection indicators.",
        description="Scan text inputs for prompt-injection and indirect-injection indicators.",
    )
    scan.add_argument(
        "paths",
        nargs="+",
        metavar="FILE",
        help="File(s) to scan. Use '-' to read from stdin.",
    )
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )
    scan.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        default="high",
        help="Minimum severity that causes a non-zero exit (default: high).",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        report = _build_report(args.paths)
    except OSError as exc:
        sys.stderr.write("promptmirror: error: %s\n" % exc)
        return 2

    if args.format == "json":
        sys.stdout.write(_render_json(report) + "\n")
    else:
        sys.stdout.write(_render_table(report) + "\n")

    threshold = Severity(args.fail_on).rank
    gated = any(f.severity.rank >= threshold for f in report.findings)
    return 1 if gated else 0


if __name__ == "__main__":
    raise SystemExit(main())
