"""PROMPTMIRROR — prompt-injection & indirect-injection scanner.

A zero-dependency, standard-library-only scanner that inspects untrusted text
destined for an LLM context window (user input, retrieved documents, tool
output, web pages) and flags prompt-injection and indirect-injection attempts.

In the spirit of utkusen/promptmap, but built to scan arbitrary context inputs
rather than test a fixed system prompt.

Public API:
    scan_text(text, source=None) -> list[Finding]
    scan_file(path) -> list[Finding]
    scan_paths(paths) -> ScanReport
    findings_to_dict(findings) -> list[dict]
    RULES — the built-in detection ruleset
    Finding, ScanReport, Severity — data types
"""
from .core import (
    RULES,
    Finding,
    ScanReport,
    Severity,
    findings_to_dict,
    scan_file,
    scan_paths,
    scan_text,
)

TOOL_NAME = "promptmirror"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "RULES",
    "Finding",
    "ScanReport",
    "Severity",
    "findings_to_dict",
    "scan_file",
    "scan_paths",
    "scan_text",
]
