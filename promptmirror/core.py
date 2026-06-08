"""Core detection engine for PROMPTMIRROR.

The engine runs a curated set of regular-expression rules over text, grouping
them into the canonical prompt-injection categories. It reports byte/line
locations, severity, and the matched snippet so findings are actionable in a
pipeline.

Design notes:
- Detection is signature-based (regex) plus a couple of structural heuristics
  (hidden Unicode control characters, suspiciously long base64-looking blobs).
  This is deterministic, explainable, and dependency-free.
- Rules are intentionally conservative on severity so that CI gating on HIGH
  findings is meaningful.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional, Pattern, Sequence


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    category: str
    severity: Severity
    description: str
    pattern: Pattern[str]


@dataclass
class Finding:
    """One matched location in a scanned input."""

    rule_id: str
    category: str
    severity: Severity
    description: str
    source: str
    line: int
    column: int
    snippet: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass
class ScanReport:
    """Aggregate result of scanning one or more inputs."""

    findings: List[Finding] = field(default_factory=list)
    scanned_sources: List[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def counts_by_severity(self) -> dict:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "tool": "promptmirror",
            "scanned_sources": self.scanned_sources,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "highest_severity": (
                    self.highest_severity.value if self.highest_severity else None
                ),
            },
            "findings": findings_to_dict(self.findings),
        }


def _rule(id_, category, severity, description, regex, flags=re.IGNORECASE):
    return Rule(
        id=id_,
        category=category,
        severity=severity,
        description=description,
        pattern=re.compile(regex, flags),
    )


# ---------------------------------------------------------------------------
# Ruleset. Each rule targets a known prompt-injection technique.
# ---------------------------------------------------------------------------
RULES: Sequence[Rule] = (
    _rule(
        "PM001",
        "instruction-override",
        Severity.HIGH,
        "Attempt to override or discard prior/system instructions",
        r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|directions?|context|messages?)",
    ),
    _rule(
        "PM002",
        "instruction-override",
        Severity.HIGH,
        "Request to disregard or forget instructions/rules",
        r"\b(?:disregard|forget|discard|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|system)?\s*(?:instructions?|rules?|guidelines?|prompts?|context)",
    ),
    _rule(
        "PM003",
        "system-prompt-leak",
        Severity.HIGH,
        "Attempt to exfiltrate the system prompt or hidden instructions",
        r"\b(?:reveal|repeat|print|show|expose|output|disclose|tell\s+me)\b[^.\n]{0,40}\b(?:system\s+prompt|initial\s+instructions?|hidden\s+(?:prompt|instructions?)|your\s+(?:instructions?|rules?|prompt))",
    ),
    _rule(
        "PM004",
        "role-manipulation",
        Severity.HIGH,
        "Jailbreak persona / developer-mode / DAN role manipulation",
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you)\b[^.\n]{0,60}\b(?:DAN|developer\s+mode|jailbreak|unrestricted|no\s+(?:rules|filters|restrictions)|do\s+anything\s+now)",
    ),
    _rule(
        "PM005",
        "role-manipulation",
        Severity.MEDIUM,
        "Fake conversation-role / chat-delimiter injection",
        r"(?:^|\n)\s*(?:###?\s*)?(?:system|assistant|user)\s*:|<\|?(?:im_start|im_end|system|assistant|user)\|?>|\[/?INST\]",
    ),
    _rule(
        "PM006",
        "safety-bypass",
        Severity.HIGH,
        "Explicit request to bypass safety / content policy",
        r"\b(?:bypass|circumvent|disable|turn\s+off|ignore)\b[^.\n]{0,40}\b(?:safety|guardrails?|content\s+(?:policy|filter)|restrictions?|moderation|alignment)",
    ),
    _rule(
        "PM007",
        "indirect-injection",
        Severity.HIGH,
        "Embedded directive aimed at an AI/assistant/LLM reader",
        r"\b(?:AI|assistant|language\s+model|LLM|chatbot|agent|model)\b[^.\n]{0,30}\b(?:must|should|will|please|now)\b[^.\n]{0,40}\b(?:ignore|send|email|forward|delete|execute|run|reply|fetch|browse|leak|reveal)",
    ),
    _rule(
        "PM008",
        "data-exfiltration",
        Severity.HIGH,
        "Instruction to exfiltrate data to an external destination",
        r"\b(?:send|email|post|upload|exfiltrate|forward|transmit|leak)\b[^.\n]{0,40}\b(?:to\s+)?(?:https?://|www\.|[\w.-]+@[\w.-]+\.\w+|attacker|external\s+(?:server|url|endpoint))",
    ),
    _rule(
        "PM009",
        "tool-abuse",
        Severity.MEDIUM,
        "Directive to invoke tools / shell / code execution",
        r"\b(?:execute|run|invoke|call)\b[^.\n]{0,30}\b(?:command|shell|bash|os\.system|subprocess|eval|the\s+following\s+(?:code|script))",
    ),
    _rule(
        "PM010",
        "prompt-fencing",
        Severity.MEDIUM,
        "Fake 'end of prompt / new instructions begin' fencing",
        r"(?:end\s+of\s+(?:prompt|instructions?|context)|new\s+instructions?\s+(?:begin|follow|start)|begin\s+new\s+(?:prompt|instructions?)|---+\s*new\s+(?:prompt|task))",
    ),
    _rule(
        "PM011",
        "secret-exfiltration",
        Severity.HIGH,
        "Attempt to extract API keys / credentials / secrets",
        r"\b(?:reveal|print|show|give\s+me|output|leak|what\s+is)\b[^.\n]{0,30}\b(?:api\s*key|secret|password|token|credential|private\s+key)",
    ),
)


# ---------------------------------------------------------------------------
# Structural heuristics (not regex rules over visible text).
# ---------------------------------------------------------------------------
_INVISIBLE_RANGES = (
    (0x200B, 0x200F),  # zero-width spaces / joiners / marks
    (0x202A, 0x202E),  # bidi overrides
    (0x2060, 0x2064),  # word joiner / invisible operators
    (0xE0000, 0xE007F),  # Unicode tag block (used to smuggle ASCII)
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM mid-text
)

_BASE64ISH = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _is_invisible(cp: int) -> bool:
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _line_col(text: str, index: int) -> tuple:
    """Return 1-based (line, column) for a character offset."""
    prefix = text[:index]
    line = prefix.count("\n") + 1
    last_nl = prefix.rfind("\n")
    col = index - last_nl  # 1-based: char after newline is column 1
    return line, col


def _snippet(text: str, start: int, end: int, radius: int = 24) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    frag = text[lo:hi].replace("\n", "\\n").replace("\r", "")
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return (prefix + frag + suffix).strip()


def scan_text(text: str, source: Optional[str] = None) -> List[Finding]:
    """Scan a string and return findings. ``source`` labels the origin."""
    source = source or "<text>"
    findings: List[Finding] = []

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            line, col = _line_col(text, m.start())
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    source=source,
                    line=line,
                    column=col,
                    snippet=_snippet(text, m.start(), m.end()),
                )
            )

    # Heuristic: hidden / invisible control characters used to smuggle text.
    for idx, ch in enumerate(text):
        if _is_invisible(ord(ch)):
            line, col = _line_col(text, idx)
            name = unicodedata.name(ch, "U+%04X" % ord(ch))
            findings.append(
                Finding(
                    rule_id="PM050",
                    category="hidden-text",
                    severity=Severity.HIGH,
                    description="Invisible/control Unicode character (possible hidden instruction): "
                    + name,
                    source=source,
                    line=line,
                    column=col,
                    snippet=_snippet(text, idx, idx + 1),
                )
            )

    # Heuristic: long base64-looking blob (possible smuggled/encoded payload).
    for m in _BASE64ISH.finditer(text):
        line, col = _line_col(text, m.start())
        findings.append(
            Finding(
                rule_id="PM051",
                category="obfuscation",
                severity=Severity.LOW,
                description="Long base64-like blob (possible encoded/obfuscated payload)",
                source=source,
                line=line,
                column=col,
                snippet=_snippet(text, m.start(), m.start() + 32, radius=0),
            )
        )

    findings.sort(key=lambda f: (-f.severity.rank, f.line, f.column, f.rule_id))
    return findings


def scan_file(path: str) -> List[Finding]:
    """Read a file as UTF-8 (replacement on error) and scan it."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return scan_text(text, source=path)


def scan_paths(paths: Iterable[str]) -> ScanReport:
    """Scan multiple files into a single report."""
    report = ScanReport()
    for p in paths:
        report.scanned_sources.append(p)
        report.findings.extend(scan_file(p))
    report.findings.sort(
        key=lambda f: (-f.severity.rank, f.source, f.line, f.column, f.rule_id)
    )
    return report


def findings_to_dict(findings: Sequence[Finding]) -> List[dict]:
    return [f.to_dict() for f in findings]
