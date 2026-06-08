"""PROMPTMIRROR — Prompt-injection scanner core."""
from __future__ import annotations
import re, base64, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "PROMPTMIRROR"
TOOL_VERSION = "0.1.0"

PATTERNS = [
    ("PM-IMP-001", "critical", 3.0, "IMPERATIVE_OVERRIDE",
     r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
     "Direct attempt to override system instructions",
     "Strip the document section before LLM ingestion or quarantine the entire file."),
    ("PM-ROL-002", "high", 2.5, "ROLE_HIJACK",
     r"(?i)you\s+are\s+(now|actually)\s+(a|an)\s+[a-z]+",
     "Persona/role takeover attempt",
     "Reject document or sandbox the LLM session."),
    ("PM-SYS-002", "high", 2.5, "SYS_PROMPT_EXTRACT",
     r"(?i)(reveal|print|show|expose)\s+(your\s+)?(system|original|initial)\s+(prompt|instructions)",
     "System-prompt exfiltration request",
     "Apply output filter / never echo system prompt."),
    ("PM-MD-001", "high", 2.5, "MD_SMUGGLE",
     r"!\[[^\]]*\]\(https?://[^)]+\?[^)]*=\{",
     "Markdown image tag with dynamic query — data exfil via image fetch",
     "Strip remote images or pin to allowlist before LLM rendering."),
    ("PM-ZWS-001", "medium", 2.0, "ZERO_WIDTH",
     r"[​-‍﻿⁠]",
     "Zero-width characters (often hide instructions)",
     "Normalize Unicode (NFKC) and strip control codepoints."),
    ("PM-TOOL-001", "high", 2.5, "TOOL_CALL_INJECT",
     r"(?i)<tool_use>|<function_call>|\{\{\s*tool\.",
     "Embedded tool/function-call directive",
     "Refuse documents containing structured tool markers from untrusted sources."),
]

def _b64_payload(text: str) -> list[tuple[int, str]]:
    """Find suspiciously long base64 blobs that decode to instruction-ish text."""
    hits = []
    for m in re.finditer(r"[A-Za-z0-9+/=]{40,}", text):
        try:
            decoded = base64.b64decode(m.group(0) + "===", validate=False).decode("utf-8", errors="ignore")
            if any(k in decoded.lower() for k in ("ignore", "system", "prompt", "you are", "reveal")):
                hits.append((m.start(), decoded[:120]))
        except Exception:
            pass
    return hits

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    files: list[Path] = []
    p = Path(target)
    if p.is_dir():
        files = [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".md", ".txt", ".html", ".rst", ".json")]
    elif p.is_file():
        files = [p]
    else:
        return result
    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid, sev, w, cat, pat, title, rem in PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=title, category=cat,
                    description=f"{title}: matched `{m.group(0)[:60]}`",
                    location=f"{f}:{line}", remediation=rem,
                    references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
                ))
        for pos, decoded in _b64_payload(text):
            line = text.count("\n", 0, pos) + 1
            result.add(Finding(
                id="PM-B64-001", severity="critical", weight=3.0,
                title="BASE64_INSTRUCTION_PAYLOAD",
                description=f"Base64 blob decodes to instruction-like content: {decoded!r}",
                location=f"{f}:{line}",
                remediation="Reject inputs with base64 instruction payloads; normalize encodings.",
                category="OBFUSCATED_INSTRUCTION",
            ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time() - t0) * 1000)
    return result
