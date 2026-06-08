# PROMPTMIRROR — Prompt-injection & indirect-injection scanner for any LLM context input

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-promptmirror.svg)](https://pypi.org/project/cognis-promptmirror/)
[![CI](https://github.com/cognis-digital/promptmirror/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/promptmirror/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Prompt-injection & indirect-injection scanner for any LLM context input.**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

## Why

Security and intelligence teams need prompt-injection & indirect-injection scanner for any LLM context input without standing up heavyweight infrastructure. `promptmirror` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

## Install

```bash
pip install cognis-promptmirror
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
promptmirror --version
promptmirror scan demos/                      # run against the bundled demo
promptmirror scan demos/ --format sarif --out r.sarif --fail-on high
promptmirror scan demos/ --format html --out report.html
promptmirror mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## What it detects

| Rule ID | Severity | Signal |
|---|---|---|
| `PM-IMP-001` | critical | Imperative Override |
| `PM-ROL-002` | high | Role Hijack |
| `PM-SYS-002` | high | Sys Prompt Extract |
| `PM-MD-001` | high | Md Smuggle |
| `PM-ZWS-001` | medium | Zero Width |
| `PM-TOOL-001` | high | Tool Call Inject |

*Rule set ships in this repo and grows over time — PRs adding detections are welcome.*

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-customer-support-email/`](demos/01-customer-support-email/SCENARIO.md)
- [`demos/02-rag-corpus-poisoning/`](demos/02-rag-corpus-poisoning/SCENARIO.md)
- [`demos/03-browser-context-base64/`](demos/03-browser-context-base64/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## Credits / Built on

Cognis composes and credits the best of open source. This tool builds on / interoperates with:

- [`utkusen/promptmap`](https://github.com/utkusen/promptmap) — pattern inspiration
- [`protectai/rebuff`](https://github.com/protectai/rebuff) — detection technique reference

Missing a credit? Open a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits the Cognis Neural Suite

`promptmirror` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `ai-security`:** [`aegis`](https://github.com/cognis-digital/aegis), [`ledgermind`](https://github.com/cognis-digital/ledgermind), [`adversa`](https://github.com/cognis-digital/adversa), [`guardpost`](https://github.com/cognis-digital/guardpost), [`hallumark`](https://github.com/cognis-digital/hallumark), [`aicard`](https://github.com/cognis-digital/aicard), [`biascope`](https://github.com/cognis-digital/biascope), [`mcpharden`](https://github.com/cognis-digital/mcpharden), [`agentlog`](https://github.com/cognis-digital/agentlog), [`ragshield`](https://github.com/cognis-digital/ragshield)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
