# mcp-ratchet

A security scanner and runtime drift monitor for MCP (Model Context
Protocol) servers.

## Why this exists

There are 17,000+ MCP server listings across various directories today,
with essentially no real vetting — the official MCP registry only checks
*namespace ownership* (who published a server), not whether the server is
safe or does what it claims. Several well-resourced tools already scan
MCP servers at install/publish time — Cisco's AI Defense MCP Scanner, Snyk
Agent Scan, mpak.dev's Trust Framework, Invariant Labs' mcp-scan. All of
them check a server **once**, at that first install or publish moment.

None of them keep watching. There's a real, documented attack class —
a server's tool definitions silently changing *after* a human approved it
("rug pull") — including a real April 2026 incident where researchers
hijacked Claude Code, Gemini CLI, and Copilot via instructions hidden in a
GitHub PR title. And there's no standardized audit-log format for MCP
tool-call activity anywhere in the industry.

mcp-ratchet is two things: a real static scanner (so it's useful on its
own, day one), and — once Phase 2 ships — a runtime proxy that fingerprints
a server's tool surface once and can only ever detect drift against that
baseline going forward. A ratchet, not a snapshot.

## Read this before trusting a report

Every finding in a report comes from one of three genuinely different
places, and they carry different weight:

- **A real Claude API call** (`scanner/checks/prompt_injection.py`) — the
  only judgment-based check. It's asked one narrow question per tool: does
  this description contain anything aimed at manipulating the agent
  reading it, not just describing the tool. A parse failure or API error
  is reported as `needs_review`, never silently folded into "clean."
- **Scripted, deterministic checks** — `permission_mismatch.py` (a small
  explicit rule table: does a tool named like it's read-only accept a
  schema parameter that lets it do more), `secret_scan.py` (regex against
  known credential shapes), `dependency_cve.py` (pinned-version lookups
  against OSV.dev). No model call, no judgment — same input always
  produces the same output.
- **Pure hashing, zero semantic judgment** — the fingerprint that backs
  drift detection. It hashes a tool's declared shape exactly.
  **A whitespace-only edit to a description still changes the hash.**
  That's a deliberate trade-off (see below), not a bug.

## What this does NOT do (not yet built)

- No VirusTotal or malware-signature scanning, unlike Cisco's scanner.
- No Docker-sandboxed dynamic execution to observe real runtime behavior,
  unlike Snyk's.
- No certification or trust-tier scoring, unlike mpak.dev.
- No cross-server or registry-wide scanning — one target per run, by
  design, not yet a limitation to fix.
- No tamper-evidence on the audit log itself, once Phase 2 ships — a
  compromised proxy could in principle falsify its own log. Named here
  deliberately even though solving it is out of scope for v1.
- No semantic/whitespace-normalized diffing — see above.
- The dependency-CVE check only looks at exact-pinned versions in a
  `requirements.txt`/`package.json` sitting next to a local target's
  launch script. No lockfile resolution, no transitive dependencies.

## Quickstart

```bash
pip install -r requirements-dev.txt

# Scan a local target
python -m scanner.run_scan --slug toy -- python tests/fixtures/toy_server.py

# Scan a remote target over HTTP
export MY_TOKEN=...
python -m scanner.run_scan --slug my-server \
    --url https://example.com/mcp --bearer-token-env MY_TOKEN

# Without ANTHROPIC_API_KEY set, every tool is reported needs_review
# for the prompt-injection check rather than silently skipped.
python -m scanner.run_scan --slug toy --skip-injection-check -- \
    python tests/fixtures/toy_server.py
```

A scan writes a JSON + HTML report to `reports/` and a baseline fingerprint
to `baselines/<slug>.json` — the second is what Phase 2's drift detection
will diff future scans against.

## Project layout

```
scanner/            Layer 1 — static analyzer (this is what's built so far)
  connect.py         MCP client: stdio or HTTP, enumerate a target's tools
  fingerprint.py      Canonical per-tool + whole-server hashing
  checks/              prompt_injection.py, permission_mismatch.py,
                        secret_scan.py, dependency_cve.py
  report.py            Assembles + renders JSON/HTML
  run_scan.py           CLI entrypoint

proxy/               Layer 2 — runtime proxy/monitor (not yet built)
reporting/           Layer 3 — dashboard (not yet built)

tests/
  fixtures/toy_server.py   A controllable MCP server with one planted
                            problem per check, used to prove each check
                            actually fires against a real MCP connection —
                            not just a hand-built dict.
```

## Tests

```bash
pytest tests/
```

The integration suite (`tests/test_scan_integration.py`) spawns the real
toy fixture over a real stdio MCP connection and asserts each planted
problem is caught by its corresponding check — the fixture is a negative
control too (clean tools must stay unflagged).
