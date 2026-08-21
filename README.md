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
own, day one), and a runtime proxy that fingerprints a server's tool
surface once and can only ever detect drift against that baseline going
forward. A ratchet, not a snapshot.

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
  **A whitespace-only edit to a description still changes the hash, and
  still produces a drift event.** That's a deliberate trade-off (see
  below), not a bug. The resulting `DriftEvent` does carry a
  `whitespace_only_change` flag so you can see at a glance that a given
  event was purely cosmetic — but that flag is informational only; it
  never suppresses or downgrades the event itself.

## What this does NOT do (not yet built)

- No VirusTotal or malware-signature scanning, unlike Cisco's scanner.
- No Docker-sandboxed dynamic execution to observe real runtime behavior,
  unlike Snyk's.
- No certification or trust-tier scoring, unlike mpak.dev.
- No cross-server or registry-wide scanning — one target per run, by
  design, not yet a limitation to fix.
- Tamper-evidence on the audit log is hash-chained (`proxy/audit_log.py`'s
  `verify_chain`, `python -m proxy.verify_log <path>`), which catches a
  log edited, reordered, or truncated *after the fact*. It does NOT
  protect against a compromised proxy computing a consistent fake chain
  from the start — that would need something outside this process's
  control entirely (an external append-only store, a signing key the
  proxy never has custody of). Named here deliberately, same as before;
  only the first half of this limitation has been solved.
- No semantic/whitespace-normalized diffing as a distinct diff mode —
  every field-level drift event now carries a `whitespace_only_change`
  flag (see above) so a cosmetic edit is labeled, but the exact-hash
  ratchet still fires on it exactly as before. A mode that suppresses
  those events outright is deliberately not offered — see "Read this
  before trusting a report" above for why that guarantee isn't
  negotiable.
- The dependency-CVE check only looks at exact-pinned versions in a
  `requirements.txt`/`package.json` sitting next to a local target's
  launch script. No lockfile resolution, no transitive dependencies.
- The proxy only monitors — it never blocks a call even when drift is
  detected. Blocking/policy-enforcement mode is a plausible future
  direction, not current behavior.
- The dashboard aggregates whatever's on disk in `reports/`/`logs/` at
  build time — it has no live/push updates, it's a static snapshot
  regenerated on every push to `main`.

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
to `baselines/<slug>.json` — the runtime proxy diffs every future
connection against that baseline.

### Runtime proxy

Point Claude Code's or Cursor's MCP config at the proxy instead of the
real server directly — it forwards every request/response transparently,
and on every `tools/list` call, diffs the live result against the
baseline written above and logs a `drift_event` for anything that
changed (tool added/removed, description/schema/annotations changed).

```bash
# Run a scan first so a baseline exists:
python -m scanner.run_scan --slug toy --skip-injection-check -- python tests/fixtures/toy_server.py

# Then run the proxy in place of the real server:
python -m proxy.run_proxy --target toy -- python tests/fixtures/toy_server.py
```

Every call is logged to `logs/<slug>-<session>.jsonl` per the schema in
`schemas/audit_log_v1.schema.json` — tool-call arguments are hashed by
default, not stored raw (`--log-raw-args` to opt in). The proxy never
blocks a call, even when drift is detected — it's a monitor, not a
policy-enforcement gate, in this version.

Every record in that file is hash-chained to the one before it, so
editing, reordering, or truncating any past line breaks the chain for
everything after it:

```bash
python -m proxy.verify_log logs/toy-20260821T221732Z.jsonl
```

Prints whether the chain is intact from genesis and, if not, the exact
line where it broke. See `proxy/audit_log.py`'s module docstring for what
this guarantees and what it explicitly doesn't (it can't catch a
compromised proxy process faking a chain from the start).

## Project layout

```
scanner/            Layer 1 — static analyzer
  connect.py          MCP client: stdio or HTTP, enumerate a target's tools
  fingerprint.py       Canonical per-tool + whole-server hashing
  checks/               prompt_injection.py, permission_mismatch.py,
                         secret_scan.py, dependency_cve.py
  report.py             Assembles + renders JSON/HTML
  run_scan.py            CLI entrypoint

proxy/               Layer 2 — runtime proxy/monitor
  client_side.py        Persistent connection to the real downstream target
  server_side.py         Presents this proxy as an MCP server upstream
  forward.py              Transparent request/response pass-through
  drift.py                 Diffs live tools/list against the Phase 1 baseline
  audit_log.py              Writes schemas/audit_log_v1.schema.json records,
                              hash-chained for tamper-evidence
  verify_log.py               CLI entrypoint: verify a log's hash chain
  run_proxy.py               CLI entrypoint

reporting/           Layer 3 — dashboard
  audit_summary.py       Aggregates reports/*.json + logs/*.jsonl per target
  dashboard.py             Renders reports/dashboard.html (self-contained,
                            no build step — this is what GitHub Pages serves)

tests/
  fixtures/toy_server.py   A controllable MCP server with one planted
                            problem per check, used to prove each check
                            actually fires against a real MCP connection —
                            not just a hand-built dict.
```

## Dashboard

```bash
python -m reporting.dashboard   # writes reports/dashboard.html
```

Deploys automatically to GitHub Pages on every push to `main`
(`.github/workflows/deploy.yml`) — same pattern as `ai-compliance-crosswalk`.
Every number on the page is real, computed from whatever's actually on disk
in `reports/` and `logs/` at build time; there's no placeholder or demo
data path.

## Tests

```bash
pytest tests/
```

The integration suite (`tests/test_scan_integration.py`) spawns the real
toy fixture over a real stdio MCP connection and asserts each planted
problem is caught by its corresponding check — the fixture is a negative
control too (clean tools must stay unflagged).

`tests/test_drift.py` is the single most important test in the repo: it
copies the toy fixture to a temp dir, takes a real baseline, edits the
copy's live source (a description change, then separately a whole new
tool), reconnects, and asserts the resulting drift is caught and correctly
attributed — the actual proof that the "rug pull" premise this project is
built on holds up against a real, live MCP connection, not a hand-built
fixture. `tests/test_forward.py` proves the proxy's transparency
requirement: its output is byte-identical to a direct connection's.
