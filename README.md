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
- `secret_scan.py` only reads a fixed, small set of file suffixes
  (`.py`, `.js`, `.ts`, `.mjs`, `.cjs`, `.json`, `.env`, `.yaml`, `.yml`,
  `.toml`), capped at 500 files per target — it does not attempt to sniff
  arbitrary binary/text content, and it only ever sees a local stdio
  target's on-disk source tree at all (a remote HTTP target has no
  filesystem this scanner can reach). Until this round, the `.env` entry
  in that suffix list never actually did anything: `Path(".env").suffix`
  is `""` in Python's pathlib (a filename with exactly one dot treats
  everything before it as the stem, not the suffix), so a literal `.env`
  file — the single most likely place a real MCP server target keeps a
  live secret — was silently skipped every time, and a variant like
  `.env.local` or `.env.production` fared no better (`.suffix` there is
  `.local`/`.production`, matching nothing in the list either). Found
  dogfooding this check against a target with a real `.env` file present.
  Fixed by checking the filename directly for the dotenv family
  (`name == ".env"` or `name.startswith(".env.")`) ahead of the suffix
  check, in `_is_scannable`. Same fix now also covers a bare `Dockerfile`
  (and env-qualified variants like `Dockerfile.prod`) and a `Procfile` —
  both extensionless, both a real place a credential ends up hardcoded
  (a Dockerfile `ENV`/`ARG` line, a Procfile process command line). Still
  not covered: any other extensionless config file outside these three
  named families (a bare `Makefile`, for instance).
- `scanner/scan_batch.py` scans a list of your own already-known targets
  in one run (`python -m scanner.scan_batch --config targets.json`),
  writing each target's usual per-target report plus one aggregate batch
  summary. This is NOT registry-wide scanning — it never discovers targets
  on its own, only scans the ones you already listed. One failing target
  doesn't abort the rest of the batch.
- Tamper-evidence on the audit log is hash-chained (`proxy/audit_log.py`'s
  `verify_chain`, `python -m proxy.verify_log <path>`), which catches a
  log edited, reordered, or truncated *after the fact*. It does NOT
  protect against a compromised proxy computing a consistent fake chain
  from the start — that would need something outside this process's
  control entirely (an external append-only store, a signing key the
  proxy never has custody of). Named here deliberately, same as before;
  only the first half of this limitation has been solved.
- The approval policy store (`policy/<slug>.json`, what `--block-on-drift`
  actually reads at proxy startup) now has the same hash-chain guarantee
  as the audit log, via a second append-only log at `policy/<slug>.jsonl`
  (`proxy/policy.py`'s `append_approval_record`/`verify_policy_chain`,
  `python -m proxy.verify_policy_log <path>`) built on the primitives
  factored out into `proxy/hash_chain.py` so both logs share one hashing
  implementation. Same bounded guarantee, not a stronger one: it catches
  the `.jsonl` history being edited, reordered, or truncated after the
  fact, not a compromised writer faking a consistent chain from genesis.
  It also does not, by itself, prove the `.json` snapshot hasn't been
  hand-edited to disagree with that history — `rebuild_snapshot_from_chain`
  reconstructs a snapshot purely from the verified `.jsonl` so a human can
  diff it against what's actually on disk in `.json` and catch exactly
  that kind of drift between "what the log says was approved" and "what
  the fast-lookup file currently claims."
- No semantic/whitespace-normalized diffing as a distinct diff mode —
  every field-level drift event now carries a `whitespace_only_change`
  flag (see above) so a cosmetic edit is labeled, but the exact-hash
  ratchet still fires on it exactly as before. A mode that suppresses
  those events outright is deliberately not offered — see "Read this
  before trusting a report" above for why that guarantee isn't
  negotiable.
- The dependency-CVE check looks at exact-pinned versions in a manifest or
  lockfile sitting next to a local target's launch script, preferring a
  lockfile over its corresponding bare manifest whenever both exist (a
  lockfile resolves every version, direct **and** transitive, rather than
  leaving it as a `^`/`~`/unpinned range): `poetry.lock`, `Pipfile.lock`,
  `requirements.txt`, `pyproject.toml` (also handles pip-compile's
  `\`-continued/`--hash=` output, not just a plain pin list), npm's
  `package-lock.json`, **Yarn's `yarn.lock`** (classic v1 lockfile format
  only — not the newer Yarn Berry/v2+ format, which is real YAML and isn't
  parsed here), then `package.json`. If both `package-lock.json` and
  `yarn.lock` exist (a migration artifact, in practice), `package-lock.json`
  wins arbitrarily; this check doesn't try to guess which one npm/yarn
  would actually honor for an install. Both lockfile parsers (`package-lock.json`
  and `yarn.lock`) used to be name-keyed: a real "diamond dependency" case
  where two different specifiers legitimately resolve the same package
  name to two different versions collapsed to whichever one was parsed
  last, silently dropping the other resolved version's CVEs. Fixed this
  round — both parsers now return every distinct `(name, version)` pair
  actually present in the lockfile (deduped only on the exact pair, so two
  specifiers resolving to the *same* version still collapse to one entry,
  but two that resolve to genuinely different versions are both kept and
  both queried against OSV.dev independently). When none of that resolves a
  package to an exact version — a bare `package.json` with `^`/`~` ranges
  and no `package-lock.json`/`yarn.lock`, a `pyproject.toml` with no
  `poetry.lock`/`Pipfile.lock` (its PEP 621 `[project.dependencies]` array
  is always a range, never a resolved version), or a `requirements.txt`
  line that isn't a plain `==` pin — `scanner/checks/transitive_deps.py`
  now does a
  **best-effort** registry-metadata walk instead of giving up: for each
  direct dependency it queries the real npm registry or PyPI's JSON API
  for that package's latest published version and that version's own
  declared dependencies, and walks outward up to `MAX_TRANSITIVE_DEPTH`
  (2) hops, with a visited-set guard so a circular dependency reference
  can't infinite-loop it. This is explicitly **not** a real dependency
  solve — no pip/npm/poetry-grade constraint-graph resolution, no
  conflict resolution across sibling requirements, no backtracking. It
  picks "latest" as its candidate version for every package it walks,
  which is not necessarily what a real installer would pick given the
  full constraint graph, so it can both over-report (packages a real
  resolver would never select because a sibling constraint ruled them
  out) and under-report (a real resolver sometimes picks an older version
  to satisfy a shared constraint, and that older version can carry an
  entirely different dependency set). Every `DependencyFinding` this check
  produces now carries a `resolution` field — `"exact"` for a lockfile
  entry or an exact pin, `"best-effort-transitive"` for anything that
  came out of this walk — so a report reader can tell at a glance which
  guarantee applies to which finding; the HTML report surfaces this as
  its own column, not a footnote.
- The proxy monitors by default and never blocks a call on its own —
  `--block-on-drift` (opt-in, off unless passed) refuses a call to any
  tool currently believed to have drifted from baseline (added, or an
  existing tool with a changed description/schema/annotations), before
  ever reaching the downstream server. "Currently believed" means as of
  the most recent `tools/list` diff this session; a call made before this
  proxy has listed tools yet cannot be assessed and is allowed through
  (fails open on missing information, not closed) — see
  `proxy/server_side.py`'s `build_proxy_server` docstring. There IS now a
  persistent policy store (`proxy/policy.py`, `policy/<slug>.json`,
  mirroring the `baselines/<slug>.json` convention): a drift event a human
  has reviewed and approved via
  `python -m proxy.approve_drift <target> <tool_name>` (reads the real
  `drift_event` records back out of that target's most recent audit log —
  it won't let you approve something never actually observed) is no
  longer blocked in future sessions, even though it's still logged and
  still shows up in the audit log/dashboard exactly as before — approval
  changes only whether a call is refused, never the historical record.
  An approval is scoped to the *exact* `tool_name` +
  `baseline_hash` + `current_hash` transition, not the tool name alone —
  a further, different edit to an already-approved tool produces a new
  `current_hash` that doesn't match, and blocks again. The approval
  history now has the same hash-chain guarantee as the audit log (see
  above): every approval is also appended to `policy/<slug>.jsonl`,
  verifiable with `python -m proxy.verify_policy_log <path>`, catching
  that file being edited, reordered, or truncated after the fact. What's
  still NOT covered: `policy/<slug>.json` — the fast-lookup snapshot
  `--block-on-drift` actually reads at startup — remains a plain
  overwritten JSON file, not a chain, so a verified `.jsonl` history does
  not by itself prove the `.json` snapshot hasn't been hand-edited to
  disagree with it. `rebuild_snapshot_from_chain` reconstructs a snapshot
  purely from the verified `.jsonl` so a human can diff it against the
  actual `.json` on disk and catch exactly that kind of drift.
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

# Scan several of your own already-known targets in one run
python -m scanner.scan_batch --config targets.json
```

`targets.json` for the batch command above:
```json
{
  "targets": [
    {"slug": "toy", "command": ["python", "tests/fixtures/toy_server.py"]},
    {"slug": "my-remote", "url": "https://example.com/mcp", "bearer_token_env": "MY_TOKEN"}
  ]
}
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
default, not stored raw (`--log-raw-args` to opt in). By default the proxy
only monitors, never blocking a call even when drift is detected. Pass
`--block-on-drift` to make it refuse a call to any tool it currently
believes has drifted from baseline instead — see the "not yet built"
section above for exactly what that mode does and doesn't cover, including
the persistent approval store.

Once you've reviewed a drift event and decided it's safe, approve it so it
stops re-blocking every future session:

```bash
python -m proxy.approve_drift toy delete_all_notes
```

Reads the real `drift_event` records for that tool back out of the
target's most recent log, and writes the exact transition into
`policy/toy.json`. See the "not yet built" section above for what this
approval is and isn't scoped to.

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
                         secret_scan.py, dependency_cve.py,
                         transitive_deps.py (best-effort registry-walk
                         resolver dependency_cve.py falls back to for a
                         bare manifest with no lockfile)
  report.py             Assembles + renders JSON/HTML
  run_scan.py            CLI entrypoint
  scan_batch.py           CLI entrypoint: scan a list of your own targets in one run

proxy/               Layer 2 — runtime proxy/monitor
  client_side.py        Persistent connection to the real downstream target
  server_side.py         Presents this proxy as an MCP server upstream
  forward.py              Transparent request/response pass-through
  drift.py                 Diffs live tools/list against the Phase 1 baseline
  audit_log.py              Writes schemas/audit_log_v1.schema.json records,
                              hash-chained for tamper-evidence
  verify_log.py               CLI entrypoint: verify a log's hash chain
  policy.py                    Persistent policy/<slug>.json store of
                                 human-approved drift transitions
  approve_drift.py               CLI entrypoint: approve a reviewed drift
                                   event out of a target's audit log
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
