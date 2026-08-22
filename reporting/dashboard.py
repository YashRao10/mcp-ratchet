"""Renders reporting/audit_summary.py's aggregated data into
reports/dashboard.html — a single, self-contained static page (no build
step, no external JS framework) that GitHub Pages serves directly.

Pure formatter: every number on this page is real, computed by
audit_summary.py from actual scan reports and audit logs on disk. This
module makes no findings of its own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from reporting.audit_summary import TargetSummary, build_summaries
from reporting.target_detail import build_and_write_all

REPO_ROOT = Path(__file__).resolve().parent.parent


def _status_pill(summary: TargetSummary) -> str:
    if summary.latest_scan is None:
        return '<span class="pill pill-unknown">no scan yet</span>'
    if summary.has_live_drift:
        return '<span class="pill pill-drift">drift detected</span>'
    if summary.is_clean:
        return '<span class="pill pill-clean">clean</span>'
    return '<span class="pill pill-flagged">findings present</span>'


def _check_chip(label: str, count: int, kind: str) -> str:
    tone = "chip-flag" if count > 0 else "chip-ok"
    return f'<span class="chip {tone}"><span class="chip-n">{count}</span>{escape(label)}</span>'


def _tier_group(tier_label: str, tier_class: str, chips: str) -> str:
    """One trust-tier's chips under a small labeled header — see README's
    "Read this before trusting a report": a finding's weight depends on
    which of three genuinely different places it came from, and the
    dashboard should make that grouping visible, not just list five chips
    with no indication of which kind of check produced which count."""
    return f'<div class="tier tier-{tier_class}"><div class="tier-label">{escape(tier_label)}</div><div class="chip-row">{chips}</div></div>'


def _target_card(summary: TargetSummary) -> str:
    scan = summary.latest_scan or {}
    s = scan.get("summary", {})
    fp = scan.get("fingerprint") or {}

    judgment_chips = "".join(
        [
            _check_chip("suspicious", s.get("suspicious_tool_count", 0), "injection"),
            _check_chip("needs review", s.get("needs_review_count", 0), "review"),
        ]
    )
    deterministic_chips = "".join(
        [
            _check_chip("perm. mismatch", s.get("mismatch_count", 0), "mismatch"),
            _check_chip("secrets", s.get("secret_count", 0), "secret"),
            _check_chip("dep. CVEs", s.get("dependency_finding_count", 0), "cve"),
        ]
    )
    tiers = (
        _tier_group("Judgment · real Claude API call", "judgment", judgment_chips)
        + _tier_group("Deterministic · scripted rules", "deterministic", deterministic_chips)
    )

    drift_rows = "".join(
        f'<li><span class="drift-type">{escape(e.get("drift_type", "?"))}</span>'
        f'<span class="drift-tool">{escape(e.get("tool_name", "?"))}</span>'
        f'<span class="drift-detail">{escape((e.get("detail") or "")[:140])}</span></li>'
        for e in summary.recent_drift_events
    )
    drift_block = (
        f'<div class="tier tier-hash"><div class="drift-log"><div class="drift-log-label">'
        f'Pure hashing · fingerprint drift</div><ul>{drift_rows}</ul></div></div>'
        if drift_rows
        else ""
    )

    scanned_at = escape(scan.get("generated_at", "never"))
    tool_count = fp.get("tool_count", "—")
    server_name = escape(scan.get("server_name") or summary.slug)

    detail_href = f"target-{summary.slug}.html"

    return f"""
    <article class="card">
      <header class="card-head">
        <div>
          <div class="card-slug"><a class="card-slug-link" href="{escape(detail_href)}">{escape(summary.slug)}</a></div>
          <div class="card-server">{server_name}</div>
        </div>
        {_status_pill(summary)}
      </header>

      <dl class="stat-row">
        <div><dt>tools</dt><dd>{tool_count}</dd></div>
        <div><dt>calls</dt><dd>{summary.call_count}</dd></div>
        <div><dt>sessions</dt><dd>{summary.session_count}</dd></div>
        <div><dt>drift</dt><dd class="{'v-warn' if summary.drift_event_count else ''}">{summary.drift_event_count}</dd></div>
      </dl>

      {tiers}

      <div class="card-foot">last scanned {scanned_at}</div>

      {drift_block}
    </article>"""


def render_dashboard(summaries: list[TargetSummary]) -> str:
    total = len(summaries)
    clean = sum(1 for s in summaries if s.is_clean and not s.has_live_drift)
    flagged = sum(1 for s in summaries if not s.is_clean)
    drifted = sum(1 for s in summaries if s.has_live_drift)
    total_calls = sum(s.call_count for s in summaries)
    total_drift_events = sum(s.drift_event_count for s in summaries)

    cards = "".join(_target_card(s) for s in summaries) or (
        '<p class="empty">No targets scanned yet. Run <code>python -m scanner.run_scan</code> '
        "against a real MCP server to populate this dashboard.</p>"
    )

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-ratchet</title>
<meta name="description" content="A security scanner and runtime drift monitor for MCP servers.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=Public+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:#0a0b0d; --surface:#14171a; --surface-2:#1b1f23; --border:#262b30; --border-strong:#353b41;
  --ink:#eef1f0; --ink-soft:#9aa3a8; --ink-faint:#5f686d;
  --brass:#c9974a; --steel:#4a9d9c; --warn:#d97757; --critical:#d1495b;
  --head:"Barlow Condensed",sans-serif; --body:"Public Sans",system-ui,sans-serif; --mono:"JetBrains Mono",Consolas,monospace;
}}
*{{box-sizing:border-box;}}
html{{background:var(--bg);}}
body{{background:var(--bg); color:var(--ink); font-family:var(--body); margin:0; font-size:15px; line-height:1.55;}}
.wrap{{max-width:1180px; margin:0 auto; padding:56px 28px 90px;}}

.top{{display:flex; justify-content:space-between; align-items:flex-end; gap:24px; flex-wrap:wrap; margin-bottom:8px;}}
.brand{{display:flex; align-items:baseline; gap:14px;}}
.mark{{font-family:var(--mono); font-size:13px; color:var(--brass); border:1px solid var(--brass); border-radius:4px; padding:2px 7px; letter-spacing:0.06em;}}
h1{{font-family:var(--head); font-weight:700; font-size:44px; letter-spacing:0.01em; margin:0; text-transform:uppercase; text-wrap:balance;}}
.tagline{{color:var(--ink-soft); font-size:15px; max-width:520px; margin:10px 0 0;}}
.meta{{font-family:var(--mono); font-size:11.5px; color:var(--ink-faint); text-align:right;}}

.stats{{display:grid; grid-template-columns:repeat(5,1fr); gap:1px; background:var(--border); border:1px solid var(--border); border-radius:10px; overflow:hidden; margin:34px 0 46px;}}
.stat{{background:var(--surface); padding:20px 18px;}}
.stat .n{{font-family:var(--mono); font-size:30px; font-weight:600; font-variant-numeric:tabular-nums; color:var(--ink);}}
.stat .l{{font-family:var(--head); font-size:13px; text-transform:uppercase; letter-spacing:0.05em; color:var(--ink-soft); margin-top:4px;}}
.stat.clean .n{{color:var(--steel);}}
.stat.flagged .n{{color:var(--warn);}}
.stat.drift .n{{color:var(--critical);}}

.grid{{display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:18px;}}
.card{{background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:20px 22px;}}
.card-head{{display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom:16px;}}
.card-slug{{font-family:var(--mono); font-size:17px; font-weight:600; color:var(--ink);}}
.card-slug-link{{color:inherit; text-decoration:none; border-bottom:1px dashed var(--border-strong);}}
.card-slug-link:hover{{color:var(--brass); border-bottom-color:var(--brass);}}
.card-server{{color:var(--ink-faint); font-size:12.5px; margin-top:2px;}}

.pill{{font-family:var(--head); font-size:12px; text-transform:uppercase; letter-spacing:0.04em; padding:4px 11px; border-radius:20px; white-space:nowrap; border:1px solid transparent;}}
.pill-clean{{background:rgba(74,157,154,0.12); color:var(--steel); border-color:rgba(74,157,154,0.35);}}
.pill-flagged{{background:rgba(217,119,87,0.12); color:var(--warn); border-color:rgba(217,119,87,0.35);}}
.pill-drift{{background:rgba(209,73,91,0.14); color:var(--critical); border-color:rgba(209,73,91,0.4);}}
.pill-unknown{{background:var(--surface-2); color:var(--ink-faint); border-color:var(--border-strong);}}

.stat-row{{display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:0 0 16px; padding:14px 0; border-top:1px solid var(--border); border-bottom:1px solid var(--border);}}
.stat-row dt{{font-family:var(--head); font-size:11px; text-transform:uppercase; letter-spacing:0.04em; color:var(--ink-faint); margin:0; white-space:nowrap;}}
.stat-row dd{{font-family:var(--mono); font-size:19px; font-weight:600; margin:2px 0 0; font-variant-numeric:tabular-nums;}}
.stat-row .v-warn{{color:var(--critical);}}

.tier{{margin-bottom:12px;}}
.tier-label{{font-family:var(--mono); font-size:10.5px; text-transform:uppercase; letter-spacing:0.05em; color:var(--ink-faint); margin-bottom:6px;}}
.tier-hash .tier-label,.tier-hash .drift-log-label{{color:var(--critical);}}
.chip-row{{display:flex; flex-wrap:wrap; gap:7px; margin-bottom:14px;}}
.chip{{font-family:var(--mono); font-size:11.5px; display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:5px; border:1px solid var(--border-strong); color:var(--ink-soft);}}
.chip-n{{font-weight:600; color:var(--ink);}}
.chip-flag{{border-color:rgba(217,119,87,0.45); background:rgba(217,119,87,0.08);}}
.chip-flag .chip-n{{color:var(--warn);}}

.card-foot{{font-family:var(--mono); font-size:11px; color:var(--ink-faint);}}

.drift-log{{margin-top:16px; padding-top:14px; border-top:1px dashed var(--border-strong);}}
.drift-log-label{{font-family:var(--head); font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:var(--critical); margin-bottom:8px;}}
.drift-log ul{{list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px;}}
.drift-log li{{font-size:12.5px; display:flex; flex-direction:column; gap:2px; background:var(--surface-2); border-radius:6px; padding:8px 10px;}}
.drift-type{{font-family:var(--mono); color:var(--critical); font-weight:600; font-size:11.5px; text-transform:uppercase;}}
.drift-tool{{font-family:var(--mono); color:var(--ink);}}
.drift-detail{{color:var(--ink-soft);}}

.empty{{color:var(--ink-faint); font-family:var(--mono); font-size:13px;}}
.empty code{{color:var(--brass);}}

footer{{margin-top:60px; padding-top:20px; border-top:1px solid var(--border); font-family:var(--mono); font-size:11px; color:var(--ink-faint); display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;}}
footer a{{color:var(--brass); text-decoration:none;}}
footer a:hover{{text-decoration:underline;}}
</style>
</head><body>
<div class="wrap">

  <div class="top">
    <div class="brand">
      <h1>mcp-ratchet</h1>
      <span class="mark">v1</span>
    </div>
    <div class="meta">generated {generated_at}</div>
  </div>
  <p class="tagline">A security scanner and runtime drift monitor for MCP servers &mdash; every install-time scanner checks once; this one keeps watching.</p>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">Targets tracked</div></div>
    <div class="stat clean"><div class="n">{clean}</div><div class="l">Clean</div></div>
    <div class="stat flagged"><div class="n">{flagged}</div><div class="l">Findings present</div></div>
    <div class="stat drift"><div class="n">{drifted}</div><div class="l">Live drift detected</div></div>
    <div class="stat"><div class="n">{total_calls}</div><div class="l">Calls audited</div></div>
  </div>

  <div class="grid">
    {cards}
  </div>

  <footer>
    <span>schema: mcp-ratchet-audit-log/1 &middot; {total_drift_events} total drift events logged</span>
    <span><a href="https://github.com/YashRao10/mcp-ratchet">github.com/YashRao10/mcp-ratchet</a></span>
  </footer>

</div>
</body></html>
"""


def build_and_write(reports_dir: Path | None = None, logs_dir: Path | None = None, out_path: Path | None = None) -> Path:
    reports_dir = reports_dir or (REPO_ROOT / "reports")
    logs_dir = logs_dir or (REPO_ROOT / "logs")
    out_path = out_path or (REPO_ROOT / "reports" / "dashboard.html")

    summaries = build_summaries(reports_dir, logs_dir)
    html = render_dashboard(summaries)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    # Per-target drill-down pages live alongside dashboard.html so the
    # dashboard's relative links ("target-<slug>.html") resolve the same
    # way locally and once GitHub Pages serves reports/ as _site/.
    build_and_write_all(reports_dir, logs_dir, out_path.parent)
    return out_path


if __name__ == "__main__":
    path = build_and_write()
    print(f"Wrote {path}")
