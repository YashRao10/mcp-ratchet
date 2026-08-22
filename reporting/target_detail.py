"""Renders one per-target drill-down page — reports/target-<slug>.html —
linked from the main dashboard card once more than the toy fixture's worth
of real data exists behind it.

Same rule as dashboard.py: pure formatter. Every tool, hash, and finding
shown here is read straight out of that target's latest scan report and
audit log; this module makes no judgment calls of its own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from reporting.audit_summary import TargetSummary, build_summaries

REPO_ROOT = Path(__file__).resolve().parent.parent


def _tool_rows(scan: dict) -> str:
    fp = scan.get("fingerprint") or {}
    canonical = fp.get("per_tool_canonical") or {}
    hashes = fp.get("per_tool_hashes") or {}
    if not canonical:
        return '<tr><td colspan="3" class="empty-cell">No tool inventory in this scan.</td></tr>'

    rows = []
    for name in sorted(canonical):
        tool = canonical[name]
        desc = (tool.get("description") or "").strip()
        short_hash = (hashes.get(name) or "")[:12]
        rows.append(
            f'<tr><td class="mono">{escape(name)}</td>'
            f'<td class="tool-desc">{escape(desc)}</td>'
            f'<td class="mono hash">{escape(short_hash)}</td></tr>'
        )
    return "".join(rows)


def _finding_list(findings: list[dict], empty_label: str) -> str:
    if not findings:
        return f'<p class="empty-cell">{escape(empty_label)}</p>'
    items = []
    for f in findings:
        # Findings from different checks carry different fields; render
        # whatever keys are present rather than assuming one check's shape.
        parts = [f'<span class="mono finding-tool">{escape(str(f.get("tool_name", f.get("name", "?"))))}</span>']
        for key, val in f.items():
            if key in ("tool_name", "name"):
                continue
            parts.append(f'<span class="finding-field"><b>{escape(key)}:</b> {escape(str(val))}</span>')
        items.append(f'<li>{"".join(parts)}</li>')
    return f'<ul class="finding-list">{"".join(items)}</ul>'


def _drift_rows(events: list[dict]) -> str:
    if not events:
        return '<p class="empty-cell">No drift events logged for this target.</p>'
    rows = []
    for e in events:
        rows.append(
            f'<tr><td class="mono">{escape(str(e.get("timestamp", "")))}</td>'
            f'<td class="mono">{escape(str(e.get("drift_type", "?")))}</td>'
            f'<td class="mono">{escape(str(e.get("tool_name", "?")))}</td>'
            f'<td>{escape(str(e.get("detail", "")))}</td></tr>'
        )
    return "".join(rows)


def render_target_detail(summary: TargetSummary) -> str:
    scan = summary.latest_scan or {}
    s = scan.get("summary", {})
    fp = scan.get("fingerprint") or {}
    server_name = escape(scan.get("server_name") or summary.slug)
    target_command = escape(str(scan.get("target_command", "")))
    generated_at = escape(str(scan.get("generated_at", "never")))
    whole_hash = escape(str(fp.get("whole_server_hash", "")))
    generated_page_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(summary.slug)} &middot; mcp-ratchet</title>
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
.wrap{{max-width:960px; margin:0 auto; padding:48px 28px 90px;}}
a.back{{font-family:var(--mono); font-size:12.5px; color:var(--brass); text-decoration:none;}}
a.back:hover{{text-decoration:underline;}}
h1{{font-family:var(--head); font-weight:700; font-size:36px; letter-spacing:0.01em; margin:14px 0 2px; text-transform:uppercase;}}
.server-name{{color:var(--ink-faint); font-size:13px; margin-bottom:20px;}}
.command{{font-family:var(--mono); font-size:12px; color:var(--ink-soft); background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:10px 14px; margin-bottom:28px; word-break:break-all;}}
.meta-row{{display:flex; gap:24px; flex-wrap:wrap; font-family:var(--mono); font-size:12px; color:var(--ink-faint); margin-bottom:36px;}}
.meta-row b{{color:var(--ink-soft);}}
h2{{font-family:var(--head); font-size:18px; text-transform:uppercase; letter-spacing:0.03em; color:var(--ink); margin:36px 0 14px; padding-top:20px; border-top:1px solid var(--border);}}
table{{width:100%; border-collapse:collapse; font-size:13px;}}
th{{text-align:left; font-family:var(--head); font-size:11px; text-transform:uppercase; letter-spacing:0.04em; color:var(--ink-faint); padding:6px 10px; border-bottom:1px solid var(--border-strong);}}
td{{padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:top; color:var(--ink-soft);}}
.mono{{font-family:var(--mono);}}
.hash{{color:var(--ink-faint); font-size:11.5px;}}
.tool-desc{{white-space:pre-wrap; max-width:520px;}}
.empty-cell{{color:var(--ink-faint); font-family:var(--mono); font-size:13px; padding:10px 0;}}
.finding-list{{list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px;}}
.finding-list li{{background:var(--surface); border:1px solid rgba(217,119,87,0.35); border-radius:6px; padding:10px 12px; font-size:12.5px; display:flex; flex-direction:column; gap:4px;}}
.finding-tool{{color:var(--warn); font-weight:600;}}
.finding-field{{color:var(--ink-soft);}}
.finding-field b{{color:var(--ink-faint); font-weight:500;}}
footer{{margin-top:60px; padding-top:20px; border-top:1px solid var(--border); font-family:var(--mono); font-size:11px; color:var(--ink-faint);}}
</style>
</head><body>
<div class="wrap">
  <a class="back" href="dashboard.html">&larr; back to dashboard</a>
  <h1>{escape(summary.slug)}</h1>
  <div class="server-name">{server_name}</div>
  <div class="command">{target_command}</div>

  <div class="meta-row">
    <span><b>last scanned:</b> {generated_at}</span>
    <span><b>tool count:</b> {fp.get("tool_count", "&mdash;")}</span>
    <span><b>calls audited:</b> {summary.call_count}</span>
    <span><b>sessions:</b> {summary.session_count}</span>
    <span><b>drift events:</b> {summary.drift_event_count}</span>
  </div>
  <div class="meta-row">
    <span><b>whole-server hash:</b> <span class="mono hash">{whole_hash}</span></span>
  </div>

  <h2>Tool inventory</h2>
  <table>
    <thead><tr><th>tool</th><th>description</th><th>hash</th></tr></thead>
    <tbody>{_tool_rows(scan)}</tbody>
  </table>

  <h2>Findings &middot; permission mismatch</h2>
  {_finding_list(scan.get("mismatch_findings") or [], "No permission mismatches.")}

  <h2>Findings &middot; secrets</h2>
  {_finding_list(scan.get("secret_findings") or [], "No secrets detected.")}

  <h2>Findings &middot; dependency CVEs</h2>
  {_finding_list(scan.get("dependency_findings") or [], "No dependency findings.")}

  <h2>Drift history &middot; pure hashing, all events</h2>
  <table>
    <thead><tr><th>timestamp</th><th>type</th><th>tool</th><th>detail</th></tr></thead>
    <tbody>{_drift_rows(summary.all_drift_events)}</tbody>
  </table>

  <footer>generated {generated_page_at} &middot; schema: mcp-ratchet-audit-log/1</footer>
</div>
</body></html>
"""


def build_and_write_all(reports_dir: Path | None = None, logs_dir: Path | None = None, out_dir: Path | None = None) -> list[Path]:
    reports_dir = reports_dir or (REPO_ROOT / "reports")
    logs_dir = logs_dir or (REPO_ROOT / "logs")
    out_dir = out_dir or (REPO_ROOT / "reports")

    summaries = build_summaries(reports_dir, logs_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for summary in summaries:
        path = out_dir / f"target-{summary.slug}.html"
        path.write_text(render_target_detail(summary), encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    paths = build_and_write_all()
    for p in paths:
        print(f"Wrote {p}")
