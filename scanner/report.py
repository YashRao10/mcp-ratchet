"""Assembles one scan run's results (fingerprint + all check outputs) into
a ScanResult, and renders it as JSON and a lightweight HTML report.

HTML rendering deliberately stays close to ai-compliance-crosswalk's
plain-formatter style: this module only formats data that scanner/run_scan.py
already computed — it does not itself decide any verdict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from scanner.checks.dependency_cve import DependencyFinding
from scanner.checks.permission_mismatch import MismatchFinding
from scanner.checks.prompt_injection import InjectionVerdict
from scanner.checks.secret_scan import SecretFinding
from scanner.fingerprint import ServerFingerprint

REPORT_SCHEMA_VERSION = 1


@dataclass
class ScanResult:
    report_schema_version: int
    target_slug: str
    target_command: str
    generated_at: str
    connect_ok: bool
    connect_error: str | None
    server_name: str | None
    server_version: str | None
    fingerprint: ServerFingerprint | None
    injection_verdicts: list[InjectionVerdict] = field(default_factory=list)
    mismatch_findings: list[MismatchFinding] = field(default_factory=list)
    secret_findings: list[SecretFinding] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)

    @property
    def suspicious_tool_count(self) -> int:
        return sum(1 for v in self.injection_verdicts if v.suspicious is True)

    @property
    def needs_review_count(self) -> int:
        return sum(1 for v in self.injection_verdicts if v.needs_review)

    @property
    def is_clean(self) -> bool:
        return (
            self.connect_ok
            and self.suspicious_tool_count == 0
            and not self.mismatch_findings
            and not self.secret_findings
            and not self.dependency_findings
        )

    def to_dict(self) -> dict:
        return {
            "report_schema_version": self.report_schema_version,
            "target_slug": self.target_slug,
            "target_command": self.target_command,
            "generated_at": self.generated_at,
            "connect_ok": self.connect_ok,
            "connect_error": self.connect_error,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "injection_verdicts": [v.to_dict() for v in self.injection_verdicts],
            "mismatch_findings": [m.to_dict() for m in self.mismatch_findings],
            "secret_findings": [s.to_dict() for s in self.secret_findings],
            "dependency_findings": [d.to_dict() for d in self.dependency_findings],
            "summary": {
                "is_clean": self.is_clean,
                "suspicious_tool_count": self.suspicious_tool_count,
                "needs_review_count": self.needs_review_count,
                "mismatch_count": len(self.mismatch_findings),
                "secret_count": len(self.secret_findings),
                "dependency_finding_count": len(self.dependency_findings),
            },
            "injection_check": {
                # TOR-11: the prompt-injection check is an LLM judgment call,
                # outside the DO-330-qualified drift-detection function. Its
                # output must never be represented as a qualified result.
                "qualification_status": "not_qualified",
                "note": "Advisory only. Carries no compliance credit; does not affect drift detection.",
            },
        }


def write_json(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def _row(*cells: str) -> str:
    return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def render_html(result: ScanResult) -> str:
    d = result.to_dict()
    summary = d["summary"]
    status = "CLEAN" if summary["is_clean"] else "FINDINGS PRESENT"
    status_class = "clean" if summary["is_clean"] else "flagged"

    injection_rows = "".join(
        _row(
            escape(v["tool_name"]),
            "NEEDS REVIEW" if v["needs_review"] else ("SUSPICIOUS" if v["suspicious"] else "clean"),
            escape(v.get("confidence") or ""),
            escape(v.get("reasoning") or v.get("raw_error") or ""),
        )
        for v in d["injection_verdicts"]
    )
    mismatch_rows = "".join(
        _row(
            escape(m["tool_name"]),
            escape(m["matched_verb_prefix"]),
            escape(", ".join(m["escalating_properties"])),
        )
        for m in d["mismatch_findings"]
    )
    secret_rows = "".join(
        _row(
            escape(s["file_path"]),
            str(s["line_number"]),
            escape(s["pattern_name"]),
            escape(s["matched_snippet"]),
        )
        for s in d["secret_findings"]
    )
    dependency_rows = "".join(
        _row(
            escape(dep["package_name"]),
            escape(dep["version"] or ""),
            escape(dep["ecosystem"]),
            escape(dep.get("resolution", "exact")),
            escape(", ".join(dep["vulnerability_ids"])),
        )
        for dep in d["dependency_findings"]
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>mcp-ratchet scan — {escape(d['target_slug'])}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#0d1113;color:#e9ece9;}}
h1,h2{{font-weight:600;}}
.status{{display:inline-block;padding:4px 12px;border-radius:20px;font-family:monospace;font-size:13px;}}
.status.clean{{background:#173026;color:#54c085;}}
.status.flagged{{background:#341a16;color:#e2705c;}}
table{{width:100%;border-collapse:collapse;margin:12px 0 28px;font-size:13px;}}
th,td{{border:1px solid #2a3234;padding:6px 10px;text-align:left;vertical-align:top;}}
th{{background:#1d2325;}}
code{{font-family:monospace;color:#5cc2b8;}}
.not-qualified{{font-family:monospace;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:#c9974a;border:1px solid rgba(201,151,74,0.5);border-radius:4px;padding:2px 7px;margin-left:8px;}}
.qual-note{{font-size:12px;color:#9aa5a3;margin:0 0 10px;max-width:640px;}}
</style></head><body>
<h1>mcp-ratchet scan report</h1>
<p><b>Target:</b> <code>{escape(d['target_slug'])}</code> — <code>{escape(d['target_command'])}</code><br>
<b>Generated:</b> {escape(d['generated_at'])}<br>
<b>Status:</b> <span class="status {status_class}">{status}</span></p>

<h2>Prompt-injection check (real Claude API verdict per tool) <span class="not-qualified">not a qualified result</span></h2>
<p class="qual-note">This check is an LLM judgment call, outside the DO-330-qualified drift-detection
function. It is advisory only and carries no compliance credit.</p>
<table><tr><th>Tool</th><th>Verdict</th><th>Confidence</th><th>Reasoning</th></tr>
{injection_rows or '<tr><td colspan="4">No tools scanned.</td></tr>'}
</table>

<h2>Permission-scope mismatch (scripted)</h2>
<table><tr><th>Tool</th><th>Matched verb</th><th>Escalating properties</th></tr>
{mismatch_rows or '<tr><td colspan="3">No mismatches found.</td></tr>'}
</table>

<h2>Secret scan (scripted, source tree only)</h2>
<table><tr><th>File</th><th>Line</th><th>Pattern</th><th>Match (redacted)</th></tr>
{secret_rows or '<tr><td colspan="4">No secrets found.</td></tr>'}
</table>

<h2>Dependency CVEs (OSV.dev)</h2>
<p style="font-size:13px;color:#9aa5a3;">"exact" resolution came from a lockfile or an exact pin — a real
resolved version. "best-effort-transitive" came from a bare manifest with
no lockfile, walked via registry metadata — an approximation, not a
guaranteed install set. See README's "what this does NOT do" section.</p>
<table><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Resolution</th><th>Vulnerability IDs</th></tr>
{dependency_rows or '<tr><td colspan="5">No dependency findings.</td></tr>'}
</table>

</body></html>
"""


def write_html(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
