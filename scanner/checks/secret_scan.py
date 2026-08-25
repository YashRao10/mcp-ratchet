"""Regex-based scan for obvious hardcoded secrets in a target server's
source, when that source is available on disk (a local launch command
pointing at a script this scanner can read).

Deliberately commodity-tier: this is pattern matching against well-known
credential shapes, not a claim of thorough secret detection. The README's
"what this does NOT do" section says so explicitly — a proper secret
scanner (entropy analysis, provider-specific validation) is a distinct,
much larger tool this project doesn't try to replace.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_api_key_assignment": re.compile(
        r"""(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']"""
    ),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
}


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    pattern_name: str
    matched_snippet: str  # kept short and non-reversible-looking, not the full secret

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "pattern_name": self.pattern_name,
            "matched_snippet": self.matched_snippet,
        }


def _redact(match_text: str) -> str:
    if len(match_text) <= 8:
        return "*" * len(match_text)
    return match_text[:4] + "…" + match_text[-4:]


def scan_file(path: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern_name, pattern in _SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                findings.append(
                    SecretFinding(
                        file_path=str(path),
                        line_number=line_number,
                        pattern_name=pattern_name,
                        matched_snippet=_redact(match.group(0)),
                    )
                )
    return findings


# Directories never worth descending into even if reachable from a target's
# launch cwd — avoids burning time/noise on dependency trees.
_SKIP_DIR_NAMES = {"node_modules", "__pycache__", ".git", "venv", ".venv", "dist", "build"}
_SCANNABLE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".env", ".yaml", ".yml", ".toml"}


def _is_scannable(path: Path) -> bool:
    """Whether scan_source_tree should read this file.

    `Path.suffix` was never actually catching dotenv files, despite ".env"
    sitting right there in _SCANNABLE_SUFFIXES: pathlib treats a leading dot
    as part of the stem for a file with only one dot in its name, so
    `Path(".env").suffix == ""`, not ".env" — and a variant like
    ".env.local" or ".env.production" has a suffix of ".local"/".production"
    instead. The net effect was that a literal `.env` file sitting right next
    to a target's launch script — the single most common place a real
    ANTHROPIC_API_KEY, bearer token, or DB password actually lives for an
    MCP server — was silently never scanned, with no error and no indication
    in the report that it had been skipped. Found dogfooding this check
    against a target with a real `.env` file present.

    Fixed by checking the filename directly for the dotenv family ahead of
    the suffix check, rather than trying to coerce pathlib's suffix
    semantics into matching it.

    Same class of problem applies to other extensionless config files that
    commonly carry real secrets: a bare `Dockerfile` (or an env-qualified
    variant like `Dockerfile.prod`) can hardcode an `ENV`/`ARG` credential,
    and a `Procfile` can hardcode one in a process command line. Both have
    no suffix at all, so they hit the same `path.suffix in
    _SCANNABLE_SUFFIXES` miss the dotenv family did — named explicitly in
    the README's "not yet built" section as a known gap until this fix.
    """
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return True
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return True
    if name == "Procfile":
        return True
    return path.suffix in _SCANNABLE_SUFFIXES


def scan_source_tree(root: Path, max_files: int = 500) -> list[SecretFinding]:
    """Walk a target server's source tree (if we have a real filesystem
    path for it — a local stdio launch command's script directory) and
    scan every plausibly-text file. Bounded by max_files so a target that
    happens to point at a huge directory can't make a scan hang.
    """
    if not root.exists():
        return []

    findings: list[SecretFinding] = []
    scanned = 0
    for path in root.rglob("*"):
        if scanned >= max_files:
            break
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if not path.is_file():
            continue
        if not _is_scannable(path):
            continue
        findings.extend(scan_file(path))
        scanned += 1
    return findings
