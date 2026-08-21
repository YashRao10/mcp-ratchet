"""CLI entrypoint to verify an audit log's hash chain (see audit_log.py's
module docstring for what this does and does not guarantee).

Usage:
    python -m proxy.verify_log logs/toy-20260821T221732Z.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proxy.audit_log import verify_chain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log_path", help="Path to a .jsonl audit log written by AuditLogWriter.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    path = Path(args.log_path)
    if not path.exists():
        print(f"No such file: {path}", file=sys.stderr)
        return 1

    result = verify_chain(path)
    print(result.detail)
    if not result.ok:
        print(f"  First problem at line {result.broken_at_line}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
