"""CLI entrypoint to verify a policy approval log's hash chain (see
proxy/policy.py's module docstring for what this does and does not
guarantee — same bounded guarantee as proxy/verify_log.py's audit-log
verifier).

Usage:
    python -m proxy.verify_policy_log policy/toy.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proxy.policy import verify_policy_chain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log_path", help="Path to a policy/<slug>.jsonl approval log written by append_approval_record().")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    path = Path(args.log_path)
    if not path.exists():
        print(f"No such file: {path}", file=sys.stderr)
        return 1

    result = verify_policy_chain(path)
    print(result.detail)
    if not result.ok:
        print(f"  First problem at line {result.broken_at_line}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
