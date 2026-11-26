"""nti-otel: command line verifier."""

from __future__ import annotations

import argparse
import json
import sys

from .chain import read_entries, verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nti-otel",
        description="Verify a hash-chained nti-otel record log.",
    )
    parser.add_argument("path", help="path to the JSONL record log")
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable result"
    )
    args = parser.parse_args(argv)

    try:
        entries = list(read_entries(args.path))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    problems = verify(entries)
    if args.json:
        print(
            json.dumps(
                {"ok": not problems, "entries": len(entries), "problems": problems}
            )
        )
    elif problems:
        print(f"FAIL: {len(problems)} problem(s) in {len(entries)} entries")
        for problem in problems[:20]:
            print(f"  - {problem}")
    else:
        first = entries[0]["record_hash"]
        last = entries[-1]["record_hash"]
        print(f"OK: {len(entries)} entries, chain intact")
        print(f"  head {first}")
        print(f"  tail {last}")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
