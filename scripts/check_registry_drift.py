"""Check whether the registry's ownership-verifier source changed since it was recorded.

Dev-only: run by hand before each release. Never imported by src/ (a test checks).
Reads the "verifier-hashes" table in docs/api-notes.md, fetches each path at the
modelcontextprotocol/registry repo's current main, and compares SHA-256 hashes. A changed file
means RG005 and the notes may no longer match the registry: re-read it, update
docs/api-notes.md ("Ownership verification code") and RG005, then record the new hashes.

Usage: uv run scripts/check_registry_drift.py [--ref main]
Exit status: 0 unchanged, 1 changed or missing, 2 could not check.
"""

import argparse
import hashlib
import re
import sys
from collections.abc import Callable
from pathlib import Path

import httpx

NOTES = Path(__file__).resolve().parents[1] / "docs/api-notes.md"
RAW = "https://raw.githubusercontent.com/modelcontextprotocol/registry/{ref}/{path}"
_TABLE_RE = re.compile(
    r"<!-- verifier-hashes:start -->(.*?)<!-- verifier-hashes:end -->", re.DOTALL
)
_ROW_RE = re.compile(r"^\| `([^`]+)` \| `([0-9a-f]{64})` \|$", re.MULTILINE)


def recorded_hashes(notes_text: str) -> dict[str, str]:
    """Path -> recorded SHA-256, from the marked table in api-notes.md."""
    match = _TABLE_RE.search(notes_text)
    if not match:
        raise ValueError("no verifier-hashes table in docs/api-notes.md")
    rows = dict(_ROW_RE.findall(match.group(1)))
    if not rows:
        raise ValueError("verifier-hashes table has no rows")
    return rows


def compare(
    recorded: dict[str, str], fetch: Callable[[str], bytes | None]
) -> dict[str, str]:
    """Path -> "unchanged", "changed" or "missing". fetch returns None for a 404."""
    result = {}
    for path, expected in recorded.items():
        body = fetch(path)
        if body is None:
            result[path] = "missing"
        else:
            result[path] = (
                "unchanged"
                if hashlib.sha256(body).hexdigest() == expected
                else "changed"
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default="main")
    args = parser.parse_args()
    recorded = recorded_hashes(NOTES.read_text(encoding="utf-8"))

    with httpx.Client(timeout=30.0) as client:

        def fetch(path: str) -> bytes | None:
            response = client.get(RAW.format(ref=args.ref, path=path))
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.content

        try:
            result = compare(recorded, fetch)
        except httpx.HTTPError as exc:
            print(f"could not check: {type(exc).__name__}", file=sys.stderr)
            return 2

    for path, state in result.items():
        print(f"{state:9}  {path}", file=sys.stderr)
    drifted = [p for p, state in result.items() if state != "unchanged"]
    if drifted:
        print(
            f"{len(drifted)} verifier file(s) differ from the recorded commit at {args.ref}.",
            file=sys.stderr,
        )
        return 1
    print(f"All {len(result)} verifier files unchanged at {args.ref}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
