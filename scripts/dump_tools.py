"""Save a server's tools/list as a benign test fixture.

Starts vuln-triage-mcp with `uvx vuln-triage-mcp` over stdio, calls tools/list, and writes
{"tools": [...]} as ASCII-only JSON (non-ASCII becomes \\uXXXX escapes), so the fixture
holds no raw hidden characters. Only run this against servers you trust: it executes them.
This is a dev script, not part of the scanner, which never runs a target.

Usage: uv run scripts/dump_tools.py [--out PATH] [--package NAME]
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

DEFAULT_OUT = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/tool_defs/benign/vuln_triage_mcp.json"
)


async def dump(package: str) -> dict:
    transport = StdioTransport(command="uvx", args=[package])
    async with Client(transport) as client:
        tools = await client.list_tools()
    return {
        "_comment": f"Benign: tools/list from `uvx {package}`, saved by scripts/dump_tools.py.",
        "tools": [
            t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--package", default="vuln-triage-mcp")
    args = parser.parse_args()

    snapshot = asyncio.run(dump(args.package))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    print(f"wrote {len(snapshot['tools'])} tools to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
