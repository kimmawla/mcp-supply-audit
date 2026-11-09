"""Save one of the maintainer's own servers' tools/list as a JSON snapshot.

Dev-only: run by hand. Never imported by src/, and never run by the scanner, which does not
execute targets. This script does execute the server, so it runs only the two servers in
SERVERS, the maintainer's own, with a fixed command each. Any other server name, and any
extra argument, is refused before anything starts. For every other server use
scripts/collect_tools_list.py, which runs the target in a locked-down container
(docs/benign-corpus.md).

The snapshot is {"_comment": ..., "tools": [...]} as ASCII-only JSON (non-ASCII becomes
\\uXXXX escapes), so it holds no raw hidden characters. The default output is
local_fixtures/<server>.tools.json (gitignored). To refresh the committed benign fixture,
review the local file and copy it by hand, or pass --out.

Usage: uv run scripts/dump_tools.py [SERVER] [--out PATH]
  SERVER  vuln-triage-mcp (default) or mcp-supply-audit
Exit status: 0 written, 2 refused or bad arguments.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Final

ROOT = Path(__file__).resolve().parents[1]
LOCAL_FIXTURES = ROOT / "local_fixtures"
DEFAULT_SERVER: Final = "vuln-triage-mcp"

# server name -> (command, args). Fixed here; nothing from the command line reaches them.
SERVERS: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "vuln-triage-mcp": ("uvx", ("vuln-triage-mcp",)),
    # Not on PyPI yet: run this checkout's own entry point.
    "mcp-supply-audit": ("uv", ("run", "--directory", str(ROOT), "mcp-supply-audit")),
}

REFUSAL: Final = (
    "dump_tools.py runs only vuln-triage-mcp and mcp-supply-audit, with fixed commands. "
    "For any other server use scripts/collect_tools_list.py (see docs/benign-corpus.md)."
)


def default_out(server: str) -> Path:
    return LOCAL_FIXTURES / f"{server}.tools.json"


def comment(server: str) -> str:
    command, args = SERVERS[server]
    shown = " ".join((command, *args)).replace(str(ROOT), ".")
    return f"Benign: tools/list from `{shown}`, saved by scripts/dump_tools.py."


async def dump(server: str) -> dict:
    # Imported here so the refusal path needs no MCP client at all.
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    command, args = SERVERS[server]
    transport = StdioTransport(command=command, args=list(args))
    async with Client(transport) as client:
        tools = await client.list_tools()
    return {
        "_comment": comment(server),
        "tools": [
            t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools
        ],
    }


def parse(argv: list[str] | None) -> argparse.Namespace | None:
    """Parsed arguments, or None (after printing REFUSAL) for anything not allowed."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], add_help=True)
    parser.add_argument("server", nargs="?", default=DEFAULT_SERVER)
    parser.add_argument("--out", type=Path)
    try:
        args, extra = parser.parse_known_args(argv)
    except SystemExit as exc:
        if exc.code == 0:  # --help
            raise
        print(REFUSAL, file=sys.stderr)
        return None
    if extra or args.server not in SERVERS:
        print(REFUSAL, file=sys.stderr)
        return None
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    if args is None:
        return 2
    out = args.out or default_out(args.server)
    snapshot = asyncio.run(dump(args.server))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    print(f"wrote {len(snapshot['tools'])} tools to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
