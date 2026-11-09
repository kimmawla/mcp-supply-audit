"""Collect one server's tools/list from a locked-down container, for the benign eval corpus.

Dev-only: run by hand, following docs/benign-corpus.md. Never imported by src/, and never run
by the scanner, which does not execute targets. This script runs the target, so it only
accepts a `docker run` command that matches the run-phase policy in docs/benign-corpus.md:

  --network none, --read-only, --cap-drop ALL, --security-opt no-new-privileges, -i, --rm,
  no -e / --env / --env-file / --privileged / --network other than none, and every -v
  mount read-only (":ro").

The docker CLI itself gets only PATH and HOME from this process (plus DOCKER_HOST and
DOCKER_CONTEXT when set, so it can reach the daemon); the container gets none of them.
Install happens beforehand, in a separate `docker run` with network (see the doc).

The snapshot is written as ASCII-only JSON (non-ASCII becomes \\uXXXX escapes), so it holds
no raw hidden characters, and an entry is appended to MANIFEST.yaml in the same folder.

Usage:
  uv run scripts/collect_tools_list.py --slug SLUG --package NAME --ecosystem npm|pypi|source \\
      --version V --source-url URL --license SPDX --image IMAGE@DIGEST \\
      [--out-dir local_fixtures/benign] -- docker run ...
Exit status: 0 written, 1 policy or collection failure, 2 bad arguments.
"""

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import date
from pathlib import Path

import yaml
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / "local_fixtures/benign"
TIMEOUT_SECONDS = 60

REQUIRED_FLAGS = ("-i", "--rm", "--read-only")
REQUIRED_PAIRS = (
    ("--network", "none"),
    ("--cap-drop", "ALL"),
    ("--security-opt", "no-new-privileges"),
)
FORBIDDEN_PREFIXES = (
    "-e",
    "--env",
    "--env-file",
    "--privileged",
    "--cap-add",
    "-p",
    "--publish",
)
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _pairs(argv: list[str]) -> list[tuple[str, str]]:
    """(flag, value) for `--flag value` and `--flag=value` forms."""
    out = []
    for i, arg in enumerate(argv):
        if arg.startswith("-") and "=" in arg:
            flag, value = arg.split("=", 1)
            out.append((flag, value))
        elif arg.startswith("-") and i + 1 < len(argv):
            out.append((arg, argv[i + 1]))
    return out


def policy_violations(argv: list[str]) -> list[str]:
    """Why argv does not match the run-phase policy; empty when it does."""
    if argv[:2] != ["docker", "run"]:
        return ["command must start with: docker run"]
    # Options end at the image name: the first argument that is not a flag or a flag value.
    opts: list[str] = []
    i = 2
    takes_value = {
        "--network",
        "--cap-drop",
        "--security-opt",
        "--user",
        "-u",
        "--tmpfs",
        "--memory",
        "-m",
        "--pids-limit",
        "-v",
        "--volume",
        "--entrypoint",
        "--name",
        "--workdir",
        "-w",
        "--cpus",
        "--mount",
    }
    while i < len(argv) and argv[i].startswith("-"):
        opts.append(argv[i])
        if argv[i] in takes_value and i + 1 < len(argv):
            opts.append(argv[i + 1])
            i += 1
        i += 1
    problems = []
    for flag in REQUIRED_FLAGS:
        if flag not in opts:
            problems.append(f"missing {flag}")
    pairs = _pairs(opts)
    for flag, value in REQUIRED_PAIRS:
        if (flag, value) not in pairs:
            problems.append(f"missing {flag} {value}")
    for flag, value in pairs:
        if flag == "--network" and value != "none":
            problems.append("--network must be none")
        if flag in ("-v", "--volume") and not value.endswith(":ro"):
            problems.append("every -v mount must end with :ro")
        if flag == "--mount" and "readonly" not in value.split(","):
            problems.append("every --mount must be readonly")
    for opt in opts:
        name = opt.split("=", 1)[0]
        if name in FORBIDDEN_PREFIXES:
            problems.append(f"{name} is not allowed")
    return problems


def docker_cli_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
    for k in ("DOCKER_HOST", "DOCKER_CONTEXT"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


async def collect(argv: list[str]) -> list[dict]:
    transport = StdioTransport(command=argv[0], args=argv[1:], env=docker_cli_env())
    async with Client(transport, timeout=TIMEOUT_SECONDS) as client:
        tools = await client.list_tools()
    return [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools]


def append_manifest(path: Path, entry: dict) -> None:
    data = {"version": 1, "snapshots": []}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or data
    data["snapshots"] = [s for s in data["snapshots"] if s.get("file") != entry["file"]]
    data["snapshots"].append(entry)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--slug", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--ecosystem", required=True, choices=("npm", "pypi", "source"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--license", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not _SLUG.match(args.slug):
        parser.error("--slug: lowercase letters, digits and '-' only")
    problems = policy_violations(command)
    if problems:
        print("run command rejected: " + "; ".join(problems), file=sys.stderr)
        return 1
    try:
        tools = asyncio.run(collect(command))
    # Any failure (docker, the server, the protocol) ends the run. Report the type only:
    # the message may quote server output.
    except Exception as exc:  # noqa: BLE001
        print(f"collection failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.slug}.json"
    snapshot = {
        "_comment": "Benign eval snapshot; provenance in MANIFEST.yaml next to this file.",
        "tools": tools,
    }
    out.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    append_manifest(
        out_dir / "MANIFEST.yaml",
        {
            "file": out.name,
            "package": args.package,
            "ecosystem": args.ecosystem,
            "version": args.version,
            "source_url": args.source_url,
            "license": args.license,
            "collected": date.today().isoformat(),
            "image": args.image,
        },
    )
    print(f"wrote {len(tools)} tools to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
