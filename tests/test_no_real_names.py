"""Tests and docs use invented zqvex-* names, never real third-party registry names.

Loads the packaged reference names (data/reference_names.json) and fails if any registry name
other than io.github.kimmawla/* appears in src/mcp_supply_audit/, tests/, docs/, scripts/,
README.md, or CLAUDE.md. src/mcp_supply_audit/data/ and local_fixtures/ are not scanned.
"""

import itertools
import json
import re
from pathlib import Path

from mcp_supply_audit.typosquat_check import read_reference_bytes

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "mcp_supply_audit"
SCANNED_DIRS = ("src/mcp_supply_audit", "tests", "docs", "scripts")
SCANNED_FILES = ("README.md", "CLAUDE.md")
# The packaged reference names are real by design.
EXCLUDED_DIRS = (SRC / "data",)
ALLOWED_PREFIX = "io.github.kimmawla/"

_NOT_NAME_CHAR = re.compile(r"[^A-Za-z0-9._/-]+")
_ENCODED_SLASH = re.compile(r"%2f", re.IGNORECASE)


def registry_names() -> frozenset[str]:
    data = json.loads(read_reference_bytes())
    names = list(data["listed"]["registry"]["names"])
    names += [e["name"] for e in data["curated"] if e["ecosystem"] == "registry"]
    return frozenset(
        n.lower() for n in names if not n.lower().startswith(ALLOWED_PREFIX)
    )


def names_in(text: str, names: frozenset[str]) -> set[str]:
    """Every `namespace/name` pair in text, including inside URLs and %2F-encoded forms."""
    found = set()
    for token in _NOT_NAME_CHAR.split(_ENCODED_SLASH.sub("/", text)):
        parts = token.split("/")
        for namespace, name in itertools.pairwise(parts):
            candidate = f"{namespace.lstrip('.')}/{name.rstrip('.')}"
            if candidate.lower() in names:
                found.add(candidate)
    return found


def scanned_files() -> list[Path]:
    files = [ROOT / f for f in SCANNED_FILES]
    for d in SCANNED_DIRS:
        files += (p for p in (ROOT / d).rglob("*") if "__pycache__" not in p.parts)
    return sorted(
        p
        for p in files
        if p.is_file() and not any(p.is_relative_to(x) for x in EXCLUDED_DIRS)
    )


def test_reference_names_loaded():
    assert len(registry_names()) > 1000


def test_detects_a_reference_name_in_any_form():
    names = registry_names()
    name = min(names)
    namespace, part = name.split("/", 1)
    assert names_in(f"see `{name}`.", names) == {name}
    assert names_in(f"/v0/servers/{namespace}%2F{part}/versions", names) == {name}
    assert names_in(f"Renamed to {name.upper()}", names) == {name.upper()}
    assert (
        names_in("io.github.kimmawla/vuln-triage-mcp ai.zqvex/zqvex-mcp", names)
        == set()
    )


def test_scans_src_but_not_its_data():
    files = scanned_files()
    assert SRC / "server.py" in files
    assert SRC / "validation.py" in files
    assert not any(p.is_relative_to(SRC / "data") for p in files)


def test_detects_a_reference_name_in_a_source_string():
    names = registry_names()
    name = min(names)
    source = (
        "_BAD_NAME = (\n"
        '    "Invalid name. Expected a registry name (<namespace>/<name>, e.g. "\n'
        f'    "{name}), or a package name."\n'
        ")\n"
    )
    assert names_in(source, names) == {name}
    invented = source.replace(name, "io.github.zqvex-owner/zqvex-server")
    assert names_in(invented, names) == set()


def test_no_real_registry_names_in_tests_or_docs():
    names = registry_names()
    hits = {}
    for path in scanned_files():
        found = names_in(path.read_text(encoding="utf-8", errors="replace"), names)
        if found:
            hits[str(path.relative_to(ROOT))] = sorted(found)
    assert hits == {}, f"real registry names found (use invented zqvex-* names): {hits}"
