"""No personal data in tracked files.

(a) No email address in a tracked file under tests/, docs/, scripts/, src/ (except
    src/mcp_supply_audit/data/), README.md or SECURITY.md, other than invented
    @example.invalid addresses, GitHub no-reply addresses, and ALLOWLIST below.
(b) Nothing under local_fixtures/ (real captures) is tracked by git.
(c) In tracked fixtures, every value inside a "_npmUser", "maintainers" or "author_email"
    block is an invented zqvex-* value (or null).

Failure messages name files, lines and JSON paths only, never the values found.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

SCANNED_DIRS = ("tests", "docs", "scripts", "src")
SCANNED_FILES = ("README.md", "SECURITY.md")
EXCLUDED_DIR = "src/mcp_supply_audit/data/"

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
ALLOWED_SUFFIXES = ("@example.invalid", "@users.noreply.github.com")
ALLOWED_EXACT = frozenset({"noreply@github.com"})

# Reviewed exceptions: none is a person's mailbox. Compared lowercased and exactly.
ALLOWLIST = frozenset(
    {
        # The git SSH user in scp-like and ssh:// repository URLs (registry.py, rules-registry.md,
        # test_registry_rules.py).
        "git@github.com",
        # npm trusted publishing's service identity, quoted in docs/api-notes.md (_npmUser).
        "npm-oidc-no-reply@github.com",
        # A mailto: input in test_registry_rules_safety.py.
        "someone@example.com",
        # URL userinfo (user:password@host) inputs in the URL-redaction tests.
        "pw@pypi.org",
        "pw@github.com",
        "pw@mcp.example.com",
        "pw@h.example",
        "ss@h.example",
        "ss-secret@h.example",
        "a@other.example",
        "git@git.zqvex.example",
        "pw@git.zqvex.example",
    }
)

PERSONAL_BLOCKS = frozenset({"_npmUser", "maintainers", "author_email"})
INVENTED = "zqvex"


# --- git helpers


def git_ls_files(*paths: str) -> list[str] | None:
    """Tracked paths under `paths`, or None when this is not a git checkout."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", *paths],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return [p for p in result.stdout.decode("utf-8").split("\0") if p]


def is_git_checkout() -> bool:
    return git_ls_files("pyproject.toml") is not None


# --- (a) email addresses


def is_allowed(address: str) -> bool:
    a = address.lower()
    return a.endswith(ALLOWED_SUFFIXES) or a in ALLOWED_EXACT or a in ALLOWLIST


def disallowed_address_lines(text: str) -> list[int]:
    """1-based line numbers holding an address that is not allowed."""
    return [
        n
        for n, line in enumerate(text.splitlines(), 1)
        if any(not is_allowed(m.group(0)) for m in EMAIL.finditer(line))
    ]


def email_scanned_files() -> list[str]:
    tracked = git_ls_files(*SCANNED_DIRS, *SCANNED_FILES)
    if tracked is None:  # not a git checkout: scan what is on disk instead
        tracked = [
            str(p.relative_to(ROOT))
            for d in SCANNED_DIRS
            for p in (ROOT / d).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts
        ] + [f for f in SCANNED_FILES if (ROOT / f).is_file()]
    return sorted(p for p in tracked if not p.startswith(EXCLUDED_DIR))


def test_scan_covers_fixtures_and_src_but_not_data():
    files = email_scanned_files()
    assert "tests/fixtures/api/npm_packument_express.json" in files
    assert "src/mcp_supply_audit/server.py" in files
    assert "README.md" in files
    assert not any(p.startswith(EXCLUDED_DIR) for p in files)


def test_address_checker():
    planted = "zqvex-real-person" + "@" + "mail.zqvex.example"
    text = "\n".join(
        [
            "zqvex-user-1@example.invalid",
            "1234+zqvex@users.noreply.github.com",
            "git+ssh://git@github.com/o/r.git",
            f'"email": "{planted}"',
            f"Name <{planted.upper()}>",
            "express@5.3.0 @modelcontextprotocol%2fsdk@1.32.2 @pytest.fixture",
        ]
    )
    assert disallowed_address_lines(text) == [4, 5]


def test_no_email_addresses_in_tracked_files():
    hits = {}
    for rel in email_scanned_files():
        path = ROOT / rel
        if not path.is_file():
            continue
        lines = disallowed_address_lines(
            path.read_text(encoding="utf-8", errors="replace")
        )
        if lines:
            hits[rel] = lines
    assert hits == {}, (
        "email addresses found (use zqvex-user-N@example.invalid, or add a reviewed entry "
        f"to ALLOWLIST); file: lines {hits}"
    )


# --- (b) local_fixtures/ is never tracked


def test_local_fixtures_not_tracked():
    tracked = git_ls_files("local_fixtures")
    if tracked is None:
        pytest.skip("not a git checkout")
    assert tracked == [], f"local_fixtures/ paths are tracked by git: {tracked}"


# --- (c) personal blocks in fixtures hold only invented values


def personal_block_violations(doc) -> list[str]:
    """JSON paths of scalar values inside personal blocks that are not invented zqvex values."""
    found: list[str] = []

    def leaves(value, path: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                leaves(v, f"{path}.{k}")
        elif isinstance(value, list):
            for i, v in enumerate(value):
                leaves(v, f"{path}[{i}]")
        elif value is not None and not (
            isinstance(value, str) and INVENTED in value.lower()
        ):
            found.append(path)

    def walk(value, path: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                if k in PERSONAL_BLOCKS:
                    leaves(v, f"{path}.{k}")
                else:
                    walk(v, f"{path}.{k}")
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{path}[{i}]")

    walk(doc, "$")
    return found


def tracked_fixtures() -> list[str]:
    tracked = git_ls_files("tests/fixtures")
    if tracked is None:
        tracked = [
            str(p.relative_to(ROOT))
            for p in (ROOT / "tests/fixtures").rglob("*")
            if p.is_file()
        ]
    return sorted(p for p in tracked if p.endswith(".json"))


def test_personal_block_checker():
    doc = {
        "maintainers": [
            {"name": "zqvex-person-1", "email": "zqvex-user-1@example.invalid"}
        ],
        "versions": {
            "1.0.0": {
                "_npmUser": {
                    "name": "Some" + "one",
                    "trustedPublisher": {"id": "github"},
                },
            }
        },
        "info": {"author_email": None, "author": "not checked here"},
    }
    assert personal_block_violations(doc) == [
        "$.versions.1.0.0._npmUser.name",
        "$.versions.1.0.0._npmUser.trustedPublisher.id",
    ]


def test_fixture_personal_blocks_are_invented():
    files = tracked_fixtures()
    assert "tests/fixtures/api/npm_packument_express.json" in files
    hits = {}
    for rel in files:
        path = ROOT / rel
        if not path.is_file():
            continue
        paths = personal_block_violations(json.loads(path.read_text(encoding="utf-8")))
        if paths:
            hits[rel] = paths
    assert hits == {}, (
        f"non-invented values in personal blocks (file: JSON paths): {hits}"
    )
