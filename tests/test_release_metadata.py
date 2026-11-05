"""Release metadata agrees across the tag, pyproject.toml, server.json and README, so an MCP
Registry publish can't drift from what PyPI ships.

server.json follows the registry's 2025-12-11 schema; the limits checked here are copied from
it (no schema validator is a dependency). On a tag push (GITHUB_REF_TYPE=tag), the tag must
match the version as well.
"""

import json
import os
import re
import tomllib
from importlib import metadata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
    "project"
]
README = (ROOT / "README.md").read_text(encoding="utf-8")

NAME = "io.github.kimmawla/mcp-supply-audit"
PACKAGE = "mcp-supply-audit"
REPOSITORY = "https://github.com/kimmawla/mcp-supply-audit"
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
# From that schema's ServerDetail: name pattern and length, description length.
NAME_RE = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
MAX_DESCRIPTION = 100
# The registry's PyPI ownership check: `mcp-name: <server name>` followed by a boundary
# (whitespace, an HTML tag, or the comment close "-->").
MCP_NAME_RE = re.compile(r"mcp-name:\s*([^\s<]+?)(?=\s|<|-->|$)")


def pypi_package() -> dict:
    assert len(SERVER_JSON["packages"]) == 1, "expected a single package"
    package = SERVER_JSON["packages"][0]
    assert package["registryType"] == "pypi"
    return package


def test_server_json_fields():
    assert SERVER_JSON["$schema"] == SCHEMA
    assert SERVER_JSON["name"] == NAME
    assert NAME_RE.match(NAME) and 3 <= len(NAME) <= 200
    assert 1 <= len(SERVER_JSON["description"]) <= MAX_DESCRIPTION
    assert SERVER_JSON["repository"] == {"url": REPOSITORY, "source": "github"}
    assert "remotes" not in SERVER_JSON
    package = pypi_package()
    assert package["identifier"] == PROJECT["name"] == PACKAGE
    assert package["transport"] == {"type": "stdio"}


def test_versions_agree():
    version = PROJECT["version"]
    assert SERVER_JSON["version"] == version
    assert pypi_package()["version"] == version
    assert metadata.version(PACKAGE) == version


@pytest.mark.skipif(os.environ.get("GITHUB_REF_TYPE") != "tag", reason="not a tag push")
def test_tag_matches_version():
    assert os.environ["GITHUB_REF_NAME"] == f"v{PROJECT['version']}"


def test_readme_marker_matches_server_name_exactly():
    assert MCP_NAME_RE.findall(README) == [SERVER_JSON["name"]]
    assert f"<!-- mcp-name: {SERVER_JSON['name']} -->" in README
    assert PROJECT["readme"] == "README.md"  # the marker reaches PyPI's description


def test_description_is_the_readme_tagline():
    tagline = re.search(r"^> (.+)$", README, re.MULTILINE)
    assert tagline, "README has no '> ' tagline"
    assert SERVER_JSON["description"] == tagline.group(1)


def test_console_script_matches_package_name():
    assert PROJECT["scripts"] == {PACKAGE: "mcp_supply_audit.server:main"}
    installed = {
        ep.name
        for ep in metadata.distribution(PACKAGE).entry_points
        if ep.group == "console_scripts"
    }
    assert installed == {PACKAGE}


def test_project_urls_and_license():
    assert PROJECT["urls"] == {
        "Repository": REPOSITORY,
        "Issues": REPOSITORY + "/issues",
    }
    assert PROJECT["license"] == "MIT"
    assert PROJECT["license-files"] == ["LICENSE"]
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
