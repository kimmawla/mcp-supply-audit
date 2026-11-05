"""Synthetic and pseudonymized fixtures keep the shape of the real responses they replace.

The real captures live in local_fixtures/ (gitignored, not in CI). When that folder exists,
each synthetic or pseudonymized fixture in tests/fixtures/api/ must have the same keys,
nesting, list lengths, and JSON types as its real counterpart; only values differ. Skipped
when the folder is absent.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "tests/fixtures/api"
LOCAL = ROOT / "local_fixtures"

SYNTHETIC = [
    "registry_server_version_deleted.json",
    "registry_server_version_deprecated.json",
    "registry_servers_page.json",
    "npm_version_mcp_server.json",
]

# Real responses whose personal fields (maintainers, _npmUser, author, contributors, PyPI
# author/maintainer and ownership users) were replaced with invented zqvex-* values.
PSEUDONYMIZED = [
    "npm_packument_express.json",
    "npm_packument_scoped_sdk.json",
    "npm_version_esbuild_latest.json",
    "npm_version_express_latest.json",
    "pypi_project_requests.json",
    "pypi_release_requests_2.32.3.json",
    "pypi_release_zero_files.json",
]

# Maps whose keys are the package's own names (npm `bin`): compared by count and value shape.
NAME_KEYED = {("bin",)}

pytestmark = pytest.mark.skipif(
    not LOCAL.is_dir(),
    reason="local_fixtures/ not present (real captures are not committed)",
)


def shape(value, path=()):
    if isinstance(value, dict):
        if path in NAME_KEYED:
            return ("name-keyed", sorted(repr(shape(v)) for v in value.values()))
        return {k: shape(v, (*path, k)) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(v, (*path, "[]")) for v in value]
    return type(value).__name__


def load(path):
    return json.loads(path.read_text(encoding="ascii"))


@pytest.mark.parametrize("name", SYNTHETIC + PSEUDONYMIZED)
def test_synthetic_fixture_matches_real_shape(name):
    real = LOCAL / name
    assert real.is_file(), f"local_fixtures/{name} is missing"
    assert shape(load(API / name)) == shape(load(real))


@pytest.mark.parametrize("name", SYNTHETIC + PSEUDONYMIZED)
def test_synthetic_fixture_differs_from_real(name):
    real = LOCAL / name
    assert real.is_file(), f"local_fixtures/{name} is missing"
    assert load(API / name) != load(real)
