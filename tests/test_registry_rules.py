import json
from pathlib import Path

import pytest

from mcp_supply_audit.detectors.registry import normalize_repo_url

API = Path(__file__).resolve().parent / "fixtures/api"


def load(name):
    return json.loads((API / name).read_text(encoding="ascii"))


# --- real fixtures


def test_registry_entry_matches_pypi_project_urls_for_vuln_triage():
    entry = load("registry_server_version.json")["server"]["repository"]["url"]
    declared = load("pypi_project_self.json")["info"]["project_urls"]["Repository"]
    assert normalize_repo_url(entry) == normalize_repo_url(declared)
    assert normalize_repo_url(entry) == "https://github.com/kimmawla/vuln-triage-mcp"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("npm_packument_express.json", "https://github.com/expressjs/express"),
        ("npm_version_express_latest.json", "https://github.com/expressjs/express"),
        (
            "npm_packument_scoped_sdk.json",
            "https://github.com/modelcontextprotocol/typescript-sdk",
        ),
        ("npm_version_esbuild_latest.json", "https://github.com/evanw/esbuild"),
    ],
)
def test_npm_repository_git_plus_and_dot_git_stripped(fixture, expected):
    raw = load(fixture)["repository"]["url"]
    assert raw.startswith("git+") and raw.endswith(".git")
    assert normalize_repo_url(raw) == expected


def test_npm_packument_and_version_doc_agree():
    packument = load("npm_packument_express.json")
    version_doc = load("npm_version_express_latest.json")
    assert normalize_repo_url(packument["repository"]["url"]) == normalize_repo_url(
        version_doc["repository"]["url"]
    )


@pytest.mark.parametrize(
    "fixture",
    [
        "registry_servers_page.json",
        "registry_server_version_deleted.json",
        "registry_server_version_deprecated.json",
    ],
)
def test_registry_urls_already_normal_and_case_kept(fixture):
    doc = load(fixture)
    # Synthetic fixtures (real captures in local_fixtures/); path case: test_transforms.
    for item in doc.get("servers", [doc]):
        url = item["server"]["repository"]["url"]
        assert normalize_repo_url(url) == url


def test_pypi_source_url_unchanged():
    url = load("pypi_project_requests.json")["info"]["project_urls"]["Source"]
    assert normalize_repo_url(url) == "https://github.com/psf/requests"


# --- each transform


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("git+https://github.com/o/r.git", "https://github.com/o/r"),
        ("https://github.com/o/r/", "https://github.com/o/r"),
        ("https://github.com/o/r.git/", "https://github.com/o/r"),
        ("https://github.com/o/r/.git", "https://github.com/o/r"),
        ("https://GitHub.COM/Owner/Repo", "https://github.com/Owner/Repo"),
        (
            "https://github.com/Zqvex-Owner/Zqvex-Repo",
            "https://github.com/Zqvex-Owner/Zqvex-Repo",
        ),
        ("https://www.github.com/o/r", "https://github.com/o/r"),
        ("https://WWW.GitLab.com/o/r.git", "https://gitlab.com/o/r"),
        ("  https://github.com/o/r  ", "https://github.com/o/r"),
        ("git+ssh://git@github.com/o/r.git", "ssh://git@github.com/o/r"),
        ("https://github.com:443/o/r", "https://github.com:443/o/r"),
        ("https://github.com/o/r#readme", "https://github.com/o/r#readme"),
        ("http://github.com/o/r", "http://github.com/o/r"),
    ],
)
def test_transforms(raw, expected):
    assert normalize_repo_url(raw) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r",
        "git+https://www.GitHub.com/O/R.git/",
        "ssh://git@github.com/o/r",
    ],
)
def test_idempotent(url):
    once = normalize_repo_url(url)
    assert normalize_repo_url(once) == once


@pytest.mark.parametrize(
    "raw",
    [
        None,
        42,
        "",
        "github:owner/repo",  # npm shorthand
        "git@github.com:owner/repo.git",  # scp-like
        "owner/repo",
        "https://",
        "https://github.com:notaport/o/r" + "x" * 2048,
    ],
)
def test_not_a_url_returns_none(raw):
    assert normalize_repo_url(raw) is None
