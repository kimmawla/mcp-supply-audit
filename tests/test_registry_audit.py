"""audit_registry_entry over real fixtures (tests/fixtures/api/). No network: respx mocks
every request and fails on any unmocked one. Positive cases are inert mutated copies of the
real io.github.kimmawla/vuln-triage-mcp entry, one change each."""

import copy
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients import _http
from mcp_supply_audit.clients._http import HttpClient
from mcp_supply_audit.detectors import registry_rules
from mcp_supply_audit.detectors.registry_rules import has_pypi_marker
from mcp_supply_audit.findings import Severity, SkippedCheck, SkipReason
from mcp_supply_audit.hidden_chars import hidden_class
from mcp_supply_audit.registry_audit import audit_registry_entry

API = Path(__file__).resolve().parent / "fixtures/api"
NAME = "io.github.kimmawla/vuln-triage-mcp"
ZWSP, RLO, BS = chr(0x200B), chr(0x202E), chr(92)

REGISTRY_RE = (
    r"^https://registry\.modelcontextprotocol\.io/v0/servers/[^/]+/versions/latest"
    r"\?include_deleted=true$"
)
PYPI_RELEASE = "https://pypi.org/pypi/vuln-triage-mcp/0.1.0/json"


def load(name):
    return json.loads((API / name).read_text(encoding="ascii"))


ENTRY = load("registry_server_version.json")
RELEASE = load("pypi_release_self_0.1.0.json")


def entry_copy():
    return copy.deepcopy(ENTRY)


def release_copy():
    return copy.deepcopy(RELEASE)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fake_sleep(delay):
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)


@pytest_asyncio.fixture
async def http():
    async with HttpClient() as client:
        yield client


async def run(http, entry, routes=None, name=NAME, release=RELEASE):
    """Mock the registry entry, the default PyPI release, and any extra routes."""
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(200, json=entry)
        )
        router.get(PYPI_RELEASE).mock(return_value=httpx.Response(200, json=release))
        for url, response in (routes or {}).items():
            router.get(url).mock(return_value=response)
        report = await audit_registry_entry(name, http)
        calls = [call.request for call in router.calls]  # respx clears calls on exit
    return report, calls


def rule_ids(report):
    return {f.rule_id for f in report.findings}


def skipped(report):
    return {s.check: s.reason for s in report.coverage.skipped}


# --- benign: the real entry


@pytest.mark.asyncio
async def test_own_entry_has_no_findings(http):
    report, calls = await run(http, ENTRY)
    assert report.findings == ()
    assert set(report.coverage.ran) == {
        "RG002",
        "RG006",
        "RG001:packages[0]",
        "RG003:packages[0]",
        "RG004:packages[0]",
        "RG005:packages[0]",
    }
    assert skipped(report) == {
        "RG007": SkipReason.NOT_DETERMINABLE,
        "RG008": SkipReason.NOT_APPLICABLE,
        "RG009": SkipReason.NOT_APPLICABLE,
        "RG010": SkipReason.NOT_APPLICABLE,
        "RG011": SkipReason.NOT_APPLICABLE,
    }
    request = calls[0]
    assert len(calls) == 2  # registry entry and the PyPI release
    assert request.url.raw_path.endswith(b"/versions/latest?include_deleted=true")
    assert b"io.github.kimmawla%2Fvuln-triage-mcp" in request.url.raw_path
    assert report.to_dict()["assessment"] == "no_findings_detected"


# --- one positive case per rule


@pytest.mark.asyncio
async def test_rg001_repository_url_changed(http):
    # RG001: registry points at a repository the PyPI package does not declare.
    entry = entry_copy()
    entry["server"]["repository"]["url"] = "https://github.com/kimmawla/some-other-repo"
    report, _ = await run(http, entry)
    assert rule_ids(report) == {"RG001"}
    (finding,) = report.findings
    assert finding.severity is Severity.HIGH
    assert "some-other-repo" not in finding.location + finding.title


@pytest.mark.asyncio
async def test_rg002_owner_changed(http):
    # RG002: repository owner differs from the io.github namespace owner. The PyPI
    # Repository link is changed the same way so RG001 still matches.
    entry = entry_copy()
    entry["server"]["repository"]["url"] = (
        "https://github.com/someone-else/vuln-triage-mcp"
    )
    release = release_copy()
    release["info"]["project_urls"]["Repository"] = (
        "https://github.com/someone-else/vuln-triage-mcp"
    )
    report, _ = await run(http, entry, release=release)
    assert rule_ids(report) == {"RG002"}


@pytest.mark.asyncio
async def test_rg003_package_does_not_exist(http):
    # RG003: identifier changed to a project PyPI does not have (release 404, project 404).
    entry = entry_copy()
    entry["server"]["packages"][0]["identifier"] = "vuln-triage-mcp-renamed"
    routes = {
        "https://pypi.org/pypi/vuln-triage-mcp-renamed/0.1.0/json": httpx.Response(
            404, json={"message": "Not Found"}
        ),
        "https://pypi.org/pypi/vuln-triage-mcp-renamed/json": httpx.Response(
            404, json={"message": "Not Found"}
        ),
    }
    report, _ = await run(http, entry, routes)
    assert rule_ids(report) == {"RG003"}
    for r in ("RG001", "RG004", "RG005"):
        assert skipped(report)[f"{r}:packages[0]"] is SkipReason.NOT_DETERMINABLE


@pytest.mark.asyncio
async def test_rg004_version_does_not_exist(http):
    # RG004: version changed to one PyPI does not have (release 404, project 200).
    entry = entry_copy()
    entry["server"]["packages"][0]["version"] = "9.9.9"
    routes = {
        "https://pypi.org/pypi/vuln-triage-mcp/9.9.9/json": httpx.Response(
            404, json={"message": "Not Found"}
        ),
        "https://pypi.org/pypi/vuln-triage-mcp/json": httpx.Response(
            200, content=b"x" * 3_867_551
        ),
    }
    report, _ = await run(http, entry, routes)
    assert rule_ids(report) == {"RG004"}
    assert report.findings[0].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_rg004_version_with_zero_files_is_info(http):
    # RG004 (info): release exists with no files, like requests 0.0.1.
    release = release_copy()
    release["urls"] = []
    report, _ = await run(http, ENTRY, release=release)
    assert rule_ids(report) == {"RG004"}
    assert report.findings[0].severity is Severity.INFO


@pytest.mark.asyncio
async def test_rg005_pypi_marker_names_other_server(http):
    # RG005: README marker names a different server.
    release = release_copy()
    release["info"]["description"] = release["info"]["description"].replace(
        f"mcp-name: {NAME}", "mcp-name: io.github.kimmawla/other-server"
    )
    report, _ = await run(http, ENTRY, release=release)
    assert rule_ids(report) == {"RG005"}
    (finding,) = report.findings
    assert finding.evidence_start == release["info"]["description"].find("mcp-name:")
    assert "other-server" in finding.to_dict()["evidence"]["untrusted_text"]


@pytest.mark.asyncio
async def test_rg005_pypi_marker_removed(http):
    # RG005: README has no marker at all.
    release = release_copy()
    release["info"]["description"] = release["info"]["description"].replace(
        f"mcp-name: {NAME}", ""
    )
    report, _ = await run(http, ENTRY, release=release)
    assert rule_ids(report) == {"RG005"}
    assert report.findings[0].title.endswith("PyPI README has no mcp-name marker")


@pytest.mark.asyncio
async def test_rg005_npm_mcp_name_names_other_server(http):
    # RG005: npm package (synthetic 1.0.1 doc) declares another mcpName.
    entry = entry_copy()
    entry["server"]["packages"] = [
        {
            "registryType": "npm",
            "identifier": "zqvex-npm-mcp",
            "version": "1.0.1",
            "transport": {"type": "stdio"},
        }
    ]
    routes = {
        "https://registry.npmjs.org/zqvex-npm-mcp/1.0.1": httpx.Response(
            200, json=load("npm_version_mcp_server.json")
        )
    }
    report, _ = await run(http, entry, routes)
    assert "RG005" in rule_ids(report)
    finding = next(f for f in report.findings if f.rule_id == "RG005")
    assert finding.title.endswith("npm package's mcpName names a different server")
    assert (
        finding.to_dict()["evidence"]["untrusted_text"] == "ai.zqvex-npm/zqvex-npm-mcp"
    )


@pytest.mark.asyncio
async def test_rg005_mcpb_static_checks(http):
    # RG005 (mcpb): URL without "mcp" and no fileSha256; the hash itself is not checkable.
    entry = entry_copy()
    entry["server"]["packages"] = [
        {
            "registryType": "mcpb",
            "identifier": "https://github.com/kimmawla/tool/releases/download/v0.1.0/tool.bin",
            "transport": {"type": "stdio"},
        }
    ]
    report, _ = await run(http, entry)
    assert [f.rule_id for f in report.findings] == ["RG005", "RG005"]
    assert (
        skipped(report)["RG005:packages[0]:fileSha256"]
        is SkipReason.UNSUPPORTED_PACKAGE_TYPE
    )
    for r in ("RG001", "RG003", "RG004"):
        assert (
            skipped(report)[f"{r}:packages[0]"] is SkipReason.UNSUPPORTED_PACKAGE_TYPE
        )


@pytest.mark.asyncio
async def test_rg006_deleted(http):
    # RG006: status deleted, with the status message from the deleted fixture.
    entry = entry_copy()
    meta = entry["_meta"]["io.modelcontextprotocol.registry/official"]
    meta["status"] = "deleted"
    meta["statusMessage"] = "Renamed to ai.zqvex-deleted/zqvex-renamed-mcp"
    report, _ = await run(http, entry)
    assert rule_ids(report) == {"RG006"}
    (finding,) = report.findings
    assert finding.title == "Entry removed from the registry"
    assert (finding.severity, finding.confidence.value) == (Severity.HIGH, "medium")
    assert (
        finding.to_dict()["evidence"]["untrusted_text"]
        == "Renamed to ai.zqvex-deleted/zqvex-renamed-mcp"
    )


@pytest.mark.asyncio
async def test_rg006_deprecated_without_message(http):
    # RG006: status deprecated, no message.
    entry = entry_copy()
    entry["_meta"]["io.modelcontextprotocol.registry/official"]["status"] = "deprecated"
    report, _ = await run(http, entry)
    (finding,) = report.findings
    assert (
        finding.title == "Entry marked deprecated in the registry (no status message)"
    )
    assert finding.severity is Severity.LOW


@pytest.mark.asyncio
async def test_rg006_documented_meta_shape_fallback(http):
    # RG006: status directly under _meta, as official-registry-requirements.md shows it.
    entry = entry_copy()
    official = entry["_meta"].pop("io.modelcontextprotocol.registry/official")
    entry["_meta"] = {**official, "status": "deleted"}
    report, _ = await run(http, entry)
    assert rule_ids(report) == {"RG006"}


@pytest.mark.asyncio
async def test_rg006_neither_meta_shape_is_shape_mismatch(http):
    # RG006: no status anywhere.
    entry = entry_copy()
    entry["_meta"] = {"something.else": {}}
    report, _ = await run(http, entry)
    assert report.findings == ()
    assert skipped(report)["RG006"] is SkipReason.SHAPE_MISMATCH


@pytest.mark.asyncio
async def test_rg008_packages_disagree(http):
    # RG008: a second PyPI package with a different identifier.
    entry = entry_copy()
    second = copy.deepcopy(entry["server"]["packages"][0])
    second["identifier"] = "vuln-triage-mcp-fork"
    entry["server"]["packages"].append(second)
    routes = {
        "https://pypi.org/pypi/vuln-triage-mcp-fork/0.1.0/json": httpx.Response(
            200, json=RELEASE
        )
    }
    report, _ = await run(http, entry, routes)
    assert rule_ids(report) == {"RG008"}
    assert (
        "packages[0]" in report.findings[0].title
        and "packages[1]" in report.findings[0].title
    )


@pytest.mark.asyncio
async def test_remote_only_rg009_rg011(http):
    # RG009 and RG011: remote-only copy with http, userinfo, a literal api_key and port 8443.
    entry = entry_copy()
    del entry["server"]["packages"]
    entry["server"]["remotes"] = [
        {
            "type": "streamable-http",
            "url": "http://user:pw@mcp.example.com:8443/mcp?api_key=abc123",
        }
    ]
    report, calls = await run(http, entry)
    assert rule_ids(report) == {"RG009", "RG011"}
    rg011 = sorted(f.title for f in report.findings if f.rule_id == "RG011")
    assert rg011 == [
        "Remote URL embeds a credential parameter",
        "Remote URL embeds credentials (userinfo)",
        "Remote URL uses an unusual port",
    ]
    for r in ("RG001", "RG003", "RG004", "RG005", "RG008"):
        assert skipped(report)[r] is SkipReason.REMOTE_ONLY
    assert (
        skipped(report)["RG010:remotes[0]"] is SkipReason.NOT_APPLICABLE
    )  # io.github name
    assert len(calls) == 1  # only the registry; the remote URL is never fetched


@pytest.mark.asyncio
async def test_rg010_domain_namespace_host_outside(http):
    # RG010: domain namespace ai.zqvex-host; one remote on zqvex-host.ai, one elsewhere.
    entry = entry_copy()
    entry["server"]["name"] = "ai.zqvex-host/vuln-triage-mcp"
    entry["server"]["remotes"] = [
        {"type": "streamable-http", "url": "https://server.zqvex-host.ai/mcp"},
        {"type": "streamable-http", "url": "https://elsewhere.example/mcp"},
    ]
    report, _ = await run(http, entry, name="ai.zqvex-host/vuln-triage-mcp")
    rg010 = [f for f in report.findings if f.rule_id == "RG010"]
    assert [f.location for f in rg010] == ["server.remotes[1].url@0"]
    assert rg010[0].severity is Severity.INFO
    assert skipped(report)["RG002"] is SkipReason.NOT_APPLICABLE


@pytest.mark.asyncio
async def test_rg011_placeholders(http):
    # RG011: credential carried by a placeholder (low), placeholder host and port not checkable.
    entry = entry_copy()
    entry["server"]["remotes"] = [
        {
            "type": "streamable-http",
            "url": "https://{host}:{port}/mcp?api_key={api_key}",
        }
    ]
    report, _ = await run(http, entry)
    (finding,) = [f for f in report.findings if f.rule_id == "RG011"]
    assert finding.severity is Severity.LOW
    assert skipped(report)["RG011:remotes[0]:port"] is SkipReason.NOT_APPLICABLE
    assert skipped(report)["RG010:remotes[0]"] is SkipReason.NOT_APPLICABLE


# --- skips, errors, and safety


@pytest.mark.asyncio
async def test_unreachable_package_index_is_a_skip_not_a_failure(http):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(200, json=ENTRY)
        )
        router.get(PYPI_RELEASE).mock(side_effect=httpx.ConnectError("refused"))
        report = await audit_registry_entry(NAME, http)
    for r in ("RG001", "RG003", "RG004", "RG005"):
        assert skipped(report)[f"{r}:packages[0]"] is SkipReason.SOURCE_UNREACHABLE
    assert {"RG002", "RG006"} <= set(report.coverage.ran)
    assert report.to_dict()["assessment"] == "no_findings_detected"


@pytest.mark.asyncio
async def test_oversized_package_response_is_response_too_large(http):
    # Just over PyPI's 512 KiB cap.
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(200, json=ENTRY)
        )
        router.get(PYPI_RELEASE).mock(
            return_value=httpx.Response(200, content=b"x" * (513 * 1024))
        )
        report = await audit_registry_entry(NAME, http)
    assert skipped(report)["RG003:packages[0]"] is SkipReason.RESPONSE_TOO_LARGE


@pytest.mark.asyncio
async def test_bad_package_body_is_shape_mismatch(http):
    report, _ = await run(http, ENTRY, release={"info": "not an object"})
    assert skipped(report)["RG005:packages[0]"] is SkipReason.SHAPE_MISMATCH


@pytest.mark.asyncio
async def test_unsupported_package_type(http):
    entry = entry_copy()
    entry["server"]["packages"][0] = {
        "registryType": "oci",
        "identifier": "ghcr.io/kimmawla/vuln-triage-mcp:0.1.0",
        "transport": {"type": "stdio"},
    }
    report, calls = await run(http, entry)
    for r in ("RG001", "RG003", "RG004", "RG005"):
        assert (
            skipped(report)[f"{r}:packages[0]"] is SkipReason.UNSUPPORTED_PACKAGE_TYPE
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "identifier", ["../etc", "vuln triage", "a/b", "vuln" + ZWSP + "triage"]
)
@pytest.mark.asyncio
async def test_hostile_package_identifier_never_sent(http, identifier):
    entry = entry_copy()
    entry["server"]["packages"][0]["identifier"] = identifier
    report, calls = await run(http, entry)
    assert skipped(report)["RG003:packages[0]"] is SkipReason.SHAPE_MISMATCH
    assert len(calls) == 1  # registry only


@pytest.mark.asyncio
async def test_entry_not_found_raises_short_tool_error(http):
    with respx.mock() as router:
        router.get(url__regex=REGISTRY_RE).mock(
            return_value=httpx.Response(
                404, json=load("registry_server_not_found.json")
            )
        )
        with pytest.raises(ToolError, match="no entry with that name"):
            await audit_registry_entry(NAME, http)


@pytest.mark.asyncio
async def test_registry_unreachable_raises_tool_error(http):
    with respx.mock() as router:
        router.get(url__regex=REGISTRY_RE).mock(
            side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(ToolError, match="no checks ran"):
            await audit_registry_entry(NAME, http)


@pytest.mark.parametrize("name", ["../..", "io.github.x%2Fy", "x", None])
@pytest.mark.asyncio
async def test_bad_name_refused_before_any_request(http, name):
    with respx.mock() as router:
        with pytest.raises(ToolError):
            await audit_registry_entry(name, http)
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_status_message_evidence_is_escaped(http):
    entry = entry_copy()
    meta = entry["_meta"]["io.modelcontextprotocol.registry/official"]
    meta["status"] = "deleted"
    meta["statusMessage"] = "Re" + ZWSP + "named" + RLO + " to x"
    report, _ = await run(http, entry)
    out = report.to_dict()
    text = out["findings"][0]["evidence"]["untrusted_text"]
    assert f"{BS}u200b" in text and f"{BS}u202e" in text
    assert all(hidden_class(c) is None for c in json.dumps(out, ensure_ascii=False))


@pytest.mark.asyncio
async def test_rule_crash_is_rule_error(http, monkeypatch):
    def boom(*args):
        raise RuntimeError("hostile " + RLO)

    monkeypatch.setattr(registry_rules, "rg003_package_exists", boom)
    report, _ = await run(http, ENTRY)
    assert (
        SkippedCheck("RG003:packages[0]", SkipReason.RULE_ERROR)
        in report.coverage.skipped
    )
    assert "hostile" not in json.dumps(report.to_dict())


# --- marker matching (package-types.mdx boundary rule)


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        (f"<!-- mcp-name: {NAME} -->", True),
        (f"<!-- mcp-name: {NAME}-->", True),
        (f"mcp-name: {NAME}", True),
        (f"mcp-name: {NAME}\nmore", True),
        (f"mcp-name: {NAME}<br>", True),
        (f"mcp-name: {NAME}.", False),  # glued punctuation prevents the match
        (f"mcp-name: {NAME}-extra", False),
        (f"mcp-name: {NAME.upper()}", False),  # case-sensitive
        (f"mcp-name:{NAME}", False),
        ("mcp-name: io.github.kimmawla/vuln-triage", False),
        (f"x mcp-name: {NAME}. then mcp-name: {NAME} ", True),
        ("", False),
    ],
)
def test_has_pypi_marker(description, expected):
    assert has_pypi_marker(description, NAME) is expected
