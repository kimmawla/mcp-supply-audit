"""audit_package over synthetic fixtures (tests/fixtures/package/) and the real vuln-triage-mcp
0.1.0 release (tests/fixtures/api/). No network: respx mocks every request and fails on any
unmocked one. Invented zqvex-* names only."""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from fastmcp.exceptions import ToolError

from mcp_supply_audit import package_audit
from mcp_supply_audit.clients import _http
from mcp_supply_audit.clients._http import HttpClient
from mcp_supply_audit.detectors import package_rules
from mcp_supply_audit.errors import NoChecksRan
from mcp_supply_audit.findings import SkipDetail, SkipReason
from mcp_supply_audit.package_audit import audit_package

TESTS = Path(__file__).resolve().parent
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
ZWSP, RLO, BS = chr(0x200B), chr(0x202E), chr(92)

PYPI = "https://pypi.org"
NPM = "https://registry.npmjs.org"
OSV_URL = "https://api.osv.dev/v1/query"
RELEASE_URL = f"{PYPI}/pypi/zqvex-pkg/1.2.0/json"
PROJECT_URL = f"{PYPI}/pypi/zqvex-pkg/json"
NPM_URL = f"{NPM}/zqvex-pkg/1.2.0"
WHL, SDIST = "zqvex_pkg-1.2.0-py3-none-any.whl", "zqvex_pkg-1.2.0.tar.gz"


def prov_url(filename, project="zqvex-pkg", version="1.2.0"):
    return f"{PYPI}/integrity/{project}/{version}/{filename}/provenance"


def load(path):
    return json.loads((TESTS / "fixtures" / path).read_text(encoding="ascii"))


RELEASE = load("package/pypi_release_zqvex.json")
PROJECT = load("package/pypi_project_zqvex.json")
NPM_DOC = load("package/npm_version_zqvex.json")
OSV_BODY = load("package/osv_query_zqvex.json")
PROV = load("package/pypi_provenance_zqvex.json")
PROV_NONE = load("package/pypi_provenance_none_zqvex.json")


def ok(body):
    return httpx.Response(200, json=body)


def unavailable():
    return httpx.Response(503)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fake_sleep(delay):
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)


@pytest_asyncio.fixture
async def http():
    async with HttpClient() as client:
        yield client


def pypi_routes(release=RELEASE, whl=PROV, sdist=PROV):
    return {
        RELEASE_URL: ok(release),
        prov_url(WHL): ok(whl) if isinstance(whl, dict) else whl,
        prov_url(SDIST): ok(sdist) if isinstance(sdist, dict) else sdist,
    }


async def run(http, name, ecosystem, version, routes, osv=None, now=NOW):
    """Mock GET routes and the OSV POST (one response, or a list for successive pages)."""
    with respx.mock(assert_all_called=False) as router:
        for url, response in routes.items():
            router.get(url).mock(return_value=response)
        osv_route = router.post(OSV_URL)
        if isinstance(osv, list):
            osv_route.mock(side_effect=osv)
        else:
            osv_route.mock(return_value=osv if osv is not None else ok({}))
        report = await audit_package(name, ecosystem, version, http, now=now)
        calls = [call.request for call in router.calls]
    return report, calls


def rule_ids(report):
    return [f.rule_id for f in report.findings]


def skipped(report):
    return {s.check: (s.reason, s.detail) for s in report.coverage.skipped}


def osv_bodies(calls):
    return [json.loads(c.content) for c in calls if c.method == "POST"]


# --- the user's own package: the real vuln-triage-mcp 0.1.0 release


@pytest.mark.asyncio
async def test_own_package_only_lacks_provenance(http):
    # Real responses: release JSON (fixture index), both files' provenance 404s (80 B and
    # 70 B, api-notes "Provenance"), and OSV's {} for 0.1.0 (api-notes OSV table).
    routes = {
        f"{PYPI}/pypi/vuln-triage-mcp/0.1.0/json": ok(
            load("api/pypi_release_self_0.1.0.json")
        ),
        prov_url(
            "vuln_triage_mcp-0.1.0-py3-none-any.whl", "vuln-triage-mcp", "0.1.0"
        ): httpx.Response(404, json=load("package/pypi_provenance_self_whl_404.json")),
        prov_url(
            "vuln_triage_mcp-0.1.0.tar.gz", "vuln-triage-mcp", "0.1.0"
        ): httpx.Response(
            404, json=load("package/pypi_provenance_self_sdist_404.json")
        ),
    }
    report, calls = await run(http, "vuln-triage-mcp", "pypi", "0.1.0", routes, ok({}))
    assert rule_ids(report) == ["PK004"]
    assert set(report.coverage.ran) == {"PK001", "PK002", "PK004", "PK005", "PK006"}
    assert skipped(report) == {
        "PK003": (SkipReason.NOT_DETERMINABLE, SkipDetail.PYPI_INSTALL_CODE)
    }
    assert len(calls) == 4  # release, two provenance files, one OSV query
    assert osv_bodies(calls) == [
        {
            "package": {"name": "vuln-triage-mcp", "ecosystem": "PyPI"},
            "version": "0.1.0",
        }
    ]
    rendered = report.to_dict()
    assert rendered["audited"] == {
        "ecosystem": "pypi",
        "name": "vuln-triage-mcp",
        "version": "0.1.0",
    }
    assert rendered["assessment"] == "findings_present"


# --- one positive per rule, end to end


@pytest.mark.asyncio
async def test_pk001_osv_advisories(http):
    report, _ = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(), ok(OSV_BODY)
    )
    assert rule_ids(report) == ["PK001"]
    assert report.findings[0].title.startswith("3 OSV advisories")


@pytest.mark.asyncio
async def test_pk002_pypi_yanked(http):
    release = copy.deepcopy(RELEASE)
    release["info"].update(yanked=True, yanked_reason="zqvex broken build")
    report, _ = await run(http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(release))
    assert rule_ids(report) == ["PK002"]


@pytest.mark.asyncio
async def test_pk003_npm_install_scripts_never_echo_commands(http):
    doc = copy.deepcopy(NPM_DOC)
    doc["scripts"] = {
        "postinstall": "node zqvex-install-marker.js",
        "install": "node zqvex-install-marker.js --again",
        "test": "node --test",
    }
    report, _ = await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: ok(doc)})
    assert rule_ids(report) == ["PK003"]
    rendered = report.to_dict()
    assert (
        rendered["findings"][0]["evidence"]["untrusted_text"] == "install, postinstall"
    )
    assert "marker" not in json.dumps(rendered)


@pytest.mark.asyncio
async def test_pk004_pypi_no_provenance(http):
    none = httpx.Response(404, json=PROV_NONE)
    report, calls = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(whl=none, sdist=none)
    )
    assert rule_ids(report) == ["PK004"]
    prov_calls = [c for c in calls if b"/integrity/" in c.url.raw_path]
    assert {c.headers["Accept"] for c in prov_calls} == {
        "application/vnd.pypi.integrity.v1+json"
    }


@pytest.mark.asyncio
async def test_pk004_npm_no_attestations(http):
    doc = copy.deepcopy(NPM_DOC)
    del doc["dist"]["attestations"]
    report, calls = await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: ok(doc)})
    assert rule_ids(report) == ["PK004"]
    assert len(calls) == 2  # version document and OSV; no attestation request


@pytest.mark.asyncio
async def test_pk005_pypi_recent(http):
    release = copy.deepcopy(RELEASE)
    for f in release["urls"]:
        f["upload_time_iso_8601"] = "2026-11-03T09:00:00.000000Z"
    report, _ = await run(http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(release))
    assert rule_ids(report) == ["PK005"]


@pytest.mark.asyncio
async def test_pk006_npm_no_repository(http):
    doc = copy.deepcopy(NPM_DOC)
    del doc["repository"]
    report, _ = await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: ok(doc)})
    assert rule_ids(report) == ["PK006"]


@pytest.mark.asyncio
async def test_npm_baseline_skips_only_pk005(http):
    report, _ = await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: ok(NPM_DOC)})
    assert report.findings == ()
    assert skipped(report) == {
        "PK005": (SkipReason.NOT_DETERMINABLE, SkipDetail.NPM_NO_PUBLISH_TIME)
    }
    assert report.to_dict()["assessment"] == "no_findings_detected"


# --- an unavailable data source skips each rule that needs it


@pytest.mark.asyncio
async def test_pk001_skipped_when_osv_unavailable(http):
    report, calls = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(), unavailable()
    )
    assert skipped(report)["PK001"] == (SkipReason.SOURCE_UNREACHABLE, None)
    assert "PK002" in report.coverage.ran
    assert len(osv_bodies(calls)) == 1 + _http.MAX_STATUS_RETRIES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "url", "rules"),
    [
        ("pypi", RELEASE_URL, ("PK002", "PK004", "PK005", "PK006")),
        ("npm", NPM_URL, ("PK002", "PK003", "PK004", "PK006")),
    ],
)
async def test_metadata_rules_skipped_when_index_unavailable(
    http, ecosystem, url, rules
):
    report, _ = await run(http, "zqvex-pkg", ecosystem, "1.2.0", {url: unavailable()})
    for rule_id in rules:
        assert skipped(report)[rule_id] == (SkipReason.SOURCE_UNREACHABLE, None)
    assert report.coverage.ran == ("PK001",)  # OSV still ran for the caller's version


@pytest.mark.asyncio
async def test_pk004_pypi_skipped_when_provenance_unavailable(http):
    report, _ = await run(
        http,
        "zqvex-pkg",
        "pypi",
        "1.2.0",
        pypi_routes(whl=httpx.Response(404, json=PROV_NONE), sdist=unavailable()),
    )
    assert skipped(report) == {
        "PK003": (SkipReason.NOT_DETERMINABLE, SkipDetail.PYPI_INSTALL_CODE),
        "PK004": (SkipReason.SOURCE_UNREACHABLE, None),
    }


@pytest.mark.asyncio
async def test_nothing_ran_is_a_tool_error(http):
    with pytest.raises(ToolError, match="no checks ran"):
        await run(
            http,
            "zqvex-pkg",
            "pypi",
            "1.2.0",
            {RELEASE_URL: unavailable()},
            unavailable(),
        )


@pytest.mark.asyncio
async def test_npm_tag_with_index_unavailable_skips_pk001(http):
    # The tag cannot be resolved, so PK001 is skipped too (OSV would answer {} for a tag),
    # leaving nothing that can run.
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{NPM}/zqvex-pkg/next").mock(return_value=unavailable())
        osv_route = router.post(OSV_URL).mock(return_value=ok({}))
        with pytest.raises(ToolError, match="no checks ran"):
            await audit_package("zqvex-pkg", "npm", "next", http, now=NOW)
        assert not osv_route.called


# --- OSV truncation


@pytest.mark.asyncio
async def test_osv_truncated_at_two_pages(http):
    page1 = {"vulns": OSV_BODY["vulns"][:2], "next_page_token": "zqvex-token-1"}
    page2 = {"vulns": OSV_BODY["vulns"][2:], "next_page_token": "zqvex-token-2"}
    report, calls = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(), [ok(page1), ok(page2)]
    )
    [f] = report.findings
    assert (
        f.title == "At least 3 OSV advisories affect this version (highest label: HIGH)"
    )
    bodies = osv_bodies(calls)
    assert len(bodies) == package_audit.PK001_MAX_PAGES
    assert bodies[1]["page_token"] == "zqvex-token-1"


# --- oversized responses


@pytest.mark.asyncio
async def test_oversized_release_json_skips_metadata_rules(http):
    too_big = httpx.Response(200, content=b" " * (512 * 1024 + 1))
    report, _ = await run(http, "zqvex-pkg", "pypi", "1.2.0", {RELEASE_URL: too_big})
    for rule_id in ("PK002", "PK004", "PK005", "PK006"):
        assert skipped(report)[rule_id] == (SkipReason.RESPONSE_TOO_LARGE, None)
    assert report.coverage.ran == ("PK001",)


@pytest.mark.asyncio
async def test_oversized_project_json_asks_for_a_version(http):
    # Large PyPI projects exceed the cap (django 630,589 B, api-notes).
    too_big = httpx.Response(200, content=b" " * (512 * 1024 + 1))
    with pytest.raises(ToolError, match="Pass a version"):
        await run(http, "zqvex-pkg", "pypi", "", {PROJECT_URL: too_big})


# --- version resolution


@pytest.mark.asyncio
async def test_pypi_latest_from_project_json(http):
    routes = {PROJECT_URL: ok(PROJECT), **pypi_routes()}
    report, calls = await run(http, "zqvex-pkg", "pypi", "", routes)
    assert report.audited.version == "1.2.0"
    assert osv_bodies(calls)[0]["version"] == "1.2.0"


@pytest.mark.asyncio
async def test_npm_latest_is_one_request(http):
    report, calls = await run(
        http, "zqvex-pkg", "npm", "", {f"{NPM}/zqvex-pkg/latest": ok(NPM_DOC)}
    )
    assert report.audited.version == "1.2.0"
    assert [c.url.raw_path for c in calls if c.method == "GET"] == [
        b"/zqvex-pkg/latest"
    ]
    assert osv_bodies(calls)[0]["version"] == "1.2.0"


@pytest.mark.asyncio
async def test_npm_dist_tag_resolves_to_document_version(http):
    doc = dict(NPM_DOC, version="1.3.0-rc.1")
    report, calls = await run(
        http,
        "@zqvex/zqvex-pkg",
        "npm",
        "next",
        {f"{NPM}/@zqvex%2Fzqvex-pkg/next": ok(doc)},
    )
    assert report.audited.version == "1.3.0-rc.1"
    assert osv_bodies(calls)[0]["version"] == "1.3.0-rc.1"


@pytest.mark.asyncio
async def test_hostile_resolved_version_is_refused(http):
    doc = dict(NPM_DOC, version="../../zqvex")
    with pytest.raises(ToolError, match="Pass a version"):
        await run(http, "zqvex-pkg", "npm", "", {f"{NPM}/zqvex-pkg/latest": ok(doc)})


MALFORMED_VERSIONS = [
    f"1.2.0{ZWSP}",
    f"1.2.0{RLO}",
    "1.2.0\nx",
    "1." + "0" * 10_240,
    "latest",  # a tag in the document's own version has resolved nothing
    "next",
    " 1.2.0",
    1.2,
    None,
    ["1.2.0"],
]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", MALFORMED_VERSIONS)
@pytest.mark.parametrize(
    ("wanted", "path", "message"),
    [
        ("", "latest", "Pass a version"),
        ("next", "next", "malformed version"),
        ("1.2.0", "1.2.0", "malformed version"),
    ],
)
async def test_malformed_npm_document_version_is_a_tool_error(
    http, bad, wanted, path, message
):
    doc = dict(NPM_DOC, version=bad)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{NPM}/zqvex-pkg/{path}").mock(return_value=ok(doc))
        osv_route = router.post(OSV_URL).mock(return_value=ok({}))
        with pytest.raises(ToolError, match=message) as excinfo:
            await audit_package("zqvex-pkg", "npm", wanted, http, now=NOW)
        assert not osv_route.called
    text = str(excinfo.value)
    assert len(text) < 200
    if isinstance(bad, str) and bad.strip() not in ("latest", "next"):
        assert bad.strip()[:20] not in text
    for hidden in (ZWSP, RLO, "\n"):
        assert hidden not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [f"1.2.0{ZWSP}", "1." + "0" * 10_240, 120, None])
async def test_malformed_pypi_latest_version_is_a_tool_error(http, bad):
    project = copy.deepcopy(PROJECT)
    project["info"]["version"] = bad
    with respx.mock(assert_all_called=False) as router:
        router.get(PROJECT_URL).mock(return_value=ok(project))
        osv_route = router.post(OSV_URL).mock(return_value=ok({}))
        with pytest.raises(ToolError, match="Pass a version") as excinfo:
            await audit_package("zqvex-pkg", "pypi", "", http, now=NOW)
        assert not osv_route.called
    assert ZWSP not in str(excinfo.value) and "0" * 20 not in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("tag", ["latest", "next", "beta"])
async def test_dist_tag_osv_request_carries_resolved_version(http, tag):
    # The document also names another package; audited keeps the caller's validated name.
    doc = dict(NPM_DOC, version="1.3.0-rc.1", name="zqvex-other")
    report, calls = await run(
        http, " zqvex-pkg ", "npm", tag, {f"{NPM}/zqvex-pkg/{tag}": ok(doc)}
    )
    assert osv_bodies(calls) == [
        {
            "package": {"name": "zqvex-pkg", "ecosystem": "npm"},
            "version": "1.3.0-rc.1",
        }
    ]
    audited = report.to_dict()["audited"]
    assert audited == {"ecosystem": "npm", "name": "zqvex-pkg", "version": "1.3.0-rc.1"}
    assert tag not in json.dumps(audited)


@pytest.mark.asyncio
async def test_pypi_audited_name_is_the_validated_input(http):
    release = copy.deepcopy(RELEASE)
    release["info"].update(name="zqvex-other", version="9.9.9")
    report, calls = await run(
        http, " zqvex-pkg ", "pypi", "1.2.0", pypi_routes(release)
    )
    assert report.to_dict()["audited"] == {
        "ecosystem": "pypi",
        "name": "zqvex-pkg",
        "version": "1.2.0",
    }
    assert osv_bodies(calls)[0]["version"] == "1.2.0"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "routes", "message"),
    [
        (
            "pypi",
            {PROJECT_URL: httpx.Response(404, json={"message": "Not Found"})},
            "no package",
        ),
        (
            "npm",
            {f"{NPM}/zqvex-pkg/latest": httpx.Response(404, json="Not Found")},
            "no package",
        ),
        ("npm", {f"{NPM}/zqvex-pkg/latest": unavailable()}, "retry, or pass a version"),
    ],
)
async def test_latest_not_resolved(http, ecosystem, routes, message):
    with pytest.raises(ToolError, match=message):
        await run(http, "zqvex-pkg", ecosystem, "", routes)


def _too_large():
    # Content-Length over the PyPI cap: refused before the body is read.
    return httpx.Response(200, content=b"{}", headers={"Content-Length": str(10**9)})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "reason", "expected"),
    [
        (
            _too_large,
            SkipReason.RESPONSE_TOO_LARGE,
            package_audit._LATEST_TOO_LARGE["pypi"],
        ),
        (
            unavailable,
            SkipReason.SOURCE_UNREACHABLE,
            package_audit._LATEST_UNREACHABLE["pypi"],
        ),
        (
            lambda: httpx.Response(200, content=b"not json"),
            SkipReason.SHAPE_MISMATCH,
            package_audit._LATEST_SHAPE["pypi"],
        ),
    ],
)
async def test_latest_error_depends_on_typed_cause(http, response, reason, expected):
    with pytest.raises(NoChecksRan) as raised:
        await run(http, "zqvex-pkg", "pypi", "", {PROJECT_URL: response()})
    assert str(raised.value) == expected
    assert raised.value.reason is reason
    assert raised.value.detail is SkipDetail.LATEST_UNRESOLVED


@pytest.mark.asyncio
async def test_latest_timeout_says_retry(http, monkeypatch):
    async def slow(*args, **kwargs):
        raise _http.SourceTimeout("PyPI did not respond within 15s.")

    monkeypatch.setattr(package_audit.pypi, "get_latest_version", slow)
    with pytest.raises(NoChecksRan) as raised:
        await package_audit.audit_package("zqvex-pkg", "pypi", "", http, now=NOW)
    assert str(raised.value) == package_audit._LATEST_UNREACHABLE["pypi"]
    assert "retry" in str(raised.value)


def test_latest_messages_are_fixed_and_distinct():
    for eco in ("pypi", "npm"):
        too_large = package_audit._LATEST_TOO_LARGE[eco]
        assert "retry" not in too_large.lower()  # a retry cannot shrink the document
        assert "Pass a version" in too_large
        assert "retry" in package_audit._LATEST_UNREACHABLE[eco]
        assert "expected form" in package_audit._LATEST_SHAPE[eco]
        assert "{" not in too_large + package_audit._LATEST_SHAPE[eco]


@pytest.mark.asyncio
async def test_missing_version_is_a_tool_error(http):
    routes = {
        RELEASE_URL: httpx.Response(404, json={"message": "Not Found"}),
        PROJECT_URL: httpx.Response(200, json={}),
    }
    with pytest.raises(ToolError, match="no such version"):
        await run(http, "zqvex-pkg", "pypi", "1.2.0", routes)
    npm_missing = httpx.Response(404, json="version not found: 1.2.0")
    with pytest.raises(ToolError, match="no such version"):
        await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: npm_missing})


# --- PyPI provenance bounds


@pytest.mark.asyncio
async def test_provenance_checks_at_most_four_files(http):
    release = copy.deepcopy(RELEASE)
    names = [f"zqvex_pkg-1.2.0-{i}.whl" for i in range(6)]
    release["urls"] = [dict(release["urls"][0], filename=n) for n in names]
    routes = {RELEASE_URL: ok(release)}
    routes |= {prov_url(n): httpx.Response(404, json=PROV_NONE) for n in names}
    report, calls = await run(http, "zqvex-pkg", "pypi", "1.2.0", routes)
    prov_calls = [c for c in calls if b"/integrity/" in c.url.raw_path]
    assert len(prov_calls) == package_rules.MAX_PROVENANCE_FILES
    assert skipped(report)["PK004"] == (
        SkipReason.NOT_DETERMINABLE,
        SkipDetail.TOO_MANY_FILES,
    )


@pytest.mark.asyncio
async def test_unknown_file_html_404_is_shape_mismatch(http):
    html = httpx.Response(
        404, text="<!DOCTYPE html><title>Page Not Found (404)</title>"
    )
    report, _ = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes(whl=html, sdist=html)
    )
    assert skipped(report)["PK004"] == (SkipReason.SHAPE_MISMATCH, None)


@pytest.mark.asyncio
async def test_hostile_filename_from_index_stays_one_segment(http):
    release = copy.deepcopy(RELEASE)
    release["urls"][0]["filename"] = "../zqvex?x=1#frag"
    release["urls"] = release["urls"][:1]
    routes = {
        RELEASE_URL: ok(release),
        f"{PYPI}/integrity/zqvex-pkg/1.2.0/..%2Fzqvex%3Fx%3D1%23frag/provenance": httpx.Response(
            404, json=PROV_NONE
        ),
    }
    report, calls = await run(http, "zqvex-pkg", "pypi", "1.2.0", routes)
    assert rule_ids(report) == ["PK004"]
    [prov] = [c for c in calls if b"/integrity/" in c.url.raw_path]
    assert prov.url.raw_path.count(b"/") == 5


@pytest.mark.asyncio
async def test_dot_dot_filename_is_refused_before_a_request(http):
    release = copy.deepcopy(RELEASE)
    release["urls"] = [dict(release["urls"][0], filename="..")]
    report, calls = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", {RELEASE_URL: ok(release)}
    )
    assert skipped(report)["PK004"] == (SkipReason.SHAPE_MISMATCH, None)
    assert not [c for c in calls if b"/integrity/" in c.url.raw_path]


@pytest.mark.asyncio
async def test_zero_file_version(http):
    release = dict(RELEASE, urls=[])
    report, calls = await run(
        http, "zqvex-pkg", "pypi", "1.2.0", {RELEASE_URL: ok(release)}
    )
    assert skipped(report)["PK004"] == (SkipReason.NOT_APPLICABLE, SkipDetail.NO_FILES)
    assert skipped(report)["PK005"] == (
        SkipReason.NOT_DETERMINABLE,
        SkipDetail.NO_FILES,
    )
    assert len(calls) == 2  # release and OSV only


# --- hostile input never reaches the network


HOSTILE_NAMES = [
    "../../zqvex",
    "zqvex-pkg?x=1",
    "zqvex-pkg#frag",
    "zqvex/pkg",
    f"zqvex{RLO}pkg",
    f"zqvex{ZWSP}pkg",
    "zqvex-pkg\nx",
    "%2e%2e",
    "z" * 300,
    "",
    None,
    ["zqvex-pkg"],
]
HOSTILE_VERSIONS = [
    "../1.0",
    "1.0/../../x",
    "1.0?x=1",
    "1.0#x",
    f"1.0{RLO}",
    "%2e%2e",
    "1" * 200,
    None,
    1.0,
]


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", ["pypi", "npm"])
@pytest.mark.parametrize("name", HOSTILE_NAMES)
async def test_hostile_name_rejected_without_requests(http, ecosystem, name):
    with respx.mock() as router:
        with pytest.raises(ToolError) as excinfo:
            await audit_package(name, ecosystem, "1.0.0", http, now=NOW)
        assert not router.calls
    if isinstance(name, str) and name.strip():
        assert name.strip() not in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", ["pypi", "npm"])
@pytest.mark.parametrize("version", HOSTILE_VERSIONS)
async def test_hostile_version_rejected_without_requests(http, ecosystem, version):
    with respx.mock() as router:
        with pytest.raises(ToolError, match="Invalid version"):
            await audit_package("zqvex-pkg", ecosystem, version, http, now=NOW)
        assert not router.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", ["cargo", "PyPI ", "registry", None, ""])
async def test_bad_ecosystem_rejected(http, ecosystem):
    with respx.mock() as router:
        with pytest.raises(ToolError, match="Invalid ecosystem"):
            await audit_package("zqvex-pkg", ecosystem, "1.0.0", http, now=NOW)
        assert not router.calls


# --- hidden characters and rule crashes


@pytest.mark.asyncio
async def test_deprecation_message_with_hidden_characters_is_escaped(http):
    doc = dict(NPM_DOC, deprecated=f"moved to zqvex-pkg-next{ZWSP}{RLO} see docs")
    report, _ = await run(http, "zqvex-pkg", "npm", "1.2.0", {NPM_URL: ok(doc)})
    assert rule_ids(report) == ["PK002"]
    text = json.dumps(report.to_dict(), ensure_ascii=False)
    assert ZWSP not in text and RLO not in text
    shown = report.to_dict()["findings"][0]["evidence"]["untrusted_text"]
    assert shown == f"deprecated: moved to zqvex-pkg-next{BS}u200b{BS}u202e see docs"


@pytest.mark.asyncio
async def test_rule_crash_is_recorded_as_rule_error(http, monkeypatch, caplog):
    def boom(*args):
        raise RuntimeError("zqvex internal detail")

    monkeypatch.setattr(package_rules, "pk006_repository", boom)
    report, _ = await run(http, "zqvex-pkg", "pypi", "1.2.0", pypi_routes())
    assert skipped(report)["PK006"] == (SkipReason.RULE_ERROR, None)
    assert {"PK001", "PK002", "PK004", "PK005"} <= set(report.coverage.ran)
    rendered = json.dumps(report.to_dict())
    assert "zqvex internal detail" not in rendered and "RuntimeError" not in rendered
    assert "PK006 failed: RuntimeError" in caplog.text  # details go to logs only
