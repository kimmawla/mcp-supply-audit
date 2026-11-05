import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx

from mcp_supply_audit.clients import _http
from mcp_supply_audit.clients._http import (
    Host,
    HttpClient,
    PostPath,
    Response,
    ShapeMismatch,
    SourceUnreachable,
)
from mcp_supply_audit.clients.osv import (
    MAX_QUERY_PAGES,
    TRUNCATED_NO_PROGRESS,
    TRUNCATED_PAGE_CAP,
    TRUNCATED_TOKEN_REPEATED,
    InvalidQuery,
    OsvEcosystem,
    OsvQuery,
    PageToken,
    build_query,
    parse_page,
    query_vulns,
)

API = Path(__file__).resolve().parent / "fixtures/api"
QUERY_URL = "https://api.osv.dev/v1/query"
NUL = chr(0)
ZWSP = chr(0x200B)
CYRILLIC_A = chr(0x0430)


def fixture_bytes(name: str) -> bytes:
    return (API / name).read_bytes()


def page(ids, token=None):
    body = {"vulns": [{"id": i, "summary": "inert"} for i in ids]}
    if token is not None:
        body["next_page_token"] = token
    return httpx.Response(200, json=body)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)


@pytest_asyncio.fixture
async def http():
    async with HttpClient() as client:
        yield client


# --- body building


@pytest.mark.parametrize(
    ("name", "ecosystem", "version", "expected"),
    [
        (
            "django",
            OsvEcosystem.PYPI,
            "1.2",
            {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "1.2"},
        ),
        (
            "@types/node",
            OsvEcosystem.NPM,
            None,
            {"package": {"name": "@types/node", "ecosystem": "npm"}},
        ),
        (
            "vuln-triage-mcp",
            OsvEcosystem.PYPI,
            "0.1.0",
            {
                "package": {"name": "vuln-triage-mcp", "ecosystem": "PyPI"},
                "version": "0.1.0",
            },
        ),
    ],
)
def test_body_holds_only_validated_values(name, ecosystem, version, expected):
    body = build_query(name, ecosystem, version).to_json_bytes()
    assert body.isascii()
    assert json.loads(body) == expected


HOSTILE_NAMES = [
    "",
    " django",
    "django\n",
    "dja" + NUL + "ngo",
    "dja" + ZWSP + "ngo",
    f"dj{CYRILLIC_A}ngo",
    "../django",
    "django/../../x",
    "%2f",
    'django","ecosystem":"npm',
    "x" * 300,
    None,
    42,
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
@pytest.mark.parametrize("ecosystem", list(OsvEcosystem))
def test_hostile_names_rejected_before_body(name, ecosystem):
    with pytest.raises(InvalidQuery):
        build_query(name, ecosystem, "1.0")


@pytest.mark.parametrize(
    "version",
    [
        "",
        " 1.0",
        "1.0 ",
        "1.0" + NUL,
        "1.0" + ZWSP,
        "1.0;rm",
        "../1.0",
        '1.0","x":"y',
        "^4.0.0",
        ">=1",
        "v" * 200,
        1.0,
    ],
)
def test_hostile_versions_rejected_before_body(version):
    with pytest.raises(InvalidQuery):
        build_query("django", OsvEcosystem.PYPI, version)


@pytest.mark.parametrize("ecosystem", ["PyPI", "pypi", "Debian:12", None])
def test_ecosystem_must_be_enum(ecosystem):
    with pytest.raises(InvalidQuery):
        build_query("django", ecosystem, "1.2")


def test_direct_construction_is_validated_too():
    with pytest.raises(InvalidQuery):
        OsvQuery("dja" + NUL + "ngo", OsvEcosystem.PYPI)


@pytest.mark.parametrize("token", ["abc", {"value": "abc"}, b"abc"])
def test_page_token_cannot_come_from_input(token):
    with pytest.raises(InvalidQuery):
        build_query("django", OsvEcosystem.PYPI, "1.2", page_token=token)
    with pytest.raises(InvalidQuery):
        PageToken("abc")


@pytest.mark.parametrize(
    ("name", "ecosystem", "version"),
    [
        ("django", OsvEcosystem.PYPI, "3.2.0"),
        ("@modelcontextprotocol/sdk", OsvEcosystem.NPM, "1.32.2"),
    ],
)
def test_every_body_string_is_a_validated_input(name, ecosystem, version):
    token = parse_page(
        Response(200, json.dumps({"next_page_token": "Tok-123_abc"}).encode(), Host.OSV)
    ).next_page_token
    body = json.loads(build_query(name, ecosystem, version, token).to_json_bytes())

    def strings(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k
                yield from strings(v)
        elif isinstance(obj, str):
            yield obj

    allowed_keys = {"package", "name", "ecosystem", "version", "page_token"}
    assert set(strings(body)) <= allowed_keys | {
        name,
        ecosystem.value,
        version,
        "Tok-123_abc",
    }


# --- response parsing


def test_parse_real_fixture():
    parsed = parse_page(
        Response(200, fixture_bytes("osv_query_express_4.0.0.json"), Host.OSV)
    )
    assert len(parsed.vulns) == 3
    assert parsed.next_page_token is None


def test_parse_empty_object_is_no_vulns():
    parsed = parse_page(Response(200, fixture_bytes("osv_query_empty.json"), Host.OSV))
    assert parsed == parse_page(Response(200, b"{}", Host.OSV))
    assert parsed.vulns == ()


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"vulns": {}}',
        b'{"vulns": [{"summary": "no id"}]}',
        b'{"vulns": [], "next_page_token": 5}',
        b'{"next_page_token": "has space"}',
        b'{"next_page_token": ""}',
        b"[" * 100 + b"]" * 100,
    ],
)
def test_parse_bad_shapes(body):
    with pytest.raises(ShapeMismatch):
        parse_page(Response(200, body, Host.OSV))


def test_parse_400_is_shape_mismatch_and_5xx_unreachable():
    with pytest.raises(ShapeMismatch):
        parse_page(
            Response(400, fixture_bytes("osv_query_invalid_cursor.json"), Host.OSV)
        )
    with pytest.raises(SourceUnreachable):
        parse_page(Response(404, b"{}", Host.OSV))


# --- pagination


@pytest.mark.asyncio
async def test_single_page(http):
    with respx.mock() as router:
        route = router.post(QUERY_URL).mock(
            return_value=httpx.Response(
                200, content=fixture_bytes("osv_query_express_4.0.0.json")
            )
        )
        result = await query_vulns(http, "express", OsvEcosystem.NPM, "4.0.0")
    assert (len(result.vulns), result.pages, result.truncated) == (3, 1, False)
    assert json.loads(route.calls.last.request.content) == {
        "package": {"name": "express", "ecosystem": "npm"},
        "version": "4.0.0",
    }


@pytest.mark.asyncio
async def test_page_cap_of_two_sets_truncated(http):
    assert MAX_QUERY_PAGES == 2
    with respx.mock() as router:
        route = router.post(QUERY_URL).mock(
            side_effect=[page(["A", "B"], "t1"), page(["C"], "t2"), page(["D"])]
        )
        result = await query_vulns(http, "django", OsvEcosystem.PYPI)
    assert route.call_count == 2
    assert [v["id"] for v in result.vulns] == ["A", "B", "C"]
    assert (result.pages, result.truncated, result.truncation_reason) == (
        2,
        True,
        TRUNCATED_PAGE_CAP,
    )
    second = json.loads(route.calls[1].request.content)
    assert second == {
        "package": {"name": "django", "ecosystem": "PyPI"},
        "page_token": "t1",
    }


@pytest.mark.asyncio
async def test_follows_tokens_until_absent(http):
    with respx.mock() as router:
        router.post(QUERY_URL).mock(
            side_effect=[page(["A"], "t1"), page(["B"], "t2"), page(["C"])]
        )
        result = await query_vulns(http, "django", OsvEcosystem.PYPI, max_pages=5)
    assert [v["id"] for v in result.vulns] == ["A", "B", "C"]
    assert (result.pages, result.truncated) == (3, False)


@pytest.mark.asyncio
async def test_stops_when_token_repeats(http):
    with respx.mock() as router:
        route = router.post(QUERY_URL).mock(
            side_effect=[page(["A"], "same"), page(["B"], "same"), page(["C"])]
        )
        result = await query_vulns(http, "django", OsvEcosystem.PYPI, max_pages=10)
    assert route.call_count == 2
    assert (result.truncated, result.truncation_reason) == (
        True,
        TRUNCATED_TOKEN_REPEATED,
    )


@pytest.mark.asyncio
async def test_stops_when_page_does_not_advance(http):
    # api-notes (vuln-triage): a misnamed token field makes OSV return page 1 again.
    with respx.mock() as router:
        route = router.post(QUERY_URL).mock(
            side_effect=[page(["A", "B"], "t1"), page(["A", "B"], "t2"), page(["C"])]
        )
        result = await query_vulns(http, "django", OsvEcosystem.PYPI, max_pages=10)
    assert route.call_count == 2
    assert [v["id"] for v in result.vulns] == ["A", "B"]
    assert (result.truncated, result.truncation_reason) == (True, TRUNCATED_NO_PROGRESS)


@pytest.mark.asyncio
async def test_hostile_input_never_reaches_the_network(http):
    with respx.mock() as router:
        with pytest.raises(InvalidQuery):
            await query_vulns(http, "dja" + NUL + "ngo", OsvEcosystem.PYPI, "1.2")
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_post_goes_only_to_osv_query(http):
    with respx.mock() as router:
        route = router.post(QUERY_URL).mock(
            return_value=httpx.Response(200, content=b"{}")
        )
        await query_vulns(http, "six", OsvEcosystem.PYPI, "1.17.0")
    request = route.calls.last.request
    assert (request.method, request.url.host, request.url.raw_path) == (
        "POST",
        "api.osv.dev",
        b"/v1/query",
    )
    assert OsvQuery.target == (Host.OSV, PostPath.OSV_QUERY)
