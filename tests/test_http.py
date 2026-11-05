import ast
import asyncio
import gzip
import json
import re
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients import _http
from mcp_supply_audit.clients._http import (
    MAX_IN_FLIGHT_PER_HOST,
    MAX_REDIRECTS,
    MAX_STATUS_RETRIES,
    Accept,
    Host,
    HostNotAllowed,
    HttpClient,
    PostBody,
    PostPath,
    Query,
    ResponseTooLarge,
    ShapeMismatch,
    SourceTimeout,
    SourceUnreachable,
    build_path,
    safe_json,
)
from mcp_supply_audit.findings import SkipReason

API = Path(__file__).resolve().parent / "fixtures/api"
REGISTRY = "https://registry.modelcontextprotocol.io"
PYPI = "https://pypi.org"
NPM = "https://registry.npmjs.org"

# Sizes measured in docs/api-notes.md.
LARGEST_VERSIONS_LIST = (
    1_990_901  # registry /versions list, over the 64 KiB registry cap
)
EXPRESS_PACKUMENT = 823_554  # npm full packument, over the 256 KiB npm cap
NUMPY_RELEASE_JSON = 63_184  # largest PyPI release JSON, under the 512 KiB cap
BOTOCORE_PROJECT_JSON = 3_867_551


def fixture_bytes(name: str) -> bytes:
    return (API / name).read_bytes()


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """Record retry delays instead of sleeping."""
    recorded: list[float] = []

    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(_http, "_sleep", fake_sleep)
    return recorded


@pytest_asyncio.fixture
async def http():
    async with HttpClient() as client:
        yield client


# --- allowlist and redirects


@pytest.mark.asyncio
async def test_non_allowlisted_host_refused_before_any_request(http):
    with respx.mock() as router:
        for bad in ("evil.example", "https://evil.example/x", Host.PYPI.value):
            with pytest.raises(HostNotAllowed):
                await http.get(bad, "/x")
        assert router.calls.call_count == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/x",
        "http://pypi.org/x",  # plain http
        "https://pypi.org:8443/x",  # other port
        "https://user:pw@pypi.org/x",  # userinfo
        "https://pypi.org.evil.example/x",
        "https://files.pythonhosted.org/x",  # real PyPI host, not on the allowlist
    ],
)
def test_allowed_host_check_rejects(url):
    with pytest.raises(HostNotAllowed):
        _http._allowed_host(httpx.URL(url))


@pytest.mark.asyncio
async def test_redirect_to_non_allowlisted_host_is_refused(http):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/pypi/requests/json").mock(
            return_value=httpx.Response(
                302, headers={"Location": "https://evil.example/steal"}
            )
        )
        evil = router.get("https://evil.example/steal").mock(
            return_value=httpx.Response(200)
        )
        with pytest.raises(SourceUnreachable, match="redirected to another host"):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
        assert evil.call_count == 0


@pytest.mark.asyncio
async def test_redirect_to_plain_http_is_refused(http):
    with respx.mock() as router:
        router.get(f"{PYPI}/pypi/requests/json").mock(
            return_value=httpx.Response(
                301, headers={"Location": "http://pypi.org/pypi/requests/json"}
            )
        )
        with pytest.raises(HostNotAllowed):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
        assert router.calls.call_count == 1


@pytest.mark.asyncio
async def test_redirect_within_allowlist_is_followed(http):
    with respx.mock() as router:
        first = router.get(f"{PYPI}/pypi/Requests/json").mock(
            return_value=httpx.Response(
                301, headers={"Location": "/pypi/requests/json"}
            )
        )
        second = router.get(f"{PYPI}/pypi/requests/json").mock(
            return_value=httpx.Response(
                200, content=fixture_bytes("pypi_project_requests.json")
            )
        )
        response = await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "Requests"})
    assert response.status == 200
    assert response.json()["info"]["name"] == "requests"
    assert (first.call_count, second.call_count) == (1, 1)


@pytest.mark.asyncio
async def test_redirect_loop_stops(http):
    with respx.mock() as router:
        route = router.get(f"{PYPI}/pypi/a/json").mock(
            return_value=httpx.Response(302, headers={"Location": "/pypi/a/json"})
        )
        with pytest.raises(SourceUnreachable, match="redirected too many times"):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "a"})
    assert route.call_count == MAX_REDIRECTS + 1


# --- path building


@pytest.mark.parametrize(
    ("name", "raw_path"),
    [
        ("requests", "/pypi/requests/json"),
        ("a/b", "/pypi/a%2Fb/json"),
        ("../admin", "/pypi/..%2Fadmin/json"),
        ("..%2f..%2fadmin", "/pypi/..%252f..%252fadmin/json"),
        ("%2f", "/pypi/%252f/json"),
        ("x?y=1#z", "/pypi/x%3Fy%3D1%23z/json"),
        ("a b", "/pypi/a%20b/json"),
        ("@types/node", "/pypi/%40types%2Fnode/json"),
        ("back" + chr(92) + "slash", "/pypi/back%5Cslash/json"),
    ],
)
@pytest.mark.asyncio
async def test_target_names_cannot_change_the_path(http, name, raw_path):
    with respx.mock() as router:
        route = router.get(url__regex=r"^https://pypi\.org/").mock(
            return_value=httpx.Response(200, json={})
        )
        await http.get(Host.PYPI, "/pypi/{p}/json", {"p": name})
    sent = route.calls.last.request.url
    assert sent.raw_path.decode() == raw_path
    assert sent.host == "pypi.org" and sent.query == b""


@pytest.mark.parametrize("name", [".", "..", "", "x" * 513])
@pytest.mark.asyncio
async def test_dot_segments_and_bad_values_refused_before_request(http, name):
    with respx.mock() as router:
        with pytest.raises(ValueError):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": name})
        assert router.calls.call_count == 0


@pytest.mark.parametrize(
    ("template", "params"),
    [
        ("pypi/{p}/json", {"p": "a"}),  # not absolute
        ("/pypi/{p}/json?x=1", {"p": "a"}),  # query in template
        ("/pypi/{p}/json#f", {"p": "a"}),
        ("/pypi/%2e%2e/{p}", {"p": "a"}),
        ("/pypi/../{p}", {"p": "a"}),
        ("//evil.example/{p}", {"p": "a"}),
        ("/pypi/{p.__class__}/json", {"p": "a"}),
        ("/pypi/{p!r}/json", {"p": "a"}),
        ("/pypi/{p}/json", {}),  # missing
        ("/pypi/{p}/json", {"p": "a", "q": "b"}),  # unused
        ("/pypi/{p}/json", {"p": 5}),
    ],
)
def test_bad_templates_and_params_rejected(template, params):
    with pytest.raises(ValueError):
        build_path(template, params)


def test_registry_name_becomes_one_segment():
    path = build_path(
        "/v0/servers/{name}/versions/latest",
        {"name": "io.github.kimmawla/vuln-triage-mcp"},
    )
    assert path == "/v0/servers/io.github.kimmawla%2Fvuln-triage-mcp/versions/latest"


# --- query and headers


@pytest.mark.asyncio
async def test_query_only_from_constants(http):
    with respx.mock() as router:
        route = router.get(
            url__regex=r"^https://registry\.modelcontextprotocol\.io/"
        ).mock(
            return_value=httpx.Response(
                200, content=fixture_bytes("registry_server_version.json")
            )
        )
        response = await http.get(
            Host.REGISTRY,
            "/v0/servers/{name}/versions/latest",
            {"name": "io.github.kimmawla/vuln-triage-mcp"},
            query=Query.INCLUDE_DELETED,
        )
    assert response.json()["server"]["name"] == "io.github.kimmawla/vuln-triage-mcp"
    url = route.calls.last.request.url
    assert (
        url.raw_path
        == b"/v0/servers/io.github.kimmawla%2Fvuln-triage-mcp/versions/latest?include_deleted=true"
    )


@pytest.mark.parametrize(
    "query", ["include_deleted=true", {"include_deleted": "true"}, (("search", "x"),)]
)
@pytest.mark.asyncio
async def test_query_from_input_rejected(http, query):
    with respx.mock() as router:
        with pytest.raises(TypeError):
            await http.get(Host.REGISTRY, "/v0/servers", query=query)
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_accept_must_be_constant(http):
    with pytest.raises(TypeError):
        await http.get(Host.NPM, "/{pkg}", {"pkg": "express"}, accept="text/html")


@pytest.mark.asyncio
async def test_headers_user_agent_no_cookies_no_credentials(http):
    with respx.mock() as router:
        route = router.get(url__regex=r"^https://registry\.npmjs\.org/").mock(
            return_value=httpx.Response(
                200,
                json={},
                headers={
                    "Set-Cookie": "session=abc; Domain=registry.npmjs.org; Path=/"
                },
            )
        )
        await http.get(Host.NPM, "/{pkg}/{v}", {"pkg": "express", "v": "latest"})
        await http.get(
            Host.NPM,
            "/{pkg}/{v}",
            {"pkg": "express", "v": "5.3.0"},
            accept=Accept.NPM_ABBREVIATED,
        )
    first, second = (c.request for c in route.calls)
    assert re.fullmatch(
        r"mcp-supply-audit/\S+ \(\+https://github\.com/kimmawla/mcp-supply-audit\)",
        first.headers["User-Agent"],
    )
    assert second.headers["Accept"] == "application/vnd.npm.install-v1+json"
    for request in (first, second):
        assert request.method == "GET"
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers


# --- size caps


@pytest.mark.asyncio
async def test_real_fixture_under_cap_is_returned(http):
    body = fixture_bytes("npm_version_express_latest.json")
    with respx.mock() as router:
        router.get(f"{NPM}/express/latest").mock(
            return_value=httpx.Response(200, content=body)
        )
        response = await http.get(
            Host.NPM, "/{pkg}/{v}", {"pkg": "express", "v": "latest"}
        )
    assert response.body == body
    assert response.json()["version"] == "5.3.0"


@pytest.mark.asyncio
async def test_largest_measured_pypi_release_fits(http):
    with respx.mock() as router:
        router.get(f"{PYPI}/pypi/numpy/2.5.4/json").mock(
            return_value=httpx.Response(200, content=b"x" * NUMPY_RELEASE_JSON)
        )
        response = await http.get(
            Host.PYPI, "/pypi/{p}/{v}/json", {"p": "numpy", "v": "2.5.4"}
        )
    assert len(response.body) == NUMPY_RELEASE_JSON


@pytest.mark.parametrize(
    ("host", "template", "params", "url", "size"),
    [
        (
            Host.REGISTRY,
            "/v0/servers/{name}/versions",
            {"name": "ai.zqvex-large/zqvex-large"},
            f"{REGISTRY}/v0/servers/ai.zqvex-large%2Fzqvex-large/versions",
            LARGEST_VERSIONS_LIST,
        ),
        (Host.NPM, "/{pkg}", {"pkg": "express"}, f"{NPM}/express", EXPRESS_PACKUMENT),
        (
            Host.OSV,
            "/v1/vulns/{id}",
            {"id": "x"},
            "https://api.osv.dev/v1/vulns/x",
            Host.OSV.value.max_bytes + 1,
        ),
    ],
)
@pytest.mark.asyncio
async def test_oversized_body_with_length_aborts(
    http, host, template, params, url, size
):
    with respx.mock() as router:
        router.get(url).mock(return_value=httpx.Response(200, content=b"x" * size))
        with pytest.raises(ResponseTooLarge) as exc:
            await http.get(host, template, params)
    assert exc.value.skip_reason is SkipReason.RESPONSE_TOO_LARGE
    assert exc.value.limit == host.value.max_bytes


@pytest.mark.asyncio
async def test_oversized_stream_without_length_stops_reading(http):
    chunk = b"x" * 16_384
    produced = 0

    async def body():
        nonlocal produced
        for _ in range(LARGEST_VERSIONS_LIST // len(chunk)):
            produced += 1
            yield chunk

    with respx.mock() as router:
        router.get(f"{REGISTRY}/v0/servers").mock(
            return_value=httpx.Response(200, content=body())
        )
        with pytest.raises(ResponseTooLarge):
            await http.get(Host.REGISTRY, "/v0/servers")
    cap_chunks = Host.REGISTRY.value.max_bytes // len(chunk)
    assert produced <= cap_chunks + 1  # stopped at the cap, not the 1.99 MB end


@pytest.mark.asyncio
async def test_compressed_body_counts_decoded_bytes(http):
    bomb = gzip.compress(b"\0" * (Host.REGISTRY.value.max_bytes * 4))
    assert len(bomb) < 4096
    with respx.mock() as router:
        router.get(f"{REGISTRY}/v0/servers").mock(
            return_value=httpx.Response(
                200, content=bomb, headers={"Content-Encoding": "gzip"}
            )
        )
        with pytest.raises(ResponseTooLarge):
            await http.get(Host.REGISTRY, "/v0/servers")


@pytest.mark.asyncio
async def test_caller_can_only_lower_the_cap(http):
    with respx.mock() as router:
        router.get(f"{NPM}/express/latest").mock(
            return_value=httpx.Response(200, content=b"x" * 5_000)
        )
        with pytest.raises(ResponseTooLarge):
            await http.get(
                Host.NPM,
                "/{pkg}/{v}",
                {"pkg": "express", "v": "latest"},
                max_bytes=4_096,
            )
        router.get(f"{NPM}/react/latest").mock(
            return_value=httpx.Response(200, content=b"x" * EXPRESS_PACKUMENT)
        )
        with pytest.raises(ResponseTooLarge):
            await http.get(
                Host.NPM, "/{pkg}/{v}", {"pkg": "react", "v": "latest"}, max_bytes=10**9
            )


@pytest.mark.asyncio
async def test_status_only_skips_body_and_cap(http):
    with respx.mock() as router:
        router.get(f"{PYPI}/pypi/botocore/json").mock(
            return_value=httpx.Response(200, content=b"x" * BOTOCORE_PROJECT_JSON)
        )
        response = await http.get(
            Host.PYPI, "/pypi/{p}/json", {"p": "botocore"}, status_only=True
        )
    assert (response.status, response.body) == (200, b"")


# --- retries and status handling


@pytest.mark.asyncio
async def test_timeout_then_success_is_two_calls(http, sleeps):
    with respx.mock() as router:
        route = router.get(f"{PYPI}/pypi/requests/json").mock(
            side_effect=[
                httpx.ReadTimeout("slow"),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        response = await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
    assert response.json() == {"ok": True}
    assert route.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.asyncio
async def test_two_timeouts_give_up_after_two_calls(http):
    with respx.mock() as router:
        route = router.get(f"{PYPI}/pypi/requests/json").mock(
            side_effect=httpx.ConnectTimeout("slow")
        )
        with pytest.raises(SourceUnreachable, match="PyPI timed out") as exc:
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
    assert route.call_count == 2
    assert exc.value.skip_reason is SkipReason.SOURCE_UNREACHABLE


@pytest.mark.asyncio
async def test_connection_error_retried_once(http):
    with respx.mock() as router:
        route = router.get(f"{NPM}/express/latest").mock(
            side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(SourceUnreachable, match="npm registry is unreachable"):
            await http.get(Host.NPM, "/{pkg}/{v}", {"pkg": "express", "v": "latest"})
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_404_is_one_call_and_body_is_returned(http):
    body = fixture_bytes("npm_version_not_found.json")
    with respx.mock() as router:
        route = router.get(url__regex=r"^https://registry\.npmjs\.org/express/").mock(
            return_value=httpx.Response(404, content=body)
        )
        response = await http.get(
            Host.NPM, "/{pkg}/{v}", {"pkg": "express", "v": "0.0.0-no-such-version"}
        )
    assert route.call_count == 1
    assert response.status == 404
    assert response.json() == "version not found: 0.0.0-no-such-version"


@pytest.mark.parametrize("status", [400, 403, 410, 422])
@pytest.mark.asyncio
async def test_other_4xx_not_retried(http, status):
    with respx.mock() as router:
        route = router.get(f"{REGISTRY}/v0/servers").mock(
            return_value=httpx.Response(
                status, content=fixture_bytes("registry_validation_error.json")
            )
        )
        response = await http.get(Host.REGISTRY, "/v0/servers")
    assert route.call_count == 1
    assert response.status == status


@pytest.mark.asyncio
async def test_429_with_retry_after_seconds(http, sleeps):
    with respx.mock() as router:
        route = router.get(f"{PYPI}/pypi/requests/json").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "2"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        response = await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
    assert response.status == 200
    assert route.call_count == 2
    assert sleeps == [2.0]


@pytest.mark.asyncio
async def test_429_retry_after_beyond_budget_fails_without_sleeping(http, sleeps):
    with respx.mock() as router:
        route = router.get(f"{PYPI}/pypi/requests/json").mock(
            return_value=httpx.Response(429, headers={"Retry-After": "60"})
        )
        with pytest.raises(SourceUnreachable, match="rate limiting"):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
    assert route.call_count == 1
    assert sleeps == []


@pytest.mark.asyncio
async def test_5xx_retried_three_times_then_unreachable_without_echoing_body(
    http, sleeps
):
    with respx.mock() as router:
        route = router.get(f"{REGISTRY}/v0/servers").mock(
            return_value=httpx.Response(503, content=b"BODY-SECRET-123 <script>")
        )
        with pytest.raises(SourceUnreachable) as exc:
            await http.get(Host.REGISTRY, "/v0/servers")
    assert route.call_count == MAX_STATUS_RETRIES + 1
    assert len(sleeps) == MAX_STATUS_RETRIES
    assert "BODY-SECRET" not in str(exc.value)
    assert str(exc.value) == "MCP Registry is unavailable (HTTP 503)."


@pytest.mark.asyncio
async def test_total_cap_raises_source_timeout(http, monkeypatch):
    monkeypatch.setattr(_http, "TOTAL_TIMEOUT_SECONDS", 0.05)

    async def stall(request):
        await asyncio.sleep(1)
        return httpx.Response(200)

    # The cancelled request is never recorded as a call.
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/pypi/requests/json").mock(side_effect=stall)
        with pytest.raises(SourceTimeout) as exc:
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "requests"})
    assert isinstance(exc.value, SourceUnreachable)
    assert not isinstance(exc.value, ToolError)
    assert exc.value.skip_reason is SkipReason.SOURCE_UNREACHABLE
    assert str(exc.value) == "PyPI did not respond within 0.05s."


def test_clients_never_raise_tool_error():
    # Clients raise typed errors; ToolError belongs to the tool layer (CLAUDE.md).
    clients = Path(_http.__file__).parent
    for path in clients.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Raise) and node.exc is not None:
                target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
                assert getattr(target, "id", None) != "ToolError", path.name


@pytest.mark.asyncio
async def test_cross_host_redirect_between_allowed_hosts_refused(http):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/pypi/express/json").mock(
            return_value=httpx.Response(
                302, headers={"Location": "https://registry.npmjs.org/express"}
            )
        )
        npm = router.get(f"{NPM}/express").mock(return_value=httpx.Response(200))
        with pytest.raises(SourceUnreachable, match="redirected to another host"):
            await http.get(Host.PYPI, "/pypi/{p}/json", {"p": "express"})
        assert npm.call_count == 0


# --- safe_json


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{",
        b"",
        b"\xff\xfe",  # not UTF-8
        b"[" * 65 + b"]" * 65,  # one past the depth limit
        b"[" * 100_000 + b"]" * 100_000,
        b'{"a": NaN}',
        b"[Infinity]",
    ],
)
def test_safe_json_rejects(body):
    with pytest.raises(ShapeMismatch) as exc:
        safe_json(body)
    assert exc.value.skip_reason is SkipReason.SHAPE_MISMATCH
    assert body[:20].decode("latin-1") not in str(exc.value) or not body


def test_safe_json_accepts_depth_limit_and_brackets_in_strings():
    assert safe_json(b"[" * 64 + b"]" * 64)
    assert safe_json(json.dumps({"d": "[" * 10_000}).encode())["d"].startswith("[[")
    assert safe_json(fixture_bytes("registry_servers_empty.json"))["servers"] == []


def test_safe_json_catches_recursion_error(monkeypatch):
    def boom(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(_http.json, "loads", boom)
    with pytest.raises(ShapeMismatch):
        safe_json(b"[]")


@pytest.mark.asyncio
async def test_response_json_uses_safe_json(http):
    with respx.mock() as router:
        router.get(f"{NPM}/express/latest").mock(
            return_value=httpx.Response(200, content=b"[" * 1000 + b"]" * 1000)
        )
        response = await http.get(
            Host.NPM, "/{pkg}/{v}", {"pkg": "express", "v": "latest"}
        )
    with pytest.raises(ShapeMismatch):
        response.json()


# --- post_json


class _OtherBody(PostBody):
    target = (Host.OSV, PostPath.OSV_QUERY)

    def to_json_bytes(self) -> bytes:
        return b"{}"


@pytest.mark.parametrize("host", [Host.PYPI, Host.NPM, Host.REGISTRY, "api.osv.dev"])
@pytest.mark.asyncio
async def test_post_to_other_host_refused_before_request(http, host):
    with respx.mock() as router:
        with pytest.raises(HostNotAllowed):
            await http.post_json(host, PostPath.OSV_QUERY, _OtherBody())
        assert router.calls.call_count == 0


@pytest.mark.parametrize("path", ["/v1/query", "/v1/querybatch", "/v1/vulns/x", None])
@pytest.mark.asyncio
async def test_post_to_other_path_refused_before_request(http, path):
    with respx.mock() as router:
        with pytest.raises(HostNotAllowed):
            await http.post_json(Host.OSV, path, _OtherBody())
        assert router.calls.call_count == 0


@pytest.mark.parametrize("body", [{"package": {}}, b"{}", '{"x": 1}', None])
@pytest.mark.asyncio
async def test_post_body_must_be_a_postbody(http, body):
    with respx.mock() as router:
        with pytest.raises(HostNotAllowed):
            await http.post_json(Host.OSV, PostPath.OSV_QUERY, body)
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_post_oversized_request_body_refused(http):
    class Big(_OtherBody):
        def to_json_bytes(self) -> bytes:
            return b'"' + b"x" * 5000 + b'"'

    with respx.mock() as router:
        with pytest.raises(HostNotAllowed):
            await http.post_json(Host.OSV, PostPath.OSV_QUERY, Big())
        assert router.calls.call_count == 0


@pytest.mark.asyncio
async def test_post_same_retry_and_cap_rules(http, sleeps):
    with respx.mock() as router:
        route = router.post("https://api.osv.dev/v1/query").mock(
            side_effect=[httpx.ReadTimeout("slow"), httpx.Response(200, content=b"{}")]
        )
        response = await http.post_json(Host.OSV, PostPath.OSV_QUERY, _OtherBody())
    assert response.json() == {}
    assert route.call_count == 2
    sent = route.calls.last.request
    assert sent.method == "POST"
    assert sent.headers["Content-Type"] == "application/json"
    assert sent.content == b"{}"
    assert "cookie" not in sent.headers


@pytest.mark.asyncio
async def test_post_over_osv_cap_aborts(http):
    with respx.mock() as router:
        router.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(
                200, content=b"x" * (Host.OSV.value.max_bytes + 1)
            )
        )
        with pytest.raises(ResponseTooLarge):
            await http.post_json(Host.OSV, PostPath.OSV_QUERY, _OtherBody())


@pytest.mark.asyncio
async def test_post_is_never_redirected(http):
    with respx.mock() as router:
        route = router.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(307, headers={"Location": "/v1/query2"})
        )
        with pytest.raises(SourceUnreachable, match="redirected a POST"):
            await http.post_json(Host.OSV, PostPath.OSV_QUERY, _OtherBody())
    assert route.call_count == 1


# --- concurrency


@pytest.mark.asyncio
async def test_at_most_four_requests_in_flight_per_host(http):
    in_flight = 0
    peak = 0

    async def slow(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return httpx.Response(200, json={})

    with respx.mock() as router:
        router.get(url__regex=r"^https://pypi\.org/").mock(side_effect=slow)
        await asyncio.gather(
            *(
                http.get(Host.PYPI, "/pypi/{p}/json", {"p": f"pkg{i}"})
                for i in range(12)
            )
        )
    assert peak == MAX_IN_FLIGHT_PER_HOST


@pytest.mark.asyncio
async def test_hosts_have_separate_limits(http):
    in_flight: dict[str, int] = {}
    peak = 0

    async def slow(request):
        nonlocal peak
        in_flight[request.url.host] = in_flight.get(request.url.host, 0) + 1
        peak = max(peak, sum(in_flight.values()))
        await asyncio.sleep(0.01)
        in_flight[request.url.host] -= 1
        return httpx.Response(200, json={})

    with respx.mock() as router:
        router.get(url__regex=r"^https://(pypi\.org|registry\.npmjs\.org)/").mock(
            side_effect=slow
        )
        await asyncio.gather(
            *(http.get(Host.PYPI, "/pypi/{p}/json", {"p": f"p{i}"}) for i in range(6)),
            *(
                http.get(Host.NPM, "/{pkg}/{v}", {"pkg": f"n{i}", "v": "latest"})
                for i in range(6)
            ),
        )
    assert peak == 2 * MAX_IN_FLIGHT_PER_HOST


def test_timeouts_and_allowlist_match_spec():
    client = HttpClient()
    assert client._client.timeout.connect == 3.0
    assert client._client.timeout.read == 8.0
    assert client._client.follow_redirects is False
    assert {h.value.hostname for h in Host} == {
        "registry.modelcontextprotocol.io",
        "pypi.org",
        "registry.npmjs.org",
        "api.osv.dev",
    }
    assert json.loads(fixture_bytes("registry_servers_empty.json")) == {
        "servers": [],
        "metadata": {"count": 0},
    }
