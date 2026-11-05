"""Shared HTTP layer: allowlisted hosts, fixed methods, retries, a total time cap, size caps.

Policy: CLAUDE.md (timeouts, retries, 15s cap, methods) and docs/tool-surface.md (allowlist,
per-host response caps). Callers never pass a URL. A GET names a Host, a path template written
in code, and the values for its placeholders; each value becomes exactly one percent-encoded
path segment. Query strings and Accept headers come only from the Query and Accept enums.
The only POST is OSV's /v1/query, with a body built by clients/osv.py.

Every failure is a typed HttpError carrying `skip_reason`; callers record a skipped check.
This module never raises ToolError (the tool layer does, when nothing can run). No error
message ever includes a response body. All JSON is parsed through safe_json.
"""

import asyncio
import json
import logging
import random
import string
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import Enum, StrEnum
from http.cookiejar import CookieJar, DefaultCookiePolicy
from importlib.metadata import PackageNotFoundError, version
from typing import Any, ClassVar, Final, Self
from urllib.parse import quote

import httpx

from mcp_supply_audit.findings import SkipReason
from mcp_supply_audit.validation import MAX_JSON_DEPTH, text_depth_exceeds

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 8.0
# Wall-clock cap per call, including retries, backoff, redirects and reading the body.
TOTAL_TIMEOUT_SECONDS = 15.0
# Retries on 429 and 5xx.
MAX_STATUS_RETRIES = 3
# Retries on timeouts and connection errors.
MAX_TRANSPORT_RETRIES = 1
BACKOFF_BASE_SECONDS = 0.5
MAX_REDIRECTS = 3
MAX_IN_FLIGHT_PER_HOST = 4
KIB: Final = 1024
MIB: Final = KIB * KIB
# Used when a host has no measured cap (docs/tool-surface.md).
DEFAULT_MAX_BYTES: Final = 4 * MIB
# Request bodies are small, code-built JSON; anything bigger is a bug.
MAX_REQUEST_BODY_BYTES: Final = 4 * KIB
_MAX_SEGMENT_LEN: Final = 512

# Indirection so tests can skip real sleeps.
_sleep = asyncio.sleep


def _user_agent() -> str:
    try:
        ver = version("mcp-supply-audit")
    except PackageNotFoundError:
        ver = "0"
    return f"mcp-supply-audit/{ver} (+https://github.com/kimmawla/mcp-supply-audit)"


USER_AGENT: Final = _user_agent()


@dataclass(frozen=True)
class HostSpec:
    hostname: str
    service: str  # named in error messages
    max_bytes: int


class Host(Enum):
    """The allowlist (docs/api-notes.md). Caps from docs/tool-surface.md."""

    REGISTRY = HostSpec("registry.modelcontextprotocol.io", "MCP Registry", 64 * KIB)
    PYPI = HostSpec("pypi.org", "PyPI", 512 * KIB)
    NPM = HostSpec("registry.npmjs.org", "npm registry", 256 * KIB)
    # About 4x the largest versioned query measured (tensorflow 2.4.0, 3,983,856 bytes).
    OSV = HostSpec("api.osv.dev", "OSV.dev", 16 * MIB)


_BY_HOSTNAME: Final[Mapping[str, Host]] = {h.value.hostname: h for h in Host}
ALLOWED_HOSTS: Final = frozenset(_BY_HOSTNAME)


class Query(Enum):
    """Every query string the scanner may send. Never built from user or target input."""

    INCLUDE_DELETED = (("include_deleted", "true"),)


class Accept(StrEnum):
    JSON = "application/json"
    NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
    PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
    PYPI_INTEGRITY = "application/vnd.pypi.integrity.v1+json"


class PostPath(StrEnum):
    """Every path the scanner may POST to."""

    OSV_QUERY = "/v1/query"


# The only (host, path) pairs post_json accepts.
ALLOWED_POSTS: Final = frozenset({(Host.OSV, PostPath.OSV_QUERY)})


class PostBody:
    """Base for request bodies. Subclasses are built only by validating builders
    (clients/osv.py) and declare the one (host, path) pair they may be sent to."""

    target: ClassVar[tuple[Host, PostPath]]

    def to_json_bytes(self) -> bytes:
        raise NotImplementedError


class HttpError(Exception):
    """Base for failures a caller turns into a skipped check (see skip_reason)."""

    skip_reason: SkipReason = SkipReason.SOURCE_UNREACHABLE


class HostNotAllowed(HttpError):
    """A request would leave the allowlist, or use a method or path that is not allowed.
    Refused before the request exists."""


class SourceUnreachable(HttpError):
    """Timeouts, connection errors, 429 or 5xx after retries, or a refused redirect."""


class SourceTimeout(SourceUnreachable):
    """The call hit the total time cap (TOTAL_TIMEOUT_SECONDS)."""


class ResponseTooLarge(HttpError):
    """The body exceeded the cap; the stream was closed without reading the rest."""

    skip_reason = SkipReason.RESPONSE_TOO_LARGE

    def __init__(self, service: str, limit: int) -> None:
        super().__init__(f"{service} response exceeded the {limit}-byte cap.")
        self.limit = limit


class ShapeMismatch(HttpError):
    """A body was not JSON of the expected shape (or too deeply nested to parse)."""

    skip_reason = SkipReason.SHAPE_MISMATCH


def _reject_constant(name: str) -> Any:
    raise ShapeMismatch(f"JSON contained {name}, which is not valid JSON.")


def safe_json(data: bytes) -> Any:
    """Parse a response body as JSON, or raise ShapeMismatch.

    Nesting deeper than MAX_JSON_DEPTH is refused before parsing, so a hostile body cannot
    hit the recursion limit; RecursionError is still caught. NaN and Infinity are refused.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ShapeMismatch("Response body is not UTF-8.") from None
    if text_depth_exceeds(text, MAX_JSON_DEPTH):
        raise ShapeMismatch(f"Response JSON is nested deeper than {MAX_JSON_DEPTH}.")
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError:
        raise ShapeMismatch("Response JSON is nested too deeply.") from None
    except ValueError:
        raise ShapeMismatch("Response body is not valid JSON.") from None


@dataclass(frozen=True)
class Response:
    status: int
    # Empty when status_only=True. Hostile data: parse it, never echo it in errors.
    body: bytes
    host: Host

    def json(self) -> Any:
        """Decode the body with safe_json. Raises ShapeMismatch."""
        return safe_json(self.body)


def build_path(template: str, params: Mapping[str, str]) -> str:
    """Fill a code-defined path template, encoding each value as one path segment.

    Every character outside unreserved ASCII is percent-encoded, including "/" and "%",
    so a value can never add a segment, a query, or a fragment. "." and ".." are refused
    because a server may resolve them even when encoded.
    """
    if (
        not template.startswith("/")
        or any(c in template for c in "?#%\\")
        or "//" in template
    ):
        raise ValueError(
            "path template must be an absolute path with no query or escapes"
        )
    out: list[str] = []
    used: set[str] = set()
    for literal, field, spec, conv in string.Formatter().parse(template):
        if ".." in literal.split("/"):
            raise ValueError("path template may not contain '..' segments")
        out.append(literal)
        if field is None:
            continue
        if not field.isidentifier() or spec or conv:
            raise ValueError("path placeholders must be plain {name} fields")
        if field not in params:
            raise ValueError(f"missing path parameter {field!r}")
        value = params[field]
        if not isinstance(value, str) or not value or len(value) > _MAX_SEGMENT_LEN:
            raise ValueError(
                f"path parameter {field!r} must be a non-empty short string"
            )
        if value in (".", ".."):
            raise ValueError(f"path parameter {field!r} may not be '.' or '..'")
        out.append(quote(value, safe=""))
        used.add(field)
    if set(params) - used:
        raise ValueError("unused path parameters")
    return "".join(out)


def _allowed_host(url: httpx.URL) -> Host:
    """Return the Host for an https URL on the allowlist, or raise HostNotAllowed."""
    host = _BY_HOSTNAME.get(url.host)
    if (
        host is None
        or url.scheme != "https"
        or url.port not in (None, 443)
        or url.userinfo
    ):
        raise HostNotAllowed("Refused a request outside the allowed hosts.")
    return host


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse Retry-After as delta-seconds or an HTTP date."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _backoff(retry: int) -> float:
    return BACKOFF_BASE_SECONDS * 2**retry + random.uniform(0, BACKOFF_BASE_SECONDS)


@dataclass(frozen=True)
class _Retry:
    delay: float | None  # None: use backoff
    failure: str
    transport: bool


@dataclass(frozen=True)
class _Redirect:
    url: httpx.URL


@dataclass(frozen=True)
class _Request:
    method: str  # "GET" or "POST"; set only by get() and post_json()
    accept: Accept
    cap: int
    status_only: bool = False
    content: bytes | None = None


class HttpClient:
    """One per tool call: each tool opens its own unless given one, and audit_server
    shares one across its sub-checks. MAX_IN_FLIGHT_PER_HOST therefore bounds requests
    within one call, not across concurrent calls. Sends GET, and POST only through
    post_json."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                READ_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS
            ),
            follow_redirects=False,  # each hop is checked here: same host only
            trust_env=False,  # no proxy or netrc credentials from the environment
            # A jar whose policy accepts no domain: Set-Cookie is ignored, Cookie never sent.
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
            transport=transport,
        )
        self._in_flight = {
            name: asyncio.Semaphore(MAX_IN_FLIGHT_PER_HOST) for name in ALLOWED_HOSTS
        }

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self,
        host: Host,
        template: str,
        params: Mapping[str, str] | None = None,
        *,
        query: Query | None = None,
        accept: Accept = Accept.JSON,
        max_bytes: int | None = None,
        status_only: bool = False,
    ) -> Response:
        """GET a path on an allowlisted host and return status and body.

        2xx and non-retryable 4xx are returned (callers interpret 404 bodies). 3xx is
        followed only to the same host. 429/5xx and transport failures are retried, then
        raise SourceUnreachable. max_bytes can only lower the host's cap. With status_only,
        the body is not read and no size cap applies.
        """
        if not isinstance(host, Host):
            raise HostNotAllowed("Refused a request outside the allowed hosts.")
        if query is not None and not isinstance(query, Query):
            raise TypeError("query must be a Query constant")
        if not isinstance(accept, Accept):
            raise TypeError("accept must be an Accept constant")
        url = httpx.URL(
            scheme="https",
            host=host.value.hostname,
            raw_path=build_path(template, params or {}).encode("ascii"),
        )
        if query is not None:
            url = url.copy_with(params=dict(query.value))
        cap = host.value.max_bytes
        if max_bytes is not None:
            cap = min(cap, max_bytes)
        return await self._send(url, host, _Request("GET", accept, cap, status_only))

    async def post_json(self, host: Host, path: PostPath, body: PostBody) -> Response:
        """POST a code-built JSON body to the one allowed (host, path) pair.

        Refused before a request exists unless (host, path) is in ALLOWED_POSTS and the
        body was built for exactly that pair. Same caps, retries and errors as get().
        A redirect is never followed for a POST.
        """
        if (
            not isinstance(host, Host)
            or not isinstance(path, PostPath)
            or (host, path) not in ALLOWED_POSTS
        ):
            raise HostNotAllowed("Refused a POST outside the allowed host and path.")
        if not isinstance(body, PostBody) or type(body).target != (host, path):
            raise HostNotAllowed(
                "Refused a POST body not built for this host and path."
            )
        content = body.to_json_bytes()
        if not isinstance(content, bytes) or len(content) > MAX_REQUEST_BODY_BYTES:
            raise HostNotAllowed("Refused a POST body that is not small JSON bytes.")
        url = httpx.URL(
            scheme="https", host=host.value.hostname, raw_path=path.encode()
        )
        request = _Request("POST", Accept.JSON, host.value.max_bytes, content=content)
        return await self._send(url, host, request)

    async def _send(self, url: httpx.URL, host: Host, request: _Request) -> Response:
        deadline = asyncio.get_running_loop().time() + TOTAL_TIMEOUT_SECONDS
        try:
            async with asyncio.timeout_at(deadline):
                return await self._with_retries(url, request, deadline)
        except TimeoutError:
            logger.warning(
                "%s %s exceeded %gs total",
                request.method,
                host.value.hostname,
                TOTAL_TIMEOUT_SECONDS,
            )
            raise SourceTimeout(
                f"{host.value.service} did not respond within {TOTAL_TIMEOUT_SECONDS:g}s."
            ) from None

    async def _with_retries(
        self, url: httpx.URL, request: _Request, deadline: float
    ) -> Response:
        status_retries = 0
        transport_retries = 0
        redirects = 0
        while True:
            host = _allowed_host(url)
            result = await self._attempt(url, host, request)
            if isinstance(result, Response):
                return result
            if isinstance(result, _Redirect):
                service = host.value.service
                redirects += 1
                if request.method != "GET":
                    raise SourceUnreachable(f"{service} redirected a POST.")
                if redirects > MAX_REDIRECTS:
                    raise SourceUnreachable(f"{service} redirected too many times.")
                if result.url.host != url.host:
                    # Same host only, even between allowlisted hosts.
                    raise SourceUnreachable(f"{service} redirected to another host.")
                _allowed_host(result.url)  # https, default port, no userinfo
                url = result.url
                continue

            if result.transport:
                if transport_retries >= MAX_TRANSPORT_RETRIES:
                    raise SourceUnreachable(result.failure)
                transport_retries += 1
                delay = _backoff(0)
            else:
                if status_retries >= MAX_STATUS_RETRIES:
                    raise SourceUnreachable(result.failure)
                delay = (
                    result.delay
                    if result.delay is not None
                    else _backoff(status_retries)
                )
                status_retries += 1

            # Sleeping past the deadline cannot succeed; fail now with the real reason.
            if delay >= deadline - asyncio.get_running_loop().time():
                raise SourceUnreachable(result.failure)
            logger.info(
                "%s %s failed (%s); retrying in %.2fs",
                request.method,
                url.host,
                result.failure,
                delay,
            )
            await _sleep(delay)

    async def _attempt(
        self, url: httpx.URL, host: Host, request: _Request
    ) -> Response | _Retry | _Redirect:
        service = host.value.service
        headers = {"User-Agent": USER_AGENT, "Accept": request.accept.value}
        if request.content is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with (
                self._in_flight[url.host],
                self._client.stream(
                    request.method, url, headers=headers, content=request.content
                ) as response,
            ):
                status = response.status_code
                if status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        raise SourceUnreachable(
                            f"{service} sent a redirect without a target."
                        )
                    return _Redirect(url.join(location))
                if status == 429:
                    return _Retry(
                        _retry_after_seconds(response),
                        f"{service} is rate limiting requests.",
                        transport=False,
                    )
                if status >= 500:
                    return _Retry(
                        _retry_after_seconds(response),
                        f"{service} is unavailable (HTTP {status}).",
                        transport=False,
                    )
                if request.status_only:
                    return Response(status, b"", host)
                return Response(
                    status, await _read_capped(response, service, request.cap), host
                )
        except httpx.TimeoutException:
            return _Retry(None, f"{service} timed out.", transport=True)
        except httpx.TransportError:
            return _Retry(None, f"{service} is unreachable.", transport=True)


async def _read_capped(response: httpx.Response, service: str, cap: int) -> bytes:
    length = response.headers.get("Content-Length", "")
    if length.isdigit() and int(length) > cap:
        raise ResponseTooLarge(service, cap)
    chunks: list[bytes] = []
    total = 0
    # Decoded bytes, so a compressed body cannot expand past the cap unnoticed.
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > cap:
            raise ResponseTooLarge(service, cap)
        chunks.append(chunk)
    return b"".join(chunks)
