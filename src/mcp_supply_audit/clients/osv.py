"""OSV.dev package queries: POST /v1/query (docs/api-notes.md, "OSV.dev").

The request body is an OsvQuery. Constructing one validates every field, so a body can only
hold a validated package name, an ecosystem from OsvEcosystem, a validated version, and a page
token taken from the previous OSV response. Pagination stops on a missing token, a repeated
token, a page with no new advisories, or the page cap, and says which.
"""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Final

from fastmcp.exceptions import ToolError

from mcp_supply_audit.clients._http import (
    Host,
    HttpClient,
    PostBody,
    PostPath,
    Response,
    ShapeMismatch,
    SourceUnreachable,
)
from mcp_supply_audit.validation import (
    validate_npm_name,
    validate_pypi_name,
    validate_version,
)

MAX_QUERY_PAGES: Final = 2
_MAX_TOKEN_LEN: Final = 1024

# Fixed truncation reasons (never text from a response).
TRUNCATED_PAGE_CAP: Final = "page_cap"
TRUNCATED_TOKEN_REPEATED: Final = "token_repeated"
TRUNCATED_NO_PROGRESS: Final = "page_did_not_advance"


class OsvEcosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"


_NAME_VALIDATORS: Final = {
    OsvEcosystem.PYPI: validate_pypi_name,
    OsvEcosystem.NPM: validate_npm_name,
}


class InvalidQuery(ValueError):
    """A query field failed validation. Raised before any body exists."""


# Only parse_page passes this, so a PageToken cannot be made from anything but a response.
_FROM_RESPONSE: Final = object()


@dataclass(frozen=True)
class PageToken:
    value: str
    _origin: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._origin is not _FROM_RESPONSE:
            raise InvalidQuery("page tokens come only from an OSV response")
        if (
            not isinstance(self.value, str)
            or not 0 < len(self.value) <= _MAX_TOKEN_LEN
            or not all("!" <= c <= "~" for c in self.value)
        ):
            raise ShapeMismatch("OSV.dev returned a malformed page token.")


@dataclass(frozen=True)
class OsvQuery(PostBody):
    target: ClassVar = (Host.OSV, PostPath.OSV_QUERY)

    name: str
    ecosystem: OsvEcosystem
    version: str | None = None  # None: all versions
    page_token: PageToken | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ecosystem, OsvEcosystem):
            raise InvalidQuery("ecosystem must be an OsvEcosystem")
        try:
            # Validators strip; a valid field must already be in its stripped form.
            if _NAME_VALIDATORS[self.ecosystem](self.name) != self.name:
                raise InvalidQuery("package name has surrounding whitespace")
            if (
                self.version is not None
                and validate_version(self.version) != self.version
            ):
                raise InvalidQuery("version has surrounding whitespace")
        except ToolError:
            raise InvalidQuery("package name or version failed validation") from None
        if self.page_token is not None and not isinstance(self.page_token, PageToken):
            raise InvalidQuery("page_token must come from a previous OSV response")

    def to_json_bytes(self) -> bytes:
        body: dict[str, Any] = {
            "package": {"name": self.name, "ecosystem": self.ecosystem.value}
        }
        if self.version is not None:
            body["version"] = self.version
        if self.page_token is not None:
            body["page_token"] = self.page_token.value
        return json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode(
            "ascii"
        )


def build_query(
    name: str,
    ecosystem: OsvEcosystem,
    version: str | None = None,
    page_token: PageToken | None = None,
) -> OsvQuery:
    """Build a validated OSV query body. Raises InvalidQuery."""
    return OsvQuery(name, ecosystem, version, page_token)


@dataclass(frozen=True)
class QueryPage:
    # Advisory records as OSV returned them: hostile text, sanitize before showing.
    vulns: tuple[dict[str, Any], ...]
    next_page_token: PageToken | None


def parse_page(response: Response) -> QueryPage:
    """Parse one /v1/query response. Raises ShapeMismatch or SourceUnreachable.

    OSV answers {} both for "no advisories" and for a package it does not know.
    """
    if response.status == 400:
        # OSV's 400s ("invalid ecosystem", "invalid cursor") mean it rejected our query.
        raise ShapeMismatch("OSV.dev rejected the query (HTTP 400).")
    if response.status != 200:
        raise SourceUnreachable(f"OSV.dev returned HTTP {response.status}.")
    data = response.json()
    if not isinstance(data, dict):
        raise ShapeMismatch("OSV.dev returned a non-object response.")
    vulns = data.get("vulns", [])
    if not isinstance(vulns, list) or not all(
        isinstance(v, dict) and isinstance(v.get("id"), str) for v in vulns
    ):
        raise ShapeMismatch("OSV.dev returned vulns in an unexpected shape.")
    token = data.get("next_page_token")
    if token is not None and not isinstance(token, str):
        raise ShapeMismatch("OSV.dev returned a malformed page token.")
    return QueryPage(
        tuple(vulns),
        PageToken(token, _origin=_FROM_RESPONSE) if token is not None else None,
    )


@dataclass(frozen=True)
class QueryResult:
    vulns: tuple[dict[str, Any], ...]  # unique by id, in first-seen order
    pages: int
    truncated: bool
    truncation_reason: str | None  # one of the TRUNCATED_* constants


async def query_vulns(
    http: HttpClient,
    name: str,
    ecosystem: OsvEcosystem,
    version: str | None = None,
    *,
    max_pages: int = MAX_QUERY_PAGES,
) -> QueryResult:
    """Collect advisories for a package (and version), following page tokens.

    Raises InvalidQuery before any request, and the HttpError subclasses from the helper.
    """
    query = build_query(name, ecosystem, version)
    seen_ids: set[str] = set()
    seen_tokens: set[str] = set()
    collected: list[dict[str, Any]] = []
    pages = 0
    while True:
        response = await http.post_json(Host.OSV, PostPath.OSV_QUERY, query)
        page = parse_page(response)
        pages += 1
        new = [v for v in page.vulns if v["id"] not in seen_ids]
        for v in new:
            seen_ids.add(v["id"])
            collected.append(v)

        token = page.next_page_token
        reason = None
        if token is None:
            return QueryResult(tuple(collected), pages, False, None)
        if not new:
            reason = TRUNCATED_NO_PROGRESS  # e.g. page 1 again: a loop, not more data
        elif token.value in seen_tokens:
            reason = TRUNCATED_TOKEN_REPEATED
        elif pages >= max_pages:
            reason = TRUNCATED_PAGE_CAP
        if reason is not None:
            return QueryResult(tuple(collected), pages, True, reason)
        seen_tokens.add(token.value)
        query = build_query(name, ecosystem, version, page_token=token)
